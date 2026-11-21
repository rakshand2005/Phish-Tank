# 🛡️ Phish Net - Container Security Tool

## Code Comments & Module Guide
**v0.1.0 — Team 15**

---

### `phishnet/integrity.py` - Image Integrity Verification
* **`verify_image_exists_on_registry(image_name)`**
  Queries the official Docker Registry API to confirm if the namespace/image is a real, registered public artifact or a non-existent typosquat. Makes a live call to Docker Hub API. A 404 response proves the image is fraudulent or typo-squatted. Falls back gracefully on network failure.
* **`check_fake_version_tag(image_name)`**
  Detects syntactically invented / non-existent version tags by querying the Docker Hub tags API.
* **`check_tag_poisoning(image_name)`**
  Detects supply chain tag poisoning by comparing the local image digest (`docker inspect`) against the current remote registry digest (fetched via Docker Hub API).
* **`check_typosquat(image_name)`**
  Uses Levenshtein distance to detect names that are suspiciously close to well-known Docker Hub images but not an exact match.
* **`verify_signature(image_name)`**
  Runs `cosign verify` to check the image against the Sigstore public instance.
* **`verify_sbom_attestation(image_name)`**
  Runs `cosign verify-attestation --type slsaprovenance` to check for SLSA provenance. Non-zero exit code is reported as a warning. Standard `cosign verify` is insufficient here because a compromised publisher's key could still sign a backdoored image - SLSA provenance provides a signed receipt of the exact build environment.
* **`check_digest_pinning(image_name)`**
  Warns if the image reference uses a mutable tag rather than `@sha256:...` Digest pinning is recommended for reproducible builds.
* **`verify_image(image_name)`**
  Orchestrates all integrity checks and returns a single `IntegrityResult`. Typosquat risk is the only condition that triggers an interactive confirmation prompt in the CLI.

---

### `phishnet/sbom.py` - SBOM Generation
* **`generate_sbom(target, output_dir, target_kind)`**
  Runs `trivy image --format cyclonedx` and parses the resulting JSON file. Raises `RuntimeError` on Trivy failure, missing binary, or 300-second timeout. Returns the parsed CycloneDX dictionary.
* **`get_packages(sbom)`**
  Iterates the components array of a CycloneDX document and converts each entry to a `Package` dataclass. Type classification is delegated to `_classify_package`.
* **`_classify_package(component)`**
  Maps a CycloneDX purl prefix (e.g., `pkg:deb/`, `pkg:pypi/`) to one of the internal type labels. Falls back to the CycloneDX type field, then to `unknown`.

---

### `phishnet/matcher.py` - CVE Matching
* **`check_db_freshness(max_age_hours)`**
  Reads `metadata.json` from Trivy's local cache (checked in three OS-specific locations). Computes DB age in hours. If no metadata file exists, the DB is treated as absent and flagged stale.
* **`update_db()`**
  Shells out to `trivy db update`. Should be called before `scan_cves()` when `DBFreshnessResult.is_stale` is True, or when `--update-db` is passed.
* **`scan_cves(target, target_kind)`**
  Runs `trivy image --format json` and returns the raw parsed JSON.
* **`parse_cve_matches(trivy_json)`**
  Traverses the Trivy JSON Results array and converts each Vulnerability entry to a `CVEMatch`. Extracts: CVE ID, package name, installed/fixed versions, severity, CVSS score, and description.

---

### `phishnet/scoring.py` - Risk Scoring & CI Gate
* **Design rationale**
  Three signals combined: CVSS v3 (theoretical severity), EPSS (statistical exploit probability from FIRST.org), CISA KEV (active exploitation flag). KEV gets the highest weight (0.40) because active exploitation is the clearest signal of real-world danger.
* **`_fetch_epss_scores(cve_ids)`**
  Batches CVE IDs into groups of `MAX_EPSS_BATCH` (30) and queries the FIRST.org EPSS API. Returns a dict mapping CVE ID to EPSS probability. Defaults to 0.0 on network errors.
* **`_fetch_kev_set()`**
  Downloads the CISA KEV JSON feed and returns a set of actively-exploited CVE IDs. Falls back to an empty set on failure - this is a conservative fallback that does not suppress any scores.
* **`_compute_priority(cvss, epss, in_kev)`**
  Applies the weighted formula: `priority = (W_CVSS x cvss/10 + W_EPSS x epss + W_KEV x int(in_kev)) x 10`. Result is clamped to `[0, 10]`.
* **`enrich_and_score(cves)`**
  Main entry point called from `main.py` after `parse_cve_matches()`. Fetches EPSS scores and the KEV set, then annotates each `CVEMatch` with `epss_score`, `in_kev`, and `priority_score`. Returns the enriched list.
* **`gate_decision(cves)`**
  Returns `(exit_code, reason)`. `exit_code` is 1 if any CVE has `priority_score > GATE_THRESHOLD` (default 7.0). This is the primary CI gate. The legacy `--fail-on` severity gate is retained for backwards compatibility.

---

### `phishnet/layers.py` - Layer Attribution
* **`get_docker_client()`**
  Creates a Docker SDK client via `docker.from_env()` and pings the daemon. Raises `RuntimeError` with an actionable message if the daemon is unreachable.
* **`get_layer_metadata(image_name)`**
  Pulls the image if not cached, then inspects its RootFS layers. Returns a list of `LayerInfo` objects with the creating command extracted from image history.
* **`attribute_cves_to_layers(cves, layer_infos)`**
  For each CVE, determines which layer introduced the vulnerable package by matching the package installation command in layer history. Sets `layer_id` and `layer_command` on the `CVEMatch` and increments the layer's `cve_count`.
* **`generate_fix_suggestions(cves, layer_infos)`**
  For fixable CVEs (`fixed_version` is known), generates a Dockerfile fix suggestion showing the original `RUN` instruction and what it should be changed to. Stored in `CVEMatch.fix_suggestion`.

---

### `phishnet/remediate.py` - Auto-Remediation (NEW)
*This module is the "wow factor" feature - `phishnet fix nginx:1.14` generates a hardened Dockerfile in one command.*
* **Data structures**
  - `DockerfileLine` - a single parsed Dockerfile instruction with its original text, instruction keyword, arguments, and a modification flag used to annotate patched lines in the output.
  - `RemediationPlan` - the complete plan: original image, upgraded base, per-manager package pins (apt, apk, pip, npm), security hardening rules, and counts of fixed vs unfixable CVEs.
* **`reconstruct_dockerfile(image_name)`**
  Runs `docker history --no-trunc` to get full layer commands, reverses the list (history is newest-first), and rebuilds an approximate Dockerfile as a list of `DockerfileLine` objects. Falls back to a minimal single-FROM Dockerfile if Docker is unavailable.
* **`_parse_history_line(created_by)`**
  Converts a `docker history` CreatedBy string into an (instruction, arguments) tuple. Strips the `/bin/sh -c` wrapper, detects `#(nop)` metadata instructions (ENV, EXPOSE, WORKDIR, ENTRYPOINT, etc.), and maps plain commands to RUN.
* **`build_remediation_plan(image_name, cves, dockerfile_lines)`**
  Produces a `RemediationPlan` by: (1) looking up the image in `BASE_IMAGE_UPGRADES` for a base upgrade path; (2) categorising fixable CVEs by package manager (apt/apk/pip/npm) using the layer_command; (3) checking for missing security hardening (non-root user, HEALTHCHECK).
* **`BASE_IMAGE_UPGRADES`**
  A hardcoded dict mapping ~30 known-old base image tags to their modern equivalents - nginx 1.14-1.25 to 1.27-bookworm, python 3.7-3.11-slim to 3.12-slim-bookworm, node 14-20 to 22-slim, ubuntu 18.04-22.04 to 24.04, debian stretch/buster/bullseye to bookworm-slim, and alpine 3.12-3.18 to 3.20.
* **`generate_patched_dockerfile(plan)`**
  Renders the patched Dockerfile string from the plan. Emits a header comment block, updated FROM line, security LABEL entries, all original instructions (with patched RUN commands where applicable), an apt/apk/pip/npm pinning layer for packages not already handled, and security hardening instructions at the end.
* **`_patch_run_command(cmd, plan)`**
  Uses regex to find bare package names in an existing apt-get install command and rewrite them with the pinned fixed version (`package=version` format).
* **`print_remediation_report(plan, patched_dockerfile)`**
  Renders a Rich terminal report showing: remediation summary stats (CVEs fixed, package pins, hardening rules), a package version pins table, a security hardening table, and a syntax-highlighted diff of the generated Dockerfile.
* **`save_patched_dockerfile(content, output_dir)`**
  Writes the patched content to `Dockerfile.patched` in the specified output directory. Creates the directory if it does not exist.

---

### `phishnet/main.py` - CLI Entry Point
* **scan command**
  Runs the full pipeline (integrity → SBOM → CVE matching → scoring → layer attribution) with Rich spinner progress indicators. Outputs a terminal report or JSON depending on `--output`. The priority-based CI gate fires after layer attribution; the legacy `--fail-on` gate fires afterward for backwards compatibility.
* **integrity command**
  Runs `integrity.py` checks only - no SBOM or CVE scan. Useful for fast pre-pull validation in scripts.
* **scan-dir command**
  Scans source dependency manifests and lockfiles with Trivy filesystem mode, then applies the same CVE parsing, EPSS/KEV scoring, reporting, and CI gates. It skips image integrity checks and Docker-layer attribution.
* **fix command (NEW)**
  Runs the full scan pipeline to collect CVEs and layer metadata, then invokes `remediate.build_remediation_plan()` and `remediate.generate_patched_dockerfile()`. Displays the remediation report via `print_remediation_report()` and optionally saves to disk via `save_patched_dockerfile()`.

#### Bug fixes documented inline
* **BUG 1**: `from __future__ import annotations` is now the very first statement.
* **BUG 2**: `import logging` is on its own clean line.
* **BUG 3+4**: `enrich_and_score` and `gate_decision` are called inside `scan()` after `cves` is populated, not at module level.
