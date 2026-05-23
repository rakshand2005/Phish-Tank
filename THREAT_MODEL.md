# 🛡️ Threat Model Write-Up
## Security Analysis & Risk Assessment
**v0.1.0 — Team 15**

### Executive Summary
**Phish Net** is a supply-chain security tool for Docker container images. It occupies a privileged position in a CI/CD pipeline: it has access to the Docker socket, makes outbound network calls to vulnerability databases, and its output directly gates production deployments. This threat model identifies six specific supply-chain attack scenarios the tool defends against, maps each to MITRE ATT&CK techniques, details the implemented defenses, and documents residual risks and recommendations.

### Scope
- The Phish Net scanner CLI and all modules in `scanner/` including the new `remediate.py`.
- External data dependencies: Docker Hub API, Trivy vulnerability DB, EPSS API (FIRST.org), CISA KEV feed, Cosign/Sigstore infrastructure.
- The execution environment: CI runner or developer workstation with Docker socket access.
- **Out of scope:** vulnerabilities in the scanned images themselves (that is the tool's output, not its attack surface).

---

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Threat Scenario |
|--------------|----------------|-----------------|
| **T1195.001** | Supply Chain Compromise: Software Dependencies | Scenarios 1 and 5 - compromised build, known CVEs |
| **T1195.002** | Supply Chain Compromise: Supply Chain | Scenario 2 - silent tag overwrite (tag poisoning) |
| **T1036** | Masquerading | Scenario 4 - typosquatting |
| **T1036.005** | Match Legitimate Name or Location | Scenario 3 - fake version tags |
| **T1553.002** | Subvert Trust Controls: Code Signing | Scenario 6 - unsigned publisher artifacts |
| **T1190** | Exploit Public-Facing Application | Scenario 5 - known CVE exploitation |

---

### Threat Scenarios & Defenses

#### Scenario 1 - Supply Chain Compromise (The SolarWinds Scenario)
- **Attack:** An attacker compromises a legitimate publisher's build server or source repository, injects a malicious backdoor during compilation, and the publisher unknowingly signs and distributes the compromised image with their official key.
- **Why standard signature verification is insufficient:** `cosign verify` only proves the publisher signed the image - it cannot prove the image was built from unmodified source. The attacker's backdoor will carry a valid signature.
- **Implemented defense - SLSA Provenance via `cosign verify-attestation`:**
  - The tool checks for a cryptographically signed receipt of the exact build ingredients and environment (SLSA Provenance).
  - If an attacker injects code during the build, the final image will not match the attested build materials, and the discrepancy is flagged as a severe supply-chain failure.
- **Residual risk:** An attacker who compromises both the source repository and the SLSA attestation infrastructure could bypass this check. This is a systemic risk outside the project's control.

#### Scenario 2 - Tag Poisoning (Silent Overwrite)
- **Attack:** An attacker compromises a publisher's Docker Hub account and overwrites an existing, widely-used tag (e.g., `redis:7.0.11`) with a malicious image. The next `docker pull` silently fetches the malicious version because developers rely on mutable tags.
- **Implemented defense - Digest Drift Detection:**
  - `integrity.py` resolves the local SHA-256 digest of what was originally pulled.
  - It then queries the OCI Registry API for the current digest of that same tag.
  - A digest mismatch immediately blocks the pipeline and alerts the user to Digest Drift.
  - Users are also actively warned to use digest pinning (`@sha256:...`) instead of mutable tags.
- **Residual risk:** A first-time pull of a poisoned tag has no previous digest to compare against. **Mitigation:** pin images to digests from the first pull and store the pinned reference in version control.

#### Scenario 3 - Fake Version Tag Injection
- **Attack:** An attacker registers a plausible but entirely fabricated version tag (e.g., `nginx:1.999.0` or `python:3.11.99`) and tricks a developer into pulling it via social engineering or a compromised Dockerfile.
- **Implemented defense:**
  - The tool queries the Docker Hub API for the specific tag provided.
  - A 404 response proves the version string is fabricated - the tool flags this as a Fake Version Tag and blocks execution before any pull occurs.

#### Scenario 4 - Typosquatting
- **Attack:** An attacker uploads a malicious image with a name one or two characters off from a popular official image (e.g., `ngimx` instead of `nginx`, or `ubntu` instead of `ubuntu`), hoping developers make a typo.
- **Implemented defense - Levenshtein Distance + Live Registry Validation:**
  - Levenshtein edit distance is computed against a curated list of 50+ popular Docker Hub images. A distance of 1 or 2 raises a Typosquat Warning.
  - A live Docker Hub API lookup confirms whether the image namespace/repo actually exists.
  - If `typosquat_risk` is True, the CLI prompts the user for interactive confirmation before continuing.
- **Residual risk:** A typosquatted image that the attacker has successfully registered on Docker Hub will pass the registry check. **Mitigation:** always use digest pinning.

#### Scenario 5 - Exploitation of Known Vulnerabilities
- **Attack:** The container image contains outdated OS packages or application dependencies with publicly known CVEs. Attackers scan for these to gain initial access or escalate privileges.
- **Implemented defense - Trivy + EPSS + CISA KEV:**
  - A CycloneDX SBOM is generated and cross-referenced against the Trivy vulnerability database (auto-refreshed if >24 h stale to prevent window-of-opportunity attacks).
  - Every CVE is enriched with EPSS (statistical probability of exploitation in the next 30 days) and the CISA KEV flag (currently being actively exploited by nation-state actors or ransomware).
  - A composite `priority_score` (0-10) replaces reliance on theoretical CVSS scores alone, blocking only CVEs that represent real and immediate risk.
  - Layer attribution identifies which specific Dockerfile instruction introduced each vulnerable package, enabling targeted fixes.
  - The new `scanner fix` command auto-generates a patched Dockerfile with base image upgrades and pinned package versions.

#### Scenario 6 - Unsigned Publisher Artifacts
- **Attack:** An attacker uploads an image masquerading as a legitimate publisher. Because the image is unsigned, there is no cryptographic proof of publisher identity.
- **Implemented defense - Cosign Signature Verification:**
  - `cosign verify` is run before scanning, tying the image to the trusted publisher's public key or OIDC identity via Sigstore's keyless transparency log.
  - An unsigned image triggers a warning. The scan continues (to still report CVEs) but the unsigned status is prominently flagged in the report.
- **Residual risk:** Compromise of the Sigstore root of trust. Systemic risk outside project control.

---

### Additional Attack Surface: The Scanner Itself

#### Docker Socket Exposure
The scanner mounts `/var/run/docker.sock`, which grants root-equivalent access to the host.
- **Implemented mitigations:** only `docker.images.pull()` and `docker.api.inspect_image()` are called - no containers are started or modified.
- **Recommendation:** add `USER scanner` (non-root) to the Dockerfile.

#### Compromised EPSS or KEV Feed
A MITM of the FIRST.org EPSS API or CISA KEV feed could suppress exploit scores.
- **Mitigation:** both feeds are fetched over HTTPS with TLS validation. On network error, scores default conservatively (0.0 / empty set) - failure never suppresses a score.

#### Gate Threshold Manipulation
An insider could raise `GATE_THRESHOLD` to 10.0 so the CI gate never fires.
- **Mitigation:** the constant is a named, auditable value at the top of `scoring.py`.
- **Recommendation:** add a startup assertion validating `0 < GATE_THRESHOLD <= 10` and that scoring weights sum to 1.0.

---

### Security Recommendations

| Priority | Recommendation | Module |
|----------|----------------|--------|
| **HIGH** | Add `USER scanner` (non-root) to Dockerfile | `Dockerfile` |
| **HIGH** | Enforce HTTPS certificate pinning for EPSS and KEV URLs | `scoring.py` |
| **MEDIUM** | Add startup assertion: weights sum to 1.0 and `0 < GATE_THRESHOLD <= 10` | `scoring.py` |
| **MEDIUM** | Support digest-only image references in CI (reject mutable tags by default) | `integrity.py` |
| **MEDIUM** | Publish SLSA provenance attestation for the scanner image itself | CI / `Dockerfile` |
| **LOW** | Implement content-hash verification for downloaded Trivy DB | `matcher.py` |
| **LOW** | Add retry with exponential back-off for EPSS/KEV API calls | `scoring.py` |
