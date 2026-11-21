# Phish Net — Implementation Plan (v0.1 → v1.0)

Goal: turn the current prototype into a complete, defensible Phish Net tool whose behaviour matches its README and threat model.

Status tags used below: **[V]** = verified by running code, **[R]** = found by reading, not yet reproduced. Every **[R]** item gets reproduced in Phase 0 before any fix is written.

---

## 1. Definition of Done

1. `docker run ... phishnet scan <image>` and `phishnet scan <image>` both work from a clean machine.
2. Each of the 6 threat scenarios in `THREAT_MODEL.md` has a reproducible demo and an automated test.
3. Integrity failures (fake tag, poisoned tag, non-existent image) **block** the gate; they do not just warn.
4. Gate decisions are explainable, configurable, and consistent between the banner, exit code and JSON output.
5. OS **and** language packages are scanned.
6. `phishnet fix` output builds, and a re-scan shows a measurable CVE drop.
7. CI runs real tests (offline, mocked) plus one integration smoke test that can actually fail.
8. Docs describe exactly what the code does, including limitations.

---

## 2. Known Gaps (baseline)

| # | Gap | Where | Tag |
|---|-----|-------|-----|
| 1 | Container entrypoint does not invoke the `phishnet` script | `Dockerfile`, `pyproject.toml` | V |
| 2 | Without KEV, max priority is 6.0 < gate 7.0, so only KEV CVEs (or the buggy 1.25x multiplier) can block | `scoring.py` | V |
| 3 | Layer attribution consumes diff IDs for empty layers → wrong layer/command | `layers.py:get_layer_metadata` | V (logic reproduced in isolation) |
| 4 | Poison multiplier is fed a *package name*, not the image name, so it effectively never fires | `scoring.py:_check_digest_drift` | R |
| 5 | "Outdated" multiplier compares a package version to the latest *image tag* of `library/<pkg>`; one HTTP call per CVE | `scoring.py` | R |
| 6 | Tag poisoning only edits `signature_warning`; `IntegrityResult.passed` ignores it | `integrity.py`, `models.py` | R |
| 7 | Digest HEAD only accepts single-manifest types; multi-arch `RepoDigests` hold the index digest → likely false positives | `integrity.py` | R |
| 8 | `ghcr.io/org/app` is looked up on Docker Hub as namespace `ghcr.io` → 404 → flagged typosquat | `integrity.py` | R |
| 9 | `click.confirm` hangs in CI; warnings go to stdout and corrupt `--output json` | `main.py` | R |
| 10 | `--pkg-types os` hardcoded: Python/Node/Java never scanned | `sbom.py`, `matcher.py` | R |
| 11 | Cosign uses `.*` identity/issuer; attestation checks `cyclonedx`, not SLSA provenance | `integrity.py` | R |
| 12 | `fix` pins old-distro versions while upgrading base; `groupadd` on Alpine; `USER appuser`; fake `HEALTHCHECK` | `remediate.py` | R |
| 13 | Banner uses severity, exit code uses priority; literal `{image}`; uses an outdated command name | `main.py` | R |
| 14 | Tests are print scripts with no assertions; smoke test masks exit code via `head` | `tests/`, `publish.yml` | R |
| 15 | Docs drift (function names, timeouts, SLSA vs CycloneDX) | `CODE_COMMENTS.md`, `THREAT_MODEL.md` | R |

---

## 3. Improving the Idea (v1.0 concept)

The prototype is "Trivy + a few checks + a score". These changes make it a distinct tool.

### 3.1 Two-axis verdict instead of one scalar
Split the decision into two independent axes, then combine:

- **Trust verdict** (is this image what I think it is?): `TRUSTED / SUSPECT / BLOCK`
  - BLOCK: fake tag, non-existent repo, digest drift vs lockfile, typosquat of a popular image.
  - SUSPECT: unsigned, unpinned, unverified publisher, very new repo.
- **Vulnerability verdict** (is it safe to run?): `PASS / WARN / BLOCK` from CVE policy.
- **Final gate** = worst of the two. Today poisoning only inflates a CVE score; a poisoned image with zero CVEs would pass.

### 3.2 Publisher trust signals (replaces pure Levenshtein)
Use Docker Hub repo metadata (official / verified publisher, pull count, repo age, last updated). A name 1–2 edits from `nginx` with 40 pulls and created last week is far stronger evidence than edit distance alone, and legitimate small images stop being false positives.

### 3.3 Digest lockfile (`phishnet.lock`)
Solves the documented **first-pull blind spot**. `phishnet lock <image>` records tag → digest (+ cosign result) in a committed file. CI then checks the registry against the lockfile *before pulling*. Drift = block. Works like `package-lock.json` for images.

### 3.4 Pre-pull checks
Run fake-tag, typosquat, digest and signature checks against the registry **without `docker pull`**, so a malicious image is never even downloaded.

### 3.5 Scan what you actually use
`phishnet scan-file Dockerfile|docker-compose.yml|k8s.yaml` extracts every `FROM` / `image:` and scans each one. This is how it fits a real pipeline.

### 3.6 Closed-loop remediation
`phishnet fix` → build patched image → re-scan → print a **before/after delta** (CVE count, KEV count, top risk). If the delta is not an improvement or the build fails, say so. Base-image suggestions come from the live Hub tags API (same family, newest non-EOL), not a hardcoded table.

### 3.7 Policy-as-code (`.phishnet.yml`)
Rules, not constants: threshold, weights, `block_on_kev`, `max_epss`, `require_signature`, `require_digest_pin`, `allowed_registries`, plus an ignore list with **expiry dates and reasons**.

### 3.8 Standard outputs
SARIF (GitHub Security tab), HTML report, saved CycloneDX SBOM, JSON with a versioned schema.

---

## 4. Target Architecture

```
CLI (main.py)
  └─ policy.py        load .phishnet.yml, defaults, validation (weights sum to 1, threshold in (0,10])
  └─ registry.py      NEW: image-ref parsing, multi-registry support, token auth,
                      manifest/digest (index-aware), tag exists, repo metadata. Cached.
  └─ integrity.py     uses registry.py; returns structured findings (not strings)
  └─ lock.py          NEW: read/write/verify phishnet.lock
  └─ sbom.py / matcher.py   Trivy wrappers (pinned version, configurable pkg-types)
  └─ scoring.py       EPSS/KEV (cached, retries), priority score; no per-CVE HTTP
  └─ verdict.py       NEW: trust verdict + vuln verdict + final gate + reasons
  └─ layers.py        correct layer mapping
  └─ remediate.py     v2 (live base-image pick, build + re-scan delta)
  └─ report.py        NEW: terminal, JSON, SARIF, HTML
```

Data-model change (`models.py`): replace string-only warnings with structured findings.

```python
@dataclass
class Finding:
    id: str            # "FAKE_TAG", "TAG_DRIFT", "TYPOSQUAT", "UNSIGNED", "UNPINNED", ...
    severity: str      # INFO / WARN / BLOCK
    message: str
    evidence: dict     # digests, edit distance, HTTP status, etc.
```

`IntegrityResult.findings: list[Finding]`; `passed` = no BLOCK findings. This removes the current hack of stuffing poison/fake-tag text into `signature_warning` / `typosquat_warning`.

---

## 5. Phases

Effort is in focused work-days for one person; adjust to your team size.

### Phase 0 — Baseline and verification (1–1.5 d)
- [ ] Create `tests/` with pytest + `conftest.py`; add `requests-mock`/`responses` and monkeypatch helpers for `subprocess.run`.
- [ ] Reproduce each **[R]** gap above as a failing test (mark `xfail` with the gap number).
- [ ] Record installed versions (Trivy, Cosign, `docker` SDK, `rich`, `click`) and check behaviour against *those* versions, not docs from memory.
- [ ] Check Trivy flags actually used (`--pkg-types`, `--skip-db-update`, `--skip-java-db-update`) exist in the pinned Trivy version.
- [ ] Capture a real multi-arch digest case (e.g. `nginx`) to confirm or refute gap 7.

**Exit:** a red test per confirmed bug; list of refuted ones removed from section 2.

### Phase 1 — Make it run and make claims true (2 d)
| Task | Files | Acceptance |
|------|-------|-----------|
| Set the container entrypoint to `phishnet`; update docs and install aliases consistently | `pyproject.toml`, `Dockerfile`, `SETUP.md`, `install.*` | `docker run <img> --help` works in CI |
| Fix layer mapping (skip empty layers; assert real-layer count == `len(diff_ids)`; fall back to command-text match) | `layers.py` | Unit test with mixed empty/non-empty history |
| Banner, exit code and JSON share one verdict object | `main.py`, `verdict.py` | Test: banner text matches exit code in all cases |
| JSON mode: all human output to stderr; stdout is only JSON | `main.py` | `phishnet scan x -o json \| jq .` succeeds when a warning fires |
| `--yes` / non-interactive: never prompt when stdin is not a TTY; typosquat BLOCK fails closed | `main.py` | Test with piped stdin |
| Fix the `{image}` f-string and use `phishnet` consistently in messages | `main.py` | grep clean |

### Phase 2 — Registry layer and integrity correctness (3 d)
- [ ] New `registry.py`: parse `host/ns/repo:tag@digest`; default to Docker Hub only when no host; support ghcr.io / quay.io / ECR / GCR via the OCI distribution API (anonymous token flow).
- [ ] Digest fetch sends Accept for **index and manifest** types (`manifest.list.v2+json`, `oci.image.index.v1+json`, manifest v2, OCI manifest); compare like-for-like with the `RepoDigests` entry. Alternatively shell out to `crane digest` / `docker buildx imagetools inspect` if simpler. Decide in Phase 0 based on what reproduces.
- [ ] Typosquat: Levenshtein **plus** repo metadata (official / verified, pulls, age). Non-Hub registries skip the Hub-existence check and use the registry's own manifest HEAD.
- [ ] Replace string warnings with `Finding`s; typosquat, fake tag and tag drift are separate findings with their own severity.
- [ ] Cosign: configurable trusted identity/issuer (from policy); default mode reports "signed by <identity>" rather than "signed". Attestation check uses `slsaprovenance` / `slsaprovenance1` and, if present, compares the subject digest to the image digest. If full material comparison is out of scope, **say so in the docs**.
- [ ] Cache registry lookups per run; retry with backoff on 429/5xx.

**Exit:** scenarios 2, 3, 4, 6 each produce the correct BLOCK/WARN finding in a mocked test; a `ghcr.io/org/app` ref no longer false-positives.

### Phase 3 — Scoring and gate redesign (2 d)
- [ ] `verdict.py`: trust verdict + vulnerability verdict + final gate with human-readable reasons list.
- [ ] Vulnerability policy (all configurable): block if `in_kev`; block if `priority >= threshold`; block if `severity == CRITICAL and fixable and epss >= x`. Remove the "KEV-only can ever block" behaviour.
- [ ] Remove per-CVE Docker Hub calls. Replace the "outdated" multiplier with something defensible, e.g. *fix available but not applied* (+bump) or image age from tag `last_updated` (one call per image).
- [ ] Poison/drift becomes a **trust** BLOCK, not a score multiplier. Keep the score pure (CVSS/EPSS/KEV).
- [ ] Startup validation: weights sum to 1.0; `0 < threshold <= 10` (already recommended in your threat model).
- [ ] Fix docstring examples to match real numbers (e.g. CVSS 9.8 / EPSS 0.01 → 2.485).

**Exit:** table-driven tests for score math and gate; CVSS 10 / EPSS 1.0 / no KEV is handled by an explicit policy rule, not by accident.

### Phase 4 — Coverage (2–3 d)
- [ ] Make Trivy `--pkg-types` configurable; default `os,library`. Update `sbom.py` / `matcher.py` and the `Package` / `CVEMatch` models (already have `pkg_type`).
- [ ] Layer attribution and fix suggestions for pip/npm/maven where Trivy provides the target path.
- [ ] `phishnet scan-file`: parse `FROM` (incl. multi-stage, `ARG` substitution, `--platform`), compose `image:`, and k8s `image:`; scan each unique image; aggregate report.
- [ ] `phishnet lock` / `phishnet verify-lock` (see 3.3). Pre-pull mode (3.4).

**Exit:** a Python-library CVE in a test image is detected; `scan-file` on a sample multi-stage Dockerfile scans every stage.

### Phase 5 — Reporting, config, suppressions (2 d)
- [ ] `report.py`: terminal (existing Rich code moved), JSON with `schema_version`, **SARIF 2.1.0**, standalone HTML, `--sbom-out`.
- [ ] `.phishnet.yml` loader with defaults + validation + `--config` override; env var overrides for CI.
- [ ] Ignore list: `{id, package?, reason, expires}`; expired entries are reported and no longer suppress.
- [ ] Add CLI flags: `--format`, `--output-file`, `--policy`, `--yes`, `--no-pull`.

**Exit:** SARIF uploads to GitHub code scanning in a test repo; expired ignore re-blocks.

### Phase 6 — Remediation v2 (2 d)
- [ ] Choose base image from live Hub tags (same family/variant, newest stable); keep the static table only as a fallback.
- [ ] When the base is upgraded, **do not** carry old-distro pinned versions; only pin packages the new base still doesn't fix, and only if the version exists in the new repo (check via `apt-cache madison` / `apk policy` in a throwaway container, or skip pinning and let the upgrade do the work).
- [ ] Distro-aware hardening: `useradd` vs `adduser`/`addgroup` (Alpine); skip `USER` when the image's entrypoint needs privileged ports (warn instead); no fake `HEALTHCHECK` — emit a commented TODO, not `CMD ["true"]`.
- [ ] Harden `reconstruct_dockerfile` for BuildKit-style history (no `#(nop)`); stop using substring `"FROM" in created_by`.
- [ ] `fix --verify`: build, re-scan, print before/after delta; non-zero exit if CVEs did not drop.

**Exit:** on `nginx:1.14` (and one Alpine and one Python image) the patched Dockerfile builds and the delta is positive.

### Phase 7 — Packaging, CI/CD, hardening (1.5 d)
- [ ] Dockerfile: pin Trivy version (download release + verify checksum, not `curl | sh` from `main`); verify Cosign checksum; pin base image by digest; non-root user where socket access allows (document the docker-group/GID approach); remove the stale "uncomment" comment.
- [ ] Decide on the baked Trivy DB: either keep it with a documented refresh, or mount a cache volume so `--rm` runs don't re-download.
- [ ] `publish.yml`: run pytest + ruff + mypy; integration job that scans a known-vulnerable image and **asserts** the exit code and JSON fields; remove the `| head` masking; sign and attest the published image (Cosign keyless + SBOM attestation) — practising what the tool preaches.
- [ ] Add a reusable GitHub Action / documented workflow snippet for users.
- [ ] Add `ruff`, `mypy`, `pre-commit`; pin `requirements.txt` with hashes or a lock file.

### Phase 8 — Evaluation and documentation (2 d)
- [ ] **Scenario demo script** (`demo/run_all.sh`): one command per threat scenario with expected output saved under `docs/evidence/`.
- [ ] **Before/after** report for `fix` (CVE counts, KEV count, top risk) as a table + screenshot.
- [ ] **Baseline comparison**: plain `trivy image` vs Phish Net on the same images; show what integrity checks and prioritisation add (e.g. ranking by KEV/EPSS vs raw CVSS).
- [ ] Rewrite `THREAT_MODEL.md` and `README.md` to match behaviour; add an honest "Limitations" section (first pull, Hub-only reputation signals, cosign trust model, SLSA scope).
- [ ] Regenerate `CODE_COMMENTS.md` from docstrings or delete it to avoid drift.
- [ ] Architecture diagram + one-page quickstart.

---

## 6. Test Plan

| Layer | What | How |
|-------|------|-----|
| Unit (offline) | `_compute_priority`, policy validation, `_parse_image_ref`, Levenshtein, history parsing, layer mapping, verdict combiner | pytest, table-driven |
| Mocked network | Hub tags/repo API, auth token + manifest HEAD (index and single), EPSS, KEV, Trivy JSON, cosign exit codes | `responses`, `monkeypatch(subprocess.run)` |
| Golden files | Terminal-free JSON and SARIF output for a fixture scan | snapshot compare |
| Integration (CI) | Scan a known-vulnerable pinned image; assert exit 1 and that expected CVE IDs appear | GitHub Actions with Docker |
| Negative/security | Malformed refs, 404/429/timeouts, offline mode (fail-open vs fail-closed per policy), huge Trivy output | pytest |

Rule for network failures: **make it a policy choice** (`fail_open: true|false`). Default for integrity checks in CI should be fail-closed with a clear message; today every failure silently defaults to "safe".

---

## 7. Demo / Evaluation Matrix (maps to threat model)

| Scenario | Input | Expected result |
|----------|-------|-----------------|
| 1 Compromised build | image with no/invalid SLSA provenance | WARN/BLOCK per policy, shows identity |
| 2 Tag poisoning | simulated digest drift vs `phishnet.lock` | trust BLOCK, exit 1 |
| 3 Fake version tag | `nginx:1.999.0` | trust BLOCK before any pull |
| 4 Typosquat | `ngimx`, `ubntu` | BLOCK with edit distance + repo metadata |
| 5 Known CVEs | `nginx:1.14` | vuln verdict from policy; ranked by KEV/EPSS |
| 6 Unsigned image | any unsigned image | WARN/BLOCK per `require_signature` |

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Docker Hub rate limits / outages break checks | Cache, backoff, explicit `fail_open` policy |
| Trivy/Cosign CLI flags change between versions | Pin versions; test against the pinned build in CI |
| Docker socket exposure | Read-only operations only; document least-privilege; prefer registry-only (no-pull) checks |
| Scope creep | Hit the **minimum cut line** below first |
| Reputation signals are Hub-specific | State it as a limitation; other registries use manifest/signature checks only |

---

## 9. Priorities and Minimum Cut Line

If time is short, finish in this order; everything above the line is the minimum for a credible "complete" project.

1. Phase 0 (tests + reproduce)
2. Phase 1 (entrypoint, layer mapping, consistent verdict/exit, clean JSON, non-interactive)
3. Phase 2 (registry fixes, structured findings, poisoning/fake-tag block)
4. Phase 3 (gate redesign)
5. Phase 8 demo + doc corrections (at least the scenario demo and before/after)

--- *cut line* ---

6. Phase 4 (language packages, `scan-file`, lockfile)
7. Phase 5 (SARIF/HTML/config)
8. Phase 6 (remediation v2)
9. Phase 7 (supply-chain hardening of your own image)

---

## 10. Suggested Timeline (≈ 3 weeks, one person)

| Week | Focus |
|------|-------|
| 1 | Phase 0, 1, 2 |
| 2 | Phase 3, 4, start 5 |
| 3 | Finish 5, Phase 6, Phase 7, Phase 8 (demo, docs, comparison) |

With a team of 3–4, split by module: **integrity/registry**, **scoring/verdict/policy**, **scanning/remediation**, **CI/docs/evidence**. The `Finding` and `Verdict` models in Phase 2–3 are the shared contract, so agree on them first.

---

## 11. Final Checklist

- [ ] Image runs via both documented methods
- [ ] All [R] gaps either reproduced and fixed, or removed from the list as refuted
- [ ] pytest green offline; integration smoke test can fail
- [ ] Integrity BLOCK findings fail the gate
- [ ] Banner / exit code / JSON agree
- [ ] OS + library packages scanned
- [ ] SARIF + JSON + terminal outputs
- [ ] `fix` verified by rebuild and re-scan
- [ ] Docs match the code; limitations stated
- [ ] Demo script and evidence folder committed
