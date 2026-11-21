# 🛡️ Phish Net — Container Security Tool

**SBOM Generation · CVE Matching · Layer Attribution · Integrity Verification · Auto-Remediation**

---

## 🎯 Project Overview (Evaluation Guide)

### What problem does this solve?
Phish Net is a comprehensive supply-chain security tool for Docker container images that prevents malicious dependencies, compromised tags, and vulnerable packages from reaching production. It combines SBOM (Software Bill of Materials) generation, CVE scanning, cryptographic integrity verification, and dynamic risk scoring into a single CI/CD-friendly pipeline. Crucially, it goes beyond reporting by offering **auto-remediation**, instantly generating a hardened Dockerfile that upgrades base images, pins safe package versions, and enforces security best practices.

### Which architecture does it target?
**Cloud-Native & CI/CD Pipelines.** It is designed to run in automated build pipelines (like GitHub Actions or GitLab CI) or locally on developer workstations to gate container deployments before they reach orchestration environments like Kubernetes.

### What MITRE ATT&CK techniques does it address?
- **T1195.001** — Supply Chain Compromise: Software Dependencies
- **T1195.002** — Supply Chain Compromise: Supply Chain (Tag Poisoning)
- **T1036.005** — Masquerading: Match Legitimate Name or Location (Typosquatting & Fake Tags)
- **T1553.002** — Subvert Trust Controls: Code Signing (Cosign Verification)
- **T1190**     — Exploit Public-Facing Application (Known CVEs)

### How do you run it?
The easiest and most robust way to evaluate Phish Net is by using the automated installation scripts. This installs a lightweight `phishnet` CLI command that automatically orchestrates the underlying Docker container for you.

**Installation on Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/rakshand2005/Phish-Tank/main/install.sh | bash
source ~/.bashrc  # (or ~/.zshrc)
```

**Installation on Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/rakshand2005/Phish-Tank/main/install.ps1 | iex
```

Once installed, you can simply use the `phishnet` command!

**Run a Full Scan:**
```bash
phishnet scan nginx:1.14
```

**Scan application dependencies before building an image:**
```bash
phishnet scan-dir .
```

`scan` checks OS packages and language libraries installed in the final image.
`scan-dir` checks dependency manifests and lockfiles in the source tree,
including transitive dependencies Trivy can resolve. Lockfiles provide the most
reliable version matching; unconstrained dependency ranges may be skipped.

**Auto-Remediate a Vulnerable Image:**
```bash
phishnet fix nginx:1.14
```

### What dependencies does it have?
- **Docker Engine / Docker Desktop** (Required for inspecting image layers via the Docker socket)
- **Trivy** (Vulnerability scanning & SBOM generation)
- **Cosign** (Cryptographic signature & attestation verification)
- **Python 3.9+** (Core orchestration logic, utilizing `click`, `rich`, `requests`, and `docker` SDK)
*(Note: If using the Dockerized installation method above, Trivy, Cosign, and Python are bundled inside the image).*

### What are known limitations or gaps?
1. **Docker Socket Requirement:** Phish Net requires access to `/var/run/docker.sock` to inspect image layers. While it only performs read-only operations (`pull` and `inspect`), exposing the socket in some strict CI environments requires specific privilege configurations.
2. **First-Pull Tag Poisoning Blindspot:** The supply-chain tag poisoning check relies on comparing the local image digest to the remote registry digest. If an image is being pulled for the very first time, there is no local baseline to detect drift.
3. **External Network Reliance:** Risk scoring depends on live queries to the FIRST.org EPSS API, CISA KEV feed, and Docker Hub API. While it fails open safely, network isolation will degrade scoring accuracy.
4. **Out of Scope:** It does not scan custom application source code (SAST) or runtime behavior (DAST) — it strictly secures the container supply chain and package dependencies.

---

## 📊 How It Works

```
Image name (input)
      │
      ▼
┌─ integrity.py ──────────────────┐
│  ✅ Cosign signature check      │
│  ✅ SBOM attestation (SLSA)     │
│  ✅ Digest pinning check        │
│  ✅ Typosquat & Tag Poisoning   │
└─────────────────────────────────┘
      │
      ▼
┌─ sbom.py ───────────────────────┐
│  ✅ Trivy → CycloneDX SBOM      │
│  ✅ Package extraction          │
└─────────────────────────────────┘
      │
      ▼
┌─ matcher.py ────────────────────┐
│  ✅ DB freshness check          │
│  ✅ Trivy CVE scanning          │
│  ✅ Fix version extraction      │
└─────────────────────────────────┘
      │
      ▼
┌─ scoring.py ────────────────────┐
│  ✅ CISA KEV active exploits    │
│  ✅ FIRST.org EPSS scores       │
│  ✅ Composite Risk Priority     │
└─────────────────────────────────┘
      │
      ▼
┌─ layers.py ─────────────────────┐
│  ✅ Docker layer inspection     │
│  ✅ CVE-to-layer attribution    │
│  ✅ Dockerfile fix suggestions  │
└─────────────────────────────────┘
      │
      ▼
┌─ remediate.py (phishnet fix) ───┐
│  ✅ Reconstruct Dockerfile      │
│  ✅ Upgrade Base Image          │
│  ✅ Pin Safe Packages           │
└─────────────────────────────────┘
```

---

## 📋 Extended CLI Reference

| Command | Description |
|---------|------------|
| `phishnet scan <image>` | Full vulnerability scan |
| `phishnet scan-dir <directory>` | Scan source dependency manifests and lockfiles |
| `phishnet scan-dir . --output json` | Source dependency findings as JSON |
| `phishnet scan <image> --output json` | JSON output to stdout |
| `phishnet scan <image> --fail-on CRITICAL` | Exit code 1 if CRITICAL found |
| `phishnet scan <image> --layers` | Include layer attribution (default: on) |
| `phishnet scan <image> --update-db` | Force update Trivy DB before scan |
| `phishnet scan <image> -v` | Verbose logging |
| `phishnet integrity <image>` | Integrity checks only |
| `phishnet fix <image>` | 🔧 Auto-generate a patched Dockerfile |
| `phishnet fix <image> --output-dir ./out` | Save patched Dockerfile to directory |
| `phishnet --version` | Show version |

---
