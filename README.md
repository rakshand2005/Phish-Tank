# 🛡️ Container Security Scanner

**SBOM Generation · CVE Matching · Layer Attribution · Integrity Verification**

A CLI tool that scans Docker images for vulnerabilities, generates a Software Bill of Materials (SBOM), attributes CVEs to specific image layers, and provides actionable fix suggestions.

> **MITRE ATT&CK:** T1195.001 — Supply Chain Compromise: Software Dependencies

---

## 🚀 Quick Start

### Install (One Command)

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/<your-repo>/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/<your-repo>/main/install.ps1 | iex
```

### Usage

```bash
# Full vulnerability scan
scanner scan nginx:1.14

# JSON output (for CI pipelines / downstream processing)
scanner scan nginx:1.14 --output json

# Block CI if critical CVEs found (exit code 1)
scanner scan nginx:1.14 --fail-on CRITICAL

# Integrity check only (signature, typosquat, digest pinning)
scanner integrity nginx:1.14
```

### Or Run Directly with Docker

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/<your-repo>:latest \
  scan nginx:1.14
```

---

## 📊 What It Does

```
Image name (input)
      │
      ▼
┌─ integrity.py ──────────────────┐
│  ✅ Cosign signature check      │
│  ✅ SBOM attestation (SLSA)     │
│  ✅ Digest pinning check        │
│  ✅ Typosquat detection         │
└─────────────────────────────────┘
      │
      ▼
┌─ sbom.py ───────────────────────┐
│  ✅ Trivy → CycloneDX SBOM     │
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
┌─ layers.py ─────────────────────┐
│  ✅ Docker layer inspection     │
│  ✅ CVE-to-layer attribution    │
│  ✅ Dockerfile fix suggestions  │
└─────────────────────────────────┘
      │
      ▼
   ScanResult JSON → scoring → report → CI gate
```

---

## 🔐 Edge Cases Handled

| Gap | How We Fix It |
|-----|--------------|
| Image not signed (Cosign) | Warns before scan, flags in report |
| No SBOM attestation (SLSA) | Checks via `cosign verify-attestation` |
| Stale vulnerability DB | Checks DB age, auto-updates if > 24h old |
| Typosquatting (e.g., `ngimx`) | Levenshtein distance against popular images |
| Mutable tags (`:latest`) | Warns about digest pinning |

---

## 🏗️ Project Structure

```
scanner/
├── __init__.py       # Package init
├── main.py           # CLI entry point (Click)
├── integrity.py      # Image integrity verification
├── sbom.py           # SBOM generation (Trivy)
├── matcher.py        # CVE matching + DB freshness
├── layers.py         # Layer attribution + fix suggestions
└── models.py         # Shared data models (contract for P3/P4)
```

---

## 👥 Team Roles

| Person | Module | Responsibility |
|--------|--------|---------------|
| **P1 (You)** | `integrity.py`, `sbom.py`, `matcher.py`, `layers.py` | SBOM + CVE + Layer Attribution |
| **P3** | `scoring.py`, `gate.py` | Risk scoring + CI gate logic |
| **P4** | `report.py` | Report output (JSON + terminal) |
| **P5** | `.github/workflows/`, `Makefile` | Demo pipeline setup |

### For P3 and P4:
1. Read `scanner/models.py` — this is the data contract
2. Use `sample_output/sample_scan.json` to develop against
3. Your code receives a `ScanResult` object from P1's pipeline

---

## 🔧 Development Setup

```bash
# Clone the repo
git clone https://github.com/<your-repo>.git
cd container-scanner

# Install Python dependencies
pip install -e .

# Requirements: Docker running + Trivy + Cosign installed
# (All included in the Dockerfile)
```

### Build the Docker image locally:
```bash
docker build -t scanner .

# Test it
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock scanner scan nginx:1.14
```

---

## 📋 CLI Reference

| Command | Description |
|---------|------------|
| `scanner scan <image>` | Full vulnerability scan |
| `scanner scan <image> --output json` | JSON output to stdout |
| `scanner scan <image> --fail-on CRITICAL` | Exit code 1 if CRITICAL found |
| `scanner scan <image> --layers` | Include layer attribution (default: on) |
| `scanner scan <image> --update-db` | Force update Trivy DB before scan |
| `scanner scan <image> -v` | Verbose logging |
| `scanner integrity <image>` | Integrity checks only |
| `scanner --version` | Show version |

---

## 📦 Tech Stack

- **Trivy** — SBOM generation + CVE scanning
- **Cosign** — Image signature verification
- **Docker SDK for Python** — Layer inspection
- **Click** — CLI framework
- **Rich** — Terminal UI (tables, colors, spinners)
- **Python 3.9+** — Orchestration

---

## 📜 License

MIT
