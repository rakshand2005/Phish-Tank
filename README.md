# 🛡️ Phish-Tank

### Container Image & Software Supply Chain Security Scanner

Phish-Tank is a Python-based security tool designed to identify potential security risks in container images and application dependencies. It helps developers and security teams assess vulnerabilities, detect suspicious image changes, evaluate software supply chain risks, and generate actionable remediation recommendations.

By combining vulnerability intelligence, container image analysis, dependency inspection, and risk prioritization, Phish-Tank provides a unified approach to improving container and application security.

---

## 🚀 Key Features

### 1. Container Image Security Scanning
- Scan container images for known security vulnerabilities.
- Integrate with Trivy for vulnerability detection.
- Analyze vulnerability severity and associated risk.
- Generate human-readable and JSON reports.

### 2. Software Supply Chain Risk Analysis
- Evaluate vulnerabilities using CVSS severity information.
- Incorporate EPSS (Exploit Prediction Scoring System) intelligence.
- Identify vulnerabilities listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.
- Prioritize security findings based on risk-related indicators.

### 3. Image Integrity Verification
- Retrieve container image metadata and digests.
- Compare image integrity information against registry data.
- Identify potential image digest mismatches.
- Support integrity checks across supported container registries.

### 4. Multi-Registry Support
Designed to work with container images hosted in supported registries, including:

- Docker Hub
- GitHub Container Registry (GHCR)
- Quay.io
- Amazon Public Elastic Container Registry (ECR)

Registry availability and authentication requirements may vary.

### 5. Application Dependency Scanning
Analyze application dependencies and supported manifests or lockfiles to identify potentially vulnerable packages.

Supported ecosystems include:
- Python
- JavaScript / Node.js
- Java / Maven

Supported file formats depend on the implemented parser and should be checked against the project documentation.

### 6. Risk Scoring and Prioritization
- Combine vulnerability information and threat intelligence.
- Provide vulnerability score breakdowns.
- Prioritize potentially dangerous findings.
- Support severity-based CI failure gates.

### 7. Automated Remediation Assistance
Generate remediation recommendations and Dockerfile-based output to help developers address identified container security risks.

### 8. CI/CD Integration
Use Phish-Tank as part of development and container security workflows to identify issues before deployment.

---

## 🏗️ Project Architecture

The project is organized into modular Python components.

| Component | Responsibility |
|---|---|
| `main.py` | CLI commands and application orchestration |
| `scoring.py` | Risk scoring and prioritization |
| `matcher.py` | Vulnerability scanning and result processing |
| `layers.py` | Container layer analysis |
| `registry.py` | Container registry interactions |
| `integrity.py` | Image integrity and digest verification |
| `dependencies.py` | Application dependency analysis |
| `tests/` | Unit and integration tests |

*Note: Refer to the actual source tree for the complete module list.*

---

## 🛠️ Technology Stack

- **Python** – Core implementation
- **Docker** – Container execution and image access
- **Trivy** – Container vulnerability scanning
- **Cosign** – Container image signing and verification capabilities
- **Click** – Command-line interface
- **Rich** – Terminal output and reporting
- **Requests** – External API and registry communication
- **EPSS & CISA KEV** – Vulnerability intelligence sources

---

## 📋 Prerequisites

Before installing Phish-Tank, ensure that you have:

- Python 3.9 or later
- Docker Desktop or Docker Engine
- Git
- Internet connectivity for registry and vulnerability intelligence lookups

For Docker-based execution, the project image provides the required scanner tooling according to the Dockerfile.

---

## 📥 Installation

### 1. Clone the repository

```bash
git clone https://github.com/rakshand2005/Phish-Tank.git
cd Phish-Tank
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -e .
```

### 4. Verify installation

```bash
phishnet --version
phishnet --help
```

---

## 🐳 Docker Setup

Build the Phish-Tank Docker image:

```bash
docker build -t phishnet:latest .
```

Verify the container:

```bash
docker run --rm phishnet:latest --help
```

Check the version:

```bash
docker run --rm phishnet:latest --version
```

Docker-based image scanning requires access to the Docker daemon. On Linux, this is commonly provided through the Docker socket.

---

## 💻 Usage

The following examples illustrate the primary CLI workflows.

### 1. Scan a Container Image

```bash
phishnet scan nginx:latest
```

Docker-based execution:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  phishnet:latest scan nginx:latest
```

### 2. Generate JSON Output

```bash
phishnet scan nginx:latest --output json
```

### 3. Scan Application Dependencies

```bash
phishnet scan-dir .
```

### 4. Verify Image Integrity

```bash
phishnet integrity nginx:latest
```

### 5. Apply a Severity-Based CI Gate

```bash
phishnet scan nginx:latest --fail-on CRITICAL
```

The command can return a non-zero exit code when the configured failure condition is met.

### 6. Generate Remediation Recommendations

```bash
phishnet fix nginx:latest --output-dir ./patched
```

Use `phishnet --help` and individual command help to confirm available options for your installed version.

---

## 🔍 How It Works

A typical Phish-Tank scanning workflow consists of the following stages:

1. **Input Collection:** Accept a container image reference or application directory.
2. **Image and Dependency Analysis:** Retrieve image metadata or inspect supported dependency manifests and lockfiles.
3. **Vulnerability Detection:** Use the configured scanning and vulnerability intelligence sources.
4. **Threat Intelligence Enrichment:** Incorporate relevant EPSS and CISA KEV information where available.
5. **Risk Evaluation:** Analyze findings and calculate risk priorities.
6. **Integrity Verification:** Compare available image digest information when requested.
7. **Report Generation:** Produce readable reports or structured JSON output.
8. **Remediation Assistance:** Generate recommendations for addressing identified risks.

---

## 🧪 Testing

Run the project's test suite:

```bash
python -m pytest -v
```

Run Python compilation checks:

```bash
python -m compileall -q phishnet tests
```

Run Docker build validation:

```bash
docker build -t phishnet:latest .
```

Some integration tests may require internet access, a running Docker daemon, and access to external container registries.

---

## 🔐 Security Considerations

- Use trusted container registries and verify image provenance where supported.
- Keep Docker, Python dependencies, and vulnerability databases updated.
- Treat registry metadata and scan results as external input.
- Docker socket access provides substantial control over the Docker daemon. Only mount it into trusted containers.
- Review remediation output before using it in production.
- Network-dependent vulnerability intelligence may be unavailable or incomplete.

Phish-Tank is intended to assist security analysis and should complement, not replace, established security review and deployment controls.

---

## ⚠️ Current Limitations

- Vulnerability intelligence and registry metadata depend on external services.
- Docker-based operations require appropriate Docker daemon access.
- Registry rate limits, authentication requirements, and network failures may affect results.
- Image tag analysis cannot independently guarantee image authenticity.
- Digest comparison alone does not establish that an image is trustworthy.
- Detection coverage depends on the scanners, databases, and supported package formats.
- Generated remediation recommendations should be reviewed and tested before deployment.

---

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Add or update tests.
5. Run the existing test suite.
6. Submit a pull request describing your changes.

---

## 📄 License

Refer to the repository's license file for applicable licensing terms.

---

## 👨‍💻 Project

**Phish-Tank — Container Image and Software Supply Chain Security Scanner**

Developed as an information security project to explore container vulnerability detection, software supply chain security, threat intelligence, image integrity, and dependency risk analysis.

**GitHub Repository:** https://github.com/rakshand2005/Phish-Tank
