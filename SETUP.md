# 🛡️ Phish Net — Setup & Evaluation Guide

Welcome to Phish Net! This guide provides step-by-step instructions on how to set up the project locally, run vulnerability scans, and evaluate the tool's capabilities.

---

## 1. Prerequisites

Before you start, ensure you have the following installed on your machine:

- **Git**
- **Docker Desktop** or Docker Engine (Required for running the scanner container)

*Note: The core engines behind this tool (Trivy and Cosign) are bundled inside our Docker image. You do **not** need to install them on your host machine to evaluate the scanner.*

---

## 2. Quick Setup

The easiest and most robust way to evaluate the scanner is by building and running its Docker image.

### Step 1: Clone the Repository
```bash
git clone https://github.com/rakshand2005/Phish-Tank.git
cd Phish-Tank
```

### Step 2: Build the Docker Image
Run this command from the root of the project directory:
```bash
docker build -t phish-net:latest .
```

---

## 3. Running the Scanner

To run the scanner, you must mount your local Docker socket. This allows the containerized scanner to inspect image layers and detect local vulnerabilities.

### Full Vulnerability Scan
Run a full scan including integrity checks, SBOM generation, CVE matching, EPSS/KEV risk scoring, and layer attribution.

**On Windows (PowerShell or Command Prompt):**
```bash
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock phish-net:latest scan nginx:1.14
```
*(Note the double slash `//var/run/docker.sock` which prevents path mangling on Windows).*

**On Linux/macOS:**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock phish-net:latest scan nginx:1.14
```

### JSON Output Format
Useful for integrating the scanner into CI/CD pipelines or piping data to other reporting tools:
```bash
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock phish-net:latest scan nginx:1.14 --output json
```

### CI Gate Logic
Test the scanner's ability to block a CI/CD pipeline if critical vulnerabilities (based on CVSS, EPSS, and active exploitation) are found:
```bash
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock phish-net:latest scan nginx:1.14 --fail-on CRITICAL
```

### Integrity Checks Only
If you only want to verify image signatures, SLSA provenance, digest pinning, and typosquatting without running a full CVE scan:
```bash
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock phish-net:latest integrity nginx:1.14
```

### Auto-Remediation (scanner fix)
Generates a patched Dockerfile that upgrades the base image, pins vulnerable package versions, adds a non-root user, and adds a HEALTHCHECK instruction.
```bash
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock phish-net:latest fix nginx:1.14
```

To save the patched Dockerfile to a local directory:
```bash
docker run --rm \
  -v //var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/patched:/output \
  phish-net:latest fix nginx:1.14 --output-dir /output
```

---

## 4. Local Python Development (Optional)

If you wish to run the Python code directly on your host machine without Docker (for development or code review):

1. **Install external dependencies:** You must install [Trivy](https://aquasecurity.github.io/trivy) and [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) globally on your OS.
2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   # Windows (Command Prompt): venv\Scripts\activate
   # Windows (PowerShell):     .\venv\Scripts\Activate.ps1
   # Linux/macOS:              source venv/bin/activate
   ```
3. **Install the package:**
   ```bash
   pip install -e .
   ```
4. **Run the CLI:**
   ```bash
   scanner --help
   ```

---

## 5. Troubleshooting

**Error: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."**
- Ensure Docker Desktop is running on your machine.
- Ensure you are passing the `-v /var/run/docker.sock:/var/run/docker.sock` (or `//var/run...` on Windows) flag when running the `docker run` command.

**Error: "Trivy not found" or "Cosign not found" when running locally without Docker:**
- The CLI relies on these external binaries. Please use the Dockerized approach (Section 3) where everything is pre-installed, or follow the steps in Section 4 to install them manually.
