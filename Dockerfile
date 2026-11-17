# ──────────────────────────────────────────────────────────────────
# Phish Net — Dockerfile
# Packages Trivy + Cosign + Docker CLI + Python into one image
# ──────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

LABEL maintainer="Team 15 - Container Security"
LABEL description="Phish Net with SBOM generation, CVE matching, and layer attribution"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ── Install system dependencies ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# ── Install Docker CLI (for layer inspection via Docker SDK) ──
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# ── Install Trivy (SBOM generation + CVE scanning) ──
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ── Install Cosign (image signature verification) ──
RUN COSIGN_VERSION="v2.4.0" \
    && curl -Lo /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
    && chmod +x /usr/local/bin/cosign

# ── Install Phish Net ──
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY phishnet/ phishnet/

RUN pip install --no-cache-dir -e .

# ── Pre-download Trivy vulnerability DB (optional, makes first scan faster) ──
# Uncomment the next line to bake the DB into the image (adds ~150MB):
RUN trivy image --download-db-only

# ── Entry point ──
ENTRYPOINT ["phishnet"]
CMD ["--help"]
