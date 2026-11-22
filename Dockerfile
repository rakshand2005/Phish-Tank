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
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# ── Install Docker CLI (for layer inspection via Docker SDK) ──
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && ARCH=$(dpkg --print-architecture) \
    && echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# ── Install Trivy (SBOM generation + CVE scanning) ──
RUN TRIVY_VERSION="v0.76.2" \
    && ARCH=$(dpkg --print-architecture) \
    && case "${ARCH}" in \
        amd64) TRIVY_ARCH="64bit" ;; \
        arm64) TRIVY_ARCH="ARM64" ;; \
        *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
    esac \
    && curl -sSL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-${TRIVY_ARCH}.tar.gz" \
    | tar -zx -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# ── Install Cosign (image signature verification) ──
RUN COSIGN_VERSION="v2.4.0" \
    && ARCH=$(dpkg --print-architecture) \
    && curl -Lo /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${ARCH}" \
    && chmod +x /usr/local/bin/cosign

# ── Install Phish Net ──
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY phishnet/ phishnet/

RUN pip install --no-cache-dir -e .

# ── Pre-download Trivy vulnerability DB (makes first scan instant & reliable) ──
RUN trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db:2

# ── Entry point ──
ENTRYPOINT ["phishnet"]
CMD ["--help"]
