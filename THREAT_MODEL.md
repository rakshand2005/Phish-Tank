# 🛡️ Container Security Scanner — Threat Model & Defenses

This document outlines the threat model for our Container Security Scanner. It details the specific supply chain attacks and vulnerabilities our tool detects, how we mitigate them, and the relevant MITRE ATT&CK mappings.

---

## 1. Supply Chain Compromise (The "SolarWinds" Scenario)
**MITRE ATT&CK ID:** [T1195.001](https://attack.mitre.org/techniques/T1195/001/) (Compromise Software Dependencies and Development Tools)

**The Threat:** An attacker compromises a legitimate publisher's build server (CI/CD pipeline) or source code repository. They inject a malicious backdoor during compilation. The publisher unknowingly signs the compromised image with their official key and distributes it.

**Our Defense (SLSA Provenance via Cosign):**
- Standard image signatures (`cosign verify`) are **not enough** to catch this, because the publisher's key is what signed the backdoor.
- Our tool enforces **SBOM Attestations** (`cosign verify-attestation`). 
- We check for a cryptographically signed receipt of the *exact ingredients and build environment* (SLSA Provenance). If an attacker sneaks a backdoor in during the build, the final image won't match the attested build materials, and our tool flags the discrepancy as a severe supply chain failure.

---

## 2. Supply Chain Tag Poisoning (Silent Overwrite)
**MITRE ATT&CK ID:** [T1195.002](https://attack.mitre.org/techniques/T1195/002/) (Compromise Software Supply Chain: Compromise Software Supply Chain)

**The Threat:** An attacker compromises a publisher's Docker Hub account and overwrites an existing, widely-used image tag (e.g., pushing a malicious image to `redis:7.0.11`). Because developers rely on tags instead of immutable digests, the next `docker pull` silently fetches the malicious image.

**Our Defense (Tag Poisoning Detection):**
- Our `integrity.py` module resolves the local SHA-256 digest of what the developer *originally* pulled.
- It then queries the OCI Registry API for the *current* digest of that same tag.
- **If the digests differ**, it means the tag was silently overwritten on the registry. Our tool immediately blocks the pipeline and alerts the user to "Digest Drift" — a massive red flag for tag poisoning.
- We also actively warn users to use **Digest Pinning** (`@sha256:...`) instead of mutable tags.

---

## 3. Fake Version Tag Injection
**The Threat:** An attacker registers a plausible-sounding but completely fabricated version tag (e.g., `nginx:1.999.0` or `python:3.11.99`) and tricks a developer into pulling it via social engineering or a compromised `package.json` / `Dockerfile`.

**Our Defense (Syntactic Fake-Tag Detection):**
- Our tool queries the Docker Hub API for the specific tag provided by the user.
- If the registry returns a 404, we know the version string is entirely fabricated. 
- The tool flags this as a "Fake Version Tag" and blocks execution, preventing the developer from pulling a shadow dependency.

---

## 4. Typosquatting
**MITRE ATT&CK ID:** [T1036](https://attack.mitre.org/techniques/T1036/) (Masquerading)

**The Threat:** An attacker uploads a malicious image with a name very similar to a popular, legitimate image (e.g., `ngimx` instead of `nginx`, or `ubntu` instead of `ubuntu`), hoping developers make a typo in their Dockerfile.

**Our Defense (Levenshtein + Registry Validation):**
- We compute the **Levenshtein edit distance** against a hardcoded list of the top 50 most popular Docker images. If an image name is 1 or 2 characters off from a popular image, we raise a high-risk Typosquat warning.
- We also perform **Live Registry Validation** to ensure the namespace/repo actually exists, catching blatant masquerades before they are pulled.

---

## 5. Exploitation of Known Vulnerabilities
**MITRE ATT&CK ID:** [T1190](https://attack.mitre.org/techniques/T1190/) (Exploit Public-Facing Application)

**The Threat:** The container image contains outdated OS packages (e.g., `apt`, `apk`) or application dependencies (e.g., `pip`, `npm`) that have publicly known vulnerabilities (CVEs). Attackers scan for these CVEs to gain initial access or escalate privileges.

**Our Defense (Trivy + EPSS + CISA KEV):**
- We generate a CycloneDX SBOM and cross-reference it against the Trivy vulnerability database (which we automatically keep fresh to prevent stale scans).
- **Risk Scoring:** Instead of relying solely on theoretical CVSS scores, our `scoring.py` module enriches every CVE with:
  - **EPSS (Exploit Prediction Scoring System):** The statistical probability that the CVE will be exploited in the wild in the next 30 days.
  - **CISA KEV (Known Exploited Vulnerabilities):** A binary flag indicating if nation-state actors or ransomware gangs are *actively* exploiting this vulnerability right now.
- We compute a composite `priority_score` (0-10) and block the CI pipeline if any CVE exceeds the critical threshold, prioritizing actual threat intelligence over theoretical severity.

---

## 6. Unsigned Publisher Artifacts
**The Threat:** An attacker uploads an image masquerading as a legitimate publisher, and developers pull it because they have no way to verify the cryptographic identity of the uploader.

**Our Defense (Cosign Signature Verification):**
- Before scanning, our tool enforces `cosign verify`.
- This ensures the image has a valid cryptographic signature tying it to the trusted publisher's public key (or OIDC identity via Sigstore's keyless transparency log). 
- If the image is unsigned, we warn the user that publisher identity cannot be established.
