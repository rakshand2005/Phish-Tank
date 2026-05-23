"""
Image Integrity Verification Module.

Performs pre-scan security checks on a Docker image:
- Typosquat detection (catches misspelled image names)
- Fake version tag detection (catches syntactically invented tag strings)
- Supply chain poisoning detection (catches silently overwritten/poisoned tags)
- Digest pinning check (warns if using tags instead of digests)
- Cosign signature verification (checks if image is signed)
- SBOM attestation check (checks for SLSA provenance)
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import logging
from typing import Optional

import requests

from scanner.models import IntegrityResult

logger = logging.getLogger(__name__)

# ---- Popular Docker Hub images for typosquat detection ----
POPULAR_IMAGES = [
    "nginx", "alpine", "ubuntu", "debian", "centos", "node",
    "python", "redis", "postgres", "mysql", "mongo", "httpd",
    "golang", "busybox", "openjdk", "ruby", "php", "perl",
    "memcached", "rabbitmq", "elasticsearch", "kibana", "logstash",
    "grafana", "prometheus", "jenkins", "sonarqube", "traefik",
    "haproxy", "consul", "vault", "terraform", "ansible",
    "wordpress", "drupal", "ghost", "nextcloud", "mariadb",
    "cassandra", "couchdb", "influxdb", "telegraf", "chronograf",
    "tomcat", "jetty", "maven", "gradle", "eclipse-temurin",
    "amazoncorretto", "rust", "swift", "dotnet", "aspnet",
]


def verify_image_exists_on_registry(image_name: str) -> tuple[bool, str]:
    """
    Queries the official Docker Registry API to confirm if the namespace/image
    is a real, registered public artifact or a non-existent typosquat.

    Makes a live call to Docker Hub API. A 404 response proves the image
    is fraudulent or typo-squatted. Falls back gracefully on network failure.

    Args:
        image_name: The full image reference (e.g., "nginx:1.14" or "user/repo").

    Returns:
        Tuple of (image_exists, message).
    """
    # Isolate registry elements: repo/name (strip tag and digest)
    parts = image_name.split(":")[0].split("@")[0].split("/")
    if len(parts) == 1:
        namespace, repo = "library", parts[0]
    else:
        namespace, repo = parts[0], parts[1]

    url = f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True, "Verified official registry tracking pathway."
        elif response.status_code == 404:
            return False, (
                f"🚨 Registry Alert: Target image '{namespace}/{repo}' does not exist "
                f"on Docker Hub. High probability of typosquatting/malicious dependency insertion."
            )
        # Any other status — inconclusive, default safe
        return True, f"API lookup inconclusive (HTTP {response.status_code}), defaulting to safe allowance."
    except requests.RequestException:
        # Fall back to Levenshtein local checks if offline or timed out
        return True, "Network timeout, falling back to local edit distance verification."


# ── Tag parsing helpers ───────────────────────────────────────────────────────

def _parse_image_ref(image_name: str) -> tuple[str, str, str]:
    """
    Split a full image reference into (namespace, repo, tag).

    Examples:
        "nginx:1.25.3"          → ("library", "nginx",  "1.25.3")
        "bitnami/redis:7.0"     → ("bitnami",  "redis",  "7.0")
        "ubuntu"                → ("library", "ubuntu", "latest")
        "alpine@sha256:abc..."  → ("library", "alpine", "latest")  ← digest ref, tag irrelevant
    """
    # Strip digest suffix first
    ref = image_name.split("@")[0]
    # Split tag
    if ":" in ref.split("/")[-1]:
        base, tag = ref.rsplit(":", 1)
    else:
        base, tag = ref, "latest"
    parts = base.split("/")
    if len(parts) == 1:
        return "library", parts[0], tag
    return parts[0], parts[1], tag


# ── Gate 1: Syntactic fake-tag detection ─────────────────────────────────────

def check_fake_version_tag(image_name: str) -> tuple[bool, Optional[str]]:
    """
    Detect syntactically invented / non-existent version tags.

    Strategy: query the Docker Hub tags API for the specific tag the user
    supplied. If the tag does not exist on the registry the version string
    is fabricated — a classic supply-chain attack vector where an attacker
    registers a plausible-sounding but fake version to shadow a real one.

    This catches things like:
        nginx:1.999.0      — version that never existed
        python:3.11.99     — invented patch level
        ubuntu:99.04       — non-existent release string

    Falls back gracefully to True (safe) on network failure so it never
    blocks a scan when the registry is unreachable.

    Args:
        image_name: Full image reference (e.g., "nginx:1.25.3").

    Returns:
        Tuple of (tag_is_fake, warning_message | None).
        tag_is_fake=True  → the tag does not exist; treat as high-risk.
        tag_is_fake=False → tag confirmed real, or check inconclusive.
    """
    namespace, repo, tag = _parse_image_ref(image_name)

    # Digest-pinned refs carry no mutable tag — skip this check
    if "@sha256:" in image_name:
        return False, None

    # "latest" is always present on official images; skip fabrication check
    if tag == "latest":
        return False, None

    url = f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags/{tag}/"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 404:
            return True, (
                f"🚨 Fake Version Tag: '{tag}' does not exist for image "
                f"'{namespace}/{repo}' on Docker Hub. "
                f"This version string appears to be fabricated — possible "
                f"shadow-tag injection or supply chain manipulation."
            )
        if resp.status_code == 200:
            logger.info("Tag '%s' confirmed real on registry for '%s/%s'.", tag, namespace, repo)
            return False, None
        # Any other HTTP status — inconclusive, default safe
        return False, None
    except requests.RequestException as e:
        logger.warning("Fake-tag check network failure for '%s': %s", image_name, e)
        return False, None


# ── Gate 2: Supply chain tag-poisoning detection ──────────────────────────────

def _resolve_local_digest(image_name: str) -> Optional[str]:
    """
    Resolve the sha256 digest of an image that is already pulled locally,
    using `docker inspect`. Returns None if docker is unavailable or the
    image is not present locally.
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image_name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            # RepoDigests entry looks like "nginx@sha256:abc..."
            match = re.search(r"sha256:([a-f0-9]{64})", output)
            if match:
                return "sha256:" + match.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _fetch_registry_digest(image_name: str) -> Optional[str]:
    """
    Fetch the current content-digest for a tag from Docker Hub's registry API
    (not the Hub UI API — the actual OCI distribution endpoint).

    Uses an anonymous token for public images. Returns None on any failure.

    The digest returned is what Docker Hub currently serves for that tag.
    If it has drifted from what was originally pulled, the tag was overwritten.
    """
    namespace, repo, tag = _parse_image_ref(image_name)

    # Step 1: get an anonymous Bearer token for the target repo
    auth_url = (
        f"https://auth.docker.io/token"
        f"?service=registry.docker.io"
        f"&scope=repository:{namespace}/{repo}:pull"
    )
    try:
        token_resp = requests.get(auth_url, timeout=5)
        if token_resp.status_code != 200:
            return None
        token = token_resp.json().get("token")
        if not token:
            return None
    except requests.RequestException as e:
        logger.warning("Registry auth token fetch failed: %s", e)
        return None

    # Step 2: HEAD the manifest — Docker returns the content-digest in headers
    manifest_url = f"https://registry-1.docker.io/v2/{namespace}/{repo}/manifests/{tag}"
    headers = {
        "Authorization": f"Bearer {token}",
        # Request the canonical manifest media types so the digest is stable
        "Accept": (
            "application/vnd.docker.distribution.manifest.v2+json,"
            "application/vnd.oci.image.manifest.v1+json"
        ),
    }
    try:
        resp = requests.head(manifest_url, headers=headers, timeout=8)
        if resp.status_code == 200:
            digest = resp.headers.get("Docker-Content-Digest") or resp.headers.get("Etag", "").strip('"')
            if digest and digest.startswith("sha256:"):
                return digest
    except requests.RequestException as e:
        logger.warning("Registry manifest HEAD failed for '%s': %s", image_name, e)

    return None


def check_tag_poisoning(image_name: str) -> tuple[bool, Optional[str]]:
    """
    Detect supply chain tag poisoning — a tag that existed and was pulled
    legitimately but has since been silently overwritten on the registry
    with a different (potentially malicious) image layer.

    Attack scenario:
        1. Developer pins "redis:7.0.11" in their Dockerfile.
        2. Attacker compromises the publisher account and pushes malicious
           layers to the same tag, updating its digest on Docker Hub.
        3. The next `docker pull` fetches the poisoned image silently —
           same tag, different content.

    Detection method:
        - Resolve the sha256 digest of the locally present image via
          `docker inspect` (what was actually pulled).
        - Fetch the current digest for the same tag from the OCI registry
          API (what Docker Hub serves right now).
        - If both are known and they differ → the tag content changed →
          high-confidence supply chain poisoning signal.

    Falls back gracefully: if either digest is unavailable (docker not
    installed, image not pulled yet, network offline) the check is skipped
    rather than raising a false positive.

    Args:
        image_name: Full image reference (e.g., "redis:7.0.11").

    Returns:
        Tuple of (is_poisoned, warning_message | None).
    """
    # Digest-pinned refs are immutable by definition — cannot be poisoned via tag
    if "@sha256:" in image_name:
        return False, None

    namespace, repo, tag = _parse_image_ref(image_name)

    local_digest    = _resolve_local_digest(image_name)
    registry_digest = _fetch_registry_digest(image_name)

    if local_digest is None:
        logger.debug("Tag-poisoning check skipped: image '%s' not found locally.", image_name)
        return False, None

    if registry_digest is None:
        logger.debug("Tag-poisoning check skipped: could not fetch registry digest for '%s'.", image_name)
        return False, None

    if local_digest != registry_digest:
        return True, (
            f"🚨 Supply Chain Poisoning Detected: Tag '{namespace}/{repo}:{tag}' "
            f"digest has CHANGED since it was pulled.\n"
            f"  Local digest (pulled):    {local_digest}\n"
            f"  Registry digest (current): {registry_digest}\n"
            f"This tag was silently overwritten on Docker Hub. "
            f"The image content no longer matches what you originally fetched. "
            f"Do NOT deploy — re-pull after confirming with the publisher, "
            f"or pin to the original digest explicitly."
        )

    logger.info(
        "Tag poisoning check passed: digest consistent for '%s/%s:%s' (%s).",
        namespace, repo, tag, local_digest,
    )
    return False, None


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def check_typosquat(image_name: str) -> tuple[bool, Optional[str]]:
    """
    Check if an image name might be a typosquat of a popular image.

    Uses Levenshtein distance to detect names that are suspiciously close
    to well-known Docker Hub images but not an exact match.

    Args:
        image_name: The image name (without tag/registry prefix).

    Returns:
        Tuple of (is_risky, warning_message).
    """
    # Extract the base image name (strip registry and tag)
    name = image_name.split("/")[-1].split(":")[0].split("@")[0]

    # If it's an exact match to a popular image, no typosquat risk
    if name in POPULAR_IMAGES:
        return False, None

    # ── Live registry validation (primary check) ──────────────────────────
    # Query Docker Hub to confirm whether the image actually exists.
    # A 404 from the registry is a strong typosquat/fraud signal, even if
    # the Levenshtein distance check below would have passed.
    registry_exists, registry_msg = verify_image_exists_on_registry(image_name)
    if not registry_exists:
        return True, registry_msg

    # ── Levenshtein fallback (offline / inconclusive registry response) ───
    # Still run the edit-distance check so we warn about suspiciously close
    # names even when the registry call defaulted to "safe allowance".
    for popular in POPULAR_IMAGES:
        distance = _levenshtein_distance(name, popular)
        # Flag if distance is 1 or 2 (very close to a popular image)
        if 0 < distance <= 2 and len(name) > 3:
            return True, (
                f"⚠️  Possible typosquat: '{name}' is {distance} edit(s) away "
                f"from popular image '{popular}'. Verify the image name. "
                f"(Registry note: {registry_msg})"
            )

    return False, None


def check_digest_pinning(image_name: str) -> tuple[bool, Optional[str]]:
    """
    Check if the image reference uses a digest pin (sha256:...).

    Using tags like :latest or :1.14 is risky because tags are mutable.
    Digest pinning (image@sha256:abc...) guarantees immutability.

    Args:
        image_name: The full image reference.

    Returns:
        Tuple of (is_pinned, warning_message).
    """
    if "@sha256:" in image_name:
        return True, None

    return False, (
        "⚠️  Image is not digest-pinned. Using a tag like ':{tag}' means the "
        "image content can change without notice. Consider pinning with "
        "'image@sha256:<digest>' for reproducible builds."
    ).format(tag=image_name.split(":")[-1] if ":" in image_name else "latest")


def verify_signature(image_name: str) -> tuple[bool, Optional[str]]:
    """
    Verify the image's Cosign signature against the Sigstore public instance.

    Args:
        image_name: The full image reference.

    Returns:
        Tuple of (is_signed, warning_message).
    """
    try:
        result = subprocess.run(
            [
                "cosign", "verify",
                "--certificate-identity-regexp", ".*",
                "--certificate-oidc-issuer-regexp", ".*",
                image_name,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.info("Image signature verified: %s", image_name)
            return True, None
        else:
            logger.warning("Image not signed: %s", result.stderr.strip())
            return False, (
                f"⚠️  Image '{image_name}' is NOT signed via Cosign/Sigstore. "
                "Cannot verify publisher identity. Proceed with caution."
            )
    except FileNotFoundError:
        logger.warning("cosign not found in PATH")
        return False, (
            "⚠️  Cosign not installed — cannot verify image signature. "
            "Install from: https://github.com/sigstore/cosign"
        )
    except subprocess.TimeoutExpired:
        return False, "⚠️  Cosign signature verification timed out."


def check_sbom_attestation(image_name: str) -> tuple[bool, Optional[str]]:
    """
    Check if the image has an SBOM attestation (SLSA provenance).

    Args:
        image_name: The full image reference.

    Returns:
        Tuple of (is_attested, warning_message).
    """
    try:
        result = subprocess.run(
            [
                "cosign", "verify-attestation",
                "--type", "cyclonedx",
                "--certificate-identity-regexp", ".*",
                "--certificate-oidc-issuer-regexp", ".*",
                image_name,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.info("SBOM attestation verified: %s", image_name)
            return True, None
        else:
            return False, (
                f"⚠️  No SBOM attestation (SLSA) found for '{image_name}'. "
                "The SBOM generated by this tool is not cryptographically "
                "linked to the image publisher."
            )
    except FileNotFoundError:
        return False, (
            "⚠️  Cosign not installed — cannot verify SBOM attestation."
        )
    except subprocess.TimeoutExpired:
        return False, "⚠️  SBOM attestation verification timed out."


def verify_image(image_name: str) -> IntegrityResult:
    """
    Run all integrity checks on an image.

    This is the main entry point for the integrity module. It runs:
    1. Typosquat detection          — misspelled image name vs popular images
    2. Fake version tag detection   — tag string that does not exist on registry
    3. Supply chain poisoning check — tag digest drifted since last pull
    4. Digest pinning check         — warns if using mutable tags
    5. Cosign signature verification
    6. SBOM attestation check

    Args:
        image_name: The full image reference (e.g., "nginx:1.25.3").

    Returns:
        IntegrityResult with all findings.
    """
    logger.info("Running integrity checks on: %s", image_name)

    # 1. Typosquat check
    typosquat_risk, typosquat_warning = check_typosquat(image_name)

    # 2. Fake version tag check (syntactic supply-chain vector)
    fake_tag, fake_tag_warning = check_fake_version_tag(image_name)
    if fake_tag:
        logger.warning("Fake version tag detected for: %s", image_name)
        # Escalate typosquat_risk so the report surfaces this prominently
        typosquat_risk = True
        if typosquat_warning:
            typosquat_warning = f"{typosquat_warning} | {fake_tag_warning}"
        else:
            typosquat_warning = fake_tag_warning

    # 3. Supply chain tag-poisoning check (digest drift)
    tag_poisoned, poison_warning = check_tag_poisoning(image_name)
    if tag_poisoned:
        logger.warning("Tag poisoning detected for: %s", image_name)

    # 4. Digest pinning check
    digest_pinned, digest_warning = check_digest_pinning(image_name)

    # 5. Cosign signature verification
    image_signed, signature_warning = verify_signature(image_name)

    # 6. SBOM attestation check
    sbom_attested, attestation_warning = check_sbom_attestation(image_name)

    # Merge poison warning into signature_warning so it surfaces in the report
    # without requiring a model change — poison is a publisher-trust failure.
    if tag_poisoned and poison_warning:
        if signature_warning:
            signature_warning = f"{signature_warning} | {poison_warning}"
        else:
            signature_warning = poison_warning
        # Also force image_signed=False — a poisoned tag cannot be trusted
        image_signed = False

    result = IntegrityResult(
        image_signed=image_signed,
        signature_warning=signature_warning,
        sbom_attested=sbom_attested,
        attestation_warning=attestation_warning,
        digest_pinned=digest_pinned,
        digest_warning=digest_warning,
        typosquat_risk=typosquat_risk,
        typosquat_warning=typosquat_warning,
    )

    logger.info(
        "Integrity check complete: signed=%s, attested=%s, pinned=%s, "
        "typosquat=%s, fake_tag=%s, poisoned=%s",
        image_signed, sbom_attested, digest_pinned,
        typosquat_risk, fake_tag, tag_poisoned,
    )

    return result