"""
Image Integrity Verification Module.

Performs pre-scan security checks on a Docker image:
- Typosquat detection (catches misspelled image names)
- Digest pinning check (warns if using tags instead of digests)
- Cosign signature verification (checks if image is signed)
- SBOM attestation check (checks for SLSA provenance)
"""

from __future__ import annotations

import subprocess
import logging
from typing import Optional

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

    # Check edit distance against all popular images
    for popular in POPULAR_IMAGES:
        distance = _levenshtein_distance(name, popular)
        # Flag if distance is 1 or 2 (very close to a popular image)
        if 0 < distance <= 2 and len(name) > 3:
            return True, (
                f"⚠️  Possible typosquat: '{name}' is {distance} edit(s) away "
                f"from popular image '{popular}'. Verify the image name."
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
    1. Typosquat detection
    2. Digest pinning check
    3. Cosign signature verification
    4. SBOM attestation check

    Args:
        image_name: The full image reference (e.g., "nginx:1.14").

    Returns:
        IntegrityResult with all findings.
    """
    logger.info("Running integrity checks on: %s", image_name)

    # Typosquat check
    typosquat_risk, typosquat_warning = check_typosquat(image_name)

    # Digest pinning check
    digest_pinned, digest_warning = check_digest_pinning(image_name)

    # Cosign signature verification
    image_signed, signature_warning = verify_signature(image_name)

    # SBOM attestation check
    sbom_attested, attestation_warning = check_sbom_attestation(image_name)

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
        "Integrity check complete: signed=%s, attested=%s, pinned=%s, typosquat=%s",
        image_signed, sbom_attested, digest_pinned, typosquat_risk,
    )

    return result
