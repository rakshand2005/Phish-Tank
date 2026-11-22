"""
Multi-Registry and OCI Distribution API Support Module.

Provides standard OCI Distribution Specification v2 support for Docker Hub,
GitHub Container Registry (ghcr.io), Quay.io, Google Container Registry (gcr.io),
AWS ECR Public (public.ecr.aws), and private/custom container registries.

Supports:
- Image reference parsing (registry, repository, tag, digest)
- Www-Authenticate challenge token authorization (RFC 6750)
- Repository and tag existence verification
- Remote content digest resolution (multi-arch index and single-manifest)
- Tag listing and latest tag resolution
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Optional
import requests

logger = logging.getLogger(__name__)

# Canonical OCI and Docker manifest media types
MANIFEST_ACCEPT_HEADERS = (
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json,"
    "application/vnd.oci.image.manifest.v1+json"
)

# Token cache: (realm, service, scope) -> token
_TOKEN_CACHE: dict[tuple[str, str, str], str] = {}


@dataclass
class ImageReference:
    """Parsed representation of a container image reference."""

    raw: str
    registry: str
    repository: str
    tag: str = "latest"
    digest: Optional[str] = None

    @property
    def is_docker_hub(self) -> bool:
        """True if the image resides on Docker Hub."""
        return self.registry in ("docker.io", "registry-1.docker.io", "index.docker.io")

    @property
    def registry_host(self) -> str:
        """Returns the actual host to use for OCI API calls."""
        if self.is_docker_hub:
            return "registry-1.docker.io"
        return self.registry

    @property
    def normalized_name(self) -> str:
        """Full canonical reference without tag/digest."""
        if self.is_docker_hub:
            return f"docker.io/{self.repository}"
        return f"{self.registry}/{self.repository}"

    def __str__(self) -> str:
        ref = f"{self.normalized_name}:{self.tag}"
        if self.digest:
            ref += f"@{self.digest}"
        return ref


def parse_image_reference(image_name: str) -> ImageReference:
    """
    Parse a container image reference into registry, repository, tag, and digest.

    Examples:
        "nginx"                                  → docker.io/library/nginx:latest
        "nginx:1.25.3"                           → docker.io/library/nginx:1.25.3
        "bitnami/redis:7.0"                      → docker.io/bitnami/redis:7.0
        "ghcr.io/owner/repo:v1.0"                → ghcr.io/owner/repo:v1.0
        "quay.io/coreos/etcd:v3.5.0"             → quay.io/coreos/etcd:v3.5.0
        "public.ecr.aws/docker/library/redis:7"  → public.ecr.aws/docker/library/redis:7
        "localhost:5000/app:dev"                 → localhost:5000/app:dev
        "ubuntu@sha256:abc..."                   → docker.io/library/ubuntu@sha256:abc...
    """
    raw = image_name.strip()
    digest = None
    if "@" in raw:
        raw_part, digest = raw.split("@", 1)
    else:
        raw_part = raw

    # Split off tag (careful not to confuse port numbers like localhost:5000)
    tag = "latest"
    if ":" in raw_part:
        last_slash = raw_part.rfind("/")
        last_colon = raw_part.rfind(":")
        if last_colon > last_slash:
            tag = raw_part[last_colon + 1:]
            raw_part = raw_part[:last_colon]

    # Check for domain/host prefix
    parts = raw_part.split("/")
    first_part = parts[0]
    has_registry_domain = (
        len(parts) > 1 and
        ("." in first_part or ":" in first_part or first_part == "localhost")
    )

    if has_registry_domain:
        registry = first_part
        repository = "/".join(parts[1:])
    else:
        registry = "docker.io"
        if len(parts) == 1:
            repository = f"library/{parts[0]}"
        else:
            repository = "/".join(parts)

    return ImageReference(
        raw=image_name,
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest,
    )


def _get_oci_auth_header(ref: ImageReference, timeout: int = 5) -> dict[str, str]:
    """
    Authenticate against an OCI registry using the Www-Authenticate challenge flow (RFC 6750).

    Returns a dict with {"Authorization": "Bearer <token>"} or empty dict if not needed.
    """
    probe_url = f"https://{ref.registry_host}/v2/"
    try:
        probe_resp = requests.get(probe_url, timeout=timeout)
        if probe_resp.status_code in (200, 204):
            return {}  # Anonymous access allowed with no token
        
        auth_header = probe_resp.headers.get("Www-Authenticate")
        if not auth_header:
            return {}

        # Parse realm, service, and scope from: Bearer realm="...",service="...",scope="..."
        realm_match = re.search(r'realm="([^"]+)"', auth_header)
        if not realm_match:
            return {}
        realm = realm_match.group(1)

        service_match = re.search(r'service="([^"]+)"', auth_header)
        service = service_match.group(1) if service_match else ""

        scope = f"repository:{ref.repository}:pull"

        cache_key = (realm, service, scope)
        if cache_key in _TOKEN_CACHE:
            return {"Authorization": f"Bearer {_TOKEN_CACHE[cache_key]}"}

        params = {}
        if service:
            params["service"] = service
        if scope:
            params["scope"] = scope

        token_resp = requests.get(realm, params=params, timeout=timeout)
        if token_resp.status_code == 200:
            token_json = token_resp.json()
            token = token_json.get("token") or token_json.get("access_token")
            if token:
                _TOKEN_CACHE[cache_key] = token
                return {"Authorization": f"Bearer {token}"}

    except requests.RequestException as e:
        logger.debug("OCI auth challenge failed for %s: %s", ref.registry, e)

    return {}


def verify_registry_image_exists(image_name: str, timeout: int = 6) -> tuple[bool, str]:
    """
    Verify if an image repository exists on its registry.

    Works across Docker Hub, GHCR, Quay, ECR, GCR, and other OCI registries.
    Returns:
        (exists: bool, message: str)
    """
    ref = parse_image_reference(image_name)

    # 1. Docker Hub fast path via official Hub API if public
    if ref.is_docker_hub:
        url = f"https://hub.docker.com/v2/repositories/{ref.repository}/"
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                return True, f"Verified image repository '{ref.repository}' on Docker Hub."
            if resp.status_code == 404:
                return False, (
                    f"🚨 Registry Alert: Target image '{ref.repository}' does not exist on Docker Hub. "
                    f"High probability of typosquatting/malicious dependency insertion."
                )
        except requests.RequestException:
            pass  # Fall back to OCI protocol below

    # 2. Standard OCI Distribution API
    headers = _get_oci_auth_header(ref, timeout=timeout)
    headers["Accept"] = MANIFEST_ACCEPT_HEADERS

    manifest_url = f"https://{ref.registry_host}/v2/{ref.repository}/manifests/{ref.tag}"
    try:
        resp = requests.head(manifest_url, headers=headers, timeout=timeout)
        if resp.status_code in (200, 204):
            return True, f"Verified image and tag on registry '{ref.registry}'."
        if resp.status_code == 404:
            # Check if the repository exists by querying tags list
            tags_url = f"https://{ref.registry_host}/v2/{ref.repository}/tags/list"
            tags_resp = requests.get(tags_url, headers=headers, timeout=timeout)
            if tags_resp.status_code == 404:
                return False, (
                    f"🚨 Registry Alert: Repository '{ref.repository}' does not exist on '{ref.registry}'. "
                    f"Possible typosquat or non-existent image."
                )
            if tags_resp.status_code == 200:
                # Repo exists, but tag is missing
                return False, (
                    f"🚨 Registry Alert: Tag '{ref.tag}' does not exist in repository '{ref.repository}' on '{ref.registry}'. "
                    f"Fabricated or non-existent version tag."
                )

        return True, f"Registry lookup returned HTTP {resp.status_code}, defaulting to safe allowance."
    except requests.RequestException as e:
        return True, f"Network timeout contacting registry '{ref.registry}': {e}"


def check_registry_tag_exists(image_name: str, timeout: int = 6) -> tuple[bool, Optional[str]]:
    """
    Detect non-existent or fabricated tags across any registry.

    Returns:
        (is_fake: bool, warning_message: Optional[str])
    """
    ref = parse_image_reference(image_name)

    # Digest-pinned refs have no mutable tag
    if "@sha256:" in image_name:
        return False, None

    # Latest tag is standard, skip fabrication check
    if ref.tag == "latest":
        return False, None

    # 1. Docker Hub specialized tags API
    if ref.is_docker_hub:
        url = f"https://hub.docker.com/v2/repositories/{ref.repository}/tags/{ref.tag}/"
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 404:
                return True, (
                    f"🚨 Fake Version Tag: '{ref.tag}' does not exist for image "
                    f"'{ref.repository}' on Docker Hub. "
                    f"This version string appears to be fabricated — possible "
                    f"shadow-tag injection or supply chain manipulation."
                )
            if resp.status_code == 200:
                return False, None
        except requests.RequestException:
            pass

    # 2. Universal OCI Registry manifest HEAD
    headers = _get_oci_auth_header(ref, timeout=timeout)
    headers["Accept"] = MANIFEST_ACCEPT_HEADERS
    manifest_url = f"https://{ref.registry_host}/v2/{ref.repository}/manifests/{ref.tag}"

    try:
        resp = requests.head(manifest_url, headers=headers, timeout=timeout)
        if resp.status_code in (200, 204):
            return False, None
        if resp.status_code == 404:
            return True, (
                f"🚨 Fake Version Tag: '{ref.tag}' does not exist for image "
                f"'{ref.repository}' on registry '{ref.registry}'."
            )
    except requests.RequestException:
        pass

    return False, None


def fetch_registry_digest(image_name: str, timeout: int = 8) -> Optional[str]:
    """
    Fetch the content-digest for an image tag from its OCI registry.

    Works for Docker Hub, GHCR, Quay, ECR, GCR, and any OCI-compliant registry.
    Returns:
        Digest string (e.g. "sha256:1234...") or None on failure.
    """
    ref = parse_image_reference(image_name)

    headers = _get_oci_auth_header(ref, timeout=timeout)
    headers["Accept"] = MANIFEST_ACCEPT_HEADERS

    manifest_url = f"https://{ref.registry_host}/v2/{ref.repository}/manifests/{ref.tag}"

    try:
        resp = requests.head(manifest_url, headers=headers, timeout=timeout)
        if resp.status_code in (200, 204):
            digest = resp.headers.get("Docker-Content-Digest") or resp.headers.get("Etag", "").strip('"')
            if digest and digest.startswith("sha256:"):
                return digest

        # If HEAD didn't return Docker-Content-Digest header, fallback to GET and calculate sha256
        resp_get = requests.get(manifest_url, headers=headers, timeout=timeout)
        if resp_get.status_code == 200:
            digest = resp_get.headers.get("Docker-Content-Digest")
            if digest and digest.startswith("sha256:"):
                return digest
            # Calculate sha256 of the raw manifest payload
            computed = "sha256:" + hashlib.sha256(resp_get.content).hexdigest()
            return computed

    except requests.RequestException as e:
        logger.debug("Failed to fetch registry digest for %s: %s", image_name, e)

    return None


def _find_highest_version_tag(tags: list[str]) -> Optional[str]:
    """Find the highest semantic release version among tag names."""
    try:
        from packaging.version import parse as _pv, InvalidVersion
    except ImportError:
        _pv = None
        InvalidVersion = Exception

    scored_tags = []
    for tag in tags:
        m = re.match(r"^v?(\d+(?:\.\d+)+)", tag)
        if not m:
            continue
        v_str = m.group(1)
        if _pv is not None:
            try:
                v = _pv(v_str)
                if not getattr(v, "is_prerelease", False):
                    scored_tags.append((v, tag))
                continue
            except InvalidVersion:
                pass
        try:
            parts = tuple(int(x) for x in v_str.split("."))
            scored_tags.append((parts, tag))
        except ValueError:
            pass

    if scored_tags:
        scored_tags.sort(key=lambda item: item[0])
        return scored_tags[-1][1]
    return None


def fetch_latest_tag_from_registry(image_name: str, timeout: int = 6) -> str:
    """
    Fetch the latest tag for an image repository across any registry.
    Prefers the highest semantic release version when available.
    """
    ref = parse_image_reference(image_name)

    # 1. Docker Hub API
    if ref.is_docker_hub:
        url = f"https://hub.docker.com/v2/repositories/{ref.repository}/tags/?page_size=50"
        try:
            res = requests.get(url, timeout=timeout)
            if res.status_code == 200:
                results = res.json().get("results", [])
                tag_names = [t.get("name", "") for t in results if t.get("name")]
                best_tag = _find_highest_version_tag(tag_names)
                if best_tag:
                    return best_tag
                if tag_names:
                    return tag_names[0]
        except requests.RequestException:
            pass

    # 2. OCI Registry tags/list
    headers = _get_oci_auth_header(ref, timeout=timeout)
    tags_url = f"https://{ref.registry_host}/v2/{ref.repository}/tags/list"
    try:
        res = requests.get(tags_url, headers=headers, timeout=timeout)
        if res.status_code == 200:
            tags = res.json().get("tags", [])
            if tags:
                best_tag = _find_highest_version_tag(tags)
                if best_tag:
                    return best_tag
                if "latest" in tags:
                    return "latest"
                return tags[-1]
    except requests.RequestException:
        pass

    return "unknown"
