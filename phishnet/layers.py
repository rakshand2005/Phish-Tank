"""
Layer Attribution Module.

Uses the Docker SDK to inspect image layers and attribute each CVE
to the specific layer that introduced it. Generates Dockerfile fix
suggestions showing which line to change.
"""

from __future__ import annotations

import logging
from typing import Optional

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
except ImportError:
    docker = None
    DockerException = Exception  # type: ignore
    ImageNotFound = Exception    # type: ignore

from phishnet.models import CVEMatch, LayerInfo

logger = logging.getLogger(__name__)


def get_docker_client():
    """
    Create a Docker SDK client.

    Returns:
        Connected Docker client.

    Raises:
        RuntimeError: If Docker daemon is not available.
    """
    if docker is None:
        raise RuntimeError(
            "docker SDK is not installed in Python environment.\n"
            "Install with 'pip install docker' or run Phish Net via Docker."
        )
    try:
        client = docker.from_env()
        client.ping()
        return client
    except DockerException as e:
        raise RuntimeError(
            f"Cannot connect to Docker daemon: {e}\n"
            "Make sure Docker is running and accessible."
        )


def pull_image(image_name: str) -> docker.models.images.Image:
    """
    Pull a Docker image from the registry.

    Args:
        image_name: The image to pull (e.g., "nginx:1.14").

    Returns:
        Docker Image object.

    Raises:
        RuntimeError: If the image cannot be pulled.
    """
    client = get_docker_client()
    logger.info("Pulling image: %s", image_name)

    try:
        image = client.images.pull(image_name)
        logger.info("Image pulled: %s (ID: %s)", image_name, image.short_id)
        return image
    except ImageNotFound:
        raise RuntimeError(f"Image not found: '{image_name}'")
    except DockerException as e:
        raise RuntimeError(f"Failed to pull image '{image_name}': {e}")


def get_layer_metadata(image_name: str) -> list[LayerInfo]:
    """
    Extract layer metadata from a Docker image using Docker SDK.

    Uses `docker history` to get the ordered list of layers with
    their commands (FROM, RUN, COPY, etc.) and sizes.

    Args:
        image_name: The image to inspect (e.g., "nginx:1.14").

    Returns:
        Ordered list of LayerInfo objects (bottom layer first).
    """
    client = get_docker_client()

    try:
        image = client.images.get(image_name)
    except ImageNotFound:
        logger.info("Image not found locally, pulling: %s", image_name)
        image = pull_image(image_name)

    # Get image history (layer commands)
    history = image.history()

    # Get diff IDs from image inspect (ordered from bottom to top)
    inspect_data = client.api.inspect_image(image_name)
    diff_ids = inspect_data.get("RootFS", {}).get("Layers", [])

    layers: list[LayerInfo] = []

    # History is in reverse order (most recent first), diff_ids are bottom-up
    # We need to match them up
    real_layer_idx = len(diff_ids) - 1

    for entry in history:
        created_by = entry.get("CreatedBy", "")
        size = entry.get("Size", 0)

        # Clean up the command string
        command = _clean_layer_command(created_by)

        # Only real layers (non-empty) have a diff ID in inspect RootFS
        if size > 0 and real_layer_idx >= 0:
            layer_id = diff_ids[real_layer_idx]
            real_layer_idx -= 1
        else:
            layer_id = f"metadata-{len(layers)}"

        layers.append(
            LayerInfo(
                layer_id=layer_id,
                command=command,
                size_bytes=size,
            )
        )

    # Reverse so bottom layer is first (build order)
    layers.reverse()

    logger.info("Found %d layers for image %s", len(layers), image_name)
    return layers


def attribute_cves_to_layers(
    cves: list[CVEMatch],
    layers: list[LayerInfo],
) -> list[CVEMatch]:
    """
    Attribute each CVE to the layer that introduced the vulnerable package.

    Uses the layer DiffID from Trivy's output to map CVEs to Docker layers.
    Enriches each CVEMatch with layer_command information.

    Args:
        cves: List of CVEMatch objects from matcher.py.
        layers: List of LayerInfo objects from get_layer_metadata().

    Returns:
        Enriched list of CVEMatch objects with layer attribution.
    """
    # Build a lookup: layer_id → LayerInfo
    layer_lookup: dict[str, LayerInfo] = {}
    for layer in layers:
        layer_lookup[layer.layer_id] = layer

    for cve in cves:
        if cve.layer_id and cve.layer_id in layer_lookup:
            layer = layer_lookup[cve.layer_id]
            cve.layer_command = layer.command

            # Track CVE count per layer
            layer.cve_count += 1
            layer.cves_introduced.append(cve.cve_id)

    attributed = sum(1 for c in cves if c.layer_command is not None)
    logger.info(
        "Attributed %d/%d CVEs to specific layers",
        attributed, len(cves),
    )

    return cves


def generate_fix_suggestions(
    cves: list[CVEMatch],
    layers: list[LayerInfo],
) -> list[CVEMatch]:
    """
    Generate Dockerfile fix suggestions for each fixable CVE.

    For CVEs introduced by a FROM instruction, suggests upgrading the
    base image. For CVEs from RUN apt-get/apk, suggests pinning to
    the fixed version.

    Args:
        cves: List of CVEMatch objects with layer attribution.
        layers: List of LayerInfo objects.

    Returns:
        CVEMatch list with fix_suggestion populated where possible.
    """
    for cve in cves:
        if not cve.is_fixable:
            continue

        if cve.layer_command:
            suggestion = _build_fix_suggestion(cve)
            if suggestion:
                cve.fix_suggestion = suggestion

    suggested = sum(1 for c in cves if c.fix_suggestion)
    logger.info("Generated %d fix suggestions", suggested)

    return cves


def _build_fix_suggestion(cve: CVEMatch) -> Optional[str]:
    """Build a human-readable fix suggestion for a single CVE."""
    cmd = (cve.layer_command or "").lower()
    pkg_type = getattr(cve, "pkg_type", "os")
    target = getattr(cve, "target_path", "") or ""

    # Application package: Python
    if pkg_type == "python" or "pip install" in cmd or "pip3 install" in cmd:
        target_info = f" in {target}" if target else ""
        return (
            f"🔧 Python package vulnerability: {cve.package} {cve.installed_version}\n"
            f"   Fix: Pin or upgrade{target_info}:\n"
            f"   RUN pip install {cve.package}>={cve.fixed_version}"
        )

    # Application package: Node.js
    if pkg_type == "node" or "npm install" in cmd or "npm i " in cmd or "yarn add" in cmd:
        target_info = f" in {target}" if target else " in package.json"
        return (
            f"🔧 Node.js package vulnerability: {cve.package} {cve.installed_version}\n"
            f"   Fix: Update dependency{target_info}:\n"
            f"   npm install {cve.package}@{cve.fixed_version}"
        )

    # Application package: Java
    if pkg_type == "java":
        target_info = f" in {target}" if target else " in pom.xml / build.gradle"
        return (
            f"🔧 Java dependency vulnerability: {cve.package} {cve.installed_version}\n"
            f"   Fix: Update dependency version{target_info} to >={cve.fixed_version}"
        )

    # Application package: Go
    if pkg_type == "go":
        return (
            f"🔧 Go module vulnerability: {cve.package} {cve.installed_version}\n"
            f"   Fix: Update module in go.mod:\n"
            f"   go get {cve.package}@{cve.fixed_version}"
        )

    # CVE from base image (FROM instruction)
    if cmd.startswith("from ") or "add file:" in cmd:
        return (
            f"🔧 Base image vulnerability: {cve.package} {cve.installed_version}\n"
            f"   Fix: Upgrade to a newer base image where "
            f"{cve.package} >= {cve.fixed_version}\n"
            f"   Dockerfile: Consider changing your FROM instruction "
            f"to use a more recent tag."
        )

    # CVE from apt-get install
    if "apt-get" in cmd or "apt " in cmd:
        return (
            f"🔧 Package installed via apt: {cve.package} {cve.installed_version}\n"
            f"   Fix: Pin to fixed version in Dockerfile:\n"
            f"   RUN apt-get install -y {cve.package}={cve.fixed_version}"
        )

    # CVE from apk add
    if "apk add" in cmd or "apk " in cmd:
        return (
            f"🔧 Package installed via apk: {cve.package} {cve.installed_version}\n"
            f"   Fix: Pin to fixed version in Dockerfile:\n"
            f"   RUN apk add {cve.package}={cve.fixed_version}"
        )

    # Generic fix suggestion
    return (
        f"🔧 Upgrade {cve.package}: {cve.installed_version} → {cve.fixed_version}\n"
        f"   Introduced by layer: {cve.layer_command[:80] if cve.layer_command else 'Unknown'}"
    )


def _clean_layer_command(created_by: str) -> str:
    """Clean up a Docker history 'CreatedBy' string for display."""
    # Remove the /bin/sh -c prefix that Docker adds
    if created_by.startswith("/bin/sh -c "):
        created_by = created_by[len("/bin/sh -c "):]

    # Remove the buildkit syntax prefix
    if created_by.startswith("#(nop) "):
        created_by = created_by[len("#(nop) "):]

    # Truncate very long commands
    if len(created_by) > 120:
        created_by = created_by[:117] + "..."

    return created_by.strip()
