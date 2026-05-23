"""
SBOM Generation Module.

Uses Trivy to generate a Software Bill of Materials (SBOM) in CycloneDX
JSON format from a Docker image. Extracts package information from the
generated SBOM.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from scanner.models import Package

logger = logging.getLogger(__name__)


def generate_sbom(image_name: str, output_dir: Optional[str] = None) -> dict:
    """
    Generate an SBOM for the given Docker image using Trivy.

    Runs: trivy image --format cyclonedx --output <file> <image>

    Args:
        image_name: The Docker image to scan (e.g., "nginx:1.14").
        output_dir: Directory to save the SBOM file. If None, uses a temp dir.

    Returns:
        Parsed CycloneDX JSON as a dictionary.

    Raises:
        RuntimeError: If Trivy fails to generate the SBOM.
    """
    if output_dir:
        sbom_path = Path(output_dir) / "sbom.json"
    else:
        sbom_path = Path(tempfile.mkdtemp()) / "sbom.json"

    logger.info("Generating SBOM for '%s' → %s", image_name, sbom_path)

    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "cyclonedx",
                "--scanners", "vuln",
                "--skip-db-update",
                "--skip-java-db-update",
                "--pkg-types", "os",
                "--output", str(sbom_path),
                "--quiet",
                image_name,
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            logger.error("Trivy SBOM generation failed: %s", error_msg)
            raise RuntimeError(
                f"Trivy SBOM generation failed for '{image_name}': {error_msg}"
            )

        if not sbom_path.exists():
            raise RuntimeError(
                f"Trivy completed but SBOM file not found at {sbom_path}"
            )

        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)

        logger.info(
            "SBOM generated: %d components found",
            len(sbom_data.get("components", [])),
        )

        return sbom_data

    except FileNotFoundError:
        raise RuntimeError(
            "Trivy not found. Install from: https://aquasecurity.github.io/trivy/"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Trivy SBOM generation timed out after 600 seconds.")


def get_packages(sbom: dict) -> list[Package]:
    """
    Extract a list of Package objects from a CycloneDX SBOM.

    Args:
        sbom: Parsed CycloneDX JSON dictionary.

    Returns:
        List of Package objects found in the SBOM.
    """
    packages = []
    components = sbom.get("components", [])

    for component in components:
        # Determine package type from CycloneDX purl or type field
        pkg_type = _classify_package(component)

        packages.append(
            Package(
                name=component.get("name", "unknown"),
                version=component.get("version", "unknown"),
                pkg_type=pkg_type,
            )
        )

    logger.info(
        "Extracted %d packages from SBOM (%s)",
        len(packages),
        _summarize_types(packages),
    )

    return packages


def _classify_package(component: dict) -> str:
    """
    Classify a CycloneDX component into a package type.

    Uses the purl (Package URL) if available, otherwise falls back
    to the component type.
    """
    purl = component.get("purl", "")

    # Map purl types to our categories
    purl_type_map = {
        "pkg:apk/": "os",
        "pkg:deb/": "os",
        "pkg:rpm/": "os",
        "pkg:pypi/": "python",
        "pkg:npm/": "node",
        "pkg:maven/": "java",
        "pkg:golang/": "go",
        "pkg:gem/": "ruby",
        "pkg:cargo/": "rust",
        "pkg:nuget/": "dotnet",
        "pkg:composer/": "php",
    }

    for prefix, pkg_type in purl_type_map.items():
        if purl.startswith(prefix):
            return pkg_type

    # Fallback: use CycloneDX component type
    comp_type = component.get("type", "")
    if comp_type == "operating-system":
        return "os"
    elif comp_type == "library":
        return "library"

    return "unknown"


def _summarize_types(packages: list[Package]) -> str:
    """Create a summary string of package type counts."""
    counts: dict[str, int] = {}
    for pkg in packages:
        counts[pkg.pkg_type] = counts.get(pkg.pkg_type, 0) + 1
    return ", ".join(f"{t}: {c}" for t, c in sorted(counts.items()))
