"""
CVE Matching Module.

Uses Trivy to scan a Docker image for known vulnerabilities (CVEs).
Includes a database freshness check to detect stale vulnerability data.
Parses Trivy's JSON output into normalized CVEMatch objects.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from phishnet.models import CVEMatch, DBFreshnessResult

logger = logging.getLogger(__name__)

# Default maximum age for the Trivy DB before warning (in hours)
MAX_DB_AGE_HOURS = 24


def check_db_freshness(max_age_hours: float = MAX_DB_AGE_HOURS) -> DBFreshnessResult:
    """
    Check the freshness of Trivy's vulnerability database.

    Reads Trivy's local DB metadata to determine when it was last updated.
    Warns if the DB is older than max_age_hours.

    Args:
        max_age_hours: Maximum acceptable age in hours before warning.

    Returns:
        DBFreshnessResult with age and staleness info.
    """
    # Trivy stores DB metadata in its cache directory
    possible_paths = [
        Path.home() / ".cache" / "trivy" / "db" / "metadata.json",
        Path("/root/.cache/trivy/db/metadata.json"),  # Docker container
        Path.home() / "Library" / "Caches" / "trivy" / "db" / "metadata.json",  # macOS
    ]

    metadata_path = None
    for path in possible_paths:
        if path.exists():
            metadata_path = path
            break

    if metadata_path is None:
        logger.info("No Trivy DB metadata found. DB will be downloaded on first scan.")
        return DBFreshnessResult(
            db_age_hours=0,
            is_stale=True,
            last_updated=None,
            warning="⚠️  No Trivy vulnerability DB found locally. It will be downloaded on first scan.",
        )

    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        # Parse the last update timestamp
        updated_at_str = metadata.get("UpdatedAt") or metadata.get("NextUpdate")
        if not updated_at_str:
            return DBFreshnessResult(
                db_age_hours=0,
                is_stale=True,
                warning="⚠️  Cannot determine Trivy DB age from metadata.",
            )

        updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age_hours = (now - updated_at).total_seconds() / 3600

        is_stale = age_hours > max_age_hours
        warning = None
        if is_stale:
            warning = (
                f"⚠️  Trivy vulnerability DB is {age_hours:.1f} hours old "
                f"(threshold: {max_age_hours}h). Run 'trivy db update' to refresh."
            )
            logger.warning(warning)

        return DBFreshnessResult(
            db_age_hours=round(age_hours, 2),
            is_stale=is_stale,
            last_updated=updated_at_str,
            warning=warning,
        )

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error("Failed to parse Trivy DB metadata: %s", e)
        return DBFreshnessResult(
            db_age_hours=0,
            is_stale=True,
            warning=f"⚠️  Failed to read Trivy DB metadata: {e}",
        )


def update_db() -> bool:
    """
    Update the Trivy vulnerability database.

    Returns:
        True if update succeeded.
    """
    logger.info("Updating Trivy vulnerability database...")
    try:
        result = subprocess.run(
            ["trivy", "image", "--download-db-only", "--db-repository", "ghcr.io/aquasecurity/trivy-db:2"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            logger.info("Trivy DB updated successfully.")
            return True
        else:
            logger.error("Trivy DB update failed: %s", result.stderr.strip())
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.error("Trivy DB update error: %s", e)
        return False


def scan_cves(target: str, target_kind: str = "image") -> dict:
    """
    Scan a Docker image for CVEs using Trivy.

    Runs: trivy image --format json <image>

    Args:
        target: Docker image reference or source directory to scan.
        target_kind: Either ``image`` or ``filesystem``.

    Returns:
        Raw Trivy JSON output as a dictionary.

    Raises:
        RuntimeError: If Trivy fails to scan.
    """
    if target_kind not in {"image", "filesystem"}:
        raise ValueError("target_kind must be 'image' or 'filesystem'")

    trivy_target = "image" if target_kind == "image" else "fs"
    pkg_types = "os,library" if target_kind == "image" else "library"
    logger.info("Scanning %s target '%s' for CVEs...", target_kind, target)

    try:
        result = subprocess.run(
            [
                "trivy", trivy_target,
                "--format", "json",
                "--scanners", "vuln",
                "--skip-db-update",
                "--skip-java-db-update",
                "--pkg-types", pkg_types,
                "--quiet",
                target,
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0 and not result.stdout:
            error_msg = result.stderr.strip()
            raise RuntimeError(
                f"Trivy CVE scan failed for '{target}': {error_msg}"
            )

        trivy_json = json.loads(result.stdout)

        total_vulns = sum(
            len(r.get("Vulnerabilities", []))
            for r in trivy_json.get("Results", [])
        )
        logger.info("CVE scan complete: %d vulnerabilities found", total_vulns)

        return trivy_json

    except FileNotFoundError:
        raise RuntimeError(
            "Trivy not found. Install from: https://aquasecurity.github.io/trivy/"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Trivy CVE scan timed out after 300 seconds.")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse Trivy JSON output: {e}")


def parse_cve_matches(trivy_json: dict) -> list[CVEMatch]:
    """
    Parse Trivy's JSON output into a normalized list of CVEMatch objects.

    Extracts vulnerability details including severity, CVSS score,
    fixed version, layer info, and description.

    Args:
        trivy_json: Raw Trivy JSON output from scan_cves().

    Returns:
        List of CVEMatch objects sorted by severity (CRITICAL first).
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    cve_matches: list[CVEMatch] = []
    seen_cves: set[str] = set()  # Deduplicate

    for result in trivy_json.get("Results", []):
        target = result.get("Target", "")
        pkg_type = _classify_cve_package(result)

        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "UNKNOWN")

            # Deduplicate: same CVE in same package
            dedup_key = f"{cve_id}:{vuln.get('PkgName', '')}"
            if dedup_key in seen_cves:
                continue
            seen_cves.add(dedup_key)

            # Extract CVSS score (prefer V3, fall back to V2)
            cvss_score = _extract_cvss_score(vuln)

            # Extract layer information (Trivy includes this in JSON output)
            layer = vuln.get("Layer", {})
            layer_id = layer.get("DiffID", None)

            cve_matches.append(
                CVEMatch(
                    cve_id=cve_id,
                    package=vuln.get("PkgName", "unknown"),
                    installed_version=vuln.get("InstalledVersion", "unknown"),
                    fixed_version=vuln.get("FixedVersion", None),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    cvss_score=cvss_score,
                    layer_id=layer_id,
                    layer_command=None,  # Will be enriched by layers.py
                    description=vuln.get("Title", vuln.get("Description", ""))[:200],
                    pkg_type=pkg_type,
                    target_path=target,
                )
            )

    # Sort by severity (CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN)
    cve_matches.sort(key=lambda c: severity_order.get(c.severity, 99))

    logger.info(
        "Parsed %d unique CVE matches (CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d)",
        len(cve_matches),
        sum(1 for c in cve_matches if c.severity == "CRITICAL"),
        sum(1 for c in cve_matches if c.severity == "HIGH"),
        sum(1 for c in cve_matches if c.severity == "MEDIUM"),
        sum(1 for c in cve_matches if c.severity == "LOW"),
    )

    return cve_matches


def _classify_cve_package(result: dict) -> str:
    """
    Determine the package ecosystem/type (python, node, java, go, etc.) from Trivy result.
    """
    target = result.get("Target", "").lower()
    type_str = (result.get("Type", "") or "").lower()
    class_str = (result.get("Class", "") or "").lower()

    type_map = {
        "pip": "python",
        "poetry": "python",
        "pipenv": "python",
        "npm": "node",
        "yarn": "node",
        "pnpm": "node",
        "nodejs": "node",
        "maven": "java",
        "gradle": "java",
        "pom": "java",
        "gomod": "go",
        "go": "go",
        "bundler": "ruby",
        "gem": "ruby",
        "cargo": "rust",
        "nuget": "dotnet",
        "composer": "php",
    }
    for k, v in type_map.items():
        if k in type_str:
            return v

    if any(p in target for p in ["requirements.txt", "setup.py", "site-packages", "pyproject.toml"]):
        return "python"
    if any(p in target for p in ["package.json", "package-lock.json", "yarn.lock", "node_modules"]):
        return "node"
    if any(p in target for p in ["pom.xml", "build.gradle", ".jar", ".war"]):
        return "java"
    if any(p in target for p in ["go.mod", "go.sum"]):
        return "go"
    if any(p in target for p in ["gemfile", "gemfile.lock"]):
        return "ruby"
    if any(p in target for p in ["cargo.toml", "cargo.lock"]):
        return "rust"

    if class_str == "lang-pkgs":
        return "library"

    return "os"


def _extract_cvss_score(vuln: dict) -> float:
    """
    Extract the best available CVSS score from a Trivy vulnerability entry.

    Prefers CVSS V3 score, falls back to V2.
    """
    # Try CVSS V3 sources (NVD, RedHat, etc.)
    cvss_v3 = vuln.get("CVSS", {})
    for source in ["nvd", "redhat", "ghsa"]:
        if source in cvss_v3:
            score = cvss_v3[source].get("V3Score")
            if score:
                return float(score)

    # Fallback: try the flat Score field
    if "Score" in vuln:
        return float(vuln["Score"])

    # Map severity to approximate score if no CVSS available
    severity_score_map = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
    }
    return severity_score_map.get(vuln.get("Severity", "UNKNOWN"), 0.0)
