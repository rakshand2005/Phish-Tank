"""
Shared data models (contract) for the Container Security Scanner.

This module defines the data structures that flow through the pipeline:
    integrity.py → sbom.py → matcher.py → layers.py → main.py → P3/P4

Person 3 (scoring) and Person 4 (reporting) should code against these
dataclasses. The ScanResult is the final output of Person 1's pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class IntegrityResult:
    """Result of image integrity verification checks."""

    image_signed: bool = False
    signature_warning: Optional[str] = None
    sbom_attested: bool = False
    attestation_warning: Optional[str] = None
    digest_pinned: bool = False
    digest_warning: Optional[str] = None
    typosquat_risk: bool = False
    typosquat_warning: Optional[str] = None

    @property
    def passed(self) -> bool:
        """True if no critical integrity issues were found."""
        return not self.typosquat_risk

    @property
    def warnings(self) -> list[str]:
        """Collect all active warnings."""
        result = []
        if self.signature_warning:
            result.append(self.signature_warning)
        if self.attestation_warning:
            result.append(self.attestation_warning)
        if self.digest_warning:
            result.append(self.digest_warning)
        if self.typosquat_warning:
            result.append(self.typosquat_warning)
        return result


@dataclass
class Package:
    """A software package found inside the container image."""

    name: str
    version: str
    pkg_type: str  # "os", "python", "node", "java", "go", "ruby", "rust"
    layer_id: Optional[str] = None
    layer_command: Optional[str] = None


@dataclass
class CVEMatch:
    """A CVE matched against a package in the image."""

    cve_id: str
    package: str
    installed_version: str
    fixed_version: Optional[str] = None
    severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: float = 0.0
    layer_id: Optional[str] = None
    layer_command: Optional[str] = None
    description: str = ""
    fix_suggestion: Optional[str] = None
    # Add to CVEMatch dataclass:
    epss_score:     float = 0.0
    in_kev:         bool  = False
    priority_score: float = 0.0

    @property
    def is_fixable(self) -> bool:
        """True if a fixed version is available."""
        return self.fixed_version is not None and self.fixed_version != ""


@dataclass
class LayerInfo:
    """Metadata about a single Docker image layer."""

    layer_id: str
    command: str
    size_bytes: int = 0
    cve_count: int = 0
    cves_introduced: list[str] = field(default_factory=list)


@dataclass
class DBFreshnessResult:
    """Result of the Trivy vulnerability database freshness check."""

    db_age_hours: float = 0.0
    is_stale: bool = False
    last_updated: Optional[str] = None
    warning: Optional[str] = None


@dataclass
class ScanResult:
    """
    Final output of Person 1's pipeline.

    This is the complete data structure handed off to:
    - Person 3 (scoring.py / gate.py) for risk scoring + CI gate logic
    - Person 4 (report.py) for JSON + terminal report output
    """

    image: str
    tag: str
    integrity: IntegrityResult
    db_freshness: DBFreshnessResult
    total_packages: int = 0
    packages: list[Package] = field(default_factory=list)
    cves: list[CVEMatch] = field(default_factory=list)
    layers: list[LayerInfo] = field(default_factory=list)
    sbom_path: Optional[str] = None
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count CVEs by severity level."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for cve in self.cves:
            severity = cve.severity.upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["UNKNOWN"] += 1
        return counts

    @property
    def has_critical(self) -> bool:
        """True if any CRITICAL severity CVEs were found."""
        return self.severity_counts["CRITICAL"] > 0

    @property
    def fixable_count(self) -> int:
        """Number of CVEs that have a known fix."""
        return sum(1 for cve in self.cves if cve.is_fixable)

    def to_dict(self) -> dict:
        """Convert to a JSON-serializable dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
