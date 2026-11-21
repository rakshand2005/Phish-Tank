"""
Risk Scoring Module — Person 3 deliverable.

Enriches each CVEMatch with three external signals:
    • CVSS v3  — code-level severity (already in CVEMatch.cvss_score from Trivy)
    • EPSS     — statistical exploit probability (0–1) from FIRST.org
    • CISA KEV — "is it being exploited RIGHT NOW?" flag from CISA

Then computes a composite priority_score (0–10) and decides whether
the CI gate should block the build.

Drop-in usage inside main.py (Step 4.5, after parse_cve_matches):

    from phishnet.scoring import enrich_and_score, gate_decision

    cves = parse_cve_matches(trivy_json)
    cves = enrich_and_score(cves)           # adds .priority_score etc.
    exit_code, reason = gate_decision(cves) # 0 = pass, 1 = block

Data sources (all free, no API key needed):
    EPSS   — https://api.first.org/data/v1/epss
    KEV    — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

from phishnet.registry import fetch_registry_digest, fetch_latest_tag_from_registry

logger = logging.getLogger(__name__)

# ── Tuneable weights ────────────────────────────────────────────────────────
# These three must sum to 1.0.
# Rationale:
#   KEV gets the most weight — active exploitation is the clearest signal.
#   EPSS next — statistical likelihood beats theoretical severity.
#   CVSS last — it tells you how bad it *could* be, not how likely it *is*.
W_CVSS = 0.25
W_EPSS = 0.35
W_KEV  = 0.40

# CI gate: block if any CVE exceeds this threshold (0–10 scale)
# Threshold set to 6.0 so critical non-KEV vulnerabilities (CVSS 10, high EPSS) can block
GATE_THRESHOLD = 6.0

# API endpoints
EPSS_API   = "https://api.first.org/data/v1/epss"
KEV_API    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Retry / timeout config
REQUEST_TIMEOUT = 10   # seconds per request
MAX_EPSS_BATCH  = 30   # FIRST.org allows up to ~100 CVE IDs per call


# ── Extended CVE model ──────────────────────────────────────────────────────

@dataclass
class ScoredCVE:
    """
    Wraps a CVEMatch with enrichment from EPSS and KEV,
    plus the computed priority_score.

    Person 4 (report.py) should iterate result.scored_cves instead of
    result.cves when this module is active.
    """
    # ── original fields (mirror CVEMatch) ──
    cve_id:            str
    package:           str
    installed_version: str
    fixed_version:     Optional[str]
    severity:          str
    cvss_score:        float
    layer_id:          Optional[str]
    layer_command:     Optional[str]
    description:       str
    fix_suggestion:    Optional[str]
    pkg_type:          str   = "os"
    target_path:       Optional[str] = None

    # ── enrichment ──
    epss_score:        float = 0.0   # 0.0–1.0 from FIRST.org
    epss_percentile:   float = 0.0   # how rare/common this EPSS is (0–1)
    in_kev:            bool  = False  # True = CISA confirmed active exploitation
    kev_date_added:    Optional[str] = None   # ISO date CISA first listed it
    tag_poisoned:      bool  = False  # True = digest drift detected (supply chain)

    # ── output ──
    priority_score:    float = 0.0   # composite 0–10
    risk_label:        str   = "LOW" # CRITICAL / HIGH / MEDIUM / LOW

    @property
    def blocks_ci(self) -> bool:
        return self.priority_score >= GATE_THRESHOLD or self.in_kev or self.tag_poisoned

    @property
    def is_fixable(self) -> bool:
        """True if a fixed version is available."""
        return self.fixed_version is not None and self.fixed_version != ""

    def score_breakdown(self) -> str:
        """Human-readable score explanation for the report."""
        cvss_contrib = (self.cvss_score / 10) * W_CVSS * 10
        epss_contrib = self.epss_score       * W_EPSS * 10
        kev_contrib  = (1.0 if self.in_kev else 0.0) * W_KEV * 10
        kev_flag     = "YES (CISA KEV)" if self.in_kev else "no"
        poison_flag  = " | ⚠️ SUPPLY CHAIN POISONED (×1.50)" if self.tag_poisoned else ""
        type_badge   = f"[{self.pkg_type.upper()}] " if self.pkg_type != "os" else ""
        return (
            f"{type_badge}CVSS {self.cvss_score:.1f} (+{cvss_contrib:.2f}) | "
            f"EPSS {self.epss_score:.4f} (+{epss_contrib:.2f}) | "
            f"KEV {kev_flag} (+{kev_contrib:.2f}) "
            f"→ priority {self.priority_score:.2f}/10{poison_flag}"
        )


# ── Data fetchers ────────────────────────────────────────────────────────────

def _fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs from FIRST.org.

    Returns a dict keyed by CVE ID:
        { "CVE-2021-44228": {"epss": 0.975, "percentile": 0.999}, ... }

    Handles batching automatically. On any network failure, returns an
    empty dict — the caller falls back to epss_score=0.0 (conservative).
    """
    result: dict[str, dict] = {}
    if not cve_ids:
        return result

    # Batch into chunks so we don't hit URL length limits
    for i in range(0, len(cve_ids), MAX_EPSS_BATCH):
        batch = cve_ids[i : i + MAX_EPSS_BATCH]
        params = {"cve": ",".join(batch)}
        try:
            resp = requests.get(EPSS_API, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("data", []):
                cve = entry.get("cve", "").upper()
                result[cve] = {
                    "epss":       float(entry.get("epss", 0.0)),
                    "percentile": float(entry.get("percentile", 0.0)),
                }
        except requests.RequestException as e:
            logger.warning("EPSS API unreachable for batch %d: %s", i // MAX_EPSS_BATCH, e)
        except (KeyError, ValueError) as e:
            logger.warning("EPSS response parse error: %s", e)

        # Be a polite API citizen
        if i + MAX_EPSS_BATCH < len(cve_ids):
            time.sleep(0.3)

    return result


def _fetch_kev() -> set[str]:
    """
    Fetch the CISA Known Exploited Vulnerabilities catalogue.

    Returns a set of CVE IDs that CISA has confirmed are being actively
    exploited in the wild. On failure, returns an empty set.
    """
    try:
        resp = requests.get(KEV_API, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return {
            vuln["cveID"].upper()
            for vuln in data.get("vulnerabilities", [])
            if "cveID" in vuln
        }
    except requests.RequestException as e:
        logger.warning("CISA KEV API unreachable: %s", e)
        return set()
    except (KeyError, ValueError) as e:
        logger.warning("CISA KEV parse error: %s", e)
        return set()


def _fetch_kev_with_dates() -> dict[str, str]:
    """
    Like _fetch_kev() but returns { cve_id: date_added } for richer reporting.
    """
    try:
        resp = requests.get(KEV_API, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return {
            vuln["cveID"].upper(): vuln.get("dateAdded", "")
            for vuln in data.get("vulnerabilities", [])
            if "cveID" in vuln
        }
    except requests.RequestException as e:
        logger.warning("CISA KEV API unreachable: %s", e)
        return {}


# ── Docker Registry helpers ───────────────────────────────────────────────────

def fetch_latest_version_from_registry(image_name: str) -> str:
    """
    Queries Docker Hub or any OCI Registry API to pull the most recent tag release for an image.
    """
    return fetch_latest_tag_from_registry(image_name)


def _version_outdated_multiplier(installed_version: str, image_name: str) -> float:
    """
    Returns a score multiplier based on how outdated the installed version is.

    Compares the installed_version against the latest tag fetched from
    the registry. If they differ, applies a penalty multiplier:
        - Same version or unknown   →  1.0  (no change)
        - Version mismatch detected →  1.25 (25 % boost; unpatched vector)
    """
    latest = fetch_latest_version_from_registry(image_name)
    if latest == "unknown":
        logger.debug("Could not determine latest version for '%s'; skipping multiplier.", image_name)
        return 1.0

    if latest != installed_version:
        logger.info(
            "Version outdated for '%s': installed=%s, latest=%s — applying patch multiplier.",
            image_name, installed_version, latest,
        )
        return 1.25

    return 1.0


# ── Supply chain poisoning signal ─────────────────────────────────────────────

# Shared session-level cache so we don't re-fetch the registry digest for
# every CVE belonging to the same image (one image → many CVEs).
_digest_cache: dict[str, bool] = {}


def _check_digest_drift(image_name: str) -> bool:
    """
    Returns True if the locally-pulled digest of image_name no longer matches
    the digest currently served by the registry (tag was silently overwritten).
    """
    if image_name in _digest_cache:
        return _digest_cache[image_name]

    import subprocess, re as _re

    def _local_digest(name: str) -> Optional[str]:
        try:
            r = subprocess.run(
                ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", name],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                m = _re.search(r"sha256:([a-f0-9]{64})", r.stdout)
                if m:
                    return "sha256:" + m.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    local = _local_digest(image_name)
    registry = fetch_registry_digest(image_name)

    drifted = bool(local and registry and local != registry)
    if drifted:
        logger.warning(
            "SCORING: digest drift detected for '%s' — local=%s registry=%s",
            image_name, local, registry,
        )

    _digest_cache[image_name] = drifted
    return drifted

    _digest_cache[image_name] = drifted
    return drifted




def _compute_priority(
    cvss_score: float,
    epss_score: float,
    in_kev: bool,
    version_multiplier: float = 1.0,   # patch-lag penalty (outdated version)
    poison_multiplier:  float = 1.0,   # supply chain penalty (digest drift)
) -> float:
    """
    Composite priority score on a 0–10 scale.

    Formula:
        priority = (cvss/10 * W_CVSS + epss * W_EPSS + kev_flag * W_KEV) * 10
                   * version_multiplier   ← outdated version penalty
                   * poison_multiplier    ← supply chain poisoning penalty

    Multipliers are independent and stack multiplicatively:
        - version_multiplier = 1.25  if installed version lags latest release
        - poison_multiplier  = 1.50  if tag digest has drifted (poisoned tag)
        - Combined worst-case: raw_score × 1.25 × 1.50 = × 1.875, capped at 10.

    With default weights (0.25 / 0.35 / 0.40):
        - KEV alone                         →  4.0/10
        - KEV + EPSS 0.97 + CVSS 9.8        → ~9.8/10
        - Pure CVSS 9.8, EPSS 0.01, no KEV  →  2.8/10
        - Any of the above + poison tag      →  × 1.5  (capped at 10)
    """
    cvss_norm = min(cvss_score, 10.0) / 10.0
    epss_norm = min(max(epss_score, 0.0), 1.0)
    kev_norm  = 1.0 if in_kev else 0.0

    raw = (cvss_norm * W_CVSS + epss_norm * W_EPSS + kev_norm * W_KEV)
    return round(min(raw * 10.0 * version_multiplier * poison_multiplier, 10.0), 3)


def _risk_label(score: float) -> str:
    """Map priority score to a human-readable risk label."""
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 3.5:
        return "MEDIUM"
    return "LOW"


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_and_score(cves: list, image_name: Optional[str] = None) -> list[ScoredCVE]:
    """
    Main entry point for Person 3.

    Takes the list[CVEMatch] from matcher.parse_cve_matches() and returns
    list[ScoredCVE] sorted by priority_score descending (most dangerous first).

    Network calls:
        1. One batched EPSS API call (all CVE IDs at once)
        2. One CISA KEV download (~200 KB JSON, cached for the session)

    Args:
        cves: list[CVEMatch] from phishnet.matcher.parse_cve_matches()
        image_name: Optional full container image reference (e.g. "nginx:1.14")

    Returns:
        list[ScoredCVE] enriched and sorted by priority_score desc.
    """
    if not cves:
        return []

    logger.info("Enriching %d CVEs with EPSS and CISA KEV data...", len(cves))

    # ── Image-level multipliers ──
    # Check tag poisoning (digest drift) once per container image
    poison_mult = 1.0
    version_mult = 1.0
    if image_name:
        if _check_digest_drift(image_name):
            poison_mult = 1.50
        # Check if container image tag lags latest release
        parts = image_name.split("@")[0]
        tag = parts.rsplit(":", 1)[1] if ":" in parts.split("/")[-1] else "latest"
        version_mult = _version_outdated_multiplier(tag, image_name)

    # ── 1. Collect all unique CVE IDs ──
    cve_ids = list({c.cve_id.upper() for c in cves})

    # ── 2. Fetch both signals in parallel (simple sequential is fine here) ──
    logger.info("Fetching EPSS scores from FIRST.org...")
    epss_data = _fetch_epss(cve_ids)

    logger.info("Fetching CISA KEV catalogue...")
    kev_data  = _fetch_kev_with_dates()

    epss_hits = sum(1 for cid in cve_ids if cid in epss_data)
    kev_hits  = sum(1 for cid in cve_ids if cid in kev_data)
    logger.info("EPSS: %d/%d hits | KEV: %d/%d hits", epss_hits, len(cve_ids), kev_hits, len(cve_ids))

    # ── 3. Build ScoredCVE objects ──
    scored: list[ScoredCVE] = []
    for cve in cves:
        cid      = cve.cve_id.upper()
        epss_rec = epss_data.get(cid, {})
        epss     = epss_rec.get("epss", 0.0)
        pct      = epss_rec.get("percentile", 0.0)
        in_kev   = cid in kev_data
        kev_date = kev_data.get(cid)

        priority = _compute_priority(cve.cvss_score, epss, in_kev, version_mult, poison_mult)

        scored.append(ScoredCVE(
            # mirror original fields
            cve_id            = cve.cve_id,
            package           = cve.package,
            installed_version = cve.installed_version,
            fixed_version     = cve.fixed_version,
            severity          = cve.severity,
            cvss_score        = cve.cvss_score,
            layer_id          = cve.layer_id,
            layer_command     = cve.layer_command,
            description       = cve.description,
            fix_suggestion    = cve.fix_suggestion,
            pkg_type          = getattr(cve, "pkg_type", "os"),
            target_path       = getattr(cve, "target_path", None),
            # enrichment
            epss_score        = epss,
            epss_percentile   = pct,
            in_kev            = in_kev,
            kev_date_added    = kev_date,
            tag_poisoned      = (poison_mult > 1.0),
            # computed
            priority_score    = priority,
            risk_label        = _risk_label(priority),
        ))

    # Sort: highest priority first
    scored.sort(key=lambda s: s.priority_score, reverse=True)

    blocking = [s for s in scored if s.blocks_ci]
    logger.info(
        "Scoring complete. %d CVEs block CI (priority >= %.1f)",
        len(blocking), GATE_THRESHOLD
    )
    return scored


def gate_decision(scored_cves: list[ScoredCVE]) -> tuple[int, str]:
    """
    CI gate logic.

    Returns:
        (0, "Pipeline can proceed.") if nothing blocks.
        (1, "<reason>") if any CVE exceeds GATE_THRESHOLD.

    Usage in main.py:

        exit_code, reason = gate_decision(scored_cves)
        if exit_code != 0:
            console.print(f"[bold red]CI GATE BLOCKED: {reason}[/bold red]")
        sys.exit(exit_code)
    """
    blockers = [s for s in scored_cves if s.blocks_ci]
    if not blockers:
        return 0, "Pipeline can proceed — no CVEs exceed the risk threshold."

    top = blockers[0]
    kev_note     = " [CISA KEV — actively exploited]" if top.in_kev else ""
    poison_note  = " [⚠️ SUPPLY CHAIN TAG POISONED]"  if top.tag_poisoned else ""
    reason = (
        f"{len(blockers)} CVE(s) exceed the risk threshold of {GATE_THRESHOLD}/10. "
        f"Worst offender: {top.cve_id} on {top.package} "
        f"(priority {top.priority_score}/10, EPSS {top.epss_score:.4f})"
        f"{kev_note}{poison_note}."
    )
    return 1, reason


# ── Quick self-test (run: python -m phishnet.scoring) ────────────────────────

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Simulate three CVEMatch-like objects using a simple namespace
    from types import SimpleNamespace

    mock_cves = [
        SimpleNamespace(
            cve_id="CVE-2021-44228",  # Log4Shell — should be KEV + high EPSS
            package="log4j", installed_version="2.14.1", fixed_version="2.17.1",
            severity="CRITICAL", cvss_score=10.0,
            layer_id=None, layer_command=None, description="Log4Shell RCE", fix_suggestion=None,
        ),
        SimpleNamespace(
            cve_id="CVE-2019-1549",   # Older OpenSSL — likely lower EPSS
            package="openssl", installed_version="1.0.2k", fixed_version="1.0.2u",
            severity="MEDIUM", cvss_score=5.3,
            layer_id=None, layer_command=None, description="Info disclosure", fix_suggestion=None,
        ),
        SimpleNamespace(
            cve_id="CVE-2023-99999",  # Fake CVE — no EPSS, no KEV
            package="somepkg", installed_version="1.0", fixed_version=None,
            severity="HIGH", cvss_score=7.8,
            layer_id=None, layer_command=None, description="Fake test CVE", fix_suggestion=None,
        ),
    ]

    print("\n=== SCORING DEMO ===\n")
    results = enrich_and_score(mock_cves)

    for r in results:
        print(f"{r.cve_id:20s}  {r.risk_label:8s}  {r.score_breakdown()}")

    print()
    code, msg = gate_decision(results)
    status = "BLOCKED" if code else "PASSED"
    print(f"CI Gate: {status} — {msg}")
