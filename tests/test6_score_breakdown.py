"""Test 6 — score_breakdown() Shows Poison Flag."""
from scanner.scoring import ScoredCVE

print("=" * 60)
print("TEST 6 — score_breakdown() Shows Poison Flag")
print("=" * 60)

cve = ScoredCVE(
    cve_id="CVE-2021-44228", package="log4j",
    installed_version="2.14.1", fixed_version="2.17.1",
    severity="CRITICAL", cvss_score=10.0,
    layer_id=None, layer_command=None,
    description="Log4Shell", fix_suggestion=None,
    epss_score=0.975, in_kev=True,
    tag_poisoned=True,    # the new field
    priority_score=10.0, risk_label="CRITICAL",
)
print(cve.score_breakdown())
# Expected: ends with  ⚠️ SUPPLY CHAIN POISONED (×1.50)
