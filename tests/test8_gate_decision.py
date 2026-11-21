"""Test 8 — gate_decision() Surfaces Poison in Block Message."""
from phishnet.scoring import ScoredCVE, gate_decision

def test_gate_decision():
    print("=" * 60)
    print("TEST 8 — gate_decision() Block Message with Poison")
    print("=" * 60)

    blocked_cve = ScoredCVE(
        cve_id="CVE-2021-44228", package="log4j",
        installed_version="2.14.1", fixed_version="2.17.1",
        severity="CRITICAL", cvss_score=10.0,
        layer_id=None, layer_command=None,
        description="Log4Shell", fix_suggestion=None,
        epss_score=0.975, in_kev=True,
        tag_poisoned=True,
        priority_score=10.0, risk_label="CRITICAL",
    )

    code, reason = gate_decision([blocked_cve])
    print(f"Exit code: {code}")
    print(f"Reason:    {reason}")
    assert code == 1
    assert "[CISA KEV — actively exploited]" in reason
    assert "[⚠️ SUPPLY CHAIN TAG POISONED]" in reason

if __name__ == "__main__":
    test_gate_decision()
