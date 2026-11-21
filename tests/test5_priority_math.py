"""Test 5 — _compute_priority multipliers stack correctly."""
from phishnet.scoring import _compute_priority

def test_priority_math():
    print("=" * 60)
    print("TEST 5 — _compute_priority Multiplier Math")
    print("=" * 60)

    # Baseline: no multipliers
    base = _compute_priority(cvss_score=7.0, epss_score=0.5, in_kev=False)
    print(f"Baseline score:              {base}")
    assert base == 3.5

    # With version lag only (×1.25)
    with_version = _compute_priority(7.0, 0.5, False, version_multiplier=1.25)
    print(f"With version lag (×1.25):    {with_version}")
    assert with_version == 4.375

    # With poison only (×1.50)
    with_poison = _compute_priority(7.0, 0.5, False, poison_multiplier=1.50)
    print(f"With poison (×1.50):         {with_poison}")
    assert with_poison == 5.25

    # Both stacked (×1.875)
    both = _compute_priority(7.0, 0.5, False, version_multiplier=1.25, poison_multiplier=1.50)
    print(f"Both stacked (×1.875):       {both}")
    assert both == 6.562

    # Ceiling check — should never exceed 10.0
    capped = _compute_priority(10.0, 1.0, True, version_multiplier=1.25, poison_multiplier=1.50)
    print(f"Max inputs with multipliers: {capped}  (must be 10.0)")
    assert capped == 10.0

if __name__ == "__main__":
    test_priority_math()
