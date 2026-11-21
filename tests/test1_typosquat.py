"""Test 1 — Typosquat detection (Levenshtein fallback)."""
from phishnet.integrity import check_typosquat

def test_typosquat():
    print("=" * 60)
    print("TEST 1 — Typosquat Detection (Levenshtein)")
    print("=" * 60)

    # Should flag: 1 edit away from "nginx" (X vs x)
    risk, msg = check_typosquat("nginX:latest")
    print(f"Typosquat risk: {risk}")
    print(f"Message: {msg}")
    assert risk is True
    assert msg is not None

    # Should pass: exact match in POPULAR_IMAGES
    risk2, msg2 = check_typosquat("nginx:latest")
    print(f"\nExact match risk: {risk2}")   # Expected: False
    print(f"Message: {msg2}")              # Expected: None
    assert risk2 is False
    assert msg2 is None

if __name__ == "__main__":
    test_typosquat()
