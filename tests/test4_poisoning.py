"""Test 4 — Supply Chain Poison Detection (Digest Drift)."""
import phishnet.integrity as integ
from phishnet.integrity import check_tag_poisoning

def test_poisoning():
    print("=" * 60)
    print("TEST 4a — No Drift (normal image)")
    print("=" * 60)

    poisoned, msg = check_tag_poisoning("nginx:1.25.3")
    print(f"Poisoned: {poisoned}")
    print(f"Message: {msg}")   # Expected: None (clean) or False if not local
    assert poisoned is False

    print()
    print("=" * 60)
    print("TEST 4b — Simulated Digest Drift (monkey-patch)")
    print("=" * 60)

    original_local = integ._resolve_local_digest
    original_reg = integ._fetch_registry_digest

    # Monkey-patch to return mismatching digests
    integ._resolve_local_digest = lambda name: "sha256:" + "a" * 64
    integ._fetch_registry_digest = lambda name: "sha256:" + "b" * 64

    try:
        poisoned2, msg2 = integ.check_tag_poisoning("nginx:1.25.3")
        print(f"Poisoned: {poisoned2}")
        print(f"Message:\n{msg2}")
        assert poisoned2 is True
        assert msg2 is not None
        assert "Supply Chain Poisoning Detected" in msg2
    finally:
        integ._resolve_local_digest = original_local
        integ._fetch_registry_digest = original_reg

if __name__ == "__main__":
    test_poisoning()
