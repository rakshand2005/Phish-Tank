"""Test 3 — Fake Version Tag Detection (Live API)."""
from phishnet.integrity import check_fake_version_tag

def test_fake_version_tag():
    print("=" * 60)
    print("TEST 3 — Fake Version Tag Detection (Live API)")
    print("=" * 60)

    # Real tag — should pass
    fake, msg = check_fake_version_tag("nginx:1.25.3")
    print(f"nginx:1.25.3 fake={fake} | {msg}")
    assert fake is False

    # Invented version — should be flagged when online (or False gracefully if offline)
    fake2, msg2 = check_fake_version_tag("nginx:1.999.0")
    print(f"\nnginx:1.999.0 fake={fake2}")
    print(f"Message: {msg2}")

    # Invented tag on python
    fake3, msg3 = check_fake_version_tag("python:3.11.999")
    print(f"\npython:3.11.999 fake={fake3}")
    print(f"Message: {msg3}")

if __name__ == "__main__":
    test_fake_version_tag()
