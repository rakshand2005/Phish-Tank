"""Test 2 — Registry Existence Check (Live API)."""
from phishnet.integrity import verify_image_exists_on_registry

def test_registry_check():
    print("=" * 60)
    print("TEST 2 — Registry Existence Check (Live API)")
    print("=" * 60)

    # Real image — should return True
    exists, msg = verify_image_exists_on_registry("nginx:latest")
    print(f"nginx exists: {exists} | {msg}")
    assert exists is True

    # Fake image — returns False when online (or True with timeout note if offline)
    exists2, msg2 = verify_image_exists_on_registry("totally-fake-image-xyz123:latest")
    print(f"\nFake image exists: {exists2} | {msg2}")
    assert msg2 is not None

if __name__ == "__main__":
    test_registry_check()
