"""Test 2 — Registry Existence Check (Live API)."""
from scanner.integrity import verify_image_exists_on_registry

print("=" * 60)
print("TEST 2 — Registry Existence Check (Live API)")
print("=" * 60)

# Real image — should return True
exists, msg = verify_image_exists_on_registry("nginx:latest")
print(f"nginx exists: {exists} | {msg}")

# Fake image — should return False with alert
exists2, msg2 = verify_image_exists_on_registry("totally-fake-image-xyz123:latest")
print(f"\nFake image exists: {exists2} | {msg2}")
