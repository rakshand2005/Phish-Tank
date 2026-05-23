"""Test 3 — Fake Version Tag Detection (Live API)."""
from scanner.integrity import check_fake_version_tag

print("=" * 60)
print("TEST 3 — Fake Version Tag Detection (Live API)")
print("=" * 60)

# Real tag — should pass
fake, msg = check_fake_version_tag("nginx:1.25.3")
print(f"nginx:1.25.3 fake={fake} | {msg}")

# Invented version — should be flagged
fake2, msg2 = check_fake_version_tag("nginx:1.999.0")
print(f"\nnginx:1.999.0 fake={fake2}")
print(f"Message: {msg2}")

# Invented tag on python
fake3, msg3 = check_fake_version_tag("python:3.11.999")
print(f"\npython:3.11.999 fake={fake3}")
print(f"Message: {msg3}")
