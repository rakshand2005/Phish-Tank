"""Test 7 — Full verify_image() End-to-End."""
import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

from scanner.integrity import verify_image

print("=" * 60)
print("TEST 7 — Full verify_image() End-to-End")
print("=" * 60)

# Test with a real image
result = verify_image("nginx:1.25.3")
print("\n── IntegrityResult (nginx:1.25.3) ──")
print(f"  signed:        {result.image_signed}")
print(f"  digest_pinned: {result.digest_pinned}")
print(f"  typosquat:     {result.typosquat_risk}")
print(f"  typosquat_msg: {result.typosquat_warning}")
print(f"  sig_warning:   {result.signature_warning}")

# Test with a fake version tag — should show typosquat_risk=True
result2 = verify_image("nginx:1.999.0")
print("\n── Fake tag result (nginx:1.999.0) ──")
print(f"  typosquat_risk: {result2.typosquat_risk}")
print(f"  warning: {result2.typosquat_warning}")
