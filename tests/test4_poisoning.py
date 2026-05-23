"""Test 4 — Supply Chain Poison Detection (Digest Drift)."""
import scanner.integrity as integ
from scanner.integrity import check_tag_poisoning

print("=" * 60)
print("TEST 4a — No Drift (normal image)")
print("=" * 60)

poisoned, msg = check_tag_poisoning("nginx:1.25.3")
print(f"Poisoned: {poisoned}")
print(f"Message: {msg}")   # Expected: None (clean)

print()
print("=" * 60)
print("TEST 4b — Simulated Digest Drift (monkey-patch)")
print("=" * 60)

original = integ._resolve_local_digest

# Monkey-patch to return a fake local digest so it always mismatches registry
integ._resolve_local_digest = lambda name: "sha256:" + "a" * 64

poisoned2, msg2 = integ.check_tag_poisoning("nginx:1.25.3")
print(f"Poisoned: {poisoned2}")
print(f"Message:\n{msg2}")

integ._resolve_local_digest = original   # restore
