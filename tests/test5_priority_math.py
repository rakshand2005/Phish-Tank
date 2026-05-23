"""Test 5 — _compute_priority multipliers stack correctly."""
from scanner.scoring import _compute_priority

print("=" * 60)
print("TEST 5 — _compute_priority Multiplier Math")
print("=" * 60)

# Baseline: no multipliers
base = _compute_priority(cvss_score=7.0, epss_score=0.5, in_kev=False)
print(f"Baseline score:              {base}")

# With version lag only (×1.25)
with_version = _compute_priority(7.0, 0.5, False, version_multiplier=1.25)
print(f"With version lag (×1.25):    {with_version}")

# With poison only (×1.50)
with_poison = _compute_priority(7.0, 0.5, False, poison_multiplier=1.50)
print(f"With poison (×1.50):         {with_poison}")

# Both stacked (×1.875)
both = _compute_priority(7.0, 0.5, False, version_multiplier=1.25, poison_multiplier=1.50)
print(f"Both stacked (×1.875):       {both}")

# Ceiling check — should never exceed 10.0
capped = _compute_priority(10.0, 1.0, True, version_multiplier=1.25, poison_multiplier=1.50)
print(f"Max inputs with multipliers: {capped}  (must be 10.0)")
