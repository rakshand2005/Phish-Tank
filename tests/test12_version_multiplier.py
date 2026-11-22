"""Test 12 — Regression tests for version_outdated_multiplier and semantic comparisons."""
from unittest.mock import patch
from phishnet.scoring import _version_outdated_multiplier, _extract_semver


def test_extract_semver():
    """Verify semantic version extraction from various Docker tags."""
    assert _extract_semver("1.14") is not None
    assert _extract_semver("1.25.3") is not None
    assert _extract_semver("v2.4.0") is not None
    assert _extract_semver("3.11-slim") is not None
    assert _extract_semver("1.27.0-alpine") is not None

    # Non-version or arbitrary tags must return None
    assert _extract_semver("latest") is None
    assert _extract_semver("alpine") is None
    assert _extract_semver("stable") is None
    assert _extract_semver("slim") is None
    assert _extract_semver("dev") is None
    assert _extract_semver("edge") is None
    assert _extract_semver("nightly") is None
    assert _extract_semver("") is None
    assert _extract_semver("main") is None


def test_arbitrary_tags_do_not_increase_risk_score():
    """Verify that arbitrary tags (like latest, alpine) never trigger 1.25 multiplier."""
    with patch("phishnet.scoring.fetch_latest_version_from_registry", return_value="1.27.3"):
        # Arbitrary / floating tags should never be penalized
        assert _version_outdated_multiplier("latest", "nginx:latest") == 1.0
        assert _version_outdated_multiplier("alpine", "redis:alpine") == 1.0
        assert _version_outdated_multiplier("stable", "app:stable") == 1.0
        assert _version_outdated_multiplier("dev", "myimage:dev") == 1.0


def test_semver_comparisons():
    """Verify correct version comparison behavior."""
    with patch("phishnet.scoring.fetch_latest_version_from_registry", return_value="1.25.3"):
        # Older version must receive patch multiplier
        assert _version_outdated_multiplier("1.14", "nginx:1.14") == 1.25
        assert _version_outdated_multiplier("1.24.0", "nginx:1.24.0") == 1.25

        # Same version must NOT receive multiplier
        assert _version_outdated_multiplier("1.25.3", "nginx:1.25.3") == 1.0

        # Newer version must NOT receive multiplier
        assert _version_outdated_multiplier("1.26.0", "nginx:1.26.0") == 1.0


def test_unknown_registry_version():
    """Verify fallback when registry fails or is unknown."""
    with patch("phishnet.scoring.fetch_latest_version_from_registry", return_value="unknown"):
        assert _version_outdated_multiplier("1.14", "nginx:1.14") == 1.0

    with patch("phishnet.scoring.fetch_latest_version_from_registry", return_value="latest"):
        # When registry only has non-version "latest", cannot establish older version
        assert _version_outdated_multiplier("1.14", "nginx:1.14") == 1.0
