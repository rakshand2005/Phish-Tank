"""Regression tests for image and source-directory Trivy targets."""
from subprocess import CompletedProcess
from unittest.mock import patch

from phishnet.matcher import scan_cves


def _trivy_result() -> CompletedProcess:
    return CompletedProcess(
        args=[], returncode=0, stdout='{"Results": []}', stderr=""
    )


@patch("phishnet.matcher.subprocess.run", return_value=_trivy_result())
def test_image_scan_requests_os_and_library_packages(run):
    assert scan_cves("example:latest") == {"Results": []}
    command = run.call_args.args[0]
    assert command[:2] == ["trivy", "image"]
    assert command[command.index("--pkg-types") + 1] == "os,library"


@patch("phishnet.matcher.subprocess.run", return_value=_trivy_result())
def test_source_scan_requests_library_packages_only(run):
    assert scan_cves(".", target_kind="filesystem") == {"Results": []}
    command = run.call_args.args[0]
    assert command[:2] == ["trivy", "fs"]
    assert command[command.index("--pkg-types") + 1] == "library"
    assert command[-1] == "."


def test_scan_rejects_unknown_target_kind():
    try:
        scan_cves(".", target_kind="unknown")
    except ValueError as error:
        assert "target_kind" in str(error)
    else:
        raise AssertionError("unknown target kind must be rejected")
