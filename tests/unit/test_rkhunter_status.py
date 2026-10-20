"""rkhunter exit mapping: warnings are not compromise."""

from __future__ import annotations

from pathlib import Path

from report import STATUS_CLEAN, STATUS_ERROR, STATUS_MALWARE, STATUS_WARNING, _cli
from rkhunter_status import rkhunter_status


def test_exit_zero_is_clean() -> None:
    assert rkhunter_status(0)["status"] == STATUS_CLEAN


def test_exit_one_is_warning_not_malware() -> None:
    result = rkhunter_status(1, log_text="Warning: hidden file\nWarning: packet sniffer\n")
    assert result["status"] == STATUS_WARNING
    assert result["status"] != STATUS_MALWARE
    assert result["warnings"] == 2


def test_other_exits_are_error() -> None:
    assert rkhunter_status(2)["status"] == STATUS_ERROR
    assert rkhunter_status(127)["status"] == STATUS_ERROR
    assert rkhunter_status(0)["warnings"] == 0
    assert rkhunter_status(2)["warnings"] == 0


def test_cli_writes_rootkit_report(tmp_path: Path) -> None:
    rc = _cli(
        [
            "--hostname",
            "host",
            "--scan-type",
            "rootkit",
            "--output-dir",
            str(tmp_path),
            "--rkhunter-exit",
            "1",
        ]
    )
    assert rc == 0
    loaded = __import__("json").loads((tmp_path / "latest.json").read_text())
    assert loaded["scan_type"] == "rootkit"
    assert loaded["components"]["rkhunter"]["status"] == STATUS_WARNING
    assert loaded["overall_status"] == STATUS_WARNING
