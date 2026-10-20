"""Parse Lynis report.dat — suggestions are never malware."""

from __future__ import annotations

from pathlib import Path

from lynis_report import lynis_status, parse_lynis_dat  # type: ignore[import-not-found]
from report import STATUS_CLEAN, STATUS_ERROR, STATUS_MALWARE, STATUS_WARNING  # type: ignore[import-not-found]


SAMPLE = """\
lynis_version=3.1.4
hardening_index=68
warning[]=AUTH-9208
suggestion[]=SSH-7408
suggestion[]=FILE-7524
"""


def test_parse_counts_and_index() -> None:
    parsed = parse_lynis_dat(SAMPLE)
    assert parsed["lynis_version"] == "3.1.4"
    assert parsed["hardening_index"] == 68
    assert parsed["warnings"] == ["AUTH-9208"]
    assert parsed["suggestions"] == ["SSH-7408", "FILE-7524"]


def test_warnings_are_warning_not_malware() -> None:
    result = lynis_status(SAMPLE, exit_code=0)
    assert result["status"] == STATUS_WARNING
    assert result["status"] != STATUS_MALWARE
    assert result["warnings"] == 1
    assert "SSH-7408" in result["message"]


def test_suggestions_only_are_clean() -> None:
    text = "lynis_version=3.1.4\nhardening_index=80\nsuggestion[]=SSH-7408\n"
    result = lynis_status(text, exit_code=1)
    assert result["status"] == STATUS_CLEAN
    assert result["exit_code"] == 1


def test_empty_report_is_error() -> None:
    result = lynis_status("", exit_code=0)
    assert result["status"] == STATUS_ERROR


def test_cli_writes_audit_report(tmp_path: Path) -> None:
    from report import _cli  # type: ignore[import-not-found]

    dat = tmp_path / "lynis-report.dat"
    dat.write_text(SAMPLE, encoding="utf-8")
    rc = _cli(
        [
            "--hostname",
            "host",
            "--scan-type",
            "audit",
            "--output-dir",
            str(tmp_path),
            "--lynis-report",
            str(dat),
            "--lynis-exit",
            "0",
        ]
    )
    assert rc == 0
    loaded = __import__("json").loads((tmp_path / "latest.json").read_text())
    assert loaded["scan_type"] == "audit"
    assert loaded["components"]["lynis"]["status"] == STATUS_WARNING
    assert loaded["overall_status"] == STATUS_WARNING
