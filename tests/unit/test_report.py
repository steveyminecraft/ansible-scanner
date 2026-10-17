"""Unit tests for scripts/report.py — written before the implementation."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from report import (  # type: ignore[import-not-found]
    STATUS_CLEAN,
    STATUS_ERROR,
    STATUS_MALWARE,
    STATUS_SKIPPED_RAM,
    build_report,
    clamav_status,
    overall_status,
    write_latest_and_ndjson,
)

SCHEMA = json.loads(
    Path(__file__).resolve().parents[2].joinpath("schemas/report-v1.schema.json").read_text()
)


def test_clamav_exit_zero_is_clean() -> None:
    assert clamav_status(0)["status"] == STATUS_CLEAN
    assert clamav_status(0)["detections"] == 0


def test_clamav_exit_one_is_malware() -> None:
    result = clamav_status(1, detections=3)
    assert result["status"] == STATUS_MALWARE
    assert result["detections"] == 3


def test_clamav_exit_two_is_error() -> None:
    assert clamav_status(2)["status"] == STATUS_ERROR


def test_clamav_ram_skip_overrides_exit() -> None:
    result = clamav_status(0, skipped_insufficient_memory=True)
    assert result["status"] == STATUS_SKIPPED_RAM


def test_overall_status_worst_wins() -> None:
    assert (
        overall_status(
            {
                "clamav": {"status": STATUS_CLEAN},
                "aide": {"status": STATUS_ERROR},
            }
        )
        == STATUS_ERROR
    )
    assert (
        overall_status({"clamav": {"status": STATUS_MALWARE}}) == STATUS_MALWARE
    )


def test_build_report_validates_against_schema() -> None:
    report = build_report(
        hostname="server01",
        scan_type="quick",
        components={"clamav": clamav_status(0)},
        scanned_paths=["/tmp"],
        duration_seconds=1.5,
    )
    jsonschema.validate(report, SCHEMA)
    assert report["schema_version"] == "1.0"
    assert report["overall_status"] == STATUS_CLEAN


def test_write_latest_and_ndjson(tmp_path: Path) -> None:
    report = build_report(
        hostname="host",
        scan_type="quick",
        components={"clamav": clamav_status(1, detections=1)},
    )
    latest = tmp_path / "latest.json"
    ndjson = tmp_path / "scans.ndjson"
    write_latest_and_ndjson(report, latest, ndjson)
    loaded = json.loads(latest.read_text())
    jsonschema.validate(loaded, SCHEMA)
    lines = ndjson.read_text().strip().splitlines()
    assert len(lines) == 1
    jsonschema.validate(json.loads(lines[0]), SCHEMA)


def test_cli_records_distro_schedule_disabled(tmp_path: Path) -> None:
    from report import _cli  # type: ignore[import-not-found]

    rc = _cli(
        [
            "--hostname",
            "host",
            "--scan-type",
            "full",
            "--output-dir",
            str(tmp_path),
            "--clamav-exit",
            "0",
            "--distro-schedule-disabled",
            "/etc/cron.d/clamav-freshclam",
        ]
    )
    assert rc == 0
    loaded = json.loads((tmp_path / "latest.json").read_text())
    jsonschema.validate(loaded, SCHEMA)
    assert loaded["scan_type"] == "full"
    assert loaded["distro_schedule_disabled"] == ["/etc/cron.d/clamav-freshclam"]


def test_write_rejects_shell_concat_style_invalid_payload(tmp_path: Path) -> None:
    latest = tmp_path / "latest.json"
    ndjson = tmp_path / "scans.ndjson"
    with pytest.raises(jsonschema.ValidationError):
        write_latest_and_ndjson({"hostname": "x"}, latest, ndjson)
