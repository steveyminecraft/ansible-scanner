"""Merged `all` reports combine components and keep the worst overall status."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from merge_reports import merge_partial_reports  # type: ignore[import-not-found]
from report import (  # type: ignore[import-not-found]
    STATUS_MALWARE,
    STATUS_WARNING,
    build_report,
    clamav_status,
    write_latest_and_ndjson,
)

SCHEMA = json.loads(
    Path(__file__).resolve().parents[2].joinpath("schemas/report-v1.schema.json").read_text()
)


def test_merge_partial_reports_worst_status_and_schema(tmp_path: Path) -> None:
    clam = build_report(
        hostname="host",
        scan_type="quick",
        components={"clamav": clamav_status(1, detections=1)},
        duration_seconds=3,
        scanned_paths=["/tmp"],
    )
    lynis = build_report(
        hostname="host",
        scan_type="audit",
        components={"lynis": {"status": STATUS_WARNING, "warnings": 2, "message": "audit"}},
        duration_seconds=4,
    )
    write_latest_and_ndjson(clam, tmp_path / "clamav" / "latest.json", tmp_path / "clamav" / "scans.ndjson")
    write_latest_and_ndjson(lynis, tmp_path / "lynis" / "latest.json", tmp_path / "lynis" / "scans.ndjson")

    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "latest.json").write_text("{not-json", encoding="utf-8")
    merged = merge_partial_reports(tmp_path, hostname="host")
    jsonschema.validate(merged, SCHEMA)
    assert merged["scan_type"] == "all"
    assert merged["overall_status"] == STATUS_MALWARE
    assert "clamav" in merged["components"]
    assert "lynis" in merged["components"]
    assert merged["duration_seconds"] == 7.0
    assert merged["scanned_paths"] == ["/tmp"]
