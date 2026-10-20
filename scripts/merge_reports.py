#!/usr/bin/env python3
"""Combine per-component latest.json files into one scan_type=all report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ntfy_alert import notify_from_env
from report import STATUS_NOT_IMPLEMENTED, build_report, write_latest_and_ndjson


def merge_partial_reports(partials_dir: Path, *, hostname: str) -> dict[str, Any]:
    components: dict[str, Any] = {}
    versions: dict[str, str] = {}
    paths: list[str] = []
    disabled: list[str] = []
    duration = 0.0
    for latest in sorted(partials_dir.glob("*/latest.json")):
        try:
            payload = json.loads(latest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"merge: skip unreadable {latest}: {exc}", file=sys.stderr)
            continue
        components.update(payload.get("components") or {})
        versions.update(payload.get("tool_versions") or {})
        for path in payload.get("scanned_paths") or []:
            if path not in paths:
                paths.append(path)
        for item in payload.get("distro_schedule_disabled") or []:
            if item not in disabled:
                disabled.append(item)
        duration += float(payload.get("duration_seconds") or 0)
    if not components:
        components["scanner"] = {
            "status": STATUS_NOT_IMPLEMENTED,
            "message": "no enabled components produced a report",
        }
    return build_report(
        hostname=hostname,
        scan_type="all",
        components=components,
        scanned_paths=paths,
        duration_seconds=duration,
        tool_versions=versions,
        distro_schedule_disabled=disabled,
    )


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge linux-security partial reports")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--partials-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    out = Path(args.output_dir)
    report = merge_partial_reports(Path(args.partials_dir), hostname=args.hostname)
    write_latest_and_ndjson(report, out / "latest.json", out / "scans.ndjson")
    notify_from_env(report, out)
    print(json.dumps({"overall_status": report["overall_status"]}, sort_keys=True))
    from report import STATUS_ERROR, STATUS_INTEGRITY, STATUS_MALWARE

    return 0 if report["overall_status"] not in {STATUS_ERROR, STATUS_MALWARE, STATUS_INTEGRITY} else 1


if __name__ == "__main__":
    sys.exit(_cli())
