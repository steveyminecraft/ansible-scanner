#!/usr/bin/env python3
"""Build schema-valid linux-security JSON reports. Do not concatenate JSON in shell."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:  # pragma: no cover - hosts without jsonschema still write JSON
    jsonschema = None  # type: ignore[assignment]

STATUS_CLEAN = "clean"
STATUS_SKIPPED_RAM = "skipped_insufficient_memory"
STATUS_NOT_IMPLEMENTED = "not_implemented"
STATUS_WARNING = "warning"
STATUS_INTEGRITY = "integrity_violation"
STATUS_MALWARE = "malware_detected"
STATUS_ERROR = "error"

_RANK = {
    STATUS_CLEAN: 0,
    STATUS_NOT_IMPLEMENTED: 1,
    STATUS_SKIPPED_RAM: 2,
    STATUS_WARNING: 3,
    STATUS_INTEGRITY: 4,
    STATUS_MALWARE: 5,
    STATUS_ERROR: 6,
}

def _schema_candidates() -> list[Path]:
    here = Path(__file__).resolve().parent
    return [
        here / "report-v1.schema.json",
        here.parent / "schemas" / "report-v1.schema.json",
        Path("/usr/local/lib/linux-security/report-v1.schema.json"),
    ]


def _load_schema() -> dict[str, Any] | None:
    for candidate in _schema_candidates():
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8"))
    return None


def clamav_status(
    exit_code: int,
    *,
    detections: int = 0,
    skipped_insufficient_memory: bool = False,
    scanned_paths: list[str] | None = None,
    message: str = "",
) -> dict[str, Any]:
    if skipped_insufficient_memory:
        status = STATUS_SKIPPED_RAM
        msg = message or "skipped: available RAM below scanner_min_ram_mib"
    elif exit_code == 0:
        status = STATUS_CLEAN
        msg = message
        detections = 0
    elif exit_code == 1:
        status = STATUS_MALWARE
        msg = message or "malware detected"
    else:
        status = STATUS_ERROR
        msg = message or "clamscan failed"
    return {
        "status": status,
        "exit_code": None if skipped_insufficient_memory else int(exit_code),
        "detections": int(detections),
        "message": msg,
        "scanned_paths": list(scanned_paths or []),
    }


def overall_status(components: dict[str, dict[str, Any]]) -> str:
    worst = STATUS_CLEAN
    worst_rank = _RANK[STATUS_CLEAN]
    for component in components.values():
        status = str(component.get("status", STATUS_ERROR))
        rank = _RANK.get(status, _RANK[STATUS_ERROR])
        if rank > worst_rank:
            worst = status if status in _RANK else STATUS_ERROR
            worst_rank = rank
    return worst


def build_report(
    *,
    hostname: str,
    scan_type: str,
    components: dict[str, dict[str, Any]],
    scanned_paths: list[str] | None = None,
    duration_seconds: float = 0,
    tool_versions: dict[str, str] | None = None,
    distro_schedule_disabled: list[str] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    report = {
        "schema_version": "1.0",
        "hostname": hostname,
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_type": scan_type,
        "overall_status": overall_status(components),
        "duration_seconds": float(duration_seconds),
        "tool_versions": dict(tool_versions or {}),
        "scanned_paths": list(scanned_paths or []),
        "distro_schedule_disabled": list(distro_schedule_disabled or []),
        "components": components,
    }
    return report


def validate_report(report: dict[str, Any]) -> None:
    schema = _load_schema()
    if schema is None or jsonschema is None:
        required = ("schema_version", "hostname", "timestamp", "scan_type", "overall_status", "components")
        missing = [key for key in required if key not in report]
        if missing:
            raise ValueError(f"report missing keys: {missing}")
        return
    jsonschema.validate(report, schema)


def write_latest_and_ndjson(report: dict[str, Any], latest: Path, ndjson: Path) -> None:
    validate_report(report)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    latest.parent.mkdir(parents=True, exist_ok=True)
    latest.write_text(payload, encoding="utf-8")
    ndjson.parent.mkdir(parents=True, exist_ok=True)
    with ndjson.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(report, sort_keys=True) + "\n")


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write linux-security JSON reports")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--scan-type", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--duration-seconds", type=float, default=0)
    parser.add_argument("--clamav-exit", type=int, default=None)
    parser.add_argument("--clamav-detections", type=int, default=0)
    parser.add_argument("--clamav-skip-ram", action="store_true")
    parser.add_argument("--clamav-message", default="")
    parser.add_argument("--scanned-path", action="append", default=[])
    parser.add_argument("--clamav-version", default="")
    parser.add_argument("--distro-schedule-disabled", action="append", default=[])
    parser.add_argument("--lynis-report", default="")
    parser.add_argument("--lynis-exit", type=int, default=None)
    parser.add_argument("--lynis-version", default="")
    parser.add_argument("--aide-exit", type=int, default=None)
    parser.add_argument("--aide-message", default="")
    parser.add_argument("--aide-changed-path", action="append", default=[])
    parser.add_argument("--aide-package-owned", action="append", default=[])
    parser.add_argument("--aide-log", default="")
    parser.add_argument("--aide-version", default="")
    parser.add_argument("--rkhunter-exit", type=int, default=None)
    parser.add_argument("--rkhunter-message", default="")
    parser.add_argument("--rkhunter-log", default="")
    parser.add_argument("--rkhunter-version", default="")
    args = parser.parse_args(argv)

    components: dict[str, dict[str, Any]] = {}
    if args.clamav_exit is not None or args.clamav_skip_ram:
        components["clamav"] = clamav_status(
            0 if args.clamav_exit is None else args.clamav_exit,
            detections=args.clamav_detections,
            skipped_insufficient_memory=args.clamav_skip_ram,
            scanned_paths=args.scanned_path,
            message=args.clamav_message,
        )
    if args.lynis_report or args.lynis_exit is not None:
        from lynis_report import lynis_status  # type: ignore[import-not-found]

        report_text = ""
        if args.lynis_report:
            report_path = Path(args.lynis_report)
            if ".." in report_path.parts:
                print("lynis-report path rejected", file=sys.stderr)
            elif report_path.is_file():
                report_text = report_path.read_text(encoding="utf-8", errors="replace")
            else:
                print(f"lynis-report missing: {report_path}", file=sys.stderr)
        components["lynis"] = lynis_status(
            report_text,
            exit_code=0 if args.lynis_exit is None else args.lynis_exit,
        )
    if args.aide_exit is not None:
        from aide_status import aide_status  # type: ignore[import-not-found]

        changed = list(args.aide_changed_path)
        owned = list(args.aide_package_owned)
        if args.aide_log:
            from aide_paths import classify_aide_log  # type: ignore[import-not-found]

            log_path = Path(args.aide_log)
            if ".." in log_path.parts:
                print("aide-log path rejected", file=sys.stderr)
            elif log_path.is_file():
                parsed_changed, parsed_owned = classify_aide_log(log_path)
                changed.extend(parsed_changed)
                owned.extend(parsed_owned)
            else:
                print(f"aide-log missing: {log_path}", file=sys.stderr)
        changed = list(dict.fromkeys(changed))
        owned = list(dict.fromkeys(owned))
        components["aide"] = aide_status(
            args.aide_exit,
            changed_paths=changed,
            package_owned_matching=owned,
            message=args.aide_message,
        )
    if args.rkhunter_exit is not None:
        from rkhunter_status import rkhunter_status  # type: ignore[import-not-found]

        log_text = ""
        if args.rkhunter_log:
            log_path = Path(args.rkhunter_log)
            if ".." in log_path.parts:
                print("rkhunter-log path rejected", file=sys.stderr)
            elif log_path.is_file():
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
            else:
                print(f"rkhunter-log missing: {log_path}", file=sys.stderr)
        components["rkhunter"] = rkhunter_status(
            args.rkhunter_exit,
            message=args.rkhunter_message,
            log_text=log_text,
        )
    if not components:
        components["clamav"] = {
            "status": STATUS_NOT_IMPLEMENTED,
            "message": "no components recorded",
        }

    versions = {}
    if args.clamav_version:
        versions["clamav"] = args.clamav_version
    if args.lynis_version:
        versions["lynis"] = args.lynis_version
    if args.aide_version:
        versions["aide"] = args.aide_version
    if args.rkhunter_version:
        versions["rkhunter"] = args.rkhunter_version

    report = build_report(
        hostname=args.hostname,
        scan_type=args.scan_type,
        components=components,
        scanned_paths=args.scanned_path,
        duration_seconds=args.duration_seconds,
        tool_versions=versions,
        distro_schedule_disabled=args.distro_schedule_disabled,
    )
    out = Path(args.output_dir)
    write_latest_and_ndjson(report, out / "latest.json", out / "scans.ndjson")
    from ntfy_alert import notify_from_env  # type: ignore[import-not-found]

    notify_from_env(report, out)
    print(json.dumps({"overall_status": report["overall_status"]}, sort_keys=True))
    return 0 if report["overall_status"] not in {STATUS_ERROR, STATUS_MALWARE, STATUS_INTEGRITY} else 1


if __name__ == "__main__":
    sys.exit(_cli())
