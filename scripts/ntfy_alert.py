#!/usr/bin/env python3
"""POST a short ntfy body when overall_status changes. Never attach report contents."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DETECTION = frozenset({"malware_detected", "integrity_violation"})
FAILURE = frozenset({"error"})
ALERTING = DETECTION | FAILURE


def should_notify(
    new_status: str,
    previous_status: str | None,
    *,
    on_detection: bool,
    on_failure: bool,
) -> bool:
    if new_status == previous_status:
        return False
    if new_status in DETECTION and on_detection:
        return True
    if new_status in FAILURE and on_failure:
        return True
    if previous_status in ALERTING and new_status not in ALERTING:
        return True
    return False


def _bool_env(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw not in {"0", "false", "False", "no"}


def _http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _post(url: str, body: str, title: str, timeout: float = 5.0) -> None:
    request = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Title": title[:250],
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        response.read()


def _counts(report: dict[str, Any]) -> tuple[int, int]:
    detections = 0
    warnings = 0
    for component in report.get("components", {}).values():
        if not isinstance(component, dict):
            continue
        detections += int(component.get("detections") or 0)
        status = str(component.get("status", ""))
        warning_count = int(component.get("warnings") or 0)
        if warning_count:
            warnings += warning_count
        elif status == "warning":
            warnings += 1
    return detections, warnings


def _body(report: dict[str, Any], report_path: str) -> str:
    detections, warnings = _counts(report)
    return "\n".join(
        [
            f"hostname={report.get('hostname', '')}",
            f"scan_type={report.get('scan_type', '')}",
            f"overall_status={report.get('overall_status', '')}",
            f"detections={detections}",
            f"warnings={warnings}",
            f"report={report_path}",
        ]
    )


def maybe_notify(
    report: dict[str, Any],
    *,
    state_path: Path,
    url: str,
    on_detection: bool,
    on_failure: bool,
    report_path: str | None = None,
) -> bool:
    url = (url or "").strip()
    if not url or os.environ.get("SCANNER_NTFY_SKIP") == "1":
        return False
    if not _http_url(url):
        print("ntfy: refused non-http URL scheme", file=sys.stderr)
        return False
    new_status = str(report.get("overall_status", ""))
    previous = None
    if state_path.is_file():
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8")).get("overall_status")
        except (OSError, json.JSONDecodeError):
            previous = None
    if not should_notify(new_status, previous, on_detection=on_detection, on_failure=on_failure):
        return False
    path = report_path or str(state_path.parent / "latest.json")
    hostname = str(report.get("hostname", "unknown"))
    title = f"linux-security {new_status} {hostname}"
    try:
        _post(url, _body(report, path), title)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"ntfy: post failed: {exc}", file=sys.stderr)
        return False
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps({"overall_status": new_status}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return True


def notify_from_env(report: dict[str, Any], output_dir: Path) -> bool:
    return maybe_notify(
        report,
        state_path=output_dir / "ntfy-state.json",
        url=os.environ.get("SCANNER_NTFY_URL", ""),
        on_detection=_bool_env("SCANNER_ALERT_ON_DETECTION", True),
        on_failure=_bool_env("SCANNER_ALERT_ON_SCAN_FAILURE", True),
        report_path=str(output_dir / "latest.json"),
    )
