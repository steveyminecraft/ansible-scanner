"""ntfy posts only on status change; empty URL is a no-op."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from ntfy_alert import (  # type: ignore[import-not-found]
    _counts,
    maybe_notify,
    should_notify,
)
from report import (  # type: ignore[import-not-found]
    STATUS_CLEAN,
    STATUS_ERROR,
    STATUS_MALWARE,
    STATUS_WARNING,
    build_report,
    clamav_status,
)


def test_counts_does_not_double_lynis_warnings() -> None:
    detections, warnings = _counts(
        {
            "components": {
                "lynis": {"status": STATUS_WARNING, "warnings": 2},
                "rkhunter": {"status": STATUS_WARNING},
            }
        }
    )
    assert detections == 0
    assert warnings == 3


def test_should_notify_skips_unchanged_status() -> None:
    assert should_notify(STATUS_MALWARE, STATUS_MALWARE, on_detection=True, on_failure=True) is False


def test_should_notify_detection_and_recovery() -> None:
    assert should_notify(STATUS_MALWARE, None, on_detection=True, on_failure=True) is True
    assert should_notify(STATUS_CLEAN, None, on_detection=True, on_failure=True) is False
    assert should_notify(STATUS_WARNING, None, on_detection=True, on_failure=True) is False
    assert should_notify(STATUS_ERROR, STATUS_CLEAN, on_detection=True, on_failure=True) is True
    assert should_notify(STATUS_CLEAN, STATUS_MALWARE, on_detection=True, on_failure=True) is True
    assert should_notify(STATUS_MALWARE, STATUS_CLEAN, on_detection=False, on_failure=True) is False


def test_empty_url_is_noop(tmp_path: Path) -> None:
    report = build_report(
        hostname="host",
        scan_type="quick",
        components={"clamav": clamav_status(1, detections=1)},
    )
    with patch("ntfy_alert._post") as post:
        sent = maybe_notify(
            report,
            state_path=tmp_path / "ntfy-state.json",
            url="",
            on_detection=True,
            on_failure=True,
        )
    assert sent is False
    post.assert_not_called()


def test_dedupe_writes_state_and_skips_second_post(tmp_path: Path) -> None:
    report = build_report(
        hostname="prod-01",
        scan_type="quick",
        components={"clamav": clamav_status(1, detections=2)},
    )
    state = tmp_path / "ntfy-state.json"
    with patch("ntfy_alert._post") as post:
        first = maybe_notify(
            report,
            state_path=state,
            url="http://127.0.0.1:9999/linux-security",
            on_detection=True,
            on_failure=True,
        )
        second = maybe_notify(
            report,
            state_path=state,
            url="http://127.0.0.1:9999/linux-security",
            on_detection=True,
            on_failure=True,
        )
    assert first is True
    assert second is False
    assert post.call_count == 1
    body = post.call_args.args[1]
    assert "prod-01" in body
    assert "malware_detected" in body
    assert "detections=2" in body
    assert "latest.json" in body
    assert "FOUND" not in body


def test_rejects_non_http_url(tmp_path: Path) -> None:
    report = build_report(
        hostname="host",
        scan_type="quick",
        components={"clamav": clamav_status(1, detections=1)},
    )
    with patch("ntfy_alert._post") as post:
        sent = maybe_notify(
            report,
            state_path=tmp_path / "state.json",
            url="file:///etc/passwd",
            on_detection=True,
            on_failure=True,
        )
    assert sent is False
    post.assert_not_called()
