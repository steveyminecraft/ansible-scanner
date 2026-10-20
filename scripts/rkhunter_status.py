#!/usr/bin/env python3
"""Map rkhunter exits. Warnings are not automatic compromise."""

from __future__ import annotations

from typing import Any

STATUS_CLEAN = "clean"
STATUS_WARNING = "warning"
STATUS_ERROR = "error"


def count_rkhunter_warnings(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip().lower().startswith("warning"))


def rkhunter_status(
    exit_code: int,
    *,
    message: str = "",
    log_text: str = "",
) -> dict[str, Any]:
    code = int(exit_code)
    if code == 0:
        status = STATUS_CLEAN
        msg = message
        warnings = 0
    elif code == 1:
        status = STATUS_WARNING
        warnings = count_rkhunter_warnings(log_text) or 1
        msg = message or f"rkhunter reported warnings={warnings}"
    else:
        status = STATUS_ERROR
        msg = message or "rkhunter failed"
        warnings = 0
    return {
        "status": status,
        "exit_code": code,
        "warnings": warnings,
        "message": msg,
    }
