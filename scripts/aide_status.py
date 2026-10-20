#!/usr/bin/env python3
"""Map AIDE exit bitmasks. Package-owned matching changes are not integrity_violation."""

from __future__ import annotations

from typing import Any

STATUS_CLEAN = "clean"
STATUS_WARNING = "warning"
STATUS_INTEGRITY = "integrity_violation"
STATUS_ERROR = "error"

_ADDED = 1
_REMOVED = 2
_CHANGED = 4
_ERROR_MIN = 14


def aide_status(
    exit_code: int,
    *,
    changed_paths: list[str] | None = None,
    package_owned_matching: list[str] | None = None,
    message: str = "",
) -> dict[str, Any]:
    code = int(exit_code)
    if code >= _ERROR_MIN:
        status = STATUS_ERROR
        msg = message or "aide failed"
    elif code == 0:
        status = STATUS_CLEAN
        msg = message
    elif code & (_ADDED | _REMOVED | _CHANGED):
        changed = list(changed_paths or [])
        owned = set(package_owned_matching or [])
        if changed and owned and all(path in owned for path in changed):
            status = STATUS_WARNING
            msg = message or "aide changes match package-owned files after updates"
        else:
            status = STATUS_INTEGRITY
            bits = []
            if code & _ADDED:
                bits.append("added")
            if code & _REMOVED:
                bits.append("removed")
            if code & _CHANGED:
                bits.append("changed")
            msg = message or ("aide " + ",".join(bits))
    else:
        status = STATUS_ERROR
        msg = message or "aide unexpected exit"
    return {
        "status": status,
        "exit_code": code,
        "message": msg,
    }
