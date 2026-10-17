#!/usr/bin/env python3
"""Parse Lynis report.dat. Suggestions are informational; never malware."""

from __future__ import annotations

from typing import Any

STATUS_CLEAN = "clean"
STATUS_WARNING = "warning"
STATUS_ERROR = "error"


def parse_lynis_dat(text: str) -> dict[str, Any]:
    version = ""
    hardening: int | None = None
    warnings: list[str] = []
    suggestions: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "lynis_version":
            version = value
        elif key == "hardening_index":
            try:
                hardening = int(value)
            except ValueError:
                hardening = None
        elif key == "warning[]" and value:
            warnings.append(value)
        elif key == "suggestion[]" and value:
            suggestions.append(value)
    return {
        "lynis_version": version,
        "hardening_index": hardening,
        "warnings": warnings,
        "suggestions": suggestions,
    }


def lynis_status(text: str, *, exit_code: int = 0) -> dict[str, Any]:
    parsed = parse_lynis_dat(text)
    if not text.strip() or (not parsed["lynis_version"] and not parsed["suggestions"] and not parsed["warnings"]):
        return {
            "status": STATUS_ERROR,
            "exit_code": int(exit_code),
            "warnings": 0,
            "message": "lynis report missing or empty",
        }
    warning_ids = parsed["warnings"]
    suggestion_ids = parsed["suggestions"]
    status = STATUS_WARNING if warning_ids else STATUS_CLEAN
    parts = [
        f"warnings={len(warning_ids)}",
        f"suggestions={len(suggestion_ids)}",
    ]
    if parsed["hardening_index"] is not None:
        parts.append(f"hardening_index={parsed['hardening_index']}")
    if warning_ids:
        parts.append("warning_ids=" + ",".join(warning_ids))
    if suggestion_ids:
        parts.append("suggestion_ids=" + ",".join(suggestion_ids))
    return {
        "status": status,
        "exit_code": int(exit_code),
        "warnings": len(warning_ids),
        "message": " ".join(parts),
    }
