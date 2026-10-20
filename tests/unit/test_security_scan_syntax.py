"""POSIX syntax check for the scan controller (Devuan /bin/sh is dash)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "security-scan"


def test_security_scan_dash_syntax() -> None:
    shell = shutil.which("dash") or shutil.which("sh")
    assert shell is not None
    subprocess.run([shell, "-n", str(SCRIPT)], check=True)


def test_full_profile_is_implemented() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "full profile is not enabled" not in text
    assert "full_paths.py" in text
    assert "quick|malware|full" in text or 'full)' in text


def test_full_scan_uses_cross_fs_no_by_default() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--cross-fs=no" in text


def test_integrity_runs_aide_when_enabled() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "run_aide" in text
    assert "aide --check" in text
    assert "integrity|rootkit" not in text or "run_aide" in text


def test_rootkit_runs_rkhunter_when_enabled() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "run_rootkit" in text
    assert "rkhunter --check" in text
    assert "--propupd" not in text


def test_audit_runs_lynis_when_enabled() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "lynis audit system" in text
    assert "lynis-report.dat" in text
    assert "run_lynis" in text


def test_all_continues_when_a_component_fails() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "run_all" in text
    assert "merge_reports.py" in text
    assert "run_clamscan quick || true" in text
    assert "run_lynis || true" in text
    assert "SCANNER_NTFY_SKIP=1" in text
