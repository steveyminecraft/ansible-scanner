"""AIDE role installs drop-in config and never inits a baseline."""

from __future__ import annotations

from pathlib import Path

ROLE = Path(__file__).resolve().parents[2] / "roles" / "aide" / "tasks" / "main.yml"
BASELINE = Path(__file__).resolve().parents[2] / "playbooks" / "aide_baseline.yml"
UPDATE = Path(__file__).resolve().parents[2] / "playbooks" / "aide_update.yml"


def test_role_does_not_init_database() -> None:
    text = ROLE.read_text(encoding="utf-8")
    assert "AIDE is not implemented" not in text
    assert "aide --init" not in text
    assert "aideinit" not in text
    assert "aide.conf.d" in text
    assert "CRON_DAILY_RUN" in text


def test_baseline_requires_confirm() -> None:
    text = BASELINE.read_text(encoding="utf-8")
    assert "scanner_aide_confirm_baseline" in text
    assert "--init" in text
    assert "unimplemented" not in text


def test_update_requires_confirm() -> None:
    text = UPDATE.read_text(encoding="utf-8")
    assert "scanner_aide_confirm_update" in text
    assert "unimplemented" not in text
