"""Rootkit role installs rkhunter drop-in and never runs --propupd."""

from __future__ import annotations

from pathlib import Path

ROLE = Path(__file__).resolve().parents[2] / "roles" / "rootkit" / "tasks" / "main.yml"
PROPUPD = Path(__file__).resolve().parents[2] / "playbooks" / "rkhunter_propupd.yml"


def test_role_installs_rkhunter_without_propupd() -> None:
    text = ROLE.read_text(encoding="utf-8")
    assert "not implemented in v1" not in text
    assert "name: rkhunter" in text
    assert "rkhunter.conf.local" in text
    assert "CRON_DAILY_RUN" in text
    assert "--propupd" not in text
    assert "chkrootkit" in text


def test_propupd_requires_confirm() -> None:
    text = PROPUPD.read_text(encoding="utf-8")
    assert "scanner_rkhunter_confirm_propupd" in text
    assert "--propupd" in text
