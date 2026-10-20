"""Lynis role installs the package and records distro cron takeover."""

from __future__ import annotations

from pathlib import Path

ROLE = Path(__file__).resolve().parents[2] / "roles" / "lynis" / "tasks" / "main.yml"


def test_lynis_role_installs_when_enabled() -> None:
    text = ROLE.read_text(encoding="utf-8")
    assert "Lynis is not implemented" not in text
    assert "name: lynis" in text
    assert "lynis-takeover" in text
    assert ".disabled-by-ansible-scanner" in text
