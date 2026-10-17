"""ClamAV role must record a single freshclam path and disable distro cron."""

from __future__ import annotations

from pathlib import Path

ROLE = Path(__file__).resolve().parents[2] / "roles" / "clamav" / "tasks" / "main.yml"


def test_freshclam_takeover_is_recorded() -> None:
    text = ROLE.read_text(encoding="utf-8")
    assert "freshclam-takeover" in text
    assert "scanner_freshclam_mode=" in text
    assert ".disabled-by-ansible-scanner" in text
    assert "cron.daily" in text
