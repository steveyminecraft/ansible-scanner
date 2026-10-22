"""Schedule templates stay disabled until opted in, and never emit AIDE."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[2]
CRON = (ROOT / "roles/common/templates/cron.d.j2").read_text(encoding="utf-8")
WEEKLY = (ROOT / "roles/common/templates/anacron-weekly.sh.j2").read_text(encoding="utf-8")
DAILY = (ROOT / "roles/common/templates/anacron.sh.j2").read_text(encoding="utf-8")


def _render(template: str, **variables: object) -> str:
    env = Environment(autoescape=False, keep_trailing_newline=True)

    def as_bool(value: object) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes"}

    env.filters["bool"] = as_bool
    base = {
        "scanner_schedule_enabled": False,
        "scanner_anacron": False,
        "scanner_clamav_enabled": True,
        "scanner_lynis_enabled": True,
        "scanner_aide_enabled": True,
        "scanner_rkhunter_enabled": True,
        "scanner_cron_quick_schedule": "30 4 * * *",
        "scanner_schedule_jobs": [
            {"schedule": "30 4 * * *", "command": "quick"},
            {"schedule": "30 5 * * 6", "command": "full"},
            {"schedule": "40 4 * * 1", "command": "audit"},
            {"schedule": "40 4 * * 3", "command": "rootkit"},
            {"schedule": "40 4 * * 4", "command": "integrity"},
        ],
    }
    base.update(variables)
    return env.from_string(template).render(base)


def _jobs(text: str) -> list[str]:
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "security-scan" in line
    ]


def test_default_job_follows_quick_schedule() -> None:
    env = Environment(autoescape=False)
    env.filters["bool"] = lambda value: bool(value)
    text = env.from_string(CRON).render(
        scanner_schedule_enabled=True,
        scanner_anacron=False,
        scanner_clamav_enabled=True,
        scanner_lynis_enabled=False,
        scanner_rkhunter_enabled=False,
        scanner_cron_quick_schedule="20 5 * * 0",
    )
    assert _jobs(text) == ["20 5 * * 0 root /usr/local/sbin/security-scan quick"]


def test_disabled_schedule_has_no_jobs() -> None:
    text = _render(CRON)
    assert "scanner_schedule_enabled is false" in text
    assert _jobs(text) == []


def test_enabled_clock_jobs_skip_aide_and_anacron_hosts() -> None:
    enabled = _render(CRON, scanner_schedule_enabled=True)
    commands = [line.rsplit(maxsplit=1)[-1] for line in _jobs(enabled)]
    assert commands == ["quick", "full", "audit", "rootkit"]
    assert "integrity" not in enabled

    anacron = _render(CRON, scanner_schedule_enabled=True, scanner_anacron=True)
    assert _jobs(anacron) == []
    assert "cron.weekly" in anacron


def test_anacron_weekly_respects_schedule_and_components() -> None:
    assert "SCANNER_SCHEDULE_ENABLED" in WEEKLY
    assert "security-scan audit" in WEEKLY
    assert "security-scan rootkit" in WEEKLY
    assert "integrity" not in WEEKLY
    assert "security-scan quick" not in WEEKLY
    assert "exec /usr/local/sbin/security-scan quick" in DAILY
