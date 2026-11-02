"""Homelab opts into weekly jobs; collection defaults stay off and skip AIDE."""

from __future__ import annotations

from pathlib import Path

import yaml
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
            {"schedule": "30 4 * * 0", "command": "quick"},
            {"schedule": "40 4 * * 0", "command": "audit"},
            {"schedule": "50 4 * * 0", "command": "rootkit"},
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
    assert commands == ["quick", "audit", "rootkit"]
    assert "integrity" not in enabled
    assert all(line.split()[4] == "0" for line in _jobs(enabled))

    anacron = _render(CRON, scanner_schedule_enabled=True, scanner_anacron=True)
    assert _jobs(anacron) == []
    assert "cron.weekly" in anacron


def test_anacron_weekly_runs_quick_audit_rootkit() -> None:
    assert "SCANNER_SCHEDULE_ENABLED" in WEEKLY
    assert "security-scan quick" in WEEKLY
    assert "security-scan audit" in WEEKLY
    assert "security-scan rootkit" in WEEKLY
    assert "integrity" not in WEEKLY
    assert "cron.daily" not in DAILY
    assert "weekly only" in DAILY


def _dow(schedule: str) -> str:
    return schedule.split()[4]


def test_homelab_inventory_is_weekly_and_enabled() -> None:
    all_vars = yaml.safe_load(
        (ROOT / "inventory/homelab/group_vars/all/main.yml").read_text(encoding="utf-8")
    )
    prod = yaml.safe_load(
        (ROOT / "inventory/homelab/group_vars/scan_prod.yml").read_text(encoding="utf-8")
    )
    pihole = yaml.safe_load(
        (ROOT / "inventory/homelab/group_vars/scan_pihole.yml").read_text(encoding="utf-8")
    )
    defaults = yaml.safe_load(
        (ROOT / "roles/common/defaults/main.yml").read_text(encoding="utf-8")
    )
    assert all_vars["scanner_schedule_enabled"] is True
    assert defaults["scanner_schedule_enabled"] is False
    assert _dow(all_vars["scanner_cron_quick_schedule"]) == "0"
    assert _dow(defaults["scanner_cron_quick_schedule"]) == "0"
    assert _dow(pihole["scanner_cron_quick_schedule"]) == "0"
    assert {job["command"] for job in prod["scanner_schedule_jobs"]} == {
        "quick",
        "audit",
        "rootkit",
    }
    assert all(_dow(job["schedule"]) == "0" for job in prod["scanner_schedule_jobs"])


def test_common_role_drops_anacron_daily() -> None:
    tasks = (ROOT / "roles/common/tasks/main.yml").read_text(encoding="utf-8")
    assert "cron.weekly/ansible-scanner" in tasks
    assert "Remove leftover anacron daily helper" in tasks
    assert "anacron.sh.j2" not in tasks
