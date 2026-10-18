"""Parse AIDE check logs and classify package-owned matching paths."""

from __future__ import annotations

from pathlib import Path

from aide_paths import classify_aide_log, parse_aide_changed_paths
from report import STATUS_WARNING, _cli


def test_parse_simple_and_aide18_lines() -> None:
    text = """
added: /etc/new
removed: /etc/old
changed: /usr/bin/curl
f     c .C...  : /etc/hosts
ignored line
"""
    assert parse_aide_changed_paths(text) == [
        "/etc/new",
        "/etc/old",
        "/usr/bin/curl",
        "/etc/hosts",
    ]
    assert parse_aide_changed_paths("failed: /etc/aide.db\nfound: /etc\n") == []


def test_classify_uses_matcher(tmp_path: Path) -> None:
    log = tmp_path / "aide-check.log"
    log.write_text("changed: /usr/bin/curl\nchanged: /etc/evil\n", encoding="utf-8")
    changed, owned = classify_aide_log(log, matcher=lambda path: path == "/usr/bin/curl")
    assert changed == ["/usr/bin/curl", "/etc/evil"]
    assert owned == ["/usr/bin/curl"]


def test_cli_package_owned_from_log_is_warning(tmp_path: Path) -> None:
    log = tmp_path / "aide-check.log"
    log.write_text("changed: /usr/bin/curl\n", encoding="utf-8")
    rc = _cli(
        [
            "--hostname",
            "host",
            "--scan-type",
            "integrity",
            "--output-dir",
            str(tmp_path),
            "--aide-exit",
            "4",
            "--aide-log",
            str(log),
            "--aide-package-owned",
            "/usr/bin/curl",
        ]
    )
    assert rc == 0
    loaded = __import__("json").loads((tmp_path / "latest.json").read_text())
    assert loaded["components"]["aide"]["status"] == STATUS_WARNING
