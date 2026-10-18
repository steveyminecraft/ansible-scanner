"""AIDE exit bitmask and package-owned informational classification."""

from __future__ import annotations

from pathlib import Path

from aide_status import aide_status  # type: ignore[import-not-found]
from report import (  # type: ignore[import-not-found]
    STATUS_CLEAN,
    STATUS_ERROR,
    STATUS_INTEGRITY,
    STATUS_WARNING,
)


def test_exit_zero_is_clean() -> None:
    assert aide_status(0)["status"] == STATUS_CLEAN


def test_added_removed_changed_are_integrity() -> None:
    assert aide_status(1)["status"] == STATUS_INTEGRITY
    assert aide_status(2)["status"] == STATUS_INTEGRITY
    assert aide_status(4)["status"] == STATUS_INTEGRITY
    assert aide_status(7)["status"] == STATUS_INTEGRITY


def test_error_band_is_error() -> None:
    assert aide_status(14)["status"] == STATUS_ERROR
    assert aide_status(15)["status"] == STATUS_ERROR
    assert aide_status(8)["status"] == STATUS_ERROR
    assert aide_status(5)["status"] == STATUS_INTEGRITY


def test_package_owned_matching_is_not_integrity() -> None:
    result = aide_status(
        4,
        changed_paths=["/usr/bin/curl"],
        package_owned_matching=["/usr/bin/curl"],
    )
    assert result["status"] == STATUS_WARNING
    assert result["status"] != STATUS_INTEGRITY


def test_unowned_change_is_integrity() -> None:
    result = aide_status(
        4,
        changed_paths=["/usr/bin/curl", "/etc/evil"],
        package_owned_matching=["/usr/bin/curl"],
    )
    assert result["status"] == STATUS_INTEGRITY


def test_cli_writes_integrity_report(tmp_path: Path) -> None:
    from report import _cli  # type: ignore[import-not-found]

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
        ]
    )
    assert rc == 1
    loaded = __import__("json").loads((tmp_path / "latest.json").read_text())
    assert loaded["scan_type"] == "integrity"
    assert loaded["components"]["aide"]["status"] == STATUS_INTEGRITY
    assert loaded["overall_status"] == STATUS_INTEGRITY
