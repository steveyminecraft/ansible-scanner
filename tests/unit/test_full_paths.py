"""Select local filesystems for security-scan full (ClamAV --cross-fs=no)."""

from __future__ import annotations

from full_paths import (  # type: ignore[import-not-found]
    parse_mounts,
    select_full_paths,
    unescape_mount,
)

MOUNTS = """\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
tank /mnt/array01 zfs rw 0 0
192.168.1.2:/export /mnt/nfs nfs4 rw 0 0
tmpfs /run tmpfs rw 0 0
overlay /var/lib/docker/overlay2 overlay rw 0 0
/dev/sdb1 /var/lib/docker ext4 rw 0 0
/dev/sdc1 /mnt/data\\040disk xfs rw 0 0
"""

EXCLUDE_PATHS = [
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/snap",
    "/mnt/array01",
]
EXCLUDE_FS = [
    "proc",
    "sysfs",
    "devtmpfs",
    "tmpfs",
    "overlay",
    "squashfs",
    "nfs",
    "nfs4",
    "cifs",
    "zfs",
]


def test_unescape_octal_space() -> None:
    assert unescape_mount("/mnt/data\\040disk") == "/mnt/data disk"


def test_unescape_ignores_invalid_octal_digits() -> None:
    assert unescape_mount("/mnt/x\\089y") == "/mnt/x\\089y"


def test_parse_mounts_yields_fstype_and_path() -> None:
    mounts = parse_mounts(MOUNTS)
    assert ("/", "ext4") in mounts
    assert ("/mnt/data disk", "xfs") in mounts


def test_select_full_paths_keeps_local_disks_skips_zfs_nfs_tmpfs_docker() -> None:
    selected = select_full_paths(
        parse_mounts(MOUNTS),
        exclude_paths=EXCLUDE_PATHS,
        exclude_fs_types=EXCLUDE_FS,
        scan_zfs=False,
        scan_network=False,
        override_paths=[],
    )
    assert selected == ["/", "/home", "/mnt/data disk"]


def test_override_paths_win() -> None:
    selected = select_full_paths(
        parse_mounts(MOUNTS),
        exclude_paths=EXCLUDE_PATHS,
        exclude_fs_types=EXCLUDE_FS,
        scan_zfs=False,
        scan_network=False,
        override_paths=["/"],
    )
    assert selected == ["/"]


def test_network_included_when_enabled() -> None:
    selected = select_full_paths(
        parse_mounts(MOUNTS),
        exclude_paths=EXCLUDE_PATHS,
        exclude_fs_types=[t for t in EXCLUDE_FS if t not in {"nfs", "nfs4"}],
        scan_zfs=False,
        scan_network=True,
        override_paths=[],
    )
    assert "/mnt/nfs" in selected


def test_zfs_included_only_when_enabled() -> None:
    selected = select_full_paths(
        parse_mounts(MOUNTS),
        exclude_paths=["/proc", "/sys", "/dev", "/run", "/var/lib/docker"],
        exclude_fs_types=[t for t in EXCLUDE_FS if t != "zfs"],
        scan_zfs=True,
        scan_network=False,
        override_paths=[],
    )
    assert "/mnt/array01" in selected
