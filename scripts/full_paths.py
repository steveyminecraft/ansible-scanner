#!/usr/bin/env python3
"""Choose local mountpoints for security-scan full (--cross-fs=no)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_NETWORK_FS = {"nfs", "nfs4", "cifs", "smb", "smbfs"}


def unescape_mount(mountpoint: str) -> str:
    chars: list[str] = []
    index = 0
    length = len(mountpoint)
    while index < length:
        if (
            mountpoint[index] == "\\"
            and index + 3 < length
            and mountpoint[index + 1] in "0123"
            and mountpoint[index + 2] in "01234567"
            and mountpoint[index + 3] in "01234567"
        ):
            chars.append(chr(int(mountpoint[index + 1 : index + 4], 8)))
            index += 4
            continue
        chars.append(mountpoint[index])
        index += 1
    return "".join(chars)


def parse_mounts(text: str) -> list[tuple[str, str]]:
    mounts: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        mounts.append((unescape_mount(parts[1]), parts[2]))
    return mounts


def _skip_fstype(
    fstype: str,
    *,
    exclude_fs_types: list[str],
    scan_zfs: bool,
    scan_network: bool,
) -> bool:
    if fstype == "zfs":
        return not scan_zfs
    if fstype in _NETWORK_FS or fstype.startswith("nfs"):
        return not scan_network
    if fstype == "fuse" or fstype.startswith("fuse."):
        return True
    return fstype in set(exclude_fs_types)


def _skip_mount(mountpoint: str, exclude_paths: list[str]) -> bool:
    for excluded in exclude_paths:
        if not excluded:
            continue
        if excluded == "/":
            continue
        trimmed = excluded.rstrip("/")
        if mountpoint == trimmed or mountpoint.startswith(trimmed + "/"):
            return True
    return False


def select_full_paths(
    mounts: list[tuple[str, str]],
    *,
    exclude_paths: list[str],
    exclude_fs_types: list[str],
    scan_zfs: bool,
    scan_network: bool,
    override_paths: list[str],
) -> list[str]:
    if override_paths:
        return list(override_paths)
    selected: list[str] = []
    seen: set[str] = set()
    for mountpoint, fstype in mounts:
        if _skip_fstype(
            fstype,
            exclude_fs_types=exclude_fs_types,
            scan_zfs=scan_zfs,
            scan_network=scan_network,
        ):
            continue
        if _skip_mount(mountpoint, exclude_paths):
            continue
        if mountpoint in seen:
            continue
        seen.add(mountpoint)
        selected.append(mountpoint)
    return selected


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List local filesystems for a full clamscan")
    parser.add_argument("--mounts-file", default="/proc/self/mounts")
    parser.add_argument("--exclude-path", action="append", default=[])
    parser.add_argument("--exclude-fs", action="append", default=[])
    parser.add_argument("--scan-zfs", default="0")
    parser.add_argument("--scan-network", default="0")
    parser.add_argument("--override-path", action="append", default=[])
    args = parser.parse_args(argv)
    text = Path(args.mounts_file).read_text(encoding="utf-8")
    paths = select_full_paths(
        parse_mounts(text),
        exclude_paths=args.exclude_path,
        exclude_fs_types=args.exclude_fs,
        scan_zfs=args.scan_zfs in {"1", "true", "True", "yes"},
        scan_network=args.scan_network in {"1", "true", "True", "yes"},
        override_paths=args.override_path,
    )
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
