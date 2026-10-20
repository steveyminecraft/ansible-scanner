#!/usr/bin/env python3
"""Parse AIDE --check output and classify package-owned matching files."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

_SIMPLE = re.compile(r"^(?:added|removed|changed|file):\s*(/\S+)", re.IGNORECASE)
_AIDE18 = re.compile(r"^[fdbclsp] +[^\n]*:\s*(/\S+)")


def parse_aide_changed_paths(text: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        match = _SIMPLE.match(line) or _AIDE18.match(line)
        if not match:
            continue
        path = match.group(1)
        if path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def dpkg_owned_and_matches(path: str) -> bool:
    if shutil.which("dpkg-query") is None:
        return False
    query = subprocess.run(
        ["dpkg-query", "-S", path],
        check=False,
        capture_output=True,
        text=True,
    )
    if query.returncode != 0 or ":" not in query.stdout:
        return False
    package = query.stdout.split(":", 1)[0].strip().split(",", 1)[0]
    if not package:
        return False
    rel = path.lstrip("/")
    names = [package, package.split(":", 1)[0]]
    info = Path("/var/lib/dpkg/info")
    expected = ""
    for name in names:
        md5_file = info / f"{name}.md5sums"
        if not md5_file.is_file():
            continue
        for line in md5_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            digest, listed = parts
            if listed.strip() == rel:
                expected = digest.strip()
                break
        if expected:
            break
    if not expected:
        return False
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    return hashlib.md5(data, usedforsecurity=False).hexdigest() == expected


def classify_aide_log(
    log_path: Path,
    matcher: Callable[[str], bool] | None = None,
) -> tuple[list[str], list[str]]:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    changed = parse_aide_changed_paths(text)
    check = matcher or dpkg_owned_and_matches
    owned = [path for path in changed if check(path)]
    return changed, owned
