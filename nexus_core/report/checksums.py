"""Byte-level GNU-compatible checksums, distinct from the semantic report hash."""
from __future__ import annotations

import hashlib
from pathlib import Path
from collections.abc import Iterable


def write_checksums(directory: Path, names: Iterable[str]) -> Path:
    lines: list[str] = []
    for name in sorted(set(names)):
        if Path(name).name != name or any(c in name for c in '\n\r\\'):
            raise ValueError("checksum filenames must be simple basenames")
        digest = hashlib.sha256()
        with (directory / name).open('rb') as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        lines.append(f'{digest.hexdigest()}  {name}\n')
    target = directory / 'report.sha256'
    target.write_text(''.join(lines), encoding='utf-8')
    return target
