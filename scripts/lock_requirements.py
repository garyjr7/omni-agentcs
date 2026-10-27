#!/usr/bin/env python3
"""Generate a hash-pinned lock from a requirements file (SEC-10).

CI installed "whatever resolved today": the requirements are range-pinned
(``pydantic>=2.13.4,<3``), so two builds of the same commit could install
different versions and nobody could tell. This script freezes one resolution and
its hashes.

The hashes are not only the artifact this machine would download: for every
pinned version **every file PyPI publishes for it** is listed (wheels for other
platforms and the sdist included), so ``pip install --require-hashes`` accepts
whichever build is compatible with the target — manylinux_2_17 or manylinux_2_28,
wheel or sdist — and rejects anything else.

Usage (defaults match the GitHub runner, not the developer's machine)::

    python scripts/lock_requirements.py requirements-dev.txt requirements-dev.lock

    pip install --require-hashes -r requirements-dev.lock
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"


def resolve(
    requirements: Path, *, python_version: str, platform: str, abi: str | None
) -> dict[str, dict]:
    """Return the frozen resolution as ``{name: {"version": ..., "hashes": set}}``."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        command = [
            sys.executable, "-m", "pip", "install", "--dry-run", "--quiet",
            "--ignore-installed", "--report", str(report),
            "--python-version", python_version, "--implementation", "cp",
            "--platform", platform, "--only-binary=:all:",
        ]
        if abi:
            command += ["--abi", abi]
        command += ["-r", str(requirements)]
        subprocess.run(command, check=True)
        data = json.loads(report.read_text(encoding="utf-8"))
    locked: dict[str, dict] = {}
    for item in data.get("install", []):
        metadata = item["metadata"]
        name = metadata["name"]
        version = metadata["version"]
        digest = item.get("download_info", {}).get("archive_info", {}).get(
            "hashes", {}
        ).get("sha256")
        locked[name] = {"version": version, "hashes": {digest} if digest else set()}
    return locked


def published_hashes(name: str, version: str, timeout: int = 30) -> set[str]:
    """Every sha256 PyPI publishes for ``name==version`` (best-effort)."""
    url = PYPI_JSON.format(name=name, version=version)
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        payload = json.load(response)
    return {
        entry["digests"]["sha256"]
        for entry in payload.get("urls", [])
        if entry.get("digests", {}).get("sha256")
    }


def render(locked: dict[str, dict], *, source: Path, target: str) -> str:
    lines = [
        f"# Generado por scripts/lock_requirements.py desde {source.name}.",
        f"# Target: {target}. No editar a mano: regenera con `make lock`.",
        "# Instalación reproducible: pip install --require-hashes -r "
        + source.name.replace(".txt", ".lock"),
        "# El fichero es autosuficiente a propósito: incluye las dependencias",
        "# transitivas, así que no lleva la línea `-r` del origen.",
        "",
    ]
    for name in sorted(locked, key=str.lower):
        entry = locked[name]
        hashes = sorted(entry["hashes"])
        if not hashes:
            lines.append(f"{name}=={entry['version']}")
            continue
        body = " \\\n    ".join(f"--hash=sha256:{digest}" for digest in hashes)
        lines.append(f"{name}=={entry['version']} \\\n    {body}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("requirements", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--python-version", default="3.12")
    parser.add_argument("--platform", default="manylinux2014_x86_64")
    parser.add_argument("--abi", default=None)
    parser.add_argument(
        "--pypi-hashes", action="store_true",
        help="list every artifact PyPI publishes for each pinned version",
    )
    arguments = parser.parse_args(argv)

    abi = arguments.abi
    if abi is None and arguments.python_version.startswith("3."):
        abi = "cp" + arguments.python_version.replace(".", "")
    target = f"CPython {arguments.python_version} / {arguments.platform}"
    if arguments.pypi_hashes:
        target += " / all published artifacts"
    locked = resolve(
        arguments.requirements,
        python_version=arguments.python_version,
        platform=arguments.platform,
        abi=abi,
    )
    if arguments.pypi_hashes:
        for name, entry in locked.items():
            try:
                entry["hashes"] |= published_hashes(name, entry["version"])
            except Exception as exc:  # noqa: BLE001 - keep the resolution's hash
                print(f"warning: {name}=={entry['version']}: {exc}", file=sys.stderr)
    arguments.output.write_text(
        render(locked, source=arguments.requirements, target=target), encoding="utf-8"
    )
    print(f"{arguments.output}: {len(locked)} paquetes, target {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
