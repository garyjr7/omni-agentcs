"""``omni hooks`` subcommand: operator approval of repository lifecycle hooks.

Repository hooks (``.agents/hooks.json``) are quasi-trusted input shipped by a
project. They are never loaded until a human operator approves them out of band.
This module is that boundary: it only ever writes the private XDG trust file and
never executes a hook. ``omni hooks trust`` shows the hash, asks for an explicit
confirmation and records ``path + sha256 + operator + date``. Any later change to
``hooks.json`` changes the hash and therefore revokes the trust automatically.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from . import render


def _operator_identity(tenant: str):
    from nexus_core.kernel.models import Identity
    import os

    return Identity(
        subject_id=os.getenv("NEXUS_OPERATOR_ID", "operator"),
        tenant_id=tenant,
        kind="human",
        roles=("operator",),
    )


def _confirm(prompt: str, reader=None) -> bool:
    reader = reader or input
    try:
        answer = str(reader(prompt)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes", "s", "si", "sí"}


def run_hooks_command(argv: list[str], tenant: str, *, reader=None) -> int:
    """Dispatch ``omni hooks <action>``; returns a process exit code."""
    parser = argparse.ArgumentParser(prog="omni hooks", add_help=False)
    parser.add_argument("action", choices=["trust", "list", "revoke"])
    parser.add_argument("path", nargs="?")
    parser.add_argument("--hash", dest="expected_hash", default=None)
    parser.add_argument("--yes", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        render.render_error("uso: omni hooks trust <path> [--hash H] | list | revoke <path>")
        return 2

    from nexus_core.hooks import (
        approve_project_hooks,
        project_hooks_path,
        revoke_project_hooks,
        trusted_project_hooks,
    )

    if args.action == "list":
        entries = trusted_project_hooks()
        if not entries:
            render.write("(no hay hooks de proyecto aprobados)")
            return 0
        for entry in entries:
            render.write(
                f"  {entry['path']}  sha256={entry['sha256'][:16]}…  "
                f"por={entry['operator_id'] or '?'}  {entry['approved_at']}"
            )
        return 0

    if not args.path:
        render.render_error(f"omni hooks {args.action} requiere <path>")
        return 2
    root = Path(args.path).expanduser()
    if args.action == "revoke":
        removed = revoke_project_hooks(root)
        render.render_status(
            f"confianza retirada: {project_hooks_path(root)}" if removed
            else "no había confianza registrada para ese proyecto"
        )
        return 0 if removed else 1

    config = project_hooks_path(root)
    if not config.is_file():
        render.render_error(f"no existe {config}")
        return 2
    if not args.yes and not _confirm(
        f"¿Aprobar los hooks de {config} para este tenant? [y/N] ", reader
    ):
        render.write("aprobación cancelada")
        return 1
    try:
        record = approve_project_hooks(root, _operator_identity(tenant), expected_hash=args.expected_hash)
    except (ValueError, PermissionError, OSError) as exc:
        render.render_error(f"no se pudo aprobar: {type(exc).__name__}: {exc}")
        return 2
    render.render_status(
        f"hooks de proyecto aprobados: {record['sha256'][:16]}… (cualquier cambio revoca la confianza)"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run_hooks_command(sys.argv[1:], "system"))
