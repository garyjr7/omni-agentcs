"""``omni tools``: operator approval of third-party tool plugins (SEC-05).

Like ``omni hooks``, this is a write to a private trust file and never loads a
plugin itself. ``trust`` shows the digest, asks for an explicit confirmation
and records ``name + target + sha256 + operator + date``; any change to the
distribution's files changes the hash and revokes the approval automatically.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import render


def _operator_identity(tenant: str):
    from nexus_core.kernel.models import Identity

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


def _find_entry(name: str):
    from nexus_core.tools import trust as trust_module

    for entry in trust_module.installed_entry_points():
        if str(getattr(entry, "name", "")) == name:
            return entry
    return None


def run_tools_command(argv: list[str], tenant: str, *, reader=None) -> int:
    """Dispatch ``omni tools <action>``; returns a process exit code."""
    parser = argparse.ArgumentParser(prog="omni tools", add_help=False)
    parser.add_argument("action", choices=["trust", "list", "revoke"])
    parser.add_argument("name", nargs="?")
    parser.add_argument("--hash", dest="expected_hash", default=None)
    parser.add_argument("--yes", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        render.render_error(
            "uso: omni tools trust <name> [--hash H] | list | revoke <name>"
        )
        return 2

    from nexus_core.tools import trust as trust_module

    if args.action == "list":
        entries = trust_module.trusted_plugins()
        if not entries:
            render.write("(no hay plugins de herramientas aprobados)")
            return 0
        for entry in entries:
            render.write(
                f"  {entry['name']}  sha256={entry['sha256'][:16]}…  "
                f"target={entry['target']}  por={entry['operator_id'] or '?'}  "
                f"{entry['approved_at']}"
            )
        return 0

    if not args.name:
        render.render_error(f"omni tools {args.action} requiere <name>")
        return 2
    if args.action == "revoke":
        removed = trust_module.revoke_plugin(args.name)
        render.render_status(
            f"confianza retirada: {args.name}" if removed
            else "no había confianza registrada para ese plugin"
        )
        return 0 if removed else 1

    entry = _find_entry(args.name)
    if entry is None:
        render.render_error(
            f"no hay ningún entry point {trust_module.ENTRY_POINT_GROUP} "
            f"con nombre {args.name}"
        )
        return 2
    if not args.yes and not _confirm(
        f"¿Aprobar el plugin de herramientas {args.name} "
        f"({getattr(entry, 'value', '?')}) para este tenant? [y/N] ",
        reader,
    ):
        render.write("aprobación cancelada")
        return 1
    try:
        record = trust_module.approve_plugin(
            args.name,
            entry,
            _operator_identity(tenant),
            expected_hash=args.expected_hash,
        )
    except (ValueError, PermissionError, OSError) as exc:
        render.render_error(f"no se pudo aprobar: {type(exc).__name__}: {exc}")
        return 2
    render.render_status(
        f"plugin aprobado: {args.name} sha256={record['sha256'][:16]}… "
        "(cualquier cambio en la distribución revoca la confianza)"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run_tools_command(sys.argv[1:], "system"))
