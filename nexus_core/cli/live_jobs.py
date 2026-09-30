"""Read-only MSF job watcher, independent from the agent's output panel."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

UUID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
TERMINAL_STATES = {"completed", "errored", "failed", "cancelled", "stopped"}


def validate_uuid(job_uuid: str) -> str:
    if not isinstance(job_uuid, str) or not UUID.fullmatch(job_uuid):
        raise ValueError("job_uuid inválido (solo letras, números, guion y guion bajo)")
    return job_uuid


async def fetch_job(job_uuid: str) -> dict:
    """Only authenticate and read module.results; never consume console output."""
    from nexus_core.integrations.metasploit.client import MetasploitClient, MetasploitConfig

    validate_uuid(job_uuid)
    config = MetasploitConfig.from_env()
    if not config.password:
        raise PermissionError("MSF RPC no configurado")
    async with MetasploitClient(config) as client:
        result = await client.get_module_results(job_uuid)
        if result.get("status") in {"denied", "unauthorized", "forbidden"}:
            raise PermissionError("consulta de job denegada")
        if result.get("status") in {"not_found", "unknown", "missing"} or result.get("error") and not result.get("status"):
            raise LookupError("job no encontrado")
        return client.redact(result)


def read_job(job_uuid: str) -> dict:
    validate_uuid(job_uuid)
    return asyncio.run(asyncio.wait_for(fetch_job(job_uuid), timeout=5.0))


def format_job(job_uuid, result):
    return f"MSF job {job_uuid}\n" + json.dumps(result, ensure_ascii=True, indent=2, default=str)


def open_view(job_uuid: str, *, env=None) -> str | None:
    """Launch only the read-only watcher, with argv and no shell interpolation."""
    validate_uuid(job_uuid)
    env = os.environ if env is None else env
    watcher = [sys.executable, "-m", "nexus_core.cli.live_jobs", "--watch", job_uuid]
    if env.get("TMUX") and shutil.which("tmux"):
        command = ["tmux", "new-window", "-n", "msf-" + job_uuid[:8], *watcher]
        kind = "tmux"
    elif env.get("DISPLAY") and shutil.which("x-terminal-emulator"):
        command = ["x-terminal-emulator", "-e", *watcher]
        kind = "terminal"
    else:
        return None
    subprocess.Popen(command, cwd=Path(__file__).resolve().parents[2], shell=False)
    return kind


def show_job(session, args):
    from . import render

    if len(args) != 2 or args[0] not in {"view-live", "watch"}:
        render.render_error("uso: /exploit view-live <job_uuid> (alias: watch)")
        return
    job_uuid = args[1]
    try:
        validate_uuid(job_uuid)
        if not session.engagement_id:
            raise PermissionError("requiere un engagement activo")
        snapshot = read_job(job_uuid)
    except (PermissionError, LookupError, ValueError) as exc:
        render.render_error(str(exc))
        return
    except Exception as exc:
        # RPC errors may contain credentials/URLs; report only their type.
        render.render_error(f"no se pudo consultar el job ({type(exc).__name__})")
        return
    # No GUI/terminal spawning from pipes or CI, even with inherited TMUX.
    kind = None
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            kind = open_view(job_uuid)
        except OSError:
            pass
    if kind:
        render.render_status(f"Vista del job {job_uuid} abierta en {kind} (solo lectura)")
    else:
        session._output.write(format_job(job_uuid, snapshot))
        render.render_status("Sin terminal secundario; se muestra el estado actual, sin seguimiento.")


def watch(job_uuid, *, interval=2.0):
    """Poll in the dedicated terminal until completion or Ctrl+C."""
    validate_uuid(job_uuid)
    try:
        while True:
            snapshot = read_job(job_uuid)
            if sys.stdout.isatty():
                print("\033[2J\033[H", end="")
            print(format_job(job_uuid, snapshot), flush=True)
            print("Solo lectura · actualiza cada 2 s · Ctrl+C para cerrar", flush=True)
            if snapshot.get("status") in TERMINAL_STATES:
                if sys.stdin.isatty() and sys.stdout.isatty():
                    input("Job finalizado. Enter para cerrar la vista.")
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"Vista no disponible ({type(exc).__name__}).", file=sys.stderr)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Vista de solo lectura de un job MSF")
    parser.add_argument("--watch", required=True, metavar="JOB_UUID")
    args = parser.parse_args(argv)
    try:
        return watch(validate_uuid(args.watch))
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
