#!/usr/bin/env python3
"""WP0 - ejecuta OMNI contra una sala real y mide flags, no tests.

Uso::

    ./bench/run_bench.py --dry-run                 # valida rooms.yaml, no toca red
    THM_ROOTME_IP=10.10.10.5 ./bench/run_bench.py --room rootme
    ./bench/run_bench.py --room rootme --room blue --runs 3

Por cada intento:

1. lee ``bench/rooms.yaml``;
2. crea un engagement firmado (``--new-engagement``) para el target del run;
3. lanza ``omni --engagement <id> --objective ... --stream-json --trust-mode``;
4. espera a que termine (o mata el grupo al vencer el timeout);
5. busca las flags en el NDJSON **y** en los artefactos del workspace;
6. escribe ``bench/results/<sala>-<timestamp>-runN.json``.

Creacion y ejecucion comparten **un solo entorno** (:func:`run_environment`):
una DB de control dentro del directorio del run. Si el creador y el agente
abren bases distintas, el id recien creado no existe para el agente y el run
muere con ``engagement no encontrado`` antes de gastar un token.

El proceso devuelve ``0`` **solo** si todas las flags esperadas aparecen. El
criterio es la flag, no el exit code de OMNI: un run que captura las flags y
muere en el reporte sigue siendo un PASS del solver (el plan mide pass@1).

Sobre ``--scope``: en el CLI solo es valido junto a ``--new-engagement``. El
runner crea el engagement el mismo (con el target del entorno, nunca con una IP
versionada) y despues pasa el id a ``--engagement``.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
DEFAULT_ROOMS = BENCH_DIR / "rooms.yaml"
DEFAULT_RESULTS = BENCH_DIR / "results"
OMNI_ENTRY = REPO_ROOT / "omni.py"

#: ``omni --new-engagement`` prints ``engagement creado: eng-... · ...``.
ENGAGEMENT_RE = re.compile(r"engagement creado:\s*(eng-[0-9a-f]+)")
TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
#: Artifacts of a room are usually small; a larger file is not a flag.
MAX_SCAN_BYTES = 5_000_000
#: Grace between SIGTERM and SIGKILL when a run exceeds its deadline.
KILL_GRACE_SECONDS = 5


# --------------------------------------------------------------------- config
def load_config(path: Path = DEFAULT_ROOMS) -> dict[str, Any]:
    """Read and validate ``rooms.yaml``; raise ``ValueError`` on a bad contract."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if data.get("version") != 1:
        raise ValueError("rooms.yaml: version must be 1")
    rooms = data.get("rooms") or {}
    if not rooms:
        raise ValueError("rooms.yaml: no rooms defined")
    for room_id, room in rooms.items():
        missing = {"target_env", "flag_regex", "expected_flags", "objective"} - set(room)
        if missing:
            raise ValueError(f"rooms.yaml: room {room_id!r} lacks {sorted(missing)}")
        try:
            re.compile(str(room["flag_regex"]))
        except re.error as exc:
            raise ValueError(f"rooms.yaml: {room_id!r} has an invalid flag_regex") from exc
        if int(room["expected_flags"]) < 1:
            raise ValueError(f"rooms.yaml: {room_id!r} expects no flags")
    data.setdefault("defaults", {})
    return data


def room_settings(config: dict[str, Any], room_id: str) -> dict[str, Any]:
    """Return the room entry with ``defaults`` applied."""
    defaults = config.get("defaults") or {}
    room = dict((config.get("rooms") or {})[room_id])
    for key in ("timeout_seconds", "max_iterations", "reset_cmd"):
        room.setdefault(key, defaults.get(key))
    if not room.get("timeout_seconds"):
        raise ValueError(f"room {room_id!r} has no timeout_seconds")
    if not room.get("max_iterations"):
        raise ValueError(f"room {room_id!r} has no max_iterations")
    return room


def resolve_target(
    room_id: str,
    room: dict[str, Any],
    overrides: dict[str, str] | None = None,
) -> str:
    """Target IP from ``--target room=IP`` or ``target_env`` (validated literal)."""
    raw = (overrides or {}).get(room_id) or os.getenv(str(room["target_env"]), "")
    text = str(raw).strip()
    if not text:
        raise ValueError(
            f"no target for {room_id!r}: export {room['target_env']} or pass "
            f"--target {room_id}=<IP>"
        )
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError(f"target for {room_id!r} must be a bare IP, got {text!r}") from exc


def build_objective(room: dict[str, Any], target: str) -> str:
    """Render the room objective; ``{target}`` is the only interpolation."""
    return " ".join(str(room["objective"]).format(target=target).split())


# ---------------------------------------------------------------------- flags
def _text(path: Path) -> str:
    try:
        if path.is_file() and path.stat().st_size <= MAX_SCAN_BYTES:
            return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return ""


def extract_flags(paths: list[Path], pattern: str) -> list[str]:
    """Every unique flag matching ``pattern`` under ``paths`` (files or dirs).

    Order is discovery order, so the JSON shows *what* was found first. The
    dedupe is what makes ``len(found) >= expected_flags`` a real count instead
    of the same match repeated in the NDJSON, the report and the artifact.
    """
    matcher = re.compile(pattern)
    found: list[str] = []
    for start in paths:
        if not start.exists():
            continue
        candidates = [start] if start.is_file() else sorted(start.rglob("*"))
        for path in candidates:
            if not path.is_file():
                continue
            text = _text(path)
            if not text:
                continue
            for match in matcher.finditer(text):
                value = match.group(0)
                if value and value not in found:
                    found.append(value)
    return found


def tokens_from_ndjson(path: Path) -> int:
    """Sum ``react.turn_telemetry.total_tokens`` from one NDJSON trace."""
    total = 0
    text = _text(path)
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "react.turn_telemetry":
            continue
        payload = event.get("payload") or {}
        try:
            total += int(payload.get("total_tokens") or 0)
        except (TypeError, ValueError):
            continue
    return total


# ------------------------------------------------------------------ execution
def _kill_group(process: subprocess.Popen[Any]) -> None:
    """Stop the run and its children; never leave a tmux/msf orphan behind."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return


def run_environment(run_dir: Path, workspace: Path) -> dict[str, str]:
    """The environment of one run; creation and agent must agree on the DB.

    ``--new-engagement`` used to inherit the operator's environment while the
    agent got a fresh ``XDG_DATA_HOME``, so the engagement the runner had just
    created lived in a database the agent never opened (``engagement no
    encontrado``, ``exit=2``, 0 tokens). Both processes now receive this dict.

    ``NEXUS_DB_PATH`` is pinned instead of left implicit because an ambient
    value (or a ``sqlite:///`` ``DATABASE_URL``, which wins over it) would
    override ``XDG_DATA_HOME`` in *both* processes: the run would then write
    into the operator's control DB instead of its own directory.
    """
    data_home = run_dir / "data"
    env = dict(os.environ)
    env["NEXUS_WORKSPACE_ROOT"] = str(workspace)
    env["XDG_DATA_HOME"] = str(data_home)
    env["NEXUS_DB_PATH"] = str(data_home / "omni" / "control.db")
    if env.get("DATABASE_URL", "").startswith("sqlite:///"):
        del env["DATABASE_URL"]
    return env


def create_engagement(
    room_id: str,
    target: str,
    *,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 180,
) -> tuple[str | None, str]:
    """Create a short-lived signed engagement for one bench run.

    ``env`` must be the environment the agent will run with, or the id is
    created in one database and looked up in another.
    """
    stamp = datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)
    command = [
        sys.executable, str(OMNI_ENTRY), "--new-engagement",
        f"bench-{room_id}-{stamp}", "--scope", f"{target}/32",
        "--valid-hours", "6", "--no-wizard",
    ]
    try:
        completed = subprocess.run(
            command, cwd=REPO_ROOT, env=env, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    output = f"{completed.stdout}\n{completed.stderr}"
    match = ENGAGEMENT_RE.search(output)
    if completed.returncode != 0 or match is None:
        return None, output.strip()[-2000:]
    return match.group(1), output.strip()[-2000:]


def list_engagements(env: dict[str, str], *, tenant: str = "system",
                     timeout_seconds: int = 180) -> tuple[bool, str]:
    """Run ``--list-engagements`` in ``env``; return ``(ok, output)``."""
    try:
        completed = subprocess.run(
            [sys.executable, str(OMNI_ENTRY), "--list-engagements", "--tenant", tenant],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return completed.returncode == 0, f"{completed.stdout}\n{completed.stderr}".strip()


def probe_engagement(tenant: str = "system") -> dict[str, Any]:
    """Create an engagement and read it back the way the agent will.

    The ``--dry-run`` self-check: same two CLI calls the runner depends on
    (create, then look up on startup), in a throwaway data directory, with no
    network traffic. A mismatch of databases -the bug this guards against-
    shows up as ``found: false`` instead of a 0-token run.
    """
    with tempfile.TemporaryDirectory(prefix="omni-bench-probe-") as tmp:
        run_dir = Path(tmp)
        workspace = run_dir / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        env = run_environment(run_dir, workspace)
        engagement_id, creation_log = create_engagement("probe", "127.0.0.1", env=env)
        if engagement_id is None:
            return {"tenant": tenant, "found": False, "engagement_id": None,
                    "detail": creation_log}
        ok, listing = list_engagements(env, tenant=tenant)
        found = ok and engagement_id in listing
        return {
            "tenant": tenant,
            "engagement_id": engagement_id,
            "found": found,
            "detail": "" if found else listing[-2000:],
        }


def _run_reset(room: dict[str, Any], *, no_reset: bool) -> str | None:
    command = room.get("reset_cmd")
    if no_reset or not command:
        return None
    argv = shlex.split(str(command))
    if not argv:
        return None
    try:
        completed = subprocess.run(
            argv, cwd=REPO_ROOT, capture_output=True, text=True,
            timeout=int(room["timeout_seconds"]), check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{type(exc).__name__}: {exc}"
    return None if completed.returncode == 0 else (completed.stderr or completed.stdout)[-2000:]


def run_once(
    *,
    room_id: str,
    room: dict[str, Any],
    target: str,
    run_number: int,
    results_dir: Path,
    timeout_seconds: int | None = None,
    no_reset: bool = False,
) -> dict[str, Any]:
    """Execute one run, collect flags and write its JSON record."""
    started_at = datetime.now(timezone.utc)
    stamp = started_at.strftime(TIMESTAMP_FORMAT)
    deadline = int(timeout_seconds or room["timeout_seconds"])
    run_dir = results_dir / f"{room_id}-{stamp}-run{run_number}"
    workspace = run_dir / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    ndjson = run_dir / "run.ndjson"
    stderr_log = run_dir / "run.stderr.log"
    objective = build_objective(room, target)

    reset_error = _run_reset(room, no_reset=no_reset)
    # One environment for the whole run: the creator, the agent and the flag
    # scan all point at ``run_dir``, so the id is created in the database the
    # agent opens.
    env = run_environment(run_dir, workspace)
    engagement_id, creation_log = create_engagement(room_id, target, env=env)
    if engagement_id is None:
        result: dict[str, Any] = {
            "room": room_id, "name": room.get("name"), "run": run_number,
            "timestamp": stamp, "target": target, "objective": objective,
            "pass": False, "error": "engagement_creation_failed",
            "detail": creation_log, "flags_found": [], "flags_expected": int(room["expected_flags"]),
            "tokens_used": 0, "duration_seconds": 0.0, "exit_code": None,
            "timed_out": False, "reset_error": reset_error,
            "db_path": env["NEXUS_DB_PATH"],
        }
        _write_result(results_dir, room_id, stamp, run_number, result)
        return result

    command = [
        sys.executable, str(OMNI_ENTRY),
        "--engagement", engagement_id,
        "--objective", objective,
        "--stream-json", "--trust-mode", "--no-tui",
        "--max-iterations", str(room["max_iterations"]),
    ]
    started = time.monotonic()
    exit_code: int | None = None
    timed_out = False
    with ndjson.open("w", encoding="utf-8") as out, stderr_log.open("w", encoding="utf-8") as err:
        process = subprocess.Popen(
            command, cwd=REPO_ROOT, env=env, stdout=out, stderr=err,
            text=True, start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=deadline)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(process)
            exit_code = process.wait(timeout=KILL_GRACE_SECONDS)
    duration = round(time.monotonic() - started, 2)

    flags = extract_flags(
        [ndjson, workspace, run_dir / "data"],
        str(room["flag_regex"]),
    )
    expected = int(room["expected_flags"])
    result = {
        "room": room_id,
        "name": room.get("name"),
        "run": run_number,
        "timestamp": stamp,
        "target": target,
        "objective": objective,
        "engagement_id": engagement_id,
        "pass": len(flags) >= expected,
        "flags_found": flags,
        "flags_expected": expected,
        "flags_missing": max(0, expected - len(flags)),
        "tokens_used": tokens_from_ndjson(ndjson),
        "duration_seconds": duration,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "reset_error": reset_error,
        "db_path": env["NEXUS_DB_PATH"],
        "ndjson": str(ndjson),
        "workspace": str(workspace),
        "stderr_log": str(stderr_log),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_result(results_dir, room_id, stamp, run_number, result)
    return result


def _write_result(
    results_dir: Path, room_id: str, stamp: str, run_number: int, result: dict[str, Any]
) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    path = results_dir / f"{room_id}-{stamp}-run{run_number}.json"
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------------ CLI
def _parse_overrides(values: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"--target expects room=IP, got {value!r}")
        room_id, target = value.split("=", 1)
        overrides[room_id.strip()] = target.strip()
    return overrides


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OMNI benchmark runner (WP0)")
    parser.add_argument("--rooms", type=Path, default=DEFAULT_ROOMS, help="rooms.yaml")
    parser.add_argument("--room", action="append", default=[], help="sala (repetible)")
    parser.add_argument("--runs", type=int, default=1, help="intentos por sala")
    parser.add_argument("--timeout", type=int, default=None, help="timeout por run (s)")
    parser.add_argument("--target", action="append", default=[], metavar="ROOM=IP")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--no-reset", action="store_true", help="no ejecutar reset_cmd")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="valida el contrato y lista las salas sin crear engagement ni tocar red",
    )
    args = parser.parse_args(argv)

    try:
        config = load_config(args.rooms)
        overrides = _parse_overrides(args.target)
        room_ids = args.room or list(config["rooms"])
        unknown = [room for room in room_ids if room not in config["rooms"]]
        if unknown:
            raise ValueError(f"unknown rooms: {unknown}")
        if args.runs < 1:
            raise ValueError("--runs must be >= 1")
    except ValueError as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        # The runner's own integration, verified without a target or a network:
        # create an engagement and look it up from the agent's side.
        engagement_check = probe_engagement()
        if not engagement_check["found"]:
            print(
                "bench: el engagement creado no aparece en la DB que abriria el agente\n"
                f"{engagement_check['detail']}",
                file=sys.stderr,
            )
            return 2
        summary = []
        for room_id in room_ids:
            room = room_settings(config, room_id)
            try:
                target = resolve_target(room_id, room, overrides)
            except ValueError:
                target = None
            summary.append({
                "room": room_id,
                "name": room.get("name"),
                "target": target,
                "target_env": room.get("target_env"),
                "flag_regex": room.get("flag_regex"),
                "expected_flags": int(room["expected_flags"]),
                "timeout_seconds": int(room["timeout_seconds"]),
                "max_iterations": int(room["max_iterations"]),
            })
        print(json.dumps(
            {"dry_run": True, "engagement_check": engagement_check, "rooms": summary},
            indent=2, ensure_ascii=False,
        ))
        return 0

    results: list[dict[str, Any]] = []
    for room_id in room_ids:
        room = room_settings(config, room_id)
        try:
            target = resolve_target(room_id, room, overrides)
        except ValueError as exc:
            print(f"bench: {exc}", file=sys.stderr)
            return 2
        for run_number in range(1, args.runs + 1):
            print(f"[bench] {room_id} run {run_number}/{args.runs} -> {target}", flush=True)
            result = run_once(
                room_id=room_id, room=room, target=target, run_number=run_number,
                results_dir=args.results_dir, timeout_seconds=args.timeout,
                no_reset=args.no_reset,
            )
            results.append(result)
            verdict = "PASS" if result["pass"] else "FAIL"
            print(
                f"[bench] {verdict} {room_id} run {run_number}: "
                f"{len(result['flags_found'])}/{result['flags_expected']} flags, "
                f"{result['tokens_used']} tokens, {result['duration_seconds']}s, "
                f"exit={result['exit_code']}",
                flush=True,
            )

    passed = sum(1 for result in results if result["pass"])
    print(f"[bench] {passed}/{len(results)} runs PASS")
    return 0 if results and passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
