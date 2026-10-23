"""Local diagnostics with JSON output that never includes API-key values."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
from urllib.parse import urlsplit

from nexus_core.config.loader import config_exists, effective_db_path
from nexus_core.config.schema import DEFAULT_MODELS, PROVIDERS, model_env_name
from nexus_core.kernel.sandbox import sandbox_path, tool_bin_dir
from nexus_core.kernel.sandbox_modes import active_mode, effective_guarantees
from nexus_core.provisioner.detector import check_all_tools, detect_managers, detect_os
from nexus_core.provisioner.installer import probe_command


def _rpc_status():
    # Probe loopback only; never send credentials from a diagnostic command.
    try:
        parsed = urlsplit(os.getenv("MSF_RPC_URL", "http://127.0.0.1:55552"))
        host, port = parsed.hostname, parsed.port or 55552
    except ValueError:
        host, port = None, 55552
    listening = False
    if host in {"127.0.0.1", "localhost", "::1"}:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                listening = True
        except OSError:
            pass
    service = probe_command(["systemctl", "is-active", "msfrpcd"], timeout=2)
    return {
        "host": host,
        "port": port,
        "listening": listening,
        "systemd_active": service.returncode == 0 and service.stdout.strip() == "active",
        "transport": os.getenv("MSF_RPC_TRANSPORT", "msgpack"),
    }


#: Where nuclei looks for its templates when the env var is not set.
NUCLEI_DEFAULT_TEMPLATES = "/opt/nuclei-templates"


def _unset(names: tuple[str, ...]) -> list[str]:
    return [name for name in names if not str(os.getenv(name) or "").strip()]


def _sshpass_available() -> bool:
    """Whether the native ssh fallback can run (``sshpass`` on the sandbox PATH)."""
    return shutil.which("sshpass", path=sandbox_path()) is not None


def _runtime_preconditions(tools, rpc) -> list[dict]:
    """Config the tools need *at run time*, checked before a run starts (Fase 3c).

    The doctor already answers "is the binary there?" and "is the service
    listening?". Rerun #3 (commit ``8de386b``) showed the next question is just
    as expensive to answer mid-run: ``msfrpcd`` was up, ``MSF_LHOST`` was unset,
    so every reverse payload died on arrival and the ``exploit`` profile burned
    three turns retrying MSF until it exhausted its budget.

    Every entry is a *warning*, never an error: running only the auxiliaries that
    need no callback is a legitimate choice, so the run is not refused -the
    operator just gets the missing variable and the one command that fixes it.
    """
    entries: list[dict] = []
    if rpc.get("listening"):
        missing = _unset(("MSF_LHOST", "MSF_LPORT"))
        if missing:
            entries.append(
                {
                    "service": "msfrpcd",
                    "missing_env": missing,
                    "severity": "warning",
                    "action": (
                        "sin callback los payloads reverse quedan unavailable; "
                        "exporta MSF_LHOST=<tu-IP-de-tun0> (y MSF_LPORT=4444)"
                    ),
                    "observed": "listening=true",
                }
            )
    if str(os.getenv("SLIVER_OPERATOR_CONFIG") or "").strip():
        missing = _unset(("SLIVER_LHOST", "SLIVER_LPORT"))
        if missing:
            entries.append(
                {
                    "service": "sliver",
                    "missing_env": missing,
                    "severity": "warning",
                    "action": (
                        "el team server se resolverá en 127.0.0.1:31337 (defaults); "
                        "exporta SLIVER_LHOST/SLIVER_LPORT si escucha en otro sitio"
                    ),
                    "observed": "operator_config=set",
                }
            )
    if not _sshpass_available():
        # Plan B of ``nexus.post.ssh_exec``: when the server refuses the paramiko
        # session, the handler replays the command with the native ``ssh``
        # client driven by ``sshpass`` (the credential already proved on the
        # board). Without the binary the fallback answers
        # ``sshpass_not_installed`` mid-run and the agent reads it as a bad
        # password. Measured in Simple CTF (2026-10-17).
        entries.append(
            {
                "service": "sshpass",
                "missing_env": [],
                "severity": "warning",
                "action": (
                    "instálalo con `sudo apt install sshpass` (lo necesita el plan B "
                    "de ssh_exec cuando el servidor rechaza la sesión paramiko)"
                ),
                "observed": "binary=absent",
            }
        )
    if getattr(tools.get("nuclei"), "present", False):
        configured = str(os.getenv("NEXUS_NUCLEI_TEMPLATES") or "").strip()
        templates = Path(configured) if configured else Path(NUCLEI_DEFAULT_TEMPLATES)
        if not templates.is_dir():
            entries.append(
                {
                    "service": "nuclei",
                    "missing_env": ["NEXUS_NUCLEI_TEMPLATES"],
                    "severity": "warning",
                    "action": (
                        f"instala los templates en {NUCLEI_DEFAULT_TEMPLATES} "
                        "o exporta NEXUS_NUCLEI_TEMPLATES=<ruta>"
                    ),
                    "observed": f"templates_dir={templates}",
                }
            )
    return entries


def _workspace_isolation() -> list[dict]:
    """Warn when the workspace already holds the report the run must produce.

    Measured in DeadDrop (2026-10-23): the campaign document with the flag, the
    ``Administrator`` NT hash and the exact recipe sat in ``docs/missions/diag``
    nine hours before the run, and the run's ``shell.exec`` greps that tree by
    design. The result was indistinguishable from discovery, so it could certify
    nothing. This is a *warning*: the operator may be running a re-test on a box
    they own, and nothing here is deleted.
    """
    from nexus_core.kernel.workspace_hygiene import scan_spoilers

    scan = scan_spoilers()
    if not scan.contaminated:
        return []
    return [
        {
            "service": "workspace",
            "missing_env": [],
            "severity": "warning",
            "action": (
                f"mueve esos {scan.total} ficheros fuera de {scan.root} antes de "
                "un run que deba demostrar descubrimiento (el motor puede leerlos)"
            ),
            "observed": f"spoilers={scan.total}",
            "files": list(scan.files),
        }
    ]


def _audit(path):
    if not path.is_file():
        return []
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1) as conn:
            rows = conn.execute(
                "SELECT created_at,action,resource_id,decision FROM kernel_audit_events ORDER BY sequence DESC LIMIT 5"
            ).fetchall()
        return [dict(zip(("created_at", "action", "resource_id", "decision"), row)) for row in rows]
    except (sqlite3.Error, OSError):
        return []


def run_doctor(paths, config, *, as_json=False) -> int:
    db = effective_db_path(config, paths)
    provider = os.getenv("LLM_PROVIDER", config.llm.default_provider)
    model = os.getenv(
        model_env_name(provider),
        config.llm.default_model
        if provider == config.llm.default_provider
        else DEFAULT_MODELS.get(provider, ""),
    )
    postgres = config.db.backend == "postgres" or os.getenv("DATABASE_URL", "").startswith(
        ("postgres://", "postgresql://")
    )
    try:
        size = db.stat().st_size if db.is_file() else 0
    except OSError:
        size = 0
    keys = {
        provider: bool(
            config.llm.api_keys.get(provider) or os.getenv(provider.upper() + "_API_KEY")
        )
        for provider in PROVIDERS
        if provider not in {"fake", "ollama"}
    }
    tools = check_all_tools()
    rpc = _rpc_status()
    report = {
        "os": asdict(detect_os()),
        "python": platform.python_version(),
        "shell": os.getenv("SHELL", ""),
        "paths": {
            name: {"path": str(path), "exists": path.exists()}
            for name, path in {
                "config": paths.config_file,
                "data": paths.data_dir,
                "state": paths.state_dir,
                "cache": paths.cache_dir,
            }.items()
        },
        "config": {
            "exists": config_exists(paths),
            "schema_version": config.schema_version,
            "default_provider": provider,
            "default_model": model,
            "api_keys": keys,
        },
        "db": {
            "path": None if postgres else str(db),
            "exists": None if postgres else db.is_file(),
            "size_bytes": None if postgres else size,
            "backend": "postgres" if postgres else "sqlite",
            "diagnostic": "remote database not queried" if postgres else "local read-only",
        },
        "sandbox": {
            "mode": active_mode().value,
            "path": sandbox_path(),
            "tool_bin_dir": str(tool_bin_dir()) if tool_bin_dir() else None,
            **effective_guarantees().to_dict(),
        },
        "managers": list(detect_managers()),
        "tools": {name: asdict(status) for name, status in tools.items()},
        "msfrpcd": rpc,
        # Operator config the tools need at run time (never a secret: only the
        # *names* of unset variables and what to do about them).
        "runtime_preconditions": (
            _runtime_preconditions(tools, rpc) + _workspace_isolation()
        ),
        "audit": [] if postgres else _audit(db),
    }
    # Protect against a secret accidentally echoed by a local version command.
    secrets = list(config.llm.api_keys.values()) + [config.scope.signing_secret]
    secrets += [
        v
        for k, v in os.environ.items()
        if any(x in k for x in ("API_KEY", "PASSWORD", "SECRET", "TOKEN"))
    ]

    def redact(value):
        if isinstance(value, str):
            for secret in secrets:
                if secret:
                    value = value.replace(secret, "[REDACTED]")
        elif isinstance(value, dict):
            return {k: redact(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [redact(v) for v in value]
        return value

    report = redact(report)
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if as_json:
        print(encoded)
    else:
        report = json.loads(encoded)
        print("OmniAgentCS Doctor\n" + "═" * 54)
        for title, key in (
            ("Sistema", "os"),
            ("Python", "python"),
            ("Shell", "shell"),
            ("Rutas XDG", "paths"),
            ("Config", "config"),
            ("Base de datos", "db"),
            ("Sandbox", "sandbox"),
            ("Gestores", "managers"),
            ("Herramientas", "tools"),
            ("msfrpcd", "msfrpcd"),
            ("Precondiciones de runtime", "runtime_preconditions"),
            ("Auditoría (últimos 5 eventos)", "audit"),
        ):
            print(f"\n{title}:")
            value = report[key]
            if key == "tools":
                for name, item in value.items():
                    print(
                        f"  {name:12} {'✓' if item['present'] else '✗'} {item['path'] or '(ausente)'}  {item['version'] or ''}"
                    )
            elif key == "sandbox":
                print(f"  modo:              {value['mode']}")
                print(f"  PATH:              {value['path']}")
                print(f"  bin de usuario:    {value['tool_bin_dir'] or '(no resoluble)'}")
                print(f"  aislamiento FS:    {'sí' if value['filesystem_isolation'] else 'no'}")
                print(f"  aislamiento red:   {'sí' if value['network_isolation'] else 'no'}")
                print(f"  process isolation: {'sí' if value['process_isolation'] else 'no'}")
                print(f"  límites recursos:  {'sí' if value['resource_limits'] else 'no'}")
                print(f"  tools network:     {'OK' if value['supports_network_tools'] else 'no'}")
            elif key == "runtime_preconditions":
                if not value:
                    print("  (sin avisos)")
                for item in value:
                    missing = ", ".join(f"{name}=unset" for name in item["missing_env"])
                    # A check can report a missing *binary* (``sshpass``) instead
                    # of an unset variable, so the two halves are optional.
                    detail = " · ".join(
                        part for part in (item.get("observed") or "", missing) if part
                    )
                    head = f"  {item['service']}:" + (f" {detail}" if detail else "")
                    print(f"{head} ({item['severity'].upper()}: {item['action']})")
            elif isinstance(value, dict):
                for name, item in value.items():
                    print(f"  {name}: {json.dumps(item, ensure_ascii=False)}")
            else:
                print("  " + json.dumps(value, ensure_ascii=False))
    return 0
