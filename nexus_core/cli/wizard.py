"""First-run onboarding. No unattended installations or partial config writes."""

from dataclasses import asdict
import getpass
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

from nexus_core.config.bootstrap import set_env_values
from nexus_core.config.loader import config_exists, effective_db_path, load_config, save_config
from nexus_core.config.schema import DEFAULT_MODELS, OmniConfig, PROVIDERS
from nexus_core.provisioner.detector import check_all_tools, detect_managers, detect_os
from nexus_core.provisioner.installer import (
    execute_install,
    format_plan,
    plan_install,
    update_shell_path,
)


#: Interface the reverse-shell callback is read from on Kali.
TUN0_INTERFACE = "tun0"
#: Upstream default of ``msfrpcd`` payloads; the handler uses the same one.
DEFAULT_MSF_LPORT = "4444"


class WizardAborted(Exception):
    """Operator cancelled onboarding before committing configuration."""


def should_run_wizard(paths, *, force_no_wizard=False):
    return (
        not force_no_wizard
        and not os.getenv("CI")
        and not os.getenv("PYTEST_CURRENT_TEST")
        and sys.stdin.isatty()
        and not config_exists(paths)
    )


def _yes(prompt):
    return input(prompt).strip().lower() in {"y", "yes", "s", "si", "sí"}


def _initial_scope(name, entries, secret):
    """Build and sign the onboarding engagement (shared with ``/engage``)."""
    from nexus_core.cli.engage import build_scope

    return build_scope(name, entries, secret, tenant_id="system", client="onboarding")


def detect_tun0_ip() -> str | None:
    """IPv4 address of the Kali ``tun0`` interface, or ``None`` when there is none.

    The reverse-shell callback has to be an address the target can reach, which
    on Kali is the VPN tunnel. Detection is best-effort and never fatal: a host
    without ``ip``, without VPN or with a differently named interface returns
    ``None`` and the operator types the address by hand. Measured need (rerun #3,
    commit ``8de386b``): ``MSF_LHOST`` absent from ``.env`` left every reverse
    payload dead, and nothing surfaced it before the run (Fase 3c).
    """
    try:
        completed = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", TUN0_INTERFACE],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    for match in re.finditer(r"\binet (\d+\.\d+\.\d+\.\d+)/", completed.stdout):
        candidate = match.group(1)
        if not candidate.startswith("127."):
            return candidate
    return None


def _configure_msf_callback(root) -> str | None:
    """Optional ``MSF_LHOST``/``MSF_LPORT``, auto-detected from ``tun0``.

    Returns the persisted callback host (or ``None`` if the operator skipped
    it). The values go to the project ``.env`` -the file the runtime loads- so a
    restart is enough to make them effective.
    """
    detected = detect_tun0_ip()
    print("\nCallback de reverse shells de Metasploit (MSF_LHOST / MSF_LPORT):")
    if detected:
        print(f"  tun0 detectada: {detected}")
    else:
        print(
            "  AVISO: no se detecta tun0 (¿VPN sin conectar?). Si lo dejas vacío,\n"
            "  las tools con payload reverse quedarán unavailable hasta que\n"
            "  exportes MSF_LHOST con una IP alcanzable desde el objetivo."
        )
    answer = input(f"MSF_LHOST [{detected or 'vacío'}]: ").strip() or (detected or "")
    if not answer:
        return None
    port = input("MSF_LPORT [4444]: ").strip() or DEFAULT_MSF_LPORT
    written = set_env_values(root, {"MSF_LHOST": answer, "MSF_LPORT": port})
    print(f"Guardado en {written}: MSF_LHOST={answer} MSF_LPORT={port}")
    return answer


def run_wizard(paths, *, root=None) -> OmniConfig:
    if config_exists(paths):
        return load_config(paths)
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    created = None
    store = None
    try:
        print("Bienvenido a OmniAgentCS — configuración inicial")
        print(
            "  AVISO · USO AUTORIZADO ÚNICAMENTE\n"
            "  OmniAgentCS es una herramienta de pruebas de penetración. Úsala solo\n"
            "  sobre objetivos para los que tengas permiso escrito. Escanear o\n"
            "  explotar sistemas sin autorización es ilegal. Tú eres responsable del\n"
            "  alcance (scope) que firmes en cada engagement."
        )
        config = OmniConfig()
        system = detect_os()
        config.provisioning.available_managers = list(detect_managers())
        tools = check_all_tools()
        print(f"Sistema: {system.distro} {system.version} ({system.arch})")
        missing = []
        for name, status in tools.items():
            print(
                f"  {'✓' if status.present else '✗'} {name}: {status.version or status.path or 'ausente'}"
            )
            config.tools_detected[name] = {
                k: (v if v is not None else "")
                for k, v in asdict(status).items()
                if k not in {"recipes_available", "verify_argv"}
            }
            if not status.present:
                missing.append(name)
        if missing and _yes("¿Revisar instalaciones de herramientas ausentes? [y/N]: "):
            for name in missing:
                try:
                    plan = plan_install(name)
                except ValueError:
                    print(f"{name}: no hay gestor compatible disponible; omitido.")
                    continue
                print(f"{name}:\n{format_plan(plan)}")
                if not _yes("¿Ejecutar este comando? [y/N/skip]: "):
                    continue
                outcome = execute_install(plan)
                print(
                    "Instalación verificada."
                    if outcome.success
                    else "Instalación fallida: " + outcome.stderr[:300]
                )
                if outcome.success and plan.installs_to:
                    update_shell_path(plan.installs_to)
        print("Proveedor: 1 Groq / 2 OpenAI / 3 Anthropic / 4 Gemini / 5 Ollama / 6 Fake / 7 DeepSeek")
        answer = input("Proveedor [1]: ").strip().lower() or "1"
        provider = (
            PROVIDERS[int(answer) - 1] if answer in {"1", "2", "3", "4", "5", "6", "7"} else answer
        )
        if provider not in PROVIDERS:
            raise ValueError("proveedor desconocido")
        defaults = DEFAULT_MODELS
        config.llm.default_provider = provider
        config.llm.default_model = (
            input(f"Modelo [{defaults[provider]}]: ").strip() or defaults[provider]
        )
        if provider not in {"fake", "ollama"}:
            config.llm.api_keys[provider] = getpass.getpass(
                "API key (oculta, Enter para configurar después): "
            ).strip()
        # Optional, but it is the difference between a working reverse payload
        # and three wasted turns (V1-17/Fase 3c). Never fatal: Enter skips it.
        _configure_msf_callback(root)
        # No paid or remote API calls are needed to save onboarding.
        if _yes("¿Crear engagement inicial con alcance autorizado por ti (24 horas)? [y/N]: "):
            name = input("Nombre: ").strip() or "Engagement inicial"
            entries = input("Dominios/CIDRs autorizados, separados por coma: ")
            config.scope.signing_secret = os.getenv(
                "NEXUS_SCOPE_SIGNING_SECRET"
            ) or secrets.token_hex(32)
            scope = _initial_scope(name, entries, config.scope.signing_secret)
            print(f"Scope: {scope.domains} / {scope.cidrs}; válido hasta {scope.valid_until}")
            if _yes("¿Guardar este alcance? [y/N]: "):
                from nexus_core.kernel.store_factory import get_control_store
                from nexus_core.scope import EngagementStore

                paths.ensure_dirs()
                store = EngagementStore(get_control_store(effective_db_path(config, paths)))
                store.store.initialize()
                created = store.create(scope)
        save_config(config, paths)
        if created:
            print(f"Engagement: {created.engagement_id}")
        print(f"Configuración guardada: {paths.config_file}")
        return config
    except BaseException as exc:
        if created and store:
            store.delete(created.tenant_id, created.engagement_id)
        if isinstance(exc, (KeyboardInterrupt, EOFError)):
            raise WizardAborted("onboarding cancelled") from None
        raise
