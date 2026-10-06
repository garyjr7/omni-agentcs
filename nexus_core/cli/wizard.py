"""First-run onboarding. No unattended installations or partial config writes."""

from dataclasses import asdict
import getpass
import os
import secrets
import sys

from nexus_core.config.loader import config_exists, effective_db_path, load_config, save_config
from nexus_core.config.schema import DEFAULT_MODELS, OmniConfig, PROVIDERS
from nexus_core.provisioner.detector import check_all_tools, detect_managers, detect_os
from nexus_core.provisioner.installer import (
    execute_install,
    format_plan,
    plan_install,
    update_shell_path,
)


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


def run_wizard(paths) -> OmniConfig:
    if config_exists(paths):
        return load_config(paths)
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
                if k != "recipes_available"
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
        print("Proveedor: 1 Groq / 2 OpenAI / 3 Anthropic / 4 Gemini / 5 Ollama / 6 Fake")
        answer = input("Proveedor [1]: ").strip().lower() or "1"
        provider = (
            PROVIDERS[int(answer) - 1] if answer in {"1", "2", "3", "4", "5", "6"} else answer
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
