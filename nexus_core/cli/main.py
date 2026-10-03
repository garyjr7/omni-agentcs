"""Entry point of the ``omni`` CLI (stdlib ``argparse`` only)."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Callable, Iterable, Sequence

from nexus_core.kernel.store_factory import get_control_store
from nexus_core.scope import EngagementStore

from . import render
from .session import DEFAULT_TENANT, OmniSession, build_llm_client

PROGRAM = "omni"
PROGRAM_VERSION = "3.0.0"

#: Run statuses that do not mean "the agent broke".
ACCEPTABLE_ONESHOT_STATUSES = frozenset({"completed", "max_iterations", "clarification"})


def build_parser() -> argparse.ArgumentParser:
    """Build the ``omni`` argument parser."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="CLI interactivo de OmniAgentCS-CLI: bucle ReAct con scope y aprobación humana.",
    )
    parser.add_argument("--engagement", metavar="ID", help="engagement activo (scope firmado)")
    parser.add_argument(
        "--tenant", default=DEFAULT_TENANT, help=f"tenant de trabajo (default: {DEFAULT_TENANT})"
    )
    parser.add_argument(
        "--objective", metavar="TEXTO", help="ejecuta un objetivo one-shot y sale (sin REPL)"
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=12,
        metavar="N",
        help="máximo de iteraciones del bucle ReAct (default: 12)",
    )
    parser.add_argument("--no-color", action="store_true", help="desactiva la salida ANSI")
    parser.add_argument("--no-tui", action="store_true", help="usa readline en lugar de la TUI")
    parser.add_argument(
        "--fullscreen",
        action="store_true",
        help=(
            "usa la pantalla alternativa (alt-screen) de la TUI; opt-in, el "
            "scrollback del terminal no queda accesible mientras corre"
        ),
    )
    parser.add_argument(
        "--trust-mode",
        action="store_true",
        help=(
            "auto-aprueba las tools de alto riesgo del engagement (nunca las "
            "destructivas); cada autorización queda auditada con trust_mode=true"
        ),
    )
    parser.add_argument(
        "--resume", metavar="RUN_ID", help="retoma un run previo (reanuda su conversación durable)"
    )
    parser.add_argument(
        "--list-engagements", action="store_true", help="lista los engagements del tenant y sale"
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {PROGRAM_VERSION}")
    for flag, help_text in (
        ("doctor", "diagnóstico del sistema"), ("json", "salida JSON para --doctor/--setup"),
        ("setup", "verifica e informa del entorno ofensivo (binarios y servicios)"),
        ("install", "con --setup: instala los componentes que falten"),
        ("yes", "auto-aprueba la ejecución de los planes de instalación"),
        ("config", "editar config global"), ("config-path", "imprimir ruta de config"),
        ("no-wizard", "omitir onboarding interactivo"), ("reset-config", "respaldar config y reiniciar onboarding"),
    ):
        parser.add_argument("--" + flag, action="store_true", help=help_text)
    return parser


def select_engagement(
    engagements: Iterable[Any],
    requested: str | None = None,
    reader: Callable[[str], str] | None = None,
) -> tuple[Any, int]:
    """Pick the active engagement; return ``(scope, exit_code)``.

    ``exit_code`` is 0 when the caller may continue (even without an active
    engagement: tools that need a scope will be denied) and non-zero when the
    selection itself failed.
    """
    scopes = list(engagements)
    by_id = {str(getattr(scope, "engagement_id", "")): scope for scope in scopes}
    if requested:
        if requested in by_id:
            return by_id[requested], 0
        render.render_error(f"engagement no encontrado: {requested}")
        return None, 2
    if not scopes:
        render.render_error("no hay engagements en este tenant; usa --list-engagements")
        return None, 0
    if len(scopes) == 1:
        render.render_status(f"engagement activo: {scopes[0].engagement_id}")
        return scopes[0], 0

    print("Engagements disponibles:")
    for index, scope in enumerate(scopes, start=1):
        print(
            f"  [{index}] {getattr(scope, 'engagement_id', '?')} · "
            f"{getattr(scope, 'name', '')} · hasta {getattr(scope, 'valid_until', '?')}"
        )
    answer = (reader or input)("Selecciona un engagement [1-N o id]: ").strip()
    if answer in by_id:
        return by_id[answer], 0
    try:
        index = int(answer)
    except (TypeError, ValueError):
        render.render_error(f"selección inválida: {answer!r}")
        return None, 2
    if 1 <= index <= len(scopes):
        return scopes[index - 1], 0
    render.render_error(f"selección fuera de rango: {index}")
    return None, 2


def _list_engagements(scopes: list[Any]) -> None:
    if not scopes:
        print("(no hay engagements en este tenant)")
        return
    for scope in scopes:
        print(
            f"  {getattr(scope, 'engagement_id', '?'):<24} "
            f"{getattr(scope, 'name', ''):<28} "
            f"cliente={getattr(scope, 'client', '?')}  hasta {getattr(scope, 'valid_until', '?')}"
        )


def main(argv: Sequence[str] | None = None, *, config=None, paths=None) -> int:
    """Run the ``omni`` CLI; returns the process exit code."""
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    render.configure_color(no_color=args.no_color)

    from nexus_core.config.loader import effective_db_path, load_config
    from nexus_core.config.xdg import resolve_xdg_paths
    paths = paths or resolve_xdg_paths()
    config = config or load_config(paths)
    store = get_control_store(effective_db_path(config, paths))
    store.initialize()
    engagements = list(EngagementStore(store).list_for_tenant(args.tenant))

    if args.list_engagements:
        _list_engagements(engagements)
        return 0

    engagement, exit_code = select_engagement(engagements, args.engagement)
    if exit_code:
        return exit_code

    try:
        llm_client = build_llm_client()
    except RuntimeError as exc:
        render.render_error(str(exc))
        return 2
    except Exception as exc:  # noqa: BLE001 - misconfigured providers must be reported
        render.render_error(f"no se pudo construir el cliente LLM: {type(exc).__name__}: {exc}")
        return 2

    session = OmniSession(
        store=store,
        tenant_id=args.tenant,
        engagement=engagement,
        llm_client=llm_client,
        max_iterations=args.max_iterations,
        run_id=args.resume,
        trust_mode=args.trust_mode,
        no_color=args.no_color,
        use_tui=False if args.no_tui or args.objective else None,
        engagement_names=[scope.name for scope in engagements],
        fullscreen=args.fullscreen,
    )
    if args.objective:
        result = session.run_objective(args.objective)
        if result is None:
            return 1
        return 0 if result.status in ACCEPTABLE_ONESHOT_STATUSES else 1
    session.run_repl()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through omni.py
    sys.exit(main())
