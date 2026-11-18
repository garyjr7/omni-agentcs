"""Entry point of the ``omni`` CLI (stdlib ``argparse`` only)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from nexus_core.kernel.store_factory import get_control_store
from nexus_core.scope import EngagementStore

from . import errors, render
from .session import DEFAULT_TENANT, OmniSession, build_llm_client

PROGRAM = "omni"
PROGRAM_VERSION = "3.0.0rc6"

#: Run statuses that do not mean "the agent broke".
ACCEPTABLE_ONESHOT_STATUSES = frozenset(
    {"completed", "max_iterations", "clarification", "time_budget"}
)


def time_budget_seconds(args: argparse.Namespace) -> int:
    """Work-time ceiling from ``--time-budget`` (s) or ``--time-budget-hours``."""
    hours = getattr(args, "time_budget_hours", None)
    if hours is not None:
        return max(0, int(round(float(hours) * 3600)))
    return max(0, int(getattr(args, "time_budget", 0) or 0))


def build_parser() -> argparse.ArgumentParser:
    """Build the ``omni`` argument parser."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="CLI interactivo de OmniAgentCS-CLI: bucle ReAct con scope y aprobación humana.",
    )
    parser.add_argument("--continue", dest="continue_engagement", metavar="ID",
                        help="retoma un engagement y su conversación persistente")
    parser.add_argument("--engagement", metavar="ID", help="engagement activo (scope firmado)")
    parser.add_argument(
        "--tenant", default=DEFAULT_TENANT, help=f"tenant de trabajo (default: {DEFAULT_TENANT})"
    )
    parser.add_argument(
        "--objective", metavar="TEXTO", help="ejecuta un objetivo one-shot y sale (sin REPL)"
    )
    parser.add_argument(
        "command",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--stream-json",
        action="store_true",
        help="modo headless: emite NDJSON (un evento por línea) y sale",
    )
    parser.add_argument(
        "--skill",
        action="append",
        metavar="NOMBRE",
        help="activa una skill de .agents/skills/<NOMBRE>/SKILL.md (repetible)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=20,
        metavar="N",
        help="máximo de iteraciones del bucle ReAct (default: 20)",
    )
    # R1: the token ceiling used to be a fixed 250k no matter what
    # ``--max-iterations`` said, so a 50-turn run died at ~21. The budget is now
    # derived from the iteration ceiling; this flag is the explicit override
    # (``0`` keeps its documented "unlimited" meaning).
    parser.add_argument(
        "--budget-tokens",
        type=int,
        default=None,
        metavar="N",
        help=(
            "techo de tokens del run (default: derivado de --max-iterations; "
            "0 = sin límite)"
        ),
    )
    # Work-time ceiling. It is measured in *work* seconds, not wall clock, so a
    # resumed run keeps what it already spent and downtime does not count. The
    # last minutes are a wrap-up window (``NEXUS_WRAP_UP_SECONDS``, 10 min by
    # default) where only the report and the plan update are accepted.
    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument(
        "--time-budget",
        type=int,
        default=0,
        metavar="SEGUNDOS",
        help=(
            "presupuesto de tiempo de trabajo en segundos (0 = sin límite); "
            "los últimos minutos son de cierre (informe + task_complete)"
        ),
    )
    time_group.add_argument(
        "--time-budget-hours",
        type=float,
        default=None,
        metavar="HORAS",
        help="igual que --time-budget, expresado en horas (admite decimales)",
    )
    # P2 (Fase 3.7): pin the subagent profile. The loop already accepted
    # ``payload["subagent"]``; without a flag an operator whose profile lacked
    # the right tool had no way to retry (``--resume``) with the right one.
    from nexus_core.agent.subagents import SUBAGENT_IDS

    parser.add_argument(
        "--subagent",
        metavar="ID",
        choices=list(SUBAGENT_IDS),
        help="fija el perfil de subagente del run (por defecto lo elige el planner)",
    )
    parser.add_argument("--no-color", action="store_true", help="desactiva la salida ANSI")
    parser.add_argument("--no-tui", action="store_true", help="usa readline en lugar de la TUI")
    parser.add_argument(
        "--no-fullscreen",
        dest="fullscreen",
        action="store_false",
        help=(
            "modo inline: no usa la pantalla alternativa (alt-screen); conserva "
            "el scrollback y el prompt del terminal a la vista"
        ),
    )
    parser.add_argument("--fullscreen", dest="fullscreen", action="store_true", help=argparse.SUPPRESS)
    parser.set_defaults(fullscreen=True)
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
        "--resume-policy",
        choices=["approve", "skip", "fail"],
        default=None,
        help=(
            "qué hacer con invocaciones en estado unknown. En headless con --resume: "
            "approve=exige aprobación durable previa; skip=marca sin efecto; fail=falla. "
            "Durante el run y solo con --trust-mode: approve=auto-aprobación auditada "
            "del reintento; skip=lo marca sin efecto; fail=bloquea"
        ),
    )
    parser.add_argument(
        "--autospawn",
        action="store_true",
        help=(
            "delega automáticamente a un subagente hijo al cambiar de familia de "
            "fase (opt-in; desactivado por defecto)"
        ),
    )
    parser.add_argument(
        "--no-autospawn", dest="autospawn", action="store_false", help=argparse.SUPPRESS
    )
    parser.set_defaults(autospawn=False)
    parser.add_argument(
        "--supervisor-budget", type=int, default=0, metavar="TOKENS",
        help="presupuesto global de tokens del árbol de subagentes (0 = sin delegación)",
    )
    parser.add_argument(
        "--list-engagements", action="store_true", help="lista los engagements del tenant y sale"
    )
    parser.add_argument(
        "--roe",
        nargs="?",
        const="show",
        metavar="ACCION",
        help=(
            "Reglas de Encuentro del engagement: show (default), path, kill "
            "(arma el kill switch) o arm (lo desarma) y sale"
        ),
    )
    parser.add_argument(
        "--new-engagement", metavar="NOMBRE",
        help="crea un engagement firmado con --scope y sale",
    )
    parser.add_argument(
        "--scope", metavar="DOMINIOS/CIDRS",
        help="alcance autorizado separado por comas, para --new-engagement",
    )
    parser.add_argument(
        "--valid-hours", type=int, default=24, metavar="N",
        help="validez en horas para --new-engagement (default: 24)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "html", "both", "sarif"],
        metavar="FMT",
        help="con 'report': formato del entregable (default: both)",
    )
    parser.add_argument(
        "--output", metavar="DIR", help="con 'report': directorio de salida"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="con 'tool': lista las tools durables del tenant y sale",
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {PROGRAM_VERSION}")
    for flag, help_text in (
        ("doctor", "diagnóstico del sistema"), ("json", "salida JSON para --doctor/--setup"),
        ("setup", "verifica e informa del entorno ofensivo (binarios y servicios)"),
        ("install", "con --setup: instala los componentes que falten"),
        ("yes", "auto-aprueba la ejecución de los planes de instalación"),
        ("config", "editar config global"), ("config-path", "imprimir ruta de config"),
        ("no-wizard", "omitir onboarding interactivo"), ("reset-config", "respaldar config y reiniciar onboarding"),
        ("about", "muestra el banner ASCII completo con las stats y sale"),
        ("banner", "usa el banner ASCII completo en el arranque del REPL"),
        ("check", "con `omni update`: solo comprueba si hay versión nueva"),
    ):
        parser.add_argument("--" + flag, action="store_true", help=help_text)
    parser.epilog = ("omni run · códigos de salida v1: 0=completed verificado; "
                     "1=incomplete; 2=aprobación pendiente; 3=provider_error; "
                     "4=governance_denial; 130=SIGINT. "
                     "Scope: governed por defecto; NEXUS_SCOPE_MODE=lab acepta scopes "
                     "unsigned con auditoría (nunca en producción).")
    return parser


def _render_about(scopes: list[Any], args: argparse.Namespace) -> None:
    """Print the full ASCII banner with live stats (``omni --about``)."""
    from .banner import build_banner, render_banner
    from .llm_env import provider_summary

    try:
        from nexus_core.tools.registry import durable_tool_definitions

        tools_count = len(durable_tool_definitions(args.tenant))
    except Exception:  # noqa: BLE001 - a broken catalog must not hide --about
        tools_count = 0
    summary, providers_count = provider_summary()
    if args.engagement:
        engagement = next(
            (
                scope
                for scope in scopes
                if str(getattr(scope, "engagement_id", "")) == args.engagement
            ),
            None,
        )
    else:
        engagement = scopes[0] if scopes else None
    text = build_banner(
        version=PROGRAM_VERSION,
        tools_count=tools_count,
        providers_count=providers_count,
        engagement_name=getattr(engagement, "name", None),
        audit_chain_valid=True,
        msfrpcd_version=None,
        llm_summary=summary,
        no_color=args.no_color,
        compact=False,
    )
    render_banner(text, no_color=args.no_color)


def _run_report_command(
    store: Any, args: Any, engagement: Any, *, output_format: str, output_dir: str | None
) -> int:
    """Handle ``omni report [--format FMT] [--output DIR]`` through the gateway."""
    from . import commands as commands_module

    if engagement is None:
        render.render_error("omni report requiere un engagement activo (usa --engagement)")
        return 2
    session = OmniSession(
        store=store,
        tenant_id=args.tenant,
        engagement=engagement,
        no_color=args.no_color,
        use_tui=False,
    )
    if output_dir:
        commands_module.cmd_report(
            session, ["export", output_dir, "--format", output_format]
        )
        return 0 if session.last_report_directory else 2
    commands_module.cmd_report(session, ["--format", output_format])
    return 0 if session.last_report_sha256 else 2


def _run_cve_command(args: Any, store: Any, tenant: str, engagement: Any) -> int:
    """Handle ``omni cve update [CVE...]`` (explicit, cache-filling update)."""
    from nexus_core.report import cve_enrichment

    command = list(args.command[1:])
    if not command or command[0].lower() != "update":
        render.render_error("uso: omni cve update [CVE-AAAA-NNNN ...]")
        return 2
    raw = command[1:]
    invalid = [item for item in raw if cve_enrichment.normalize_cve(item) is None]
    if invalid:
        render.render_error(f"CVE inválido: {invalid[0]}")
        return 2
    cves = [cve_enrichment.normalize_cve(item) or item for item in raw]
    if not cves and engagement is not None and store is not None:
        from nexus_core.report.extractor import extract_findings_sync

        findings, _ = extract_findings_sync(store, tenant, engagement.engagement_id)
        cves = cve_enrichment.collect_cves(findings)
    if not cves:
        render.render_error(
            "omni cve update requiere ids CVE o un engagement con hallazgos CVE"
        )
        return 2
    render.render_status(f"actualizando {len(cves)} CVE(s) desde NVD/EPSS/CISA KEV...")
    summary = cve_enrichment.update_cves(cves)
    render.render_status(
        f"NVD {summary['nvd_updated']} · EPSS {summary['epss_updated']} · "
        f"KEV {'ok' if summary['kev_updated'] else 'no'}"
    )
    for error in summary["errors"]:
        render.write(f"  ! {error}")
    return 1 if summary["errors"] else 0


def select_engagement(
    engagements: Iterable[Any],
    requested: str | None = None,
    reader: Callable[[str], str] | None = None,
    *,
    announce: bool = True,
) -> tuple[Any, int]:
    """Pick the active engagement; return ``(scope, exit_code)``.

    ``exit_code`` is 0 when the caller may continue (even without an active
    engagement: tools that need a scope will be denied) and non-zero when the
    selection itself failed. ``announce=False`` suppresses the auto-selection
    notice on the terminal's main screen, so the TUI's dedicated screen opens
    without a residual line above the banner.
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
        if announce:
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


def headless_requested(args: Any) -> bool:
    """Whether this invocation will write a machine record to stdout (P17).

    Mirrors the dispatch rules: ``run`` is always headless, and ``--json`` /
    ``--stream-json`` make a one-shot objective headless. Subcommands other than
    ``run`` print for a human.
    """
    subcommand = str(args.command[0]) if args.command else ""
    if subcommand == "run":
        return True
    if subcommand:
        return False
    return bool(args.objective and (args.stream_json or args.json))


def _revalidate_plan_on_resume(session: OmniSession) -> list[str]:
    """Demote the TODOs an earlier run ticked without the promised evidence.

    DeadDrop (2026-10-22): ``apk-creds`` was closed by a ``credential`` fact the
    shadow crack produced, so a resumed run started at 7/12 and never went back
    for the decompilation. The corrected plan is written **before** the first
    turn and reported once, so the operator sees the count change; a failure here
    never blocks the resume (the turn loop reconciles normally afterwards).
    """
    from nexus_core.agent.engagement_plan import load_plan_for, reconcile, save_plan
    from nexus_core.kernel.blackboard import Blackboard, is_verified_fact

    engagement_id = getattr(session, "engagement_id", None)
    root = str(getattr(session, "workspace_root", "") or "") or None
    if not engagement_id:
        return []
    try:
        plan = load_plan_for(
            engagement_id, root, store=session.store, tenant_id=session.tenant_id
        )
        if plan is None or not any(todo.done and todo.verified_by for todo in plan.todos):
            return []
        facts = [
            fact
            for fact in Blackboard(session.store).list_facts(
                session.tenant_id, engagement_id, limit=2000
            )
            if is_verified_fact(fact)
        ]
        updated, _ = reconcile(plan, facts, engagement_id=engagement_id, revalidate=True)
    except Exception as exc:  # noqa: BLE001 - a resume must never be blocked by this
        render.render_error(f"no se pudo revisar el plan cargado: {type(exc).__name__}")
        return []
    if updated is None or updated is plan:
        return []
    demoted = [
        before.id
        for before, after in zip(plan.todos, updated.todos)
        if before.done and not after.done
    ]
    if not demoted:
        return []
    save_plan(updated, root, store=session.store, tenant_id=session.tenant_id)
    done, total = len(updated.todos) - len(updated.pending), len(updated.todos)
    render.render_status(
        f"plan recalculado: {', '.join(demoted)} vuelve a pendiente "
        f"(la prueba no cumple la condición) · {done}/{total}"
    )
    return demoted


def main(argv: Sequence[str] | None = None, *, config: Any = None, paths: Any = None) -> int:
    """Run the ``omni`` CLI; returns the process exit code.

    Under ``--json``/``--stream-json`` stdout carries the run record and nothing
    else, so the **whole** dispatch runs with human output on stderr: a banner or
    an error raised before the run starts is as polluting as one emitted during
    it (P17).
    """
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    render.configure_color(no_color=args.no_color)
    if headless_requested(args):
        from .headless import human_output_on_stderr

        with human_output_on_stderr():
            return _dispatch(args, config=config, paths=paths)
    return _dispatch(args, config=config, paths=paths)


def _dispatch(args: Any, *, config: Any = None, paths: Any = None) -> int:
    """Body of :func:`main` (already inside the P17 stdout guard when headless)."""
    # ``omni run "<objetivo>" [--json|--stream-json]``: a light subcommand shim.
    # The CLI is argparse-by-flags, so ``run`` is a positional we interpret
    # rather than a real subparser (see docs/missions/FASE3B_ECOSYSTEM.md §7).
    objective = args.objective
    headless_mode: str | None = None
    subcommand: str | None = None
    if args.command:
        subcommand = str(args.command[0])
        if subcommand == "run":
            objective = " ".join(args.command[1:]).strip() or objective
            headless_mode = "stream" if args.stream_json else "json"
        elif subcommand not in {
            "report", "cve", "tool", "hooks", "resume", "auth", "update",
        }:
            render.render_error(f"subcomando desconocido: {subcommand}")
            return 2
    elif args.stream_json and objective:
        headless_mode = "stream"
    elif args.json and objective:
        headless_mode = "json"

    from nexus_core.config.loader import effective_db_path, load_config
    from nexus_core.config.xdg import resolve_xdg_paths
    paths = paths or resolve_xdg_paths()
    config = config or load_config(paths)

    # ``omni auth login`` before the control store is opened on purpose: a key is
    # exactly what you configure when a run cannot start, and it must not depend
    # on a healthy database.
    if subcommand == "auth":
        from .auth_cli import run_auth_command

        return int(run_auth_command(list(args.command[1:])))

    # ``omni update`` likewise: the upgrade must work on a machine whose
    # database (or whose config) is exactly what is broken.
    if subcommand == "update":
        from .update import run_update_command

        extra = ["--check"] if getattr(args, "check", False) else []
        return int(run_update_command([*args.command[1:], *extra]))

    store = get_control_store(effective_db_path(config, paths))
    store.initialize()
    engagements = list(EngagementStore(store).list_for_tenant(args.tenant))

    # ``omni tool --list`` is a catalog read: it needs no engagement, so answer
    # it before the engagement selection (which would otherwise prompt).
    if subcommand == "tool" and args.list:
        from .tool import list_tools

        return int(list_tools(args.tenant))

    # ``omni hooks ...`` is an operator-governed write to the private trust file;
    # it needs no engagement and never executes a hook itself.
    if subcommand == "hooks":
        from .hooks_cli import run_hooks_command

        return int(run_hooks_command(list(args.command[1:]), args.tenant))

    # ``omni tools ...`` governs third-party tool plugins (SEC-05). It only
    # writes the private trust file; discovery is what enforces the decision.
    if subcommand == "tools":
        from .tools_cli import run_tools_command

        return int(run_tools_command(list(args.command[1:]), args.tenant))

    # ``omni resume ...`` decides what to do with invocations left ``unknown``.
    if subcommand == "resume":
        from .resume_cli import run_resume_command

        return int(run_resume_command(list(args.command[1:]), store, args.tenant))

    if args.list_engagements:
        _list_engagements(engagements)
        return 0

    if args.about:
        _render_about(engagements, args)
        return 0

    if args.new_engagement:
        if not args.scope:
            render.render_error(
                "--new-engagement requiere --scope (dominios/CIDRs separados por coma)"
            )
            return 2
        from .engage import create_engagement

        try:
            created = create_engagement(
                store, args.new_engagement, args.scope,
                tenant_id=args.tenant, hours=args.valid_hours,
            )
        except ValueError as exc:
            render.render_error(str(exc))
            return 2
        print(
            f"engagement creado: {created.engagement_id} · {created.name} · "
            f"cidrs={list(created.cidrs)} · dominios={list(created.domains)}"
        )
        return 0

    # When the interactive TUI will own the screen, keep the terminal's main
    # screen untouched before the alt-screen switch: no residual notice above
    # the banner.
    from .tui.session import should_use_tui

    tui_expected = not (args.no_tui or objective or subcommand) and should_use_tui()
    if args.continue_engagement and args.engagement and args.continue_engagement != args.engagement:
        render.render_error("--continue y --engagement deben identificar el mismo engagement")
        return 2
    requested = args.continue_engagement or args.engagement
    if not requested and not objective and not subcommand and not args.roe and not args.resume:
        from pathlib import Path

        from .workspace import bind_workspace
        engagement, exit_code = bind_workspace(store, args.tenant, Path.cwd()), 0
    else:
        engagement, exit_code = select_engagement(
            engagements, requested, announce=not tui_expected
        )
    if exit_code:
        return exit_code

    if args.roe:
        if engagement is None:
            render.render_error("--roe requiere un engagement activo")
            return 2
        from .roe_cli import run_roe_action

        code, lines = run_roe_action(args.roe, engagement.engagement_id)
        for line in lines:
            print(line)
        return int(code)

    # ``omni report`` / ``omni cve update``: subcommands that do not need a
    # model client. Both go through the durable gateway like everything else.
    if subcommand == "report":
        return _run_report_command(
            store, args, engagement,
            output_format=args.format or "both", output_dir=args.output,
        )
    if subcommand == "cve":
        return _run_cve_command(args, store, args.tenant, engagement)

    # ``omni tool``: invoke one governed tool without an LLM (manual operation).
    if subcommand == "tool":
        from .tool import run_tool_command

        rest = list(args.command[1:])
        if not rest:
            render.render_error("uso: omni tool <tool_id> '<json>' | omni tool --list")
            return 2
        return int(run_tool_command(
            store,
            args.tenant,
            engagement,
            rest[0],
            rest[1:],
            trust_mode=args.trust_mode,
        ))

    try:
        llm_client = build_llm_client()
    except Exception as exc:  # noqa: BLE001 - misconfigured providers must be reported
        errors.report_plain_error(exc, operation="construir el cliente LLM")
        return 2

    session = OmniSession(
        store=store,
        tenant_id=args.tenant,
        engagement=engagement,
        llm_client=llm_client,
        max_iterations=args.max_iterations,
        budget_tokens=args.budget_tokens,
        time_budget_seconds=time_budget_seconds(args),
        run_id=args.resume,
        trust_mode=args.trust_mode,
        # V1-54: the retry policy of an ``unknown`` invocation. It only reaches
        # the gateway while trust mode is on (``effective_resume_policy``).
        resume_policy=str(args.resume_policy or ""),
        no_color=args.no_color,
        use_tui=False if args.no_tui or objective else None,
        engagement_names=[scope.name for scope in engagements],
        fullscreen=args.fullscreen,
        show_art_banner=args.banner,
        subagent=args.subagent,
    )
    # Skills are opt-in per run: the operator names them, nothing is implicit.
    session.active_skills = list(args.skill or [])

    session.autospawn = bool(args.autospawn)
    session.supervisor_budget = int(args.supervisor_budget or 0)

    # ``--continue``/``--resume`` are the only entry points that load a plan
    # another run wrote, so they are the only ones that distrust it (Tanda C, 5b).
    if args.continue_engagement or args.resume:
        _revalidate_plan_on_resume(session)

    # A resume with an explicit unknown-invocation policy is resolved before the
    # run starts, so a crashed step is never silently replayed by headless.
    if args.resume and args.resume_policy and headless_mode:
        from .resume_cli import apply_resume_policy

        verdict = apply_resume_policy(store, args.tenant, args.resume, args.resume_policy)
        if verdict == "blocked":
            render.render_error(
                "resume bloqueado: hay invocaciones unknown sin aprobación durable"
            )
            return 2
        if verdict == "failed":
            render.render_error("resume marcado como fallido por política")
            return 1

    if objective and headless_mode:
        from .headless import run_headless

        return int(run_headless(
            session, objective, mode=headless_mode,
            max_iterations=args.max_iterations,
            budget_tokens=args.budget_tokens,
            time_budget_seconds=time_budget_seconds(args),
        ))
    if objective:
        result = session.run_objective(objective)
        if result is None:
            return 1
        return 0 if result.status in ACCEPTABLE_ONESHOT_STATUSES else 1
    session.run_repl()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through omni.py
    sys.exit(main())
