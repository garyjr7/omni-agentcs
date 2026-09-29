"""Interactive human-approval callback for the ``omni`` REPL.

The callback is the human side of the durable approval flow: when the gateway
decides that a tool needs a person, this module shows the request, reads the
operator's answer and registers a *durable* approval row (``kernel_approvals``)
before the loop hands the ``approval_id`` to ``execute_tool``.
"""

from __future__ import annotations

import getpass
import json
import re
from typing import TYPE_CHECKING, Any, Callable

from nexus_core.agent.react import ApprovalDecision
from nexus_core.kernel.approvals import ApprovalService

from . import render

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

APPROVE_WORDS = frozenset({"y", "yes", "s", "si", "sí", "ok"})
DENY_WORDS = frozenset({"n", "no", "reject", "rechazar"})
MAX_PROMPT_ATTEMPTS = 5
EDITABLE_SEPARATOR = re.compile(r"[,\s]+")


def default_operator_id() -> str:
    """Identity of the human at the keyboard (never the agent identity)."""
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - headless environments without a user db
        user = "operator"
    return f"operator:{user}"


def _tool_definition(tenant_id: str, tool_id: str) -> Any:
    from nexus_core.tools.registry import durable_tool_definitions

    entry = durable_tool_definitions(tenant_id).get(tool_id)
    if entry is None:
        return None
    return entry[0] if isinstance(entry, tuple) else entry


def _show_definition(tenant_id: str, tool_id: str) -> None:
    """Print the tool definition behind a ``?`` request."""
    definition = _tool_definition(tenant_id, tool_id)
    if definition is None:
        render.render_error(f"tool desconocida: {tool_id}")
        return
    risk = getattr(definition.risk, "value", str(getattr(definition, "risk", "unknown")))
    print(render.paint(f"  {tool_id}", render.BOLD))
    print(f"    descripción: {getattr(definition, 'description', '') or '(sin descripción)'}")
    print(f"    riesgo:      {risk}")
    print(f"    permisos:    {list(getattr(definition, 'required_permissions', ()) or ())}")
    print(f"    scope:       obligatorio={bool(getattr(definition, 'scope_required', False))}"
          f" campo={getattr(definition, 'scope_target_field', None)}")
    print(
        "    input_schema: "
        + json.dumps(getattr(definition, "input_schema", {}) or {}, ensure_ascii=False, sort_keys=True)
    )


def edit_arguments(arguments: dict[str, Any], reader: Callable[[str], str]) -> dict[str, Any] | None:
    """Line-by-line argument editor (Enter keeps, ``-`` removes a key)."""
    edited = dict(arguments or {})
    print("  Edita los argumentos (Enter mantiene el valor, '-' elimina la clave):")
    for key in list(edited):
        current = edited[key]
        try:
            raw = reader(f"    {key} [{current}]: ")
        except (EOFError, KeyboardInterrupt):
            render.render_error("edición cancelada")
            return None
        text = str(raw or "").strip()
        if not text:
            continue
        if text == "-":
            edited.pop(key, None)
            continue
        if isinstance(current, list):
            edited[key] = [item for item in EDITABLE_SEPARATOR.split(text) if item]
        else:
            edited[key] = text
    return edited


def _register_approval(
    session: "OmniSession",
    service: ApprovalService,
    tenant_id: str,
    run_id: str,
    action: str,
) -> str | None:
    """Create and decide the durable approval row; ``None`` on any failure."""
    try:
        run_context = session.build_run_context(run_id)
        approval = service.request(run_context, action)
        service.decide(
            approval["id"],
            tenant_id,
            session.operator_id,
            True,
            f"approved from omni CLI by {session.operator_id}",
        )
    except Exception as exc:  # noqa: BLE001 - never authorize on a failed row
        render.render_error(
            f"no se pudo registrar la aprobación durable: {type(exc).__name__}: {exc}"
        )
        return None
    return str(approval["id"])


def make_approval_callback(
    session: "OmniSession",
    store: Any,
    tenant_id: str,
    run_id: str,
) -> Callable[[str, dict[str, Any], Any], ApprovalDecision | None]:
    """Build the callback installed as ``ReActConfig.on_approval_needed``."""
    service = ApprovalService(store)

    def callback(tool_id: str, arguments: dict[str, Any], decision: Any) -> ApprovalDecision:
        action = f"execute:tool:{tool_id}"
        reader = session.input_reader
        for _ in range(MAX_PROMPT_ATTEMPTS):
            if tool_id == "nexus.system.install_tool":
                from nexus_core.provisioner.installer import approval_action, format_plan, plan_install
                from nexus_core.kernel.schema_validation import validate
                try:
                    validate(arguments, _tool_definition(tenant_id, tool_id).input_schema)
                    plan = plan_install(arguments["tool_name"], arguments.get("manager"))
                    action = approval_action(plan, dry_run=arguments.get("dry_run", False))
                    print("Comando exacto de instalación:\n" + format_plan(plan))
                except (ValueError, KeyError):
                    return ApprovalDecision(approved=False, reason="no valid install plan")
            try:
                answer = render.render_approval_prompt(
                    tool_id, arguments, decision, reader=reader
                )
            except (EOFError, KeyboardInterrupt):
                render.render_status("aprobación interrumpida: se trata como rechazo")
                return ApprovalDecision(approved=False, reason="operator interrupted")
            choice = str(answer or "").strip().lower()

            if choice in APPROVE_WORDS:
                approval_id = _register_approval(session, service, tenant_id, run_id, action)
                if approval_id is None:
                    return ApprovalDecision(
                        approved=False, reason="durable approval could not be registered"
                    )
                render.render_status(f"aprobado por {session.operator_id} ({approval_id})")
                return ApprovalDecision(approved=True, approval_id=approval_id, edited_arguments=arguments if tool_id == "nexus.system.install_tool" else None)

            if choice in DENY_WORDS:
                render.render_status("rechazado por el operador")
                return ApprovalDecision(approved=False, reason="user denied")

            if choice == "e":
                edited = edit_arguments(arguments, reader or input)
                if edited is None:
                    continue
                if tool_id == "nexus.system.install_tool":
                    arguments = edited
                    continue
                approval_id = _register_approval(session, service, tenant_id, run_id, action)
                if approval_id is None:
                    return ApprovalDecision(
                        approved=False, reason="durable approval could not be registered"
                    )
                render.render_status(
                    f"aprobado con argumentos editados ({approval_id})"
                )
                return ApprovalDecision(
                    approved=True, approval_id=approval_id, edited_arguments=edited
                )

            if choice == "?":
                _show_definition(tenant_id, tool_id)
                continue

            render.render_error("opción no válida: usa y (aprobar), n (rechazar), e (editar) o ?")

        return ApprovalDecision(
            approved=False, reason=f"no valid answer after {MAX_PROMPT_ATTEMPTS} attempts"
        )

    return callback
