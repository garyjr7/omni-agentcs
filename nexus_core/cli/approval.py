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
from nexus_core.kernel.audit import AuditWriter

from . import render

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

APPROVE_WORDS = frozenset({"y", "yes", "s", "si", "sí", "ok"})
DENY_WORDS = frozenset({"n", "no", "reject", "rechazar"})
MAX_PROMPT_ATTEMPTS = 5
EDITABLE_SEPARATOR = re.compile(r"[,\s]+")

#: Risk levels ``--trust-mode`` must never authorize on its own.
NEVER_TRUSTED_RISKS = frozenset({"destructive"})
TRUST_MODE_ACTION = "tool.trust_mode_approved"


def os_user() -> str:
    """Operating-system user at the keyboard (never the agent identity)."""
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - headless environments without a user db
        return "operator"


def default_operator_id() -> str:
    """Identity of the human at the keyboard (never the agent identity)."""
    return f"operator:{os_user()}"


def _risk_of(tenant_id: str, tool_id: str) -> str:
    """Declared risk of a tool, or ``""`` when it cannot be resolved."""
    definition = _tool_definition(tenant_id, tool_id)
    if definition is None:
        return ""
    return str(
        getattr(definition.risk, "value", getattr(definition, "risk", "")) or ""
    ).lower()


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
    render.write(render.paint(f"  {tool_id}", render.BOLD))
    render.write(f"    descripción: {getattr(definition, 'description', '') or '(sin descripción)'}")
    render.write(f"    riesgo:      {risk}")
    render.write(f"    permisos:    {list(getattr(definition, 'required_permissions', ()) or ())}")
    render.write(f"    scope:       obligatorio={bool(getattr(definition, 'scope_required', False))}"
          f" campo={getattr(definition, 'scope_target_field', None)}")
    render.write(
        "    input_schema: "
        + json.dumps(getattr(definition, "input_schema", {}) or {}, ensure_ascii=False, sort_keys=True)
    )


def edit_arguments(arguments: dict[str, Any], reader: Callable[[str], str]) -> dict[str, Any] | None:
    """Line-by-line argument editor (Enter keeps, ``-`` removes a key)."""
    edited = dict(arguments or {})
    render.write("  Edita los argumentos (Enter mantiene el valor, '-' elimina la clave):")
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


def _exact_action(
    tenant_id: str,
    tool_id: str,
    arguments: dict[str, Any],
    *,
    show_plan: bool = False,
) -> str:
    """Return the action the gateway will *consume* for this call.

    Most tools are approved as ``execute:tool:<id>``, but
    ``nexus.system.install_tool`` is approved per **exact plan**: the gateway
    rewrites the action to ``execute:tool:nexus.system.install_tool:<sha256>``
    (``kernel/tool_gateway.py``). Registering the bare id made the durable row
    unverifiable, so the very first install of a run was rejected as "approval
    is invalid or already used" -the measured death of the Hijack V1 run at
    iteration 38, where the approval had been created one line earlier.
    """
    if tool_id != "nexus.system.install_tool":
        return f"execute:tool:{tool_id}"
    from nexus_core.kernel.schema_validation import validate
    from nexus_core.provisioner.installer import approval_action, format_plan, plan_install

    definition = _tool_definition(tenant_id, tool_id)
    if definition is None:
        raise ValueError("tool not found")
    validate(arguments, getattr(definition, "input_schema", {}) or {})
    plan = plan_install(arguments["tool_name"], arguments.get("manager"))
    if show_plan:
        render.write("Comando exacto de instalación:\n" + format_plan(plan))
    return approval_action(plan, dry_run=arguments.get("dry_run", False))


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


def _audit_trust_mode(
    session: "OmniSession",
    tenant_id: str,
    run_id: str,
    tool_id: str,
    arguments: dict[str, Any],
    approval_id: str,
) -> None:
    """Record why an automatic authorization happened (reportable evidence)."""
    AuditWriter(session.store).append(
        tenant_id=tenant_id,
        trace_id=run_id,
        actor_id=session.operator_id,
        action=TRUST_MODE_ACTION,
        resource_type="tool",
        resource_id=tool_id,
        payload={
            "trust_mode": True,
            "trusted_by": os_user(),
            "operator_id": session.operator_id,
            "tool_id": tool_id,
            "run_id": run_id,
            "approval_id": approval_id,
            "argument_keys": sorted(arguments or {}),
        },
        decision="allow",
    )


def _trust_authorization(
    session: "OmniSession",
    service: ApprovalService,
    tenant_id: str,
    run_id: str,
    tool_id: str,
    arguments: dict[str, Any],
    action: str,
) -> ApprovalDecision:
    """Auto-authorize one high-risk call, still durably approved and audited."""
    render.render_trust_mode(tool_id, arguments, session.operator_id)
    approval_id = _register_approval(session, service, tenant_id, run_id, action)
    if approval_id is None:
        return ApprovalDecision(
            approved=False, reason="durable approval could not be registered (trust mode)"
        )
    _audit_trust_mode(session, tenant_id, run_id, tool_id, arguments, approval_id)
    render.render_status(
        f"trust mode: aprobado automáticamente por {session.operator_id} ({approval_id})"
    )
    return ApprovalDecision(approved=True, approval_id=approval_id, reason="trust_mode")


def make_approval_callback(
    session: "OmniSession",
    store: Any,
    tenant_id: str,
    run_id: str,
    *,
    trust_mode: bool = False,
) -> Callable[[str, dict[str, Any], Any], ApprovalDecision | None]:
    """Build the callback installed as ``ReActConfig.on_approval_needed``.

    With ``trust_mode`` the callback authorizes high-risk tools without asking,
    but it never auto-approves ``DESTRUCTIVE`` tools: those keep the interactive
    ``y/n/e/?`` prompt.
    """
    service = ApprovalService(store)

    def callback(tool_id: str, arguments: dict[str, Any], decision: Any) -> ApprovalDecision:
        action = f"execute:tool:{tool_id}"
        reader = session.input_reader
        if reader is None and session._tui.use_tui:
            reader = session._tui.prompt
        if trust_mode and _risk_of(tenant_id, tool_id) not in NEVER_TRUSTED_RISKS:
            # Same exact action as the interactive path: an install is approved
            # for its plan, and trust mode must not weaken that invariant.
            try:
                action = _exact_action(tenant_id, tool_id, arguments)
            except (ValueError, KeyError, AttributeError):
                return ApprovalDecision(approved=False, reason="no valid install plan")
            return _trust_authorization(
                session, service, tenant_id, run_id, tool_id, arguments, action
            )
        for _ in range(MAX_PROMPT_ATTEMPTS):
            if tool_id == "nexus.system.install_tool":
                try:
                    action = _exact_action(
                        tenant_id, tool_id, arguments, show_plan=True
                    )
                except (ValueError, KeyError, AttributeError):
                    return ApprovalDecision(approved=False, reason="no valid install plan")
            try:
                answer = render.render_approval_prompt(
                    tool_id, arguments, decision, reader=reader,
                    risk=_risk_of(tenant_id, tool_id),
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
