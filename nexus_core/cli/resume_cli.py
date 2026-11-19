"""``omni resume``: decide what to do with invocations left in ``unknown``.

After a crash between an effect and its recorded observation the journal refuses
to replay the step automatically. The operator is the only one who can decide,
and this module is the surface for that decision:

* ``omni resume <run_id>`` lists the ``unknown`` invocations (tool, target,
  argument hash) so the operator can see what is at stake;
* ``--retry <invocation_id>`` records a durable human approval bound to that
  invocation (the retry then re-enters full governance);
* ``--skip <invocation_id>`` marks it ``failed`` with an audit note asserting the
  operator saw no effect, so the run can continue without a replay.

Headless runs cannot prompt: ``--resume-policy`` picks ``approve`` (only consume
a *pre-existing* approval; otherwise block), ``skip`` or ``fail``.
"""

from __future__ import annotations

import argparse

from . import render


def _identity(tenant: str, subject: str):
    from nexus_core.kernel.models import Identity

    return Identity(subject_id=subject, tenant_id=tenant, kind="human", roles=("operator",))


def _print_unknown(items) -> None:
    if not items:
        render.write("(no hay invocaciones en estado 'unknown')")
        return
    for item in items:
        render.write(
            f"  {item['invocation_id']}  tool={item['tool_id']}  "
            f"target={item.get('target') or '-'}  args={item['arguments_hash'][:16]}…  "
            f"step={str(item.get('step_key') or '')[:16]}…"
        )


def run_resume_command(argv: list[str], store, tenant: str, *, reader=None) -> int:
    """Dispatch ``omni resume ...``; returns a process exit code."""
    parser = argparse.ArgumentParser(prog="omni resume", add_help=False)
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--retry", dest="retry", default=None)
    parser.add_argument("--skip", dest="skip", default=None)
    parser.add_argument("--operator", default="operator")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        render.render_error("uso: omni resume <run_id> [--retry ID | --skip ID]")
        return 2

    from nexus_core.kernel.invocation_journal import InvocationJournal

    journal = InvocationJournal(store)
    if args.retry or args.skip:
        target = args.retry or args.skip
        item = journal.get(target, tenant)
        if item is None:
            render.render_error(f"invocación desconocida: {target}")
            return 2
        if args.skip:
            try:
                journal.mark_failed(target, tenant, reason="operator skipped")
            except PermissionError as exc:
                render.render_error(str(exc))
                return 2
            render.render_status(f"invocación {target} marcada sin efecto (skip)")
            return 0
        context = _run_context(store, tenant, item)
        from nexus_core.kernel.approvals import ApprovalService

        approvals = ApprovalService(store)
        approval = approvals.request(context, f"retry:invocation:{target}")
        approvals.decide(
            approval["id"], tenant, args.operator, True, actor_roles=("approver",)
        )
        render.render_status(
            f"retry aprobado para {target} (approval {approval['id']}). "
            "Reanuda el run y el gateway consumirá esta aprobación."
        )
        return 0

    if not args.run_id:
        render.render_error("uso: omni resume <run_id> [--retry ID | --skip ID]")
        return 2
    items = journal.unknown_for_run(tenant, args.run_id)
    if not items:
        render.write(f"(el run {args.run_id} no tiene invocaciones unknown)")
        return 0
    render.write(f"Invocaciones unknown del run {args.run_id}:")
    _print_unknown(items)
    render.write("Decide con --retry <id> (aprobación humana) o --skip <id> (sin efecto).")
    return 0


def _run_context(store, tenant: str, item: dict):
    """Requester context for the retry approval.

    The retry is *requested* on behalf of the run (a workload), while the human
    operator decides it, so the governance rule that forbids self-approval is
    respected rather than bypassed.
    """
    from nexus_core.kernel.models import Identity, RunContext

    return RunContext(
        tenant_id=tenant,
        identity=Identity(subject_id="nexus-resume", tenant_id=tenant, kind="workload", roles=()),
        run_id=item["run_id"],
        store=store,
    )


def apply_resume_policy(store, tenant: str, run_id: str, policy: str) -> str:
    """Headless resume policy; returns ``continue``, ``blocked`` or ``failed``.

    ``approve`` never fabricates an approval: it only proceeds when a durable one
    already exists for every unknown invocation, otherwise it blocks (exit 2).
    ``skip`` records the operator's no-effect decision. ``fail`` reports the run
    as failed without touching the journal.
    """
    from nexus_core.kernel.invocation_journal import InvocationJournal

    if policy not in {"approve", "skip", "fail"}:
        raise ValueError(f"unknown resume policy: {policy}")
    journal = InvocationJournal(store)
    items = journal.unknown_for_run(tenant, run_id)
    if not items:
        return "continue"
    if policy == "fail":
        return "failed"
    if policy == "skip":
        for item in items:
            journal.mark_failed(item["invocation_id"], tenant, reason="headless skip")
        return "continue"
    # approve: require a durable, unconsumed approval for every unknown step.
    for item in items:
        action = f"retry:invocation:{item['invocation_id']}"
        with store.connect() as conn:
            row = conn.execute(
                "SELECT id FROM kernel_approvals WHERE tenant_id=? AND run_id=? AND action=? "
                "AND status='approved' AND consumed_at IS NULL LIMIT 1",
                (tenant, item["run_id"], action),
            ).fetchone()
        if not row:
            return "blocked"
    return "continue"
