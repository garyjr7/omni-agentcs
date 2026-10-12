#!/usr/bin/env python3
"""Agent-free driver for OMNI's governed tools.

The human operator picks each step: this script invokes **one** ``nexus.*`` tool
per call through the exact same gate the ReAct loop uses —
``OmniSession.invoke_tool`` → ``execute_tool`` (policy, signed scope, approval,
audit). No LLM is contacted and no ReAct loop is started, so a full engagement
can be worked step by step while every call stays governed and audited.

Usage::

    .venv/bin/python scripts/omni_tool.py --list
    .venv/bin/python scripts/omni_tool.py --engagement eng-XXXX nexus.recon.nmap \
        '{"target": "10.0.0.1", "flags": "-sV"}'

``--batch FILE`` runs a sweep of jobs (one JSON object per line, with ``tool_id``
and ``arguments``) through that *same* governed entry point, in one process: the
runner bounds concurrency globally and per target instead of starting one CLI per
job (V0-9), and every job ends as ``completed``, ``failed`` or ``cancelled`` in
the report, so a determinate negative (V0-22) is recorded instead of thrown away.

High-risk tools are auto-authorized by ``--trust-mode`` (default on, exactly like
``omni --trust-mode``); destructive tools are never auto-approved and this
driver has no interactive stdin, so they are denied. Every result is printed as
JSON so it can be captured for review.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _deny_reader(_prompt: str = "") -> str:
    """No interactive operator: refuse anything trust-mode did not authorize."""
    return "n"


def _load_context(tenant: str, engagement_id: str | None, trust_mode: bool):
    from nexus_core.cli.engage import get_engagement
    from nexus_core.cli.session import OmniSession
    from nexus_core.config.loader import effective_db_path, load_config
    from nexus_core.config.xdg import resolve_xdg_paths
    from nexus_core.kernel.store_factory import get_control_store

    paths = resolve_xdg_paths()
    config = load_config(paths)
    # Verify the engagement HMAC the same way the CLI does: expose the configured
    # secret so ScopeValidator actually checks the signature instead of skipping.
    secret = str(getattr(config.scope, "signing_secret", "") or "")
    if secret:
        os.environ.setdefault("NEXUS_SCOPE_SIGNING_SECRET", secret)

    store = get_control_store(effective_db_path(config, paths))
    store.initialize()

    engagement = None
    if engagement_id:
        engagement = get_engagement(store, tenant, engagement_id)
        if engagement is None:
            raise SystemExit(f"error: engagement not found: {engagement_id}")

    session = OmniSession(
        store=store,
        tenant_id=tenant,
        engagement=engagement,
        llm_client=None,
        use_tui=False,
        trust_mode=trust_mode,
        input_reader=_deny_reader,
    )
    return session


def _job_invoke(session, tenant: str, batch_id: str):
    """Build the governed entry point for one batched job.

    Identical to the single-tool path: the pre-invocation approval handshake is
    the one the ReAct loop and the REPL use, and the call goes through
    ``execute_tool``. The difference is only who schedules it.
    """
    from nexus_core.agent.react import ReActConfig, _operator_approval_gate
    from nexus_core.cli.approval import make_approval_callback
    from nexus_core.kernel.runtime import ExecutionContext, execute_tool
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions(tenant)

    async def invoke(job):
        entry = catalog.get(job.tool_id)
        if entry is None:
            raise KeyError(f"unknown tool: {job.tool_id}")
        definition = entry[0] if isinstance(entry, tuple) else entry
        run_id = f"{batch_id}-{job.index}"
        payload = {
            "tool_id": job.tool_id,
            "arguments": dict(job.arguments),
            "identity": session.agent_identity_payload,
            "engagement_id": job.engagement_id or session.engagement_id,
            "permissions": list(session.permissions),
            "trace_id": run_id,
            "session_id": session._ensure_work_session() or session.conversation_id,
        }
        # A distinct run per job: two jobs that happen to share arguments are still
        # two invocations, and the journal must not read the second as a reuse.
        task = {"id": run_id, "tenant_id": tenant, "run_id": run_id,
                "task_type": "tool.invoke", "payload": payload}
        context = ExecutionContext(session.store, task, session.worker_id)
        config = ReActConfig(
            on_approval_needed=make_approval_callback(
                session, session.store, tenant, run_id, trust_mode=session.trust_mode
            )
        )
        denial = _operator_approval_gate(
            config=config, context=context, definition=definition, tool_payload=payload
        )
        if denial is not None:
            raise PermissionError(
                str(denial.get("reason") or denial.get("status") or "operator denied")
            )
        return await execute_tool(payload, context)

    return catalog, invoke


def _batch(session, tenant: str, args) -> int:
    from uuid import uuid4

    from nexus_core.kernel.batch import jobs_from_records, run_batch

    path = Path(args.batch)
    if not path.is_file():
        print(f"error: batch file not found: {path}", file=sys.stderr)
        return 2
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"error: {path}:{number} is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(record, dict):
            print(f"error: {path}:{number} must be a JSON object", file=sys.stderr)
            return 2
        records.append(record)
    try:
        jobs = jobs_from_records(records)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    batch_id = f"batch-{uuid4().hex[:8]}"
    catalog, invoke = _job_invoke(session, tenant, batch_id)
    # The target groups jobs that must not overlap: derive it from the tool's own
    # scope field instead of guessing from the argument names.
    prepared = []
    for job in jobs:
        entry = catalog.get(job.tool_id)
        field = getattr(entry[0], "scope_target_field", None) if entry else None
        target = str(job.arguments.get(field) or "") if field else job.target
        prepared.append(job if target == job.target else _replace_target(job, target))

    report = asyncio.run(
        run_batch(
            prepared,
            invoke,
            max_concurrency=args.max_concurrency,
            per_target_concurrency=args.per_target,
        )
    )
    if args.out:
        Path(args.out).write_text(
            "".join(json.dumps(item.to_dict(), ensure_ascii=False) + "\n"
                    for item in report.results),
            encoding="utf-8",
        )
    summary = report.to_dict()
    summary.pop("results")
    summary["batch_id"] = batch_id
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    for item in report.results:
        if item.status != "completed":
            print(f"{item.status}: job {item.index} {item.tool_id} "
                  f"{item.error_type or ''} {item.error}".rstrip(), file=sys.stderr)
    return 1 if report.failed else 0


def _replace_target(job, target: str):
    from dataclasses import replace

    return replace(job, target=target)


def _list_tools(tenant: str) -> int:
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions(tenant)
    for tool_id in sorted(catalog):
        entry = catalog[tool_id]
        definition = entry[0] if isinstance(entry, tuple) else entry
        description = (getattr(definition, "description", "") or "").strip().splitlines()
        summary = description[0] if description else ""
        print(f"{tool_id}\t{summary}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool_id", nargs="?", help="tool id, e.g. nexus.recon.nmap")
    parser.add_argument(
        "arguments",
        nargs="?",
        default="{}",
        help="JSON object with the tool arguments (default: {})",
    )
    parser.add_argument("--engagement", default=None, help="engagement id (signed scope)")
    parser.add_argument("--tenant", default="system", help="tenant (default: system)")
    parser.add_argument(
        "--trust-mode",
        dest="trust_mode",
        action="store_true",
        default=True,
        help="auto-authorize high-risk tools (default)",
    )
    parser.add_argument(
        "--no-trust-mode",
        dest="trust_mode",
        action="store_false",
        help="require interactive approval (this driver cannot prompt: denies)",
    )
    parser.add_argument("--list", action="store_true", help="list tools and exit")
    parser.add_argument(
        "--batch",
        default=None,
        help="NDJSON file of jobs ({tool_id, arguments, engagement?}), one per line",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="write the per-job results of --batch as NDJSON to this path",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=4,
        help="in-flight jobs allowed by --batch (default: 4)",
    )
    parser.add_argument(
        "--per-target",
        type=int,
        default=1,
        help="in-flight jobs allowed per target by --batch (default: 1)",
    )
    args = parser.parse_args(argv)

    if args.list:
        return _list_tools(args.tenant)
    if args.batch:
        if args.max_concurrency < 1 or args.per_target < 1:
            parser.error("--max-concurrency and --per-target must be >= 1")
        return _batch(_load_context(args.tenant, args.engagement, args.trust_mode),
                      args.tenant, args)
    if not args.tool_id:
        parser.error("tool_id is required (or use --list / --batch)")

    try:
        arguments = json.loads(args.arguments or "{}")
    except json.JSONDecodeError as exc:
        print(f"error: arguments is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(arguments, dict):
        print("error: arguments must be a JSON object", file=sys.stderr)
        return 2

    session = _load_context(args.tenant, args.engagement, args.trust_mode)
    result = session.invoke_tool(args.tool_id, arguments)
    if result is None:
        print(json.dumps({"tool_id": args.tool_id, "status": "denied_or_failed"}, indent=2))
        return 1
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
