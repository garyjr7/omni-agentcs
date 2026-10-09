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

High-risk tools are auto-authorized by ``--trust-mode`` (default on, exactly like
``omni --trust-mode``); destructive tools are never auto-approved and this
driver has no interactive stdin, so they are denied. Every result is printed as
JSON so it can be captured for review.
"""

from __future__ import annotations

import argparse
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
    args = parser.parse_args(argv)

    if args.list:
        return _list_tools(args.tenant)
    if not args.tool_id:
        parser.error("tool_id is required (or use --list)")

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
