"""``omni tool``: invoke one durable tool through the governed gateway.

The agent-free counterpart of the ReAct loop: the operator names one ``nexus.*``
tool plus its JSON arguments and it runs through exactly the same gate the agent
uses — ``OmniSession.invoke_tool`` → ``execute_tool`` (policy, signed scope,
approval, audit). No LLM is contacted, so a full engagement can be driven step by
step without spending a token; every call stays governed and audited.

Usage::

    omni tool --list
    omni --engagement eng-XXXX tool nexus.recon.nmap '{"target": "10.0.0.1", "profile": "service"}'

Options follow the usual argparse rule: put the flags *before* the positional
``<tool_id> '<json>'`` group or *after* it, never between the two.

High-risk tools are auto-authorized by ``--trust-mode`` exactly like
``omni --trust-mode``; destructive tools are never auto-approved and this
subcommand has no interactive stdin, so they are denied fail-closed.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from . import render


def _deny_reader(_prompt: str = "") -> str:
    """No interactive operator: refuse anything trust-mode did not authorize."""
    return "n"


def list_tools(tenant: str) -> int:
    """Print ``tool_id<TAB>summary`` for every durable tool, then return 0."""
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions(tenant)
    for tool_id in sorted(catalog):
        entry = catalog[tool_id]
        definition = entry[0] if isinstance(entry, tuple) else entry
        description = (getattr(definition, "description", "") or "").strip().splitlines()
        summary = description[0] if description else ""
        print(f"{tool_id}\t{summary}")
    return 0


def parse_arguments(raw: Sequence[str]) -> dict[str, Any]:
    """Join and decode the JSON object passed after the tool id.

    Raises ``ValueError`` when the text is not valid JSON or is not an object.
    """
    text = " ".join(str(item) for item in raw).strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"arguments is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("arguments must be a JSON object")
    return value


def run_tool_command(
    store: Any,
    tenant: str,
    engagement: Any,
    tool_id: str,
    raw_arguments: Sequence[str],
    *,
    trust_mode: bool = False,
) -> int:
    """Invoke one tool through the governed gate; return the process exit code.

    Exit codes: ``0`` when the tool verified its post-condition, ``1`` when it
    was denied/failed or did not verify, ``2`` on a usage error (bad JSON).
    """
    from .session import OmniSession

    try:
        arguments = parse_arguments(raw_arguments)
    except ValueError as exc:
        render.render_error(str(exc))
        return 2

    session = OmniSession(
        store=store,
        tenant_id=tenant,
        engagement=engagement,
        llm_client=None,
        use_tui=False,
        trust_mode=trust_mode,
        input_reader=_deny_reader,
    )
    result = session.invoke_tool(tool_id, arguments)
    if result is None:
        # ``invoke_tool`` already rendered the reason (unknown tool, denied by
        # the operator, scope violation, or a handler error).
        return 1
    output = result.get("output") if isinstance(result, dict) else None
    print(
        json.dumps(
            output if isinstance(output, dict) else result,
            indent=2,
            default=str,
            ensure_ascii=False,
        )
    )
    if not isinstance(output, dict):
        return 1
    return 0 if output.get("verified") else 1


__all__ = ["list_tools", "parse_arguments", "run_tool_command"]
