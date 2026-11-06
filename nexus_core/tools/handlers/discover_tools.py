"""``nexus.system.discover_tools``: reveal hidden tools for this run.

Tool hiding would be another dead end without a way out. The default profile
shows five tools; when the model needs something else it asks for a **group**
(``recon``, ``web``, ``post``, ``exploit``, ``c2``, ``attack``, ``session``,
``report``, ``knowledge`` …) or for a keyword, and this tool activates the
matching tools for the run. From the next turn they travel in the prompt and
the model may invoke them.

It is read-only and never touches a target: it only decides what the model is
shown. The gateway still governs every activated call (scope, RoE, risk,
approval).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.profiles import (
    activate_tools,
    catalog_groups,
    search_tools,
)

#: Literal (not an alias): the catalog-consistency AST check resolves a
#: ``tool_id=`` name only when it is a module-level string constant.
TOOL_ID = "nexus.system.discover_tools"


class DiscoverToolsRequest(BaseModel):
    """Either a group, a keyword, or neither (list the groups)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    group: str | None = Field(default=None, max_length=40)
    query: str | None = Field(default=None, max_length=120)


def discover_tools_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable definition of ``nexus.system.discover_tools``."""
    return ToolDefinition(
        tool_id=TOOL_ID,
        tenant_id=tenant_id,
        name="Discover tools",
        description=(
            "Revela tools ocultas para este run: pasa el grupo (recon, web, post, "
            "exploit, c2, attack, session, report, knowledge…) o un término "
            "(nmap, smb, privesc). Sin argumentos lista los grupos disponibles."
        ),
        input_schema=DiscoverToolsRequest.model_json_schema(),
        risk=RiskLevel.READ_ONLY,
        effect="read_only",
        scope_required=False,
        timeout_seconds=30,
        max_output_bytes=100_000,
        required_permissions=[f"execute:tool:{TOOL_ID}"],
    )


def _resolve_group(groups: dict[str, list[str]], requested: str) -> str | None:
    """Exact group, unique prefix, or a near-miss of the group name.

    A model that writes ``reconn`` (or ``reconx``) meant ``recon``: failing on a
    one-letter typo costs a whole turn and teaches nothing about the catalogue.
    """
    from difflib import get_close_matches

    wanted = str(requested or "").strip().lower()
    if not wanted:
        return None
    if wanted in groups:
        return wanted
    matches = [name for name in groups if name.startswith(wanted)]
    if len(matches) == 1:
        return matches[0]
    close = get_close_matches(wanted, list(groups), n=1, cutoff=0.75)
    return close[0] if close else None


def _groups_in_query(groups: dict[str, list[str]], query: str) -> list[str]:
    """Groups whose name appears as a word of *query* (``recon nmap full``)."""
    words = {
        word for word in str(query or "").lower().replace("-", " ").split() if word
    }
    return sorted(name for name in groups if name in words)


async def discover_tools_handler(
    arguments: dict[str, Any], context: RunContext
) -> ToolResult:
    """Activate the requested tools for this run and answer what is now visible."""
    from nexus_core.tools.registry import durable_tool_definitions

    request = DiscoverToolsRequest.model_validate(arguments)
    catalog = durable_tool_definitions(context.tenant_id)
    groups = catalog_groups(catalog)

    selected: list[str] = []
    resolved_group = _resolve_group(groups, request.group or "")
    if request.group and resolved_group is None:
        return ToolResult(
            output={
                "error": f"unknown tool group '{request.group}'",
                "groups": sorted(groups),
                "guidance": (
                    "Usa un grupo de la lista (o `query` con un término del tool id) "
                    "y vuelve a llamar."
                ),
            },
            verified=False,
            outcome="error",
            verification_method="discover_tools_unknown_group",
            evidence={"requested_group": request.group},
        )
    if resolved_group:
        selected = list(groups[resolved_group])
    matched_groups: list[str] = []
    if request.query:
        selected = sorted(set(selected) | set(search_tools(catalog, request.query)))
        if not selected:
            # The query named a group instead of a tool (``recon``, ``web``):
            # reveal that group's tools rather than failing on a near-synonym.
            matched_groups = _groups_in_query(groups, request.query)
            selected = sorted(
                {tool for name in matched_groups for tool in groups[name]}
            )
        if not selected:
            return ToolResult(
                output={
                    "error": f"no tool matches '{request.query}'",
                    "groups": sorted(groups),
                    "suggested_groups": [
                        name
                        for name in sorted(groups)
                        if name[:3] in request.query.lower()
                    ][:5],
                    "guidance": (
                        "Usa un grupo de `groups` (recon, web, post, exploit, c2, "
                        "attack, session, report, knowledge…) o un término del id "
                        "de la tool (nmap, smb, privesc)."
                    ),
                },
                verified=False,
                outcome="error",
                verification_method="discover_tools_no_match",
                evidence={"query": request.query},
            )

    newly = activate_tools(context.run_id, selected)
    if not request.group and not request.query:
        summary = (
            "grupos disponibles: "
            + ", ".join(
                f"{name} ({len(tools)})" for name, tools in sorted(groups.items())
            )
        )
        return ToolResult(
            output={
                "groups": {name: tools for name, tools in sorted(groups.items())},
                "activated": [],
                "summary": summary,
            },
            verified=True,
            verification_method="discover_tools_groups",
            evidence={"group_count": len(groups)},
            stdout=summary,
        )

    summary = (
        f"{len(selected)} tool(s) disponible(s) desde el próximo turno"
        + (f": {', '.join(selected[:10])}" if selected else "")
    )
    return ToolResult(
        output={
            "group": resolved_group or ", ".join(matched_groups),
            "query": request.query or "",
            "activated": newly,
            "tools": selected,
            "summary": summary,
        },
        verified=bool(selected),
        verification_method="discover_tools_activated",
        evidence={
            "group": resolved_group or ", ".join(matched_groups),
            "activated_total": len(newly),
            "tools_total": len(selected),
        },
        stdout=summary,
    )


__all__ = [
    "DiscoverToolsRequest",
    "TOOL_ID",
    "discover_tools_definition",
    "discover_tools_handler",
]
