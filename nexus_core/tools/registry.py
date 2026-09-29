"""Registro central de herramientas durables del kernel NEXUS."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from nexus_core.kernel.models import RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.tool_gateway import ToolGateway

Handler = Callable[[dict[str, Any], RunContext], Awaitable[ToolResult]]


def durable_tool_definitions(
    tenant_id: str = "system",
) -> dict[str, tuple[ToolDefinition, Handler]]:
    """
    Devuelve el catálogo completo {tool_id: (definition, handler)}.

    Importa handlers perezosamente para no acoplar el kernel al paquete
    tools en tiempo de import. ``tenant_id`` fija el tenant dueño de las
    definiciones (el runtime pasa el tenant de la task).
    """
    from .handlers.nmap import nmap_definition, nmap_handler
    from .handlers.system import system_status_definition, system_status_handler
    from .handlers.workspace import workspace_search_definition, workspace_search_handler

    catalog = {
        "nexus.system.status": (system_status_definition(tenant_id), system_status_handler),
        "nexus.workspace.search": (
            workspace_search_definition(tenant_id),
            workspace_search_handler,
        ),
        "nexus.recon.nmap": (nmap_definition(tenant_id), nmap_handler),
    }
    return catalog


def register_durable_tools(gateway: ToolGateway, tenant_id: str = "system") -> None:
    """Registra todas las tools durables en un gateway dado."""
    for definition, handler in durable_tool_definitions(tenant_id).values():
        gateway.register(definition, handler)
