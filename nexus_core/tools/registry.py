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
    from .handlers.ffuf import ffuf_definition, ffuf_handler
    from .handlers.httpx import httpx_definition, httpx_handler
    from .handlers.nmap import nmap_definition, nmap_handler
    from .handlers.msf_search import msf_search_definition, msf_search_handler
    from .handlers.msf_auxiliary import msf_auxiliary_definition, msf_auxiliary_handler
    from .handlers.msf_exploit import msf_exploit_definition, msf_exploit_handler
    from .handlers.msf_session_list import (
        msf_session_list_definition,
        msf_session_list_handler,
    )
    from .handlers.msf_session_kill import (
        msf_session_kill_definition,
        msf_session_kill_handler,
    )
    from .handlers.msf_session_interact import (
        msf_session_interact_definition,
        msf_session_interact_handler,
    )
    from .handlers.report_generate import (
        report_generate_definition,
        report_generate_handler,
    )
    from .handlers.nuclei import nuclei_definition, nuclei_handler
    from .handlers.subfinder import subfinder_definition, subfinder_handler
    from .handlers.system import system_status_definition, system_status_handler
    from .handlers.system_env import check_env_definition, check_env_handler
    from .handlers.system_install import install_tool_definition, install_tool_handler
    from .handlers.workspace import workspace_search_definition, workspace_search_handler

    catalog = {
        "nexus.system.check_env": (check_env_definition(tenant_id), check_env_handler),
        "nexus.system.install_tool": (install_tool_definition(tenant_id), install_tool_handler),
        "nexus.system.status": (system_status_definition(tenant_id), system_status_handler),
        "nexus.workspace.search": (
            workspace_search_definition(tenant_id),
            workspace_search_handler,
        ),
        "nexus.recon.nmap": (nmap_definition(tenant_id), nmap_handler),
        "nexus.recon.subfinder": (subfinder_definition(tenant_id), subfinder_handler),
        "nexus.recon.httpx": (httpx_definition(tenant_id), httpx_handler),
        "nexus.web.nuclei": (nuclei_definition(tenant_id), nuclei_handler),
        "nexus.web.ffuf": (ffuf_definition(tenant_id), ffuf_handler),
        "nexus.exploit.msf_search": (msf_search_definition(tenant_id), msf_search_handler),
        "nexus.exploit.msf_auxiliary": (msf_auxiliary_definition(tenant_id), msf_auxiliary_handler),
        "nexus.exploit.msf_exploit": (msf_exploit_definition(tenant_id), msf_exploit_handler),
        "nexus.session.list": (msf_session_list_definition(tenant_id), msf_session_list_handler),
        "nexus.session.kill": (msf_session_kill_definition(tenant_id), msf_session_kill_handler),
        "nexus.session.interact": (
            msf_session_interact_definition(tenant_id),
            msf_session_interact_handler,
        ),
        "nexus.report.generate": (
            report_generate_definition(tenant_id),
            report_generate_handler,
        ),
    }
    return catalog


def register_durable_tools(gateway: ToolGateway, tenant_id: str = "system") -> None:
    """Registra todas las tools durables en un gateway dado."""
    for definition, handler in durable_tool_definitions(tenant_id).values():
        gateway.register(definition, handler)
