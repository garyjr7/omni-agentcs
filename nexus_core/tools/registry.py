"""Registro central de herramientas durables del kernel NEXUS.

``tool_catalog`` expone el catálogo tal como lo ve el runtime (V1-8), para que
el inventario, el CLI y los artefactos de auditoría describan la misma versión.
"""

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

    Los builtins de abajo son la base; encima se fusionan las herramientas
    auto-registradas con ``@register_tool`` / entry-points ``nexus.tools``
    (H7), de modo que un plugin puede añadir una tool **sin tocar este módulo**.
    Un builtin gana salvo que el registro pida ``replace=True``.
    """
    from .handlers.ffuf import ffuf_definition, ffuf_handler
    from .handlers.httpx import httpx_definition, httpx_handler
    from .handlers.ftp import ftp_definition, ftp_handler
    from .handlers.nfs import nfs_definition, nfs_handler
    from .handlers.cred_bruteforce import (
        cred_bruteforce_definition,
        cred_bruteforce_handler,
    )
    from .handlers.crack_hash import crack_hash_definition, crack_hash_handler
    from .handlers.ssh_post import (
        enum_system_definition,
        enum_system_handler,
        ssh_exec_definition,
        ssh_exec_handler,
        ssh_upload_definition,
        ssh_upload_handler,
    )
    from .handlers.pivot import (
        pivot_bruteforce_definition,
        pivot_bruteforce_handler,
        pivot_http_definition,
        pivot_http_handler,
    )
    from .handlers.privesc_hints import (
        privesc_hints_definition,
        privesc_hints_handler,
    )
    from .handlers.knowledge_facts import (
        query_facts_definition,
        query_facts_handler,
        record_fact_definition,
        record_fact_handler,
    )
    from .handlers.nmap import nmap_definition, nmap_handler
    from .handlers.dns import dns_query_definition, dns_query_handler
    from .handlers.dns_update import dns_update_definition, dns_update_handler
    from .handlers.tftp import tftp_definition, tftp_handler
    from .handlers.dpapi import dpapi_definition, dpapi_handler
    from .handlers.impacket_changepasswd import (
        impacket_changepasswd_definition,
        impacket_changepasswd_handler,
    )
    from .handlers.nopac import nopac_definition, nopac_handler
    from .handlers.sqlmap import sqlmap_definition, sqlmap_handler
    from .handlers.gobuster import gobuster_definition, gobuster_handler
    from .handlers.nikto import nikto_definition, nikto_handler
    from .handlers.whatweb import whatweb_definition, whatweb_handler
    from .handlers.http_request import http_request_definition, http_request_handler
    from .handlers.listener import listener_definition, listener_handler
    from .handlers.ntlm_capture import ntlm_capture_definition, ntlm_capture_handler
    from .handlers.winrm import winrm_exec_definition, winrm_exec_handler
    from .handlers.searchsploit import searchsploit_definition, searchsploit_handler
    from .handlers.exploit_prep import exploit_prep_definition, exploit_prep_handler
    from .handlers.exploit_upload import (
        exploit_upload_definition,
        exploit_upload_handler,
    )
    from .handlers.dalfox import dalfox_definition, dalfox_handler
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
    from .handlers.workspace import (
        workspace_read_definition,
        workspace_read_handler,
        workspace_search_definition,
        workspace_search_handler,
    )
    from .handlers.netexec import netexec_definition, netexec_handler
    from .handlers.smb import (
        smb_definition,
        smb_handler,
        smb_upload_definition,
        smb_upload_handler,
    )
    from .handlers.bloodhound import bloodhound_definition, bloodhound_handler
    from .handlers.impacket_secretsdump import (
        impacket_secretsdump_definition,
        impacket_secretsdump_handler,
    )
    from .handlers.impacket_getuserspns import (
        getuserspns_definition,
        impacket_getuserspns_handler,
    )
    from .handlers.impacket_psexec import psexec_definition, impacket_psexec_handler
    from .handlers.sliver_server import (
        sliver_server_definition,
        sliver_server_handler,
    )
    from .handlers.sliver_implants import (
        sliver_implants_definition,
        sliver_implants_handler,
    )
    from .handlers.sliver_sessions import (
        sliver_sessions_definition,
        sliver_sessions_handler,
    )
    from .handlers.sliver_exec import sliver_exec_definition, sliver_exec_handler
    from .handlers.sliver_pivot import sliver_pivot_definition, sliver_pivot_handler
    from .handlers.sliver_generate import (
        sliver_generate_definition,
        sliver_generate_handler,
    )
    from .handlers.sliver_deploy import (
        sliver_deploy_definition,
        sliver_deploy_handler,
    )
    from .handlers.sliver_loot import sliver_loot_definition, sliver_loot_handler
    from .handlers.playbook import playbook_definition, playbook_handler
    from .handlers.plan_engagement import (
        create_plan_definition,
        create_plan_handler,
        get_plan_status_definition,
        get_plan_status_handler,
        update_plan_definition,
        update_plan_handler,
    )
    from .handlers.pwn import (
        pwn_analyze_definition,
        pwn_analyze_handler,
        ret2libc_definition,
        ret2libc_handler,
    )
    from .handlers.wp import (
        wp_bruteforce_definition,
        wp_bruteforce_handler,
        wp_enum_definition,
        wp_enum_handler,
        wp_exec_definition,
        wp_exec_handler,
    )

    catalog = {
        "nexus.system.check_env": (check_env_definition(tenant_id), check_env_handler),
        "nexus.system.install_tool": (install_tool_definition(tenant_id), install_tool_handler),
        "nexus.system.status": (system_status_definition(tenant_id), system_status_handler),
        "nexus.workspace.search": (
            workspace_search_definition(tenant_id),
            workspace_search_handler,
        ),
        "nexus.workspace.read": (
            workspace_read_definition(tenant_id),
            workspace_read_handler,
        ),
        "nexus.orchestrator.create_plan": (
            create_plan_definition(tenant_id),
            create_plan_handler,
        ),
        "nexus.orchestrator.update_plan": (
            update_plan_definition(tenant_id),
            update_plan_handler,
        ),
        "nexus.orchestrator.get_plan_status": (
            get_plan_status_definition(tenant_id),
            get_plan_status_handler,
        ),
        "nexus.recon.nmap": (nmap_definition(tenant_id), nmap_handler),
        "nexus.recon.dns": (dns_query_definition(tenant_id), dns_query_handler),
        "nexus.post.dns_update": (dns_update_definition(tenant_id), dns_update_handler),
        "nexus.post.tftp": (tftp_definition(tenant_id), tftp_handler),
        "nexus.post.dpapi": (dpapi_definition(tenant_id), dpapi_handler),
        "nexus.attack.impacket_changepasswd": (
            impacket_changepasswd_definition(tenant_id),
            impacket_changepasswd_handler,
        ),
        "nexus.attack.nopac": (nopac_definition(tenant_id), nopac_handler),
        "nexus.recon.subfinder": (subfinder_definition(tenant_id), subfinder_handler),
        "nexus.recon.httpx": (httpx_definition(tenant_id), httpx_handler),
        "nexus.recon.ftp": (ftp_definition(tenant_id), ftp_handler),
        # V9 (Hijack): NFS was visible and unreachable because ``mount`` needs
        # root. ``showmount`` and libnfs read it unprivileged.
        "nexus.recon.nfs": (nfs_definition(tenant_id), nfs_handler),
        "nexus.cred.bruteforce": (
            cred_bruteforce_definition(tenant_id),
            cred_bruteforce_handler,
        ),
        "nexus.post.crack_hash": (crack_hash_definition(tenant_id), crack_hash_handler),
        "nexus.post.ssh_exec": (ssh_exec_definition(tenant_id), ssh_exec_handler),
        "nexus.post.ssh_upload": (
            ssh_upload_definition(tenant_id),
            ssh_upload_handler,
        ),
        "nexus.post.enum_system": (enum_system_definition(tenant_id), enum_system_handler),
        "nexus.post.pivot_bruteforce": (
            pivot_bruteforce_definition(tenant_id),
            pivot_bruteforce_handler,
        ),
        "nexus.post.pivot_http": (pivot_http_definition(tenant_id), pivot_http_handler),
        "nexus.post.privesc_hints": (
            privesc_hints_definition(tenant_id),
            privesc_hints_handler,
        ),
        "nexus.knowledge.record_fact": (
            record_fact_definition(tenant_id),
            record_fact_handler,
        ),
        "nexus.knowledge.query_facts": (
            query_facts_definition(tenant_id),
            query_facts_handler,
        ),
        "nexus.web.nuclei": (nuclei_definition(tenant_id), nuclei_handler),
        "nexus.web.ffuf": (ffuf_definition(tenant_id), ffuf_handler),
        "nexus.web.sqlmap": (sqlmap_definition(tenant_id), sqlmap_handler),
        "nexus.web.dalfox": (dalfox_definition(tenant_id), dalfox_handler),
        "nexus.recon.gobuster": (gobuster_definition(tenant_id), gobuster_handler),
        "nexus.recon.nikto": (nikto_definition(tenant_id), nikto_handler),
        "nexus.recon.whatweb": (whatweb_definition(tenant_id), whatweb_handler),
        "nexus.web.request": (http_request_definition(tenant_id), http_request_handler),
        "nexus.post.listener": (listener_definition(tenant_id), listener_handler),
        "nexus.post.ntlm_capture": (
            ntlm_capture_definition(tenant_id),
            ntlm_capture_handler,
        ),
        "nexus.win.winrm_exec": (winrm_exec_definition(tenant_id), winrm_exec_handler),
        "nexus.exploit.searchsploit": (
            searchsploit_definition(tenant_id),
            searchsploit_handler,
        ),
        "nexus.exploit.find_and_prepare": (
            exploit_prep_definition(tenant_id),
            exploit_prep_handler,
        ),
        # V11: the PoC has to reach the target. It recognises an ASP.NET theme
        # control (BlogEngine's .ascx), injects the callback and uploads it with
        # csrf_mode, returning the durable session when it executes commands.
        "nexus.exploit.compile_and_upload": (
            exploit_upload_definition(tenant_id),
            exploit_upload_handler,
        ),
        "nexus.recon.netexec": (netexec_definition(tenant_id), netexec_handler),
        "nexus.recon.smb": (smb_definition(tenant_id), smb_handler),
        "nexus.post.smb_upload": (
            smb_upload_definition(tenant_id),
            smb_upload_handler,
        ),
        "nexus.recon.bloodhound_python": (
            bloodhound_definition(tenant_id),
            bloodhound_handler,
        ),
        "nexus.attack.impacket_secretsdump": (
            impacket_secretsdump_definition(tenant_id),
            impacket_secretsdump_handler,
        ),
        "nexus.attack.impacket_getuserspns": (
            getuserspns_definition(tenant_id),
            impacket_getuserspns_handler,
        ),
        "nexus.attack.impacket_psexec": (
            psexec_definition(tenant_id),
            impacket_psexec_handler,
        ),
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
        "nexus.c2.sliver_server": (
            sliver_server_definition(tenant_id),
            sliver_server_handler,
        ),
        "nexus.c2.sliver_implants": (
            sliver_implants_definition(tenant_id),
            sliver_implants_handler,
        ),
        "nexus.c2.sliver_sessions": (
            sliver_sessions_definition(tenant_id),
            sliver_sessions_handler,
        ),
        "nexus.c2.sliver_exec": (sliver_exec_definition(tenant_id), sliver_exec_handler),
        "nexus.c2.sliver_pivot": (sliver_pivot_definition(tenant_id), sliver_pivot_handler),
        "nexus.c2.sliver_generate": (
            sliver_generate_definition(tenant_id),
            sliver_generate_handler,
        ),
        "nexus.c2.sliver_deploy": (
            sliver_deploy_definition(tenant_id),
            sliver_deploy_handler,
        ),
        "nexus.c2.sliver_loot": (sliver_loot_definition(tenant_id), sliver_loot_handler),
        "nexus.orchestrator.playbook": (
            playbook_definition(tenant_id),
            playbook_handler,
        ),
        "nexus.pwn.analyze": (pwn_analyze_definition(tenant_id), pwn_analyze_handler),
        "nexus.pwn.ret2libc": (ret2libc_definition(tenant_id), ret2libc_handler),
        "nexus.web.wp_enum": (wp_enum_definition(tenant_id), wp_enum_handler),
        "nexus.web.wp_bruteforce": (
            wp_bruteforce_definition(tenant_id),
            wp_bruteforce_handler,
        ),
        "nexus.web.wp_exec": (wp_exec_definition(tenant_id), wp_exec_handler),
    }
    from .handlers.web_upload import web_upload_definition, web_upload_handler
    from .handlers.shell_exec import shell_exec_definition, shell_exec_handler
    from .handlers.shell_exec_local import (
        shell_exec_definition as shell_exec_local_definition,
        shell_exec_handler as shell_exec_local_handler,
    )
    from .handlers.session_pty import (
        session_pty_definition,
        session_pty_handler,
    )
    from .handlers.jobs import jobs_definition, jobs_handler
    from .handlers.git_dump import git_dump_definition, git_dump_handler
    from .handlers.skill import (
        skill_list_definition,
        skill_list_handler,
        skill_load_definition,
        skill_load_handler,
    )
    catalog.update({
        "nexus.web.upload": (web_upload_definition(tenant_id), web_upload_handler),
        "nexus.post.shell_exec": (shell_exec_definition(tenant_id), shell_exec_handler),
        # WP1: the universal execution substrate. ``nexus.post.shell_exec``
        # stays as the owned-session adapter; these two run *local* processes
        # through the sandbox and keep them alive across turns.
        "nexus.shell.exec": (shell_exec_local_definition(tenant_id), shell_exec_local_handler),
        "nexus.session.pty": (session_pty_definition(tenant_id), session_pty_handler),
        "nexus.post.job": (jobs_definition(tenant_id), jobs_handler),
        "nexus.web.git_dump": (git_dump_definition(tenant_id), git_dump_handler),
        # WP4: the loop's dynamic skill loader. Read-only and scope-free: the
        # agent lists the catalogue and loads the recipe it needs when stuck.
        "nexus.skill.list": (skill_list_definition(tenant_id), skill_list_handler),
        "nexus.skill.load": (skill_load_definition(tenant_id), skill_load_handler),
    })
    from .execution_contract import with_execution_contract

    catalog = {key: (definition, with_execution_contract(definition, handler))
               for key, (definition, handler) in catalog.items()}
    # Additive overlay: decorator/entry-point registrations never shadow a
    # builtin unless they explicitly opt in. Discovery is cached and non-fatal.
    from .registration import discovered_registrations

    for tool_id, registration in discovered_registrations().items():
        if tool_id in catalog and not registration.replace:
            continue
        catalog[tool_id] = (
            registration.resolve_definition(tenant_id),
            registration.handler,
        )
    return catalog


def register_durable_tools(gateway: ToolGateway, tenant_id: str = "system") -> None:
    """Registra todas las tools durables en un gateway dado."""
    for definition, handler in durable_tool_definitions(tenant_id).values():
        gateway.register(definition, handler)


#: Manifest schema version. Bumped when the shape below changes so a consumer
#: can reject a catalog it does not understand.
CATALOG_SCHEMA_VERSION = "1.0.0"


def tool_catalog(tenant_id: str = "system") -> dict[str, Any]:
    """Return the *runtime* catalog as machine-readable JSON.

    This is the single source the audit ledger must agree with (V1-8): it is
    built from the same ``durable_tool_definitions`` the gateway registers, so a
    regex or a stale document can no longer report a different count.
    """
    from nexus_core.tools.parsers import PARSERS_VERSION

    entries = []
    for tool_id, (definition, _handler) in sorted(durable_tool_definitions(tenant_id).items()):
        entries.append(
            {
                "tool_id": tool_id,
                "version": definition.version,
                "risk": definition.risk.value,
                "effect": definition.effect,
                "enabled": definition.enabled,
                "scope_required": definition.scope_required,
                "scope_target_field": definition.scope_target_field,
                "sandbox_required": definition.sandbox_required,
                "idempotent": definition.idempotent,
                "required_permissions": list(definition.required_permissions),
            }
        )
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "parsers_version": PARSERS_VERSION,
        "tool_count": len(entries),
        "tools": entries,
    }
