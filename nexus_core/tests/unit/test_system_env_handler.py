import asyncio
from unittest.mock import patch
import pytest

from nexus_core.provisioner.detector import ToolStatus
from nexus_core.tests.msf_support import context
from nexus_core.tools.handlers import system_env as module
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.usefixtures("onboarding_env")


def run(arguments=None):
    return asyncio.run(module.check_env_handler(arguments or {}, context()))


def test_check_env_returns_os_and_managers():
    result = run()
    assert result.verified and "os" in result.output and "managers" in result.output


def test_check_env_checks_specific_tools_only():
    status = ToolStatus("nmap", True, "/bin/nmap", "7", ("apt",))
    with patch.object(module, "check_tool", return_value=status) as check:
        result = run({"tools": ["nmap"]})
    check.assert_called_once_with("nmap")
    assert list(result.output["tools"]) == ["nmap"]


def test_check_env_includes_version_when_present(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    assert run({"tools": ["nmap"]}).output["tools"]["nmap"]["version"] == "Nmap version 1.2.3"


def test_check_env_handles_tool_absent():
    assert not run({"tools": ["nmap"]}).output["tools"]["nmap"]["present"]


def test_check_env_never_executes_shell(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    run({"tools": ["nmap"]})
    assert all(call.kwargs["shell"] is False for call in onboarding_env.run.call_args_list)


def test_check_env_registered_in_catalog():
    catalog = durable_tool_definitions()
    assert "nexus.system.check_env" in catalog
    assert {
        "nexus.exploit.msf_exploit",
        "nexus.session.list",
        "nexus.session.kill",
        "nexus.session.interact",
        "nexus.report.generate",
        "nexus.web.sqlmap",
        "nexus.web.dalfox",
        "nexus.recon.gobuster",
        "nexus.recon.whatweb",
        "nexus.exploit.searchsploit",
        "nexus.recon.netexec",
        "nexus.recon.bloodhound_python",
        "nexus.attack.impacket_secretsdump",
        "nexus.attack.impacket_getuserspns",
        "nexus.attack.impacket_psexec",
        "nexus.c2.sliver_server",
        "nexus.c2.sliver_implants",
        "nexus.c2.sliver_sessions",
        "nexus.c2.sliver_exec",
        "nexus.c2.sliver_pivot",
        "nexus.c2.sliver_generate",
        "nexus.c2.sliver_deploy",
        "nexus.c2.sliver_loot",
        "nexus.orchestrator.playbook",
        "nexus.recon.ftp",
        "nexus.recon.dns",
        "nexus.post.dns_update",
        "nexus.post.tftp",
        "nexus.post.dpapi",
        "nexus.post.ssh_upload",
        "nexus.recon.nikto",
        "nexus.cred.bruteforce",
        "nexus.post.crack_hash",
        "nexus.post.ssh_exec",
        "nexus.post.enum_system",
        "nexus.post.privesc_hints",
        "nexus.post.pivot_bruteforce",
        "nexus.post.pivot_http",
        "nexus.knowledge.record_fact",
        "nexus.knowledge.query_facts",
        "nexus.web.wp_enum",
        "nexus.web.wp_bruteforce",
        "nexus.web.wp_exec",
    } <= set(catalog)
    # 64 after RUN_sala12 (THM Intrusion Detection): nexus.post.ssh_upload (SFTP
    # drop of a PE-assist script onto a host with no outbound network) and
    # nexus.recon.nikto (web scan with the -Tuning/-evasion/-Pause knobs);
    # 62 after adding the governed DPAPI/KeePass loot (nexus.post.dpapi) in
    # the synthetic run; 61 was the governed TFTP payload delivery (nexus.post.tftp) in the
    # same room; 60 were the governed DNS query, dynamic DNS update, AD password
    # reset and AD escalation (RUN_sala10); 56 were the two Windows tools.
    # 72 after the Brute It v7 fixes; 73 with nexus.post.crack_hash (offline
    # john, the step that turns a held hash/key into a usable credential); 76
    # with the three PLAN MODE tools that write/read the engagement's TODOs;
    # 77 with nexus.recon.nfs (V9/Hijack: read NFS exports without root);
    # 78 with nexus.exploit.find_and_prepare (V10/HackPark: copy and read a PoC).
    # 79 with nexus.exploit.compile_and_upload (V11: ship the PoC).
    # 82 with nexus.post.verify_route (Tanda A) and nexus.post.http_server
    # (Tanda G: host the payload an SSRF has to fetch back).
    # 83 with nexus.attack.ad_user_enum (B1: confirm an account without a
    # password, before spending a lockout attempt on it).
    assert len(catalog) == 83
