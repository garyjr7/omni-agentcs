"""Fase 2: perfiles de tools (tool hiding) y el puente ``execute_and_parse``."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.tools import profiles
from nexus_core.tools.handlers import execute_and_parse as bridge
from nexus_core.tools.output_parsers import parse_output, summarize
from nexus_core.tools.registry import durable_tool_definitions

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 10.0.0.1" start="1" startstr="x">
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
    </ports>
  </host>
  <runstats><finished elapsed="1.5" timestr="x"/><hosts up="1" down="0"/></runstats>
</nmaprun>"""


def _context(run_id: str) -> RunContext:
    return RunContext(
        "system",
        Identity("agent", "system", kind="agent", roles=("operator",)),
        run_id=run_id,
    )


def test_split_capture_strips_the_shell_markers() -> None:
    raw = "$ nmap -oX - 10.0.0.1\n<xml/>\n[stderr]\nwarn\n[exit=0 timed_out=False]\n"
    assert bridge.split_capture(raw) == ("<xml/>", "warn")


def test_nmap_parser_reads_open_ports_and_summarizes() -> None:
    parsed = parse_output("nmap", NMAP_XML)
    assert parsed["open_ports"] == ["21", "22"]
    assert summarize(parsed) == "2 puerto(s) abierto(s) (21, 22) · 1 host(s) up"


def test_unknown_parser_is_refused_with_the_closed_list() -> None:
    with pytest.raises(ValueError, match="nmap, text"):
        parse_output("nmap_parser", NMAP_XML)


def test_default_profile_hides_everything_but_the_five_tools() -> None:
    catalog = durable_tool_definitions("system")
    profiles.reset_tools()
    visible = profiles.visible_tool_ids(catalog, run_id="run-hide")
    assert visible == set(profiles.DEFAULT_TOOL_IDS) | {profiles.DISCOVERY_TOOL_ID}
    assert "nexus.recon.nmap" not in visible
    assert "nexus.recon.nmap" not in profiles.visible_catalog(catalog, run_id="run-hide")


def test_activation_and_skills_reveal_tools_for_that_run_only() -> None:
    catalog = durable_tool_definitions("system")
    profiles.reset_tools()
    profiles.activate_tools(
        "run-a", profiles.tools_for_skill("web-upload-webshell", catalog)
    )
    assert "nexus.web.request" in profiles.visible_tool_ids(catalog, run_id="run-a")
    assert "nexus.web.request" not in profiles.visible_tool_ids(catalog, run_id="run-b")


def test_a_skill_can_declare_its_tools() -> None:
    text = "---\ntools: nexus.recon.nmap, nexus.recon.ftp\n---\n"
    assert profiles.declared_tools(text) == ["nexus.recon.nmap", "nexus.recon.ftp"]


def test_execute_and_parse_parses_the_shell_capture(monkeypatch) -> None:
    async def fake_shell(arguments, context):
        return ToolResult(
            output={"summary": "3 líneas", "exit_code": 0},
            verified=True,
            stdout="3 líneas",
            evidence={"exit_code": 0},
        )

    monkeypatch.setattr(bridge, "shell_exec_handler", fake_shell)
    result = asyncio.run(
        bridge.execute_and_parse_handler(
            {"command": "printf hi", "parser_name": "text"}, _context("run-parse")
        )
    )
    assert result.success and result.output["parsed"]["parser"] == "text"
    assert result.evidence["parser"] == "text"


def test_a_denied_shell_keeps_the_shell_outcome(monkeypatch) -> None:
    async def fake_shell(arguments, context):
        return ToolResult(
            output={"error": "scope denied"}, verified=False, outcome="scope_denied"
        )

    monkeypatch.setattr(bridge, "shell_exec_handler", fake_shell)
    result = asyncio.run(
        bridge.execute_and_parse_handler(
            {"command": "nmap 8.8.8.8", "parser_name": "nmap"}, _context("run-denied")
        )
    )
    assert result.outcome == "scope_denied"


def test_an_unknown_parser_is_a_correctable_error(monkeypatch) -> None:
    async def fake_shell(arguments, context):
        return ToolResult(output={"summary": "x"}, verified=True, stdout="x")

    monkeypatch.setattr(bridge, "shell_exec_handler", fake_shell)
    result = asyncio.run(
        bridge.execute_and_parse_handler(
            {"command": "printf hi", "parser_name": "buffer"}, _context("run-bad")
        )
    )
    assert not result.success and result.outcome == "error"
    assert result.output["available_parsers"] == ["nmap", "text"]
    assert "known parsers" in result.output["error"]
