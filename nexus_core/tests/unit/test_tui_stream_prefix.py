from nexus_core.cli.tui.stream import tool_prefix, PREFIXES


def test_prefix_nmap():
    assert tool_prefix("nexus.recon.nmap") == "[Recon-NMAP]"


def test_prefix_nuclei():
    assert tool_prefix("nexus.web.nuclei") == "[Web-Nuclei]"


def test_prefix_unknown_defaults_to_tool():
    assert tool_prefix("nexus.new") == "[Tool]"


def test_prefix_all_durable_tools_resolve():
    from nexus_core.tools.registry import durable_tool_definitions
    for tool_id in durable_tool_definitions():
        assert tool_prefix(tool_id).startswith("[")


def test_prefix_web_recon_tools_use_generic_fallback():
    """The web/recon mission may not touch ``nexus_core/cli``; its five tools
    therefore fall back to the generic ``[Tool]`` prefix."""
    web_recon_tools = {
        "nexus.web.sqlmap",
        "nexus.recon.gobuster",
        "nexus.recon.whatweb",
        "nexus.exploit.searchsploit",
        "nexus.web.dalfox",
    }
    assert not (web_recon_tools & PREFIXES.keys())
    assert all(tool_prefix(tool_id) == "[Tool]" for tool_id in web_recon_tools)


def test_prefix_case_insensitive():
    assert tool_prefix("NEXUS.RECON.NMAP") == "[Recon-NMAP]"


def test_prefix_handles_malformed_id():
    for value in (None, "", {}, 123, "nexus\nrecon"):
        assert tool_prefix(value) == "[Tool]"
