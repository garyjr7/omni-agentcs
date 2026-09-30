from nexus_core.cli.tui.stream import tool_prefix, PREFIXES


def test_prefix_nmap():
    assert tool_prefix("nexus.recon.nmap") == "[Recon-NMAP]"


def test_prefix_nuclei():
    assert tool_prefix("nexus.web.nuclei") == "[Web-Nuclei]"


def test_prefix_unknown_defaults_to_tool():
    assert tool_prefix("nexus.new") == "[Tool]"


def test_prefix_all_durable_tools_have_mapping():
    from nexus_core.tools.registry import durable_tool_definitions
    assert set(durable_tool_definitions()) <= PREFIXES.keys()


def test_prefix_case_insensitive():
    assert tool_prefix("NEXUS.RECON.NMAP") == "[Recon-NMAP]"


def test_prefix_handles_malformed_id():
    for value in (None, "", {}, 123, "nexus\nrecon"):
        assert tool_prefix(value) == "[Tool]"
