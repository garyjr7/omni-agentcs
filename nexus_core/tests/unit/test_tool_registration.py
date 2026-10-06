"""Extensible tool registration: decorator, discovery and precedence (H7)."""

from __future__ import annotations

import pytest

from nexus_core.kernel.models import ToolDefinition
from nexus_core.tools import registration
from nexus_core.tools.registry import durable_tool_definitions, register_durable_tools

PLUGIN_ID = "test.plugin.echo"


async def _echo_handler(payload, context):  # pragma: no cover - never invoked
    raise AssertionError("handler must not run during registration")


def _echo_definition(tenant_id: str) -> ToolDefinition:
    return ToolDefinition(
        name="echo",
        tool_id=PLUGIN_ID,
        tenant_id=tenant_id,
        input_schema={"type": "object", "properties": {}},
        description="echo plugin",
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    registration.clear_registrations()
    yield
    registration.clear_registrations()


def test_register_tool_decorator_adds_the_tool():
    @registration.register_tool(PLUGIN_ID, definition_factory=_echo_definition)
    async def handler(payload, context):
        return None

    assert handler.__name__ == "handler"  # decorator returns the function
    catalog = durable_tool_definitions("acme")
    assert PLUGIN_ID in catalog
    definition, registered = catalog[PLUGIN_ID]
    assert definition.tenant_id == "acme"
    assert registered is handler


def test_register_tool_accepts_a_fixed_definition():
    fixed = _echo_definition("system")
    registration.register_tool(PLUGIN_ID, definition=fixed)(_echo_handler)
    catalog = durable_tool_definitions("whatever")
    assert catalog[PLUGIN_ID][0] is fixed


def test_register_tool_requires_a_definition():
    with pytest.raises(TypeError):
        registration.register_tool(PLUGIN_ID)


def test_builtin_wins_unless_replace():
    registration.register_tool(PLUGIN_ID, definition_factory=_echo_definition)(_echo_handler)
    registration.register_tool(
        "nexus.recon.nmap", definition_factory=_echo_definition
    )(_echo_handler)
    catalog = durable_tool_definitions()
    assert catalog["nexus.recon.nmap"][1] is not _echo_handler


def test_replace_overrides_a_builtin():
    registration.register_tool(
        "nexus.recon.nmap", definition_factory=_echo_definition, replace=True
    )(_echo_handler)
    catalog = durable_tool_definitions()
    assert catalog["nexus.recon.nmap"][1] is _echo_handler


def test_register_durable_tools_includes_plugins():
    registration.register_tool(PLUGIN_ID, definition_factory=_echo_definition)(_echo_handler)

    class _Gateway:
        def __init__(self):
            self.registered = {}

        def register(self, definition, handler):
            self.registered[definition.tool_id] = (definition, handler)

    gateway = _Gateway()
    register_durable_tools(gateway, "system")
    assert PLUGIN_ID in gateway.registered


def test_discovery_scans_the_handler_package():
    report = registration.discover(force=True)
    assert report.modules > 0
    assert report.errors == ()


def test_discovery_is_idempotent():
    first = registration.discover(force=True)
    second = registration.discover()
    assert first.modules == second.modules


def test_discovery_is_non_fatal_on_broken_modules(monkeypatch):
    original = registration.importlib.import_module

    def _flaky(name, *args, **kwargs):
        if name.endswith(".nmap"):
            raise ImportError("boom")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(registration.importlib, "import_module", _flaky)
    report = registration.discover(force=True)
    assert any("nmap" in name for name, _ in report.errors)
    # The catalog still builds; only the broken plugin is skipped.
    assert "nexus.recon.nmap" in durable_tool_definitions()


def test_clear_registrations_removes_plugins():
    registration.register_tool(PLUGIN_ID, definition_factory=_echo_definition)(_echo_handler)
    assert PLUGIN_ID in durable_tool_definitions()
    registration.clear_registrations()
    assert PLUGIN_ID not in durable_tool_definitions()


def test_entry_point_group_is_namespaced():
    assert registration.ENTRY_POINT_GROUP == "nexus.tools"
