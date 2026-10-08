"""P0-3: extensions require explicit capabilities and governed transport."""
import asyncio
from unittest.mock import patch
import pytest
from nexus_core.integrations.mcp.client import MCPServerConfig, MCPTool, _SDKSession
from nexus_core.integrations.mcp.gateway_bridge import make_definition_factory
from nexus_core.agent.subagents import SUBAGENTS_BY_ID, permits


def manifest(**changes):
    return dict(effects=['exec', 'network'], scope_required=True,
                scope_target_field='target', sandbox_required=True, **changes)


def test_mcp_effect_manifest_is_mandatory():
    with pytest.raises(ValueError, match='capabilit'):
        make_definition_factory(MCPServerConfig('x', allowed_tools=('exec',)), MCPTool('x','exec',''))('system')


def test_mcp_tool_without_scope_is_rejected():
    caps = manifest()
    del caps['scope_required']
    with pytest.raises(ValueError):
        config = MCPServerConfig('x', allowed_tools=('exec',), capabilities={'exec': caps})
        make_definition_factory(config, MCPTool('x','exec',''))('system')


def test_mcp_tool_not_in_readonly_permits():
    config = MCPServerConfig('x', allowed_tools=('exec',), capabilities={'exec': manifest()})
    definition = make_definition_factory(config, MCPTool('x','exec',''))('system')
    assert not permits(SUBAGENTS_BY_ID['recon'], 'mcp.x.exec', definition)


def test_mcp_stdio_runs_inside_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv('NEXUS_SANDBOX_MODE', 'local_strict')
    from nexus_core.kernel.sandbox import LocalSandbox
    config = MCPServerConfig('x', command='python3', workspace_root=str(tmp_path),
                             allowed_tools=('exec',), capabilities={'exec': manifest()})
    with patch.object(LocalSandbox, 'open_stdio') as launch:
        from nexus_core.integrations.mcp.transport import sandbox_stdio_client
        # Inspect launch through the transport; no server or network needed.
        class Opened(Exception):
            pass
        launch.side_effect = Opened
        async def check():
            with pytest.raises(Opened):
                async with sandbox_stdio_client(config):
                    pass
        asyncio.run(check())
        launch.assert_called_once()
    assert _SDKSession(config)._transport().__class__ is not None


def test_mcp_definition_inherits_scope_and_effects():
    config = MCPServerConfig('x', capabilities={'exec': manifest()})
    definition = make_definition_factory(config, MCPTool('x','exec',''))('system')
    assert definition.scope_required and definition.scope_target_field == 'target'
    assert definition.sandbox_required and set(definition.effects) == {'exec','network'}


def test_real_stdio_child_uses_sandbox_environment(tmp_path, monkeypatch):
    import json
    from nexus_core.kernel.sandbox import LocalSandbox
    monkeypatch.setenv('NEXUS_SCOPE_SIGNING_SECRET','never-inherit-this')
    async def check():
        sandbox = LocalSandbox(tmp_path, ('python3',))
        async with sandbox.open_stdio(['python3','-c',
                'import os,json; print(json.dumps(dict(cwd=os.getcwd(),home=os.environ["HOME"],secret=os.getenv("NEXUS_SCOPE_SIGNING_SECRET"))),flush=True)']) as child:
            data = json.loads(await child.stdout.readline())
            assert data['cwd'] == str(tmp_path)
            assert data['home'] == str(sandbox.sandbox_home)
            assert data['secret'] is None
    asyncio.run(check())


def test_mcp_without_manifest_cannot_start_transport():
    from nexus_core.integrations.mcp.client import MCPClient
    from unittest.mock import MagicMock
    factory = MagicMock()
    async def check():
        with pytest.raises(ValueError, match='capabilit'):
            async with MCPClient(MCPServerConfig('bad',allowed_tools=('exec',)),session_factory=factory):
                pass
    asyncio.run(check())
    factory.assert_not_called()


def test_mcp_output_schema_cannot_fetch_external_refs(monkeypatch):
    from nexus_core.integrations.mcp.client import validate_output_schema
    from unittest.mock import MagicMock
    fetch = MagicMock(side_effect=AssertionError("network access forbidden"))
    monkeypatch.setattr("urllib.request.urlopen", fetch)
    with pytest.raises(Exception, match="Unresolvable"):
        validate_output_schema({"$ref":"http://127.0.0.1/private-schema"},{})
    fetch.assert_not_called()
    validate_output_schema({"type":"object","properties":{"n":{"type":"integer","minimum":1}}},{"n":1})
    with pytest.raises(Exception, match="minimum"):
        validate_output_schema({"type":"integer","minimum":1},0)
