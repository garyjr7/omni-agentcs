"""MCP (Model Context Protocol) integration, always behind the gateway.

Layout:

* :mod:`~nexus_core.integrations.mcp.client` — the SDK behind one async,
  timeout-bounded facade with a secret-free child environment;
* :mod:`~nexus_core.integrations.mcp.registry` — the explicit ``mcp_servers.toml``
  allowlist plus tool discovery/caching;
* :mod:`~nexus_core.integrations.mcp.gateway_bridge` — registers allowlisted
  tools as durable tools and enforces the allowlist on every call.

Importing this package never opens a connection and never requires the ``mcp``
SDK: the SDK is imported lazily inside the transport, so a machine without it can
still run every non-MCP path.
"""

from .client import (
    DEFAULT_CALL_TIMEOUT,
    MCPCallResult,
    MCPClient,
    MCPError,
    MCPServerConfig,
    MCPTimeout,
    MCPTool,
    MCPUnavailable,
    sanitized_env,
)
from .gateway_bridge import sync_from_config, sync_registry
from .registry import MCPRegistry, config_path, load_config, parse_config

__all__ = [
    "DEFAULT_CALL_TIMEOUT",
    "MCPCallResult",
    "MCPClient",
    "MCPError",
    "MCPRegistry",
    "MCPServerConfig",
    "MCPTimeout",
    "MCPTool",
    "MCPUnavailable",
    "config_path",
    "load_config",
    "parse_config",
    "sanitized_env",
    "sync_from_config",
    "sync_registry",
]
