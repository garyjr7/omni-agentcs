"""MCP registry: the explicit server allowlist and its discovered tools.

There is **no implicit discovery**. An MCP server is used only when it is listed
in ``mcp_servers.toml`` *and* names the tools it exposes in ``allowed_tools``;
anything else is refused before a process is spawned or a socket is opened. A
malformed entry raises instead of being skipped, so a typo cannot silently turn
into "no allowlist" and then into a permissive run.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tomllib
from typing import Any

from .client import (
    MCPClient,
    MCPServerConfig,
    MCPTool,
    SessionFactory,
    TRANSPORT_HTTP,
    TRANSPORT_STDIO,
)

#: Environment override for the config path (tests and non-XDG deployments).
CONFIG_ENV = "NEXUS_MCP_CONFIG"
#: File name inside the omni config directory.
CONFIG_FILENAME = "mcp_servers.toml"
#: Config directory name used when XDG paths are unavailable.
CONFIG_DIRNAME = "omni"


def config_path(paths: Any = None) -> Path:
    """Resolve ``mcp_servers.toml``: ``$NEXUS_MCP_CONFIG`` → XDG → ``~/.config/omni``."""
    override = os.getenv(CONFIG_ENV, "").strip()
    if override:
        return Path(override)
    if paths is not None:
        directory = getattr(paths, "config_dir", None)
        if directory is not None:
            return Path(directory) / CONFIG_FILENAME
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().config_dir / CONFIG_FILENAME


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def parse_server(entry: dict[str, Any]) -> MCPServerConfig:
    """Validate one ``[[servers]]`` table into an :class:`MCPServerConfig`."""
    name = str(entry.get("name") or "").strip()
    if not name:
        raise ValueError("cada servidor MCP requiere 'name'")
    transport = str(entry.get("transport") or TRANSPORT_STDIO).strip().lower()
    if transport not in {TRANSPORT_STDIO, TRANSPORT_HTTP}:
        raise ValueError(f"servidor MCP '{name}': transporte no soportado '{transport}'")
    if transport == TRANSPORT_STDIO and not str(entry.get("command") or "").strip():
        raise ValueError(f"servidor MCP '{name}': el transporte stdio requiere 'command'")
    if transport == TRANSPORT_HTTP and not str(entry.get("url") or "").strip():
        raise ValueError(f"servidor MCP '{name}': el transporte http requiere 'url'")
    env = entry.get("env") or {}
    if not isinstance(env, dict):
        raise ValueError(f"servidor MCP '{name}': 'env' debe ser una tabla")
    config = MCPServerConfig(
        name=name,
        capabilities=entry.get("capabilities") or {},
        workspace_root=str(entry.get("workspace_root") or "."),
        transport=transport,
        command=str(entry.get("command") or ""),
        args=_as_str_tuple(entry.get("args")),
        env={str(key): str(value) for key, value in env.items()},
        url=str(entry.get("url") or ""),
        allowed_tools=_as_str_tuple(entry.get("allowed_tools")),
        requires_approval=_as_str_tuple(entry.get("requires_approval")),
        call_timeout=float(entry.get("call_timeout") or 30.0),
        connect_timeout=float(entry.get("connect_timeout") or 30.0),
    )

    config.validate_capabilities()
    return config


def parse_config(text: str) -> list[MCPServerConfig]:
    """Parse ``mcp_servers.toml`` text into validated configs (never connects)."""
    document = tomllib.loads(text)
    entries = document.get("servers") or []
    if not isinstance(entries, list):
        raise ValueError("'servers' debe ser una lista de tablas [[servers]]")
    configs = [parse_server(entry) for entry in entries]
    names = [config.name for config in configs]
    if len(set(names)) != len(names):
        raise ValueError("nombres de servidor MCP duplicados en la configuración")
    return configs


def load_config(path: str | Path | None = None, *, paths: Any = None) -> list[MCPServerConfig]:
    """Load the allowlist from disk; an absent file means *no servers*."""
    target = Path(path) if path is not None else config_path(paths)
    if not target.is_file():
        return []
    return parse_config(target.read_text(encoding="utf-8"))


@dataclass
class _CacheEntry:
    tools: list[MCPTool]


class MCPRegistry:
    """Config + discovered tools for every allowlisted server.

    Discovery happens once per server and is cached; a server that is down is
    recorded as unavailable rather than retried on every call.
    """

    def __init__(
        self,
        configs: list[MCPServerConfig] | None = None,
        *,
        session_factory: SessionFactory | None = None,
    ):
        self._configs = {config.name: config for config in (configs or [])}
        self._session_factory = session_factory
        self._cache: dict[str, _CacheEntry] = {}
        self._errors: dict[str, str] = {}

    # ------------------------------------------------------------- accessors
    @property
    def configs(self) -> dict[str, MCPServerConfig]:
        return dict(self._configs)

    def server(self, name: str) -> MCPServerConfig | None:
        return self._configs.get(str(name))

    def errors(self) -> dict[str, str]:
        return dict(self._errors)

    def cached_tools(self) -> dict[str, list[MCPTool]]:
        return {name: list(entry.tools) for name, entry in self._cache.items()}

    def client(self, name: str) -> MCPClient:
        config = self.server(name)
        if config is None:
            raise KeyError(f"servidor MCP no autorizado: {name}")
        return MCPClient(config, session_factory=self._session_factory)

    # ------------------------------------------------------------ discovery
    async def discover_tools(self, name: str) -> list[MCPTool]:
        """Discover and cache one server's tools (fail-closed on any error)."""
        config = self.server(name)
        if config is None:
            raise KeyError(f"servidor MCP no autorizado: {name}")
        if name in self._cache:
            return list(self._cache[name].tools)
        try:
            async with self.client(name) as client:
                tools = await client.list_tools()
        except Exception as exc:  # noqa: BLE001 - a broken server must not fatal
            self._errors[name] = f"{type(exc).__name__}: {exc}"
            return []
        self._cache[name] = _CacheEntry(tools=list(tools))
        return list(tools)

    async def discover_all(self) -> dict[str, list[MCPTool]]:
        """Discover every allowlisted server; returns ``{server: [tools]}``."""
        discovered: dict[str, list[MCPTool]] = {}
        for name in sorted(self._configs):
            discovered[name] = await self.discover_tools(name)
        return discovered

    def reset(self) -> None:
        """Forget the discovery cache and the recorded errors."""
        self._cache.clear()
        self._errors.clear()


__all__ = [
    "CONFIG_DIRNAME",
    "CONFIG_ENV",
    "CONFIG_FILENAME",
    "MCPRegistry",
    "config_path",
    "load_config",
    "parse_config",
    "parse_server",
]
