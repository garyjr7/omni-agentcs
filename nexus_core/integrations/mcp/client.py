"""MCP client: the official SDK behind one async, timeout-bounded facade.

Built on the official ``mcp`` Python SDK (``modelcontextprotocol.io``), which
gives us stdio, HTTP and SSE transports and a versioned protocol implementation
instead of a hand-rolled one. This module adds the *policy* the SDK cannot know:

* **Hard timeouts** on connect, initialize and every call, so a wedged server
  fails closed instead of hanging an engagement.
* **A secret-free child environment.** A stdio MCP server is a subprocess: if we
  handed it our ``os.environ`` it would inherit ``NEXUS_SCOPE_SIGNING_SECRET``,
  the LLM API keys and the database URL (rule 7). The child gets only a small
  allowlist of benign variables plus whatever the operator configured.
* **One normalized tool/result view**, so the registry and the gateway bridge
  never touch SDK types.

Nothing here executes a tool: :class:`MCPClient` only *talks* to a server. Every
result is returned as text and becomes a governed observation downstream.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
import os
import re
from typing import Any, AsyncContextManager, Callable

#: Default ceiling for a single MCP call.
DEFAULT_CALL_TIMEOUT = 30.0
#: Default ceiling for connecting + initializing a server.
DEFAULT_CONNECT_TIMEOUT = 30.0
#: Default ceiling for ``tools/list``.
DEFAULT_LIST_TIMEOUT = 15.0

#: Environment variables a stdio server may inherit from us. Everything else is
#: dropped: an MCP server must never see the signed-scope secret, the LLM keys or
#: the database URL.
BENIGN_ENV_KEYS: frozenset[str] = frozenset(
    {"PATH", "HOME", "LANG", "TERM", "TMPDIR", "TMP", "TEMP", "USER", "SHELL", "PWD"}
)
#: Substrings that disqualify an inherited variable, even if it looked benign.
SECRET_ENV_MARKERS: tuple[str, ...] = (
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "CREDENTIAL",
    "PRIVATE", "SESSION", "COOKIE", "DATABASE_URL", "DSN",
)
_NAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]")

TRANSPORT_STDIO = "stdio"
TRANSPORT_HTTP = "http"


class MCPError(RuntimeError):
    """Base class of every MCP failure surfaced to the caller."""


class MCPUnavailable(MCPError):
    """Raised when a server cannot be reached or refuses the session (fail-closed)."""


class MCPTimeout(MCPError):
    """Raised when a server does not answer inside its timeout budget."""


def safe_name(value: str) -> str:
    """Sanitize a server/tool name for use inside a durable tool id."""
    return _NAME_SAFE.sub("_", str(value)).strip("_") or "unnamed"


def sanitized_env(
    *,
    base: dict[str, str] | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return the environment a stdio MCP server is allowed to inherit.

    ``base`` defaults to ``os.environ``; only :data:`BENIGN_ENV_KEYS` survive, and
    anything whose name looks like a secret is dropped even then. ``extra`` is
    applied on top (the operator asked for those explicitly).
    """
    source = os.environ if base is None else base
    allowed: dict[str, str] = {}
    for key, value in source.items():
        if key not in BENIGN_ENV_KEYS:
            continue
        upper = key.upper()
        if any(marker in upper for marker in SECRET_ENV_MARKERS):
            continue
        allowed[key] = value
    allowed.update(extra or {})
    return allowed


@dataclass(frozen=True)
class MCPServerConfig:
    """One allowlisted MCP server, straight from ``mcp_servers.toml``."""

    name: str
    transport: str = TRANSPORT_STDIO
    command: str = ""
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    #: Tool names this server may expose. Empty means "no tool is allowed",
    #: which is the fail-closed default.
    allowed_tools: tuple[str, ...] = ()
    #: Subset of ``allowed_tools`` that needs durable human approval.
    requires_approval: tuple[str, ...] = ()
    call_timeout: float = DEFAULT_CALL_TIMEOUT
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT

    def allows(self, tool_name: str) -> bool:
        return str(tool_name) in self.allowed_tools

    def needs_approval(self, tool_name: str) -> bool:
        return str(tool_name) in self.requires_approval

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "url": self.url,
            "allowed_tools": list(self.allowed_tools),
            "requires_approval": list(self.requires_approval),
            "call_timeout": self.call_timeout,
            "connect_timeout": self.connect_timeout,
            # The env values are never echoed: they may hold tokens.
            "env_keys": sorted(self.env),
        }


@dataclass(frozen=True)
class MCPTool:
    """A tool advertised by an MCP server, normalized for our registry."""

    server: str
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    title: str = ""

    @property
    def tool_id(self) -> str:
        """Durable tool id, e.g. ``mcp.filesystem.read_file``."""
        return f"mcp.{safe_name(self.server)}.{safe_name(self.name)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "server": self.server,
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_schema,
        }


@dataclass(frozen=True)
class MCPCallResult:
    """Normalized outcome of one MCP call (text plus the server's error flag)."""

    text: str
    is_error: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"is_error": bool(self.is_error), "text_chars": len(self.text)}


#: An async context manager yielding an object with the SDK's session surface
#: (``initialize`` / ``list_tools`` / ``call_tool``). Injectable so tests can
#: drive the boundary without spawning a real server.
SessionFactory = Callable[[MCPServerConfig], AsyncContextManager[Any]]


def sdk_session(config: MCPServerConfig) -> AsyncContextManager[Any]:
    """Open a real SDK session (stdio or streamable HTTP)."""
    return _sdk_session(config)


class _SDKSession:
    """Async context manager adapting the SDK's transports to one session.

    Kept as a class (not an ``asynccontextmanager``) so the two nested context
    managers — transport and session — share an explicit :class:`AsyncExitStack`.
    """

    def __init__(self, config: MCPServerConfig):
        self.config = config
        self._stack: AsyncExitStack | None = None
        self.session: Any = None

    async def __aenter__(self) -> Any:
        from mcp import ClientSession

        self._stack = AsyncExitStack()
        try:
            streams = await self._stack.enter_async_context(self._transport())
        except BaseException as exc:  # noqa: BLE001 - any transport error is "unavailable"
            await self._stack.aclose()
            self._stack = None
            raise MCPUnavailable(
                f"no se pudo abrir el transporte de '{self.config.name}': "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        read, write = streams[0], streams[1]
        try:
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await asyncio.wait_for(
                session.initialize(), timeout=self.config.connect_timeout
            )
        except asyncio.TimeoutError as exc:
            await self._stack.aclose()
            self._stack = None
            raise MCPTimeout(
                f"el servidor '{self.config.name}' no inicializó en "
                f"{self.config.connect_timeout}s"
            ) from exc
        except BaseException as exc:  # noqa: BLE001
            await self._stack.aclose()
            self._stack = None
            raise MCPUnavailable(
                f"el servidor '{self.config.name}' falló al inicializar: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        self.session = session
        return session

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None

    def _transport(self) -> AsyncContextManager[Any]:
        if self.config.transport == TRANSPORT_HTTP:
            from mcp.client.streamable_http import streamable_http_client

            return streamable_http_client(self.config.url)
        from mcp import StdioServerParameters
        from mcp.client.stdio import stdio_client

        return stdio_client(
            StdioServerParameters(
                command=self.config.command,
                args=list(self.config.args),
                env=sanitized_env(extra=self.config.env),
            )
        )


def _sdk_session(config: MCPServerConfig) -> AsyncContextManager[Any]:
    return _SDKSession(config)


def _extract_text(result: Any) -> str:
    """Flatten an SDK ``CallToolResult`` into plain text (never raises)."""
    parts: list[str] = []
    for block in getattr(result, "content", None) or ():
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(str(text))
        else:
            parts.append(str(block))
    if getattr(result, "structured_content", None) is not None:
        parts.append(repr(result.structured_content))
    return "\n".join(parts)


class MCPClient:
    """One live session with one MCP server, bounded by hard timeouts."""

    def __init__(self, config: MCPServerConfig, *, session_factory: SessionFactory | None = None):
        self.config = config
        self._session_factory = session_factory or sdk_session
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def __aenter__(self) -> MCPClient:
        self._stack = AsyncExitStack()
        try:
            self._session = await self._stack.enter_async_context(
                self._session_factory(self.config)
            )
        except BaseException:
            await self._stack.aclose()
            self._stack = None
            raise
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self._session = None

    @property
    def session(self) -> Any:
        if self._session is None:
            raise MCPUnavailable(f"'{self.config.name}' no está conectado")
        return self._session

    async def list_tools(self, *, timeout: float | None = None) -> list[MCPTool]:
        """Return the server's tools, normalized (fail-closed on timeout)."""
        limit = DEFAULT_LIST_TIMEOUT if timeout is None else timeout
        try:
            result = await asyncio.wait_for(self.session.list_tools(), timeout=limit)
        except asyncio.TimeoutError as exc:
            raise MCPTimeout(
                f"tools/list de '{self.config.name}' excedió {limit}s"
            ) from exc
        except MCPError:
            raise
        except BaseException as exc:  # noqa: BLE001
            raise MCPUnavailable(
                f"tools/list de '{self.config.name}' falló: {type(exc).__name__}: {exc}"
            ) from exc
        tools: list[MCPTool] = []
        for item in getattr(result, "tools", None) or ():
            tools.append(
                MCPTool(
                    server=self.config.name,
                    name=str(getattr(item, "name", "") or ""),
                    title=str(getattr(item, "title", "") or ""),
                    description=str(getattr(item, "description", "") or ""),
                    input_schema=dict(getattr(item, "input_schema", None) or {}),
                )
            )
        return tools

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None, *, timeout: float | None = None
    ) -> MCPCallResult:
        """Call one tool, bounding it by ``timeout`` (fail-closed on timeout)."""
        limit = self.config.call_timeout if timeout is None else timeout
        try:
            result = await asyncio.wait_for(
                self.session.call_tool(name, arguments or {}), timeout=limit
            )
        except asyncio.TimeoutError as exc:
            raise MCPTimeout(
                f"la llamada '{name}' de '{self.config.name}' excedió {limit}s"
            ) from exc
        except MCPError:
            raise
        except BaseException as exc:  # noqa: BLE001
            raise MCPUnavailable(
                f"la llamada '{name}' de '{self.config.name}' falló: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return MCPCallResult(
            text=_extract_text(result), is_error=bool(getattr(result, "is_error", False))
        )


__all__ = [
    "MCPCallResult",
    "BENIGN_ENV_KEYS",
    "DEFAULT_CALL_TIMEOUT",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_LIST_TIMEOUT",
    "MCPClient",
    "MCPError",
    "MCPServerConfig",
    "MCPTimeout",
    "MCPTool",
    "MCPUnavailable",
    "SECRET_ENV_MARKERS",
    "TRANSPORT_HTTP",
    "TRANSPORT_STDIO",
    "SessionFactory",
    "safe_name",
    "sanitized_env",
    "sdk_session",
]
