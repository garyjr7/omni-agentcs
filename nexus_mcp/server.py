"""Official-SDK MCP gateway for local development and approved clients.

Run over stdio:
    python -m nexus_mcp.server

Run Streamable HTTP locally:
    NEXUS_MCP_TRANSPORT=streamable-http python -m nexus_mcp.server
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl

from nexus_core.config import NEXUS_DB_PATH
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.llm.abstraction import LLMConfig, LLMFactory, LLMMessage, LLMProvider

store = get_control_store(NEXUS_DB_PATH)
store.initialize()

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True,
    openWorldHint=False,
)
WRITE_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True,
    openWorldHint=False,
)


def is_remote_transport() -> bool:
    return os.getenv("NEXUS_MCP_TRANSPORT", "stdio") == "streamable-http"


def validate_remote_configuration(host: str) -> None:
    """Fail closed before binding a remotely reachable MCP listener."""
    if host in {"127.0.0.1", "localhost", "::1"}:
        return
    environment = os.getenv("NEXUS_ENV", "development").strip().lower()
    local_container = (
        os.getenv("NEXUS_MCP_TRUST_LOCAL_CONTAINER", "false").lower() == "true"
    )
    if local_container:
        if environment == "production":
            raise SystemExit("NEXUS_MCP_TRUST_LOCAL_CONTAINER is forbidden in production")
        return
    issuer = os.getenv("OIDC_ISSUER", "").strip()
    public_url = os.getenv("NEXUS_MCP_PUBLIC_URL", "").strip()
    audience = os.getenv("OIDC_AUDIENCE", "").strip()
    for label, value in (("OIDC_ISSUER", issuer), ("NEXUS_MCP_PUBLIC_URL", public_url)):
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.fragment:
            raise SystemExit(f"{label} must be an HTTPS URL without credentials or fragments")
    if not audience:
        raise SystemExit("OIDC_AUDIENCE is required for remote MCP token audience binding")


class NexusOIDCTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            from nexus_api.auth.oidc import oidc_verifier
            claims = await oidc_verifier.verify(token)
            import jwt
            raw_claims = jwt.decode(token, options={"verify_signature": False})
            scopes = raw_claims.get("scope", "").split()
            return AccessToken(
                token=token, client_id=str(raw_claims.get("client_id", raw_claims["sub"])),
                scopes=scopes, subject=str(raw_claims["sub"]),
                expires_at=raw_claims.get("exp"), claims={**raw_claims, **claims},
            )
        except Exception:
            return None


def build_server() -> MCPServer:
    kwargs: dict[str, Any] = {}
    issuer = os.getenv("OIDC_ISSUER", "").strip()
    public_url = os.getenv("NEXUS_MCP_PUBLIC_URL", "").strip()
    if issuer or public_url:
        if not issuer or not public_url:
            raise RuntimeError("OIDC_ISSUER and NEXUS_MCP_PUBLIC_URL must be configured together")
        kwargs = {
            "token_verifier": NexusOIDCTokenVerifier(),
            "auth": AuthSettings(
                issuer_url=AnyHttpUrl(issuer), resource_server_url=AnyHttpUrl(public_url),
                required_scopes=["nexus:read"],
            ),
        }
    return MCPServer(
        "bajioware-nexus", title="BAJIOWARE NEXUS", version="0.5.0",
        instructions=(
        "NEXUS is an enterprise agent directory and execution control plane. "
        "Tools exposed here are tenant-scoped and read-only unless explicitly documented."
        ), **kwargs,
    )


mcp = build_server()


def tenant() -> str:
    access = get_access_token()
    if access and access.claims and access.claims.get("tenant_id"):
        return str(access.claims["tenant_id"])
    return os.getenv("NEXUS_MCP_TENANT", "system")


@mcp.tool(annotations=READ_ONLY)
async def nexus_status() -> dict[str, Any]:
    """Return the health and offline-development capabilities of NEXUS."""
    return {
        "status": "ready",
        "tenant_id": tenant(),
        "offline_llm": True,
        "gateways": ["mcp", "rest", "cli"],
    }


@mcp.tool(annotations=READ_ONLY)
async def list_nexus_agents() -> list[dict[str, Any]]:
    """List registered agent definitions for the configured tenant."""
    return store.list_definitions("kernel_agents", tenant())


@mcp.tool(annotations=READ_ONLY)
async def list_nexus_tools() -> list[dict[str, Any]]:
    """List registered tool definitions for the configured tenant."""
    return store.list_definitions("kernel_tools", tenant())


@mcp.tool(annotations=READ_ONLY)
async def debug_with_fake_llm(message: str, scenario: str = "echo") -> dict[str, Any]:
    """Exercise the NEXUS model contract without consuming API tokens."""
    client = LLMFactory.create(LLMConfig(provider=LLMProvider.FAKE, model="nexus-fake-v1"))
    response = await client.complete(
        [LLMMessage(role="user", content=message)], scenario=scenario
    )
    return {
        "content": response.content,
        "provider": response.provider.value,
        "tokens_are_estimated": True,
        "tokens": response.total_tokens,
    }


@mcp.tool(annotations=WRITE_IDEMPOTENT)
async def submit_nexus_goal(goal: str, idempotency_key: str) -> dict[str, Any]:
    """Create a durable pending run; workers execute it only after policy checks."""
    if is_remote_transport():
        if os.getenv("NEXUS_MCP_ENABLE_WRITE_TOOLS", "false").lower() != "true":
            raise PermissionError("remote MCP write tools are disabled")
        access = get_access_token()
        if not access or "nexus:write" not in access.scopes:
            raise PermissionError("nexus:write scope is required")
    if not goal.strip():
        raise ValueError("goal is required")
    return store.create_run(
        tenant(), {"goal": goal, "source": "mcp"}, idempotency_key=idempotency_key
    )


def main() -> None:
    transport = os.getenv("NEXUS_MCP_TRANSPORT", "stdio")
    if transport not in {"stdio", "streamable-http"}:
        raise SystemExit("NEXUS_MCP_TRANSPORT must be stdio or streamable-http")
    if transport == "streamable-http":
        host = os.getenv("NEXUS_MCP_HOST", "127.0.0.1")
        validate_remote_configuration(host)
        mcp.run(
            transport="streamable-http", host=host,
            port=int(os.getenv("NEXUS_MCP_PORT", "8000")),
            json_response=True, stateless_http=True, max_request_body_size=4 * 1024 * 1024,
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
