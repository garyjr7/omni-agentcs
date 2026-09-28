"""In-memory MCP protocol smoke without a network port or paid model."""

import asyncio
import os
import tempfile
from pathlib import Path


async def smoke() -> None:
    with tempfile.TemporaryDirectory() as directory:
        os.environ.update({
            "NEXUS_DB_PATH": str(Path(directory) / "mcp.db"),
            "NEXUS_ENV": "development",
            "NEXUS_MCP_TENANT": "system",
        })
        from mcp import Client

        from nexus_mcp.server import mcp, store

        store.initialize()
        async with Client(mcp) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"nexus_status", "debug_with_fake_llm", "submit_nexus_goal"} <= names
            status = await client.call_tool("nexus_status", {})
            fake = await client.call_tool(
                "debug_with_fake_llm", {"message": "hola", "scenario": "echo"}
            )
            assert not status.is_error
            assert not fake.is_error


if __name__ == "__main__":
    asyncio.run(smoke())
