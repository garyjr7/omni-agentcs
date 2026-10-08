"""MCP framing over processes owned and cleaned up by the effective sandbox."""
from contextlib import asynccontextmanager
import asyncio
import anyio
from mcp.types import JSONRPCMessage
from mcp.shared.message import SessionMessage
from nexus_core.kernel.sandbox import sandbox_for_environment, OCISandbox


@asynccontextmanager
async def sandbox_stdio_client(config):
    config.validate_capabilities()
    sandbox = sandbox_for_environment(config.workspace_root, allowed_programs=(config.command,))
    argv = [config.command, *config.args]
    kwargs = {"extra_env": config.env}
    if isinstance(sandbox, OCISandbox):
        import os
        kwargs["image"] = os.getenv("NEXUS_SANDBOX_IMAGE", "python:3.12-alpine")
    async with sandbox.open_stdio(argv, **kwargs) as process:
        sender, read = anyio.create_memory_object_stream(0)
        write, receiver = anyio.create_memory_object_stream(0)

        async def read_lines():
            async with sender:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        return
                    try:
                        item = SessionMessage(JSONRPCMessage.model_validate_json(line))
                    except ValueError as exc:
                        item = exc
                    await sender.send(item)

        async def write_lines():
            async with receiver:
                async for item in receiver:
                    data = item.message.model_dump_json(by_alias=True, exclude_unset=True)
                    process.stdin.write((data + "\n").encode())
                    await process.stdin.drain()

        readers = [asyncio.create_task(read_lines()), asyncio.create_task(write_lines())]
        try:
            yield read, write
        finally:
            for task in readers:
                task.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            await read.aclose()
            await write.aclose()
