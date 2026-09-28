"""Constrained local process runner for development.

Production deployments should replace this implementation with an OCI or
microVM runtime. Shell parsing is deliberately unsupported.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
from uuid import uuid4


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class LocalSandbox:
    def __init__(
        self,
        workspace_root: str | Path,
        allowed_programs: Iterable[str] = ("python3", "git", "rg"),
        max_output_bytes: int = 1_000_000,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_programs = frozenset(allowed_programs)
        self.max_output_bytes = max_output_bytes

    def resolve_workspace(self, relative: str = ".") -> Path:
        candidate = (self.workspace_root / relative).resolve()
        if candidate != self.workspace_root and self.workspace_root not in candidate.parents:
            raise PermissionError("sandbox path escapes workspace")
        return candidate

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str = ".",
        timeout_seconds: float = 30,
    ) -> SandboxResult:
        if not argv or argv[0] not in self.allowed_programs:
            raise PermissionError("program is not allowed in this sandbox")
        working_directory = self.resolve_workspace(cwd)
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(working_directory),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "NEXUS_SANDBOX": "1"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
            timed_out = False
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            timed_out = True
        return SandboxResult(
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout=stdout[:self.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=stderr[:self.max_output_bytes].decode("utf-8", errors="replace"),
            timed_out=timed_out,
        )


class OCISandbox:
    """Ephemeral Docker/Podman sandbox for untrusted agent commands."""

    def __init__(
        self,
        workspace_root: str | Path,
        allowed_images: Iterable[str],
        runtime: str = "docker",
        memory: str = "512m",
        cpus: str = "1.0",
        pids_limit: int = 128,
    ):
        if runtime not in {"docker", "podman"}:
            raise ValueError("OCI runtime must be docker or podman")
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_images = frozenset(allowed_images)
        self.runtime = runtime
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit

    def build_argv(self, image: str, command: Sequence[str]) -> list[str]:
        if image not in self.allowed_images:
            raise PermissionError("sandbox image is not allowlisted")
        if not command:
            raise ValueError("sandbox command is required")
        name = f"nexus-sandbox-{uuid4().hex[:12]}"
        return [
            self.runtime, "run", "--rm", "--name", name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--user", "65532:65532",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--mount", f"type=bind,src={self.workspace_root},dst=/workspace,rw",
            "--workdir", "/workspace",
            image,
            *command,
        ]

    async def run(
        self,
        image: str,
        command: Sequence[str],
        timeout_seconds: float = 120,
    ) -> SandboxResult:
        argv = self.build_argv(image, command)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
            timed_out = False
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            timed_out = True
        return SandboxResult(
            process.returncode if process.returncode is not None else -1,
            stdout.decode("utf-8", errors="replace")[:1_000_000],
            stderr.decode("utf-8", errors="replace")[:1_000_000],
            timed_out,
        )


def sandbox_for_environment(workspace_root: str | Path):
    environment = os.getenv("NEXUS_ENV", "development").lower()
    if environment == "production":
        images = [item.strip() for item in os.getenv(
            "NEXUS_SANDBOX_IMAGES", "python:3.12-alpine"
        ).split(",") if item.strip()]
        return OCISandbox(
            workspace_root, images, runtime=os.getenv("NEXUS_OCI_RUNTIME", "docker")
        )
    return LocalSandbox(workspace_root)
