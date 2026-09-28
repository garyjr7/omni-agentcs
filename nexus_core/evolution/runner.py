"""Isolated workspaces and protected-baseline checks for evolution campaigns."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, Sequence
from uuid import uuid4

from nexus_core.kernel.sandbox import LocalSandbox, OCISandbox

DEFAULT_EXCLUDES = {".git", ".env", ".venv", "node_modules", "data", "dist", "__pycache__"}


class EvolutionWorkspace:
    def __init__(self, source_root: str | Path, lab_root: str | Path):
        self.source_root = Path(source_root).resolve()
        self.lab_root = Path(lab_root).resolve()
        self.lab_root.mkdir(parents=True, exist_ok=True)

    def prepare(self, proposal_id: str) -> Path:
        destination = self.lab_root / f"{proposal_id}-{uuid4().hex[:8]}"
        shutil.copytree(
            self.source_root,
            destination,
            ignore=shutil.ignore_patterns(*DEFAULT_EXCLUDES),
        )
        return destination

    @staticmethod
    def hashes(root: Path, protected_paths: Iterable[str]) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for relative in protected_paths:
            path = (root / relative).resolve()
            if root.resolve() != path and root.resolve() not in path.parents:
                raise PermissionError("protected path escapes workspace")
            if path.is_file():
                result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            elif path.is_dir():
                for item in sorted(path.rglob("*")):
                    if item.is_file() and "__pycache__" not in item.parts:
                        key = str(item.relative_to(root))
                        result[key] = hashlib.sha256(item.read_bytes()).hexdigest()
        return result

    @staticmethod
    def assert_protected_unchanged(
        baseline: Dict[str, str], candidate_root: Path
    ) -> None:
        candidate = EvolutionWorkspace.hashes(candidate_root, baseline.keys())
        changed = sorted(
            key for key, digest in baseline.items() if candidate.get(key) != digest
        )
        if changed:
            raise PermissionError(f"candidate modified protected baseline files: {changed}")


class EvolutionRunner:
    def __init__(self, sandbox: LocalSandbox | OCISandbox):
        self.sandbox = sandbox

    async def evaluate(
        self,
        commands: Sequence[Sequence[str]],
        *,
        image: str | None = None,
    ) -> list[dict]:
        results = []
        for command in commands:
            if isinstance(self.sandbox, OCISandbox):
                if not image:
                    raise ValueError("OCI evaluation requires an image")
                result = await self.sandbox.run(image, command)
            else:
                result = await self.sandbox.run(command)
            results.append({"command": list(command), **asdict(result)})
            if result.exit_code != 0 or result.timed_out:
                break
        return results
