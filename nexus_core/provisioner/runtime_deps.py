"""Runtime Python dependencies a durable tool imports at execution time.

:mod:`nexus_core.provisioner.binaries` verifies host *executables* by identity;
this module tracks the Python *modules* a handler loads during a run. A missing
module is not a security problem, but it silently kills a whole capability:
``ssh_post`` needs ``paramiko`` and, without it, every ``nexus.post.*`` call dies
with ``ssh_unavailable``. The run preflight retires those tools up front instead
of letting the agent burn iterations rediscovering it (H5 of the RUN7 report).
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import Callable, Iterable

#: A module finder takes a dotted name and returns a spec (or ``None``).
ModuleFinder = Callable[[str], object]


@dataclass(frozen=True)
class PythonRequirement:
    """One Python module a handler imports, and the tools it powers."""

    module: str
    purpose: str
    install: str
    #: Durable tools retired for the run when the module is absent.
    tool_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation of the requirement."""
        return {
            "module": self.module,
            "purpose": self.purpose,
            "install": self.install,
            "tool_ids": list(self.tool_ids),
        }


#: Modules the durable handlers import at runtime (not hard runtime deps of the
#: CLI itself, so the package can still start without them).
PYTHON_REQUIREMENTS: tuple[PythonRequirement, ...] = (
    PythonRequirement(
        module="paramiko",
        purpose=(
            "Post-explotación SSH (nexus.post.ssh_exec / ssh_upload / "
            "enum_system / pivot_bruteforce / pivot_http)"
        ),
        install="pip install 'paramiko>=3.4,<6'",
        tool_ids=(
            "nexus.post.ssh_exec",
            "nexus.post.ssh_upload",
            "nexus.post.enum_system",
            "nexus.post.pivot_bruteforce",
            "nexus.post.pivot_http",
        ),
    ),
)


def _module_available(module: str, finder: ModuleFinder) -> bool:
    """Return whether ``module`` can be imported; never raises."""
    try:
        return finder(module) is not None
    except (ImportError, ValueError):
        # ``ValueError``: the name exists in ``sys.modules`` as ``None``.
        return False


def missing_python_modules(
    *,
    find_spec: ModuleFinder | None = None,
    requirements: Iterable[PythonRequirement] = PYTHON_REQUIREMENTS,
) -> tuple[str, ...]:
    """Durable tools retired because a required Python module is absent.

    Only in-process module resolution happens here (``importlib.util.find_spec``
    by default): no module is imported, no process is spawned.
    """
    finder = find_spec or importlib.util.find_spec
    missing: list[str] = []
    for requirement in requirements:
        if _module_available(requirement.module, finder):
            continue
        for tool_id in requirement.tool_ids:
            if tool_id not in missing:
                missing.append(tool_id)
    return tuple(sorted(missing))


__all__ = [
    "PYTHON_REQUIREMENTS",
    "ModuleFinder",
    "PythonRequirement",
    "missing_python_modules",
]
