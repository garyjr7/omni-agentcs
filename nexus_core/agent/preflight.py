"""Fail-closed preflight before an autonomous run spends tokens.

A run that starts against a *wrong* binary burns tokens and then dies with an
opaque post-condition error. This module is the cheap gate in front of that: it
probes the identity of the critical binaries and, when one is the wrong variant,
refuses to start unless the operator has explicitly acknowledged the degradation.

The escape hatch exists on purpose: a missing/wrong optional tool should not make
an engagement impossible to run at all, it should make the agent *degrade*. The
operator opts in with ``NEXUS_ALLOW_DEGRADED_TOOLS=1`` and the run proceeds with
the affected tools treated as unavailable (see B3 in the loop).
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

from nexus_core.provisioner.binaries import (
    BINARY_IDENTITIES,
    BinaryIdentity,
    IdentityCheck,
    VersionRunner,
    check_binary_identities,
    default_version_runner,
    identity_problems,
    missing_tool_binaries,
)
from nexus_core.provisioner.runtime_deps import (
    ModuleFinder,
    missing_python_modules,
)

#: Operator opt-in to continue when a binary is present but wrong.
DEGRADED_TOOLS_ENV = "NEXUS_ALLOW_DEGRADED_TOOLS"

#: Set to ``0`` to skip the run preflight entirely (e.g. hermetic tests).
PREFLIGHT_ENV = "NEXUS_PREFLIGHT_BINARIES"

_TRUTHY = {"1", "true", "yes", "on"}


def env_flag(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    """Read a boolean env flag (truthy values: 1/true/yes/on; case-insensitive)."""
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in _TRUTHY


@dataclass(frozen=True)
class PreflightVerdict:
    """Result of probing the critical binaries."""

    problems: tuple[IdentityCheck, ...]
    degraded: bool
    #: Durable tools whose binary is absent: usable in principle, dead in
    #: practice, so the loop starts with them retired (B6).
    unavailable_tools: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """True when the run may start (no problems, or degradation is allowed)."""
        return not self.problems or self.degraded

    def message(self) -> str:
        """Operator-facing, one-line-per-problem explanation."""
        if not self.problems:
            return "preflight OK: binarios esperados verificados"
        lines = [
            "preflight falló: hay binarios equivocados en el PATH",
        ]
        for problem in self.problems:
            lines.append(f"  - {problem.name} ({problem.binary_path}): {problem.detail}")
            if problem.install:
                lines.append(f"      instala: {problem.install}")
        if self.degraded:
            lines.append(
                "continuando en modo degradado "
                f"({DEGRADED_TOOLS_ENV} está activo): esos tools se marcarán "
                "como no disponibles."
            )
        else:
            lines.append(
                "corrige los binarios o exporta "
                f"{DEGRADED_TOOLS_ENV}=1 para continuar de forma degradada."
            )
        return "\n".join(lines)


def _unavailable_tools(
    *,
    which: Callable[[str], str | None],
    identities: Iterable[BinaryIdentity],
    module_finder: ModuleFinder | None,
) -> tuple[str, ...]:
    """Union of tools with an absent binary and tools with an absent module."""
    retired = set(missing_tool_binaries(which=which, identities=identities))
    retired.update(missing_python_modules(find_spec=module_finder))
    return tuple(sorted(retired))


def preflight_binaries(
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: VersionRunner = default_version_runner,
    env: Mapping[str, str] | None = None,
    identities: Iterable[BinaryIdentity] = BINARY_IDENTITIES,
    module_finder: ModuleFinder | None = None,
) -> PreflightVerdict:
    """Probe the critical binaries and decide whether a run may start."""
    from nexus_core.kernel.sandbox_modes import SandboxPolicy

    environment = dict(os.environ if env is None else env)
    SandboxPolicy.resolve(environment)
    checks = check_binary_identities(which=which, run=run, identities=identities)
    problems = tuple(identity_problems(checks))
    degraded = env_flag(environment, DEGRADED_TOOLS_ENV)
    return PreflightVerdict(
        problems=problems,
        degraded=degraded,
        unavailable_tools=_unavailable_tools(
            which=which, identities=identities, module_finder=module_finder
        ),
    )


def unavailable_tools_from_env(
    *,
    which: Callable[[str], str | None] = shutil.which,
    env: Mapping[str, str] | None = None,
    module_finder: ModuleFinder | None = None,
) -> set[str]:
    """Tools the run must start without because their binary/module is absent.

    Covers both host binaries (B6) and runtime Python modules (H5: a missing
    ``paramiko`` retires ``nexus.post.*``). Honours ``NEXUS_PREFLIGHT_BINARIES=0``
    so hermetic tests (and an operator who knows better) can skip the probe. Only
    ``which``/``find_spec`` lookups happen here: no binary or module is loaded.
    """
    environment = dict(os.environ if env is None else env)
    if not env_flag(environment, PREFLIGHT_ENV, default=True):
        return set()
    return set(
        _unavailable_tools(
            which=which,
            identities=BINARY_IDENTITIES,
            module_finder=module_finder,
        )
    )


__all__ = [
    "DEGRADED_TOOLS_ENV",
    "PREFLIGHT_ENV",
    "PreflightVerdict",
    "env_flag",
    "preflight_binaries",
    "unavailable_tools_from_env",
]
