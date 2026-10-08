"""Explicit sandbox modes and the guarantees each one actually offers.

The runtime used to pick a sandbox solely from ``NEXUS_ENV`` without saying
what isolation it provided. A detector could call a binary "present" while the
runner failed to execute it, and operators had no single place to read which
guarantees were in force. This module names the modes and their guarantees, and
resolves the active one from the environment.

``OCI_NETWORK`` is documented in ``docs/adr/ADR-004-sandbox-modes.md`` but not
implemented yet: constructing it raises ``NotImplementedError`` on purpose so
nobody silently runs network tools behind an assumed firewall.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class SandboxMode(str, Enum):
    LOCAL = "local"                # development, no isolation
    LOCAL_STRICT = "local_strict"  # allowlist + workspace + ephemeral HOME + pg
    OCI = "oci"                    # isolated container, no network
    OCI_NETWORK = "oci_network"    # container with scope-filtered network


@dataclass(frozen=True)
class SandboxGuarantees:
    """What a mode actually guarantees (declarative, not aspirational)."""

    filesystem_isolation: bool
    network_isolation: bool
    process_isolation: bool
    resource_limits: bool
    user_isolation: bool
    persistent_across_calls: bool
    supports_network_tools: bool

    def to_dict(self) -> dict[str, bool]:
        """Return a JSON-serializable representation of the guarantees."""
        return {
            "filesystem_isolation": self.filesystem_isolation,
            "network_isolation": self.network_isolation,
            "process_isolation": self.process_isolation,
            "resource_limits": self.resource_limits,
            "user_isolation": self.user_isolation,
            "persistent_across_calls": self.persistent_across_calls,
            "supports_network_tools": self.supports_network_tools,
        }


GUARANTEES: dict[SandboxMode, SandboxGuarantees] = {
    SandboxMode.LOCAL: SandboxGuarantees(
        filesystem_isolation=False,
        network_isolation=False,
        process_isolation=False,
        resource_limits=False,
        user_isolation=False,
        persistent_across_calls=True,
        supports_network_tools=True,
    ),
    SandboxMode.LOCAL_STRICT: SandboxGuarantees(
        filesystem_isolation=False,
        network_isolation=False,
        process_isolation=False,
        resource_limits=False,
        user_isolation=False,
        persistent_across_calls=True,
        supports_network_tools=True,
    ),
    SandboxMode.OCI: SandboxGuarantees(
        filesystem_isolation=True,
        network_isolation=True,
        process_isolation=True,
        resource_limits=True,
        user_isolation=True,
        persistent_across_calls=False,
        supports_network_tools=False,
    ),
    SandboxMode.OCI_NETWORK: SandboxGuarantees(
        filesystem_isolation=True,
        network_isolation=False,  # filtered to the scope, not absent
        process_isolation=True,
        resource_limits=True,
        user_isolation=True,
        persistent_across_calls=False,
        supports_network_tools=True,
    ),
}

#: Environment variable that overrides the mode explicitly.
MODE_ENV = "NEXUS_SANDBOX_MODE"


def parse_mode(value: str | None) -> SandboxMode | None:
    """Return the :class:`SandboxMode` named by ``value`` (or ``None``)."""
    if not value:
        return None
    text = str(value).strip().lower()
    for mode in SandboxMode:
        if mode.value == text:
            return mode
    return None


class UnknownSandboxMode(ValueError):
    """Unknown configuration cannot silently select a weaker policy."""


class SandboxModeMismatch(RuntimeError):
    """The executor does not enforce the selected mode."""


class SandboxModeNotImplemented(NotImplementedError):
    """The requested policy has no implementing executor."""


def _build_executor(mode, workspace_root, allowed_programs, env):
    from .sandbox import LocalSandbox, OCISandbox

    if mode is SandboxMode.OCI:
        images = [v.strip() for v in env.get("NEXUS_SANDBOX_IMAGES", "python:3.12-alpine").split(",") if v.strip()]
        return OCISandbox(workspace_root, images, runtime=env.get("NEXUS_OCI_RUNTIME", "docker"))
    return LocalSandbox(workspace_root, **({"allowed_programs": allowed_programs} if allowed_programs is not None else {}))


class SandboxPolicy:
    """Single resolution boundary, including reporting and process execution.

    Local modes constrain argv, cwd and HOME to a workspace; they do NOT
    isolate host filesystem, processes or network. A process group is cleanup,
    not a security namespace. OCI guarantees describe enforced launch flags,
    not a claim that a container engine is installed or healthy.
    """

    @staticmethod
    def resolve(env=None, *, workspace_root=".", allowed_programs=None):
        from .sandbox import LocalSandbox, OCISandbox

        env = os.environ if env is None else env
        raw = env.get(MODE_ENV)
        if raw is not None:
            mode = parse_mode(raw)
            if mode is None:
                raise UnknownSandboxMode(f"unknown sandbox mode: {raw!r}")
        else:
            mode = SandboxMode.OCI if env.get("NEXUS_ENV", "development").lower() == "production" else SandboxMode.LOCAL_STRICT
        if mode is SandboxMode.OCI_NETWORK:
            raise SandboxModeNotImplemented("oci_network requires an enforced egress policy; not implemented")
        executor = _build_executor(mode, workspace_root, allowed_programs, env)
        expected = OCISandbox if mode is SandboxMode.OCI else LocalSandbox
        if not isinstance(executor, expected):
            raise SandboxModeMismatch(f"{mode.value} requires {expected.__name__}, got {type(executor).__name__}")
        effective = SandboxMode.OCI if isinstance(executor, OCISandbox) else SandboxMode.LOCAL
        return mode, executor, GUARANTEES[effective].to_dict()


def active_mode() -> SandboxMode:
    return SandboxPolicy.resolve()[0]


def effective_guarantees(mode: SandboxMode | str | None = None) -> SandboxGuarantees:
    env = dict(os.environ)
    if mode is not None:
        env[MODE_ENV] = mode.value if isinstance(mode, SandboxMode) else str(mode)
    return SandboxGuarantees(**SandboxPolicy.resolve(env)[2])


# Compatibility alias: still resolves the executor, never the declared table.
guarantees_for = effective_guarantees


def sandbox_for_mode(mode, workspace_root, allowed_programs=None):
    env = dict(os.environ)
    if mode is not None:
        env[MODE_ENV] = mode.value if isinstance(mode, SandboxMode) else str(mode)
    return SandboxPolicy.resolve(env, workspace_root=workspace_root, allowed_programs=allowed_programs)[1]
