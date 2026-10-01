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
from pathlib import Path
from typing import Any


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
        process_isolation=True,
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


def active_mode() -> SandboxMode:
    """Resolve the active sandbox mode from the environment.

    ``NEXUS_SANDBOX_MODE`` wins; otherwise ``NEXUS_ENV=production`` selects
    ``oci`` and everything else selects ``local_strict`` (the default runner now
    isolates the process group and the HOME).
    """
    explicit = parse_mode(os.getenv(MODE_ENV))
    if explicit is not None:
        return explicit
    if os.getenv("NEXUS_ENV", "development").lower() == "production":
        return SandboxMode.OCI
    return SandboxMode.LOCAL_STRICT


def guarantees_for(mode: SandboxMode | str | None = None) -> SandboxGuarantees:
    """Return the guarantees of ``mode`` (active mode when omitted)."""
    resolved = mode if isinstance(mode, SandboxMode) else parse_mode(mode)
    return GUARANTEES[resolved or active_mode()]


def sandbox_for_mode(
    mode: SandboxMode | str | None,
    workspace_root: str | Path,
    allowed_programs: Any = None,
) -> Any:
    """Build the sandbox implementation for ``mode``.

    ``oci_network`` is designed but not implemented: enabling it raises instead
    of silently running with an unenforced network policy.
    """
    from .sandbox import LocalSandbox, OCISandbox

    resolved = mode if isinstance(mode, SandboxMode) else parse_mode(mode)
    resolved = resolved or SandboxMode.LOCAL_STRICT
    if resolved is SandboxMode.OCI_NETWORK:
        raise NotImplementedError(
            "sandbox mode 'oci_network' is documented in "
            "docs/adr/ADR-004-sandbox-modes.md but not implemented yet; the "
            "scope-filtered firewall hook is missing"
        )
    if resolved is SandboxMode.OCI:
        images = [
            item.strip()
            for item in os.getenv("NEXUS_SANDBOX_IMAGES", "python:3.12-alpine").split(",")
            if item.strip()
        ]
        return OCISandbox(
            workspace_root, images, runtime=os.getenv("NEXUS_OCI_RUNTIME", "docker")
        )
    if allowed_programs is None:
        return LocalSandbox(workspace_root)
    return LocalSandbox(workspace_root, allowed_programs)


__all__ = [
    "GUARANTEES",
    "MODE_ENV",
    "SandboxGuarantees",
    "SandboxMode",
    "active_mode",
    "guarantees_for",
    "parse_mode",
    "sandbox_for_mode",
]
