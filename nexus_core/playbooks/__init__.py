"""Declarative playbook packages (data) plus their strict loader.

``nexus_core/playbooks/*.yaml`` describe multi-phase, gated assessment chains in
data: which ``nexus.*`` tool to call, what blackboard fact completes the step,
which kill-chain phase and capability profile the phase belongs to, and which
per-turn telemetry signals the phase depends on. :mod:`~nexus_core.playbooks.loader`
validates them (strict JSON Schema) and converts them into the engine's own
:class:`~nexus_core.agent.playbooks.Playbook` objects, which the ReAct loop
surfaces in its prompt.

``red_team_base`` is the foundational chain: low-noise reconnaissance, staging
and interaction with the application surface, execution on an owned session, and
local privilege-elevation heuristics.
"""

from __future__ import annotations

from .loader import (
    DOCUMENT_SCHEMA,
    NOISE_LEVELS,
    PACKAGE_DIR,
    SUPPORTED_SCHEMA_VERSIONS,
    FactPredicate,
    LoadedPackage,
    LoadedPhase,
    PlaybookSchemaError,
    build_predicate,
    describe_gate,
    load_package,
    load_package_text,
    load_packages,
    package_paths,
    validate_against_catalog,
)

#: Package shipped with BAJIOWARE, used as the default engagement frame.
BASE_PLAYBOOK_ID = "red_team_base"

__all__ = [
    "BASE_PLAYBOOK_ID",
    "DOCUMENT_SCHEMA",
    "FactPredicate",
    "LoadedPackage",
    "LoadedPhase",
    "NOISE_LEVELS",
    "PACKAGE_DIR",
    "PlaybookSchemaError",
    "SUPPORTED_SCHEMA_VERSIONS",
    "build_predicate",
    "describe_gate",
    "load_package",
    "load_package_text",
    "load_packages",
    "package_paths",
    "validate_against_catalog",
]
