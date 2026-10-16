"""Strict, typed loader for declarative playbook packages (YAML).

``nexus_core/agent/playbooks.py`` used to hold the deterministic chains as
Python literals. That is fine for three chains and wrong for a library: a
playbook is *data* (an ordered list of gated ``nexus.*`` steps), and editing
data should not mean editing the engine.

This loader reads a YAML package, validates it against a strict JSON Schema
(Draft 2020-12, through ``kernel.schema_validation``), and turns every phase
into the very same :class:`~nexus_core.agent.playbooks.Playbook` the engine
already understands — so a declarative chain and a hand-written one are
indistinguishable to the loop, the prompt and ``nexus.orchestrator.playbook``.

Design rules
------------
* **Fail closed, never silently wrong.** A malformed package raises
  :class:`PlaybookSchemaError`; the registry above decides whether that is fatal
  (tests, ``doctor``) or degraded (a run must not die because a YAML file was
  edited in a hurry).
* **No execution.** The loader produces guidance only; the gateway still
  scopes, approves, audits and post-conditions every call.
* **Single vocabulary.** Fact types come from ``kernel.blackboard``, planner
  phases from ``agent.planner``, profiles from ``agent.subagents`` and telemetry
  signals from ``agent.turn_telemetry``. A package cannot invent any of them.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from nexus_core.agent.playbooks import Playbook, PlaybookStep
from nexus_core.agent.planner import PHASE_IDS
from nexus_core.agent.subagents import SUBAGENT_IDS
from nexus_core.agent.turn_telemetry import TURN_TELEMETRY_SIGNALS
from nexus_core.kernel.blackboard import FACT_TYPES
from nexus_core.kernel.schema_validation import SchemaValidationError, validate

#: Directory holding the packaged ``*.yaml`` playbooks.
PACKAGE_DIR = Path(__file__).resolve().parent

#: Recognised document versions (a package must declare one).
SUPPORTED_SCHEMA_VERSIONS = (1,)

#: Free-form noise budget a phase declares, used for operator guidance.
NOISE_LEVELS = ("low", "medium", "high")

FactList = Sequence[Mapping[str, Any]]
FactPredicate = Callable[[list[dict[str, Any]]], bool]


class PlaybookSchemaError(ValueError):
    """A package is not a valid playbook document."""


_STEP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["step_id", "title", "tool_id", "produces", "rationale", "verification"],
    "properties": {
        "step_id": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$", "maxLength": 64},
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "tool_id": {"type": "string", "pattern": "^[a-z][a-z0-9_.]*$", "maxLength": 128},
        "produces": {
            "anyOf": [
                {"type": "null"},
                {"type": "string", "enum": list(FACT_TYPES)},
            ]
        },
        "rationale": {"type": "string", "minLength": 1, "maxLength": 2000},
        "verification": {"type": "string", "minLength": 1, "maxLength": 2000},
        "notes": {"type": "string", "minLength": 1, "maxLength": 2000},
    },
}

_GATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "always": {"const": True},
        "any_fact_types": {
            "type": "array",
            "items": {"type": "string", "enum": list(FACT_TYPES)},
            "minItems": 1,
            "uniqueItems": True,
        },
        "all_fact_types": {
            "type": "array",
            "items": {"type": "string", "enum": list(FACT_TYPES)},
            "minItems": 1,
            "uniqueItems": True,
        },
        "min_count": {"type": "integer", "minimum": 1, "maximum": 1000},
    },
    "oneOf": [
        {"required": ["always"], "maxProperties": 1},
        {"required": ["any_fact_types"], "not": {"anyOf": [
            {"required": ["always"]}, {"required": ["all_fact_types"]}]}},
        {"required": ["all_fact_types"], "not": {"anyOf": [
            {"required": ["always"]}, {"required": ["any_fact_types"]}]}},
    ],
}

_PHASE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "phase_id",
        "title",
        "planner_phase",
        "subagent",
        "objective",
        "gate",
        "steps",
    ],
    "properties": {
        "phase_id": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$", "maxLength": 64},
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "planner_phase": {"type": "string", "enum": list(PHASE_IDS)},
        "subagent": {"type": "string", "enum": list(SUBAGENT_IDS)},
        "noise": {"type": "string", "enum": list(NOISE_LEVELS)},
        "objective": {"type": "string", "minLength": 1, "maxLength": 2000},
        "gate": _GATE_SCHEMA,
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 12,
            "items": _STEP_SCHEMA,
        },
        "telemetry": {
            "type": "array",
            "items": {"type": "string", "enum": sorted(TURN_TELEMETRY_SIGNALS)},
            "uniqueItems": True,
            "maxItems": 8,
        },
    },
}

DOCUMENT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "playbook_id",
        "version",
        "title",
        "description",
        "phases",
    ],
    "properties": {
        "schema_version": {"type": "integer", "enum": list(SUPPORTED_SCHEMA_VERSIONS)},
        "playbook_id": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$", "maxLength": 64},
        "version": {"type": "string", "minLength": 1, "maxLength": 32},
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "description": {"type": "string", "minLength": 1, "maxLength": 4000},
        "phases": {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": _PHASE_SCHEMA,
        },
    },
}


@dataclass(frozen=True)
class LoadedPhase:
    """One phase of a package: the engine's playbook plus its applicability gate."""

    playbook: Playbook
    predicate: FactPredicate
    #: ``phase_id`` inside the package, and the profile declared for it.
    phase_id: str
    planner_phase: str
    subagent: str
    objective: str

    def to_dict(self) -> dict[str, Any]:
        payload = self.playbook.to_dict()
        payload.update(
            {
                "phase_id": self.phase_id,
                "planner_phase": self.planner_phase,
                "subagent": self.subagent,
                "objective": self.objective,
            }
        )
        return payload


@dataclass(frozen=True)
class LoadedPackage:
    """A whole validated package (its phases, in declared order)."""

    playbook_id: str
    version: str
    title: str
    description: str
    source: str
    phases: tuple[LoadedPhase, ...]

    @property
    def playbooks(self) -> tuple[Playbook, ...]:
        return tuple(phase.playbook for phase in self.phases)

    def gates(self) -> dict[str, FactPredicate]:
        """``playbook_id -> predicate`` for the engine's gate table."""
        return {phase.playbook.playbook_id: phase.predicate for phase in self.phases}

    def phase(self, playbook_id: str) -> LoadedPhase | None:
        return next(
            (item for item in self.phases if item.playbook.playbook_id == playbook_id), None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "phases": [phase.to_dict() for phase in self.phases],
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PlaybookSchemaError(message)


def _fact_types(records: FactList) -> set[str]:
    """Fact types present on the blackboard (accepts the raw ``list_facts()`` rows)."""
    found: set[str] = set()
    for fact in records or ():
        if not isinstance(fact, Mapping):
            continue
        fact_type = fact.get("fact_type") or fact.get("type")
        if fact_type:
            found.add(str(fact_type))
    return found


def _counts(records: FactList) -> dict[str, int]:
    counts: dict[str, int] = {}
    for fact in records or ():
        if not isinstance(fact, Mapping):
            continue
        fact_type = fact.get("fact_type") or fact.get("type")
        if fact_type:
            counts[str(fact_type)] = counts.get(str(fact_type), 0) + 1
    return counts


def build_predicate(gate: Mapping[str, Any]) -> FactPredicate:
    """Turn a validated ``gate`` block into a pure blackboard predicate."""

    def predicate(facts: list[dict[str, Any]]) -> bool:
        if gate.get("always") is True:
            return True
        counts = _counts(facts)
        minimum = int(gate.get("min_count") or 1)
        any_types = [str(item) for item in gate.get("any_fact_types") or ()]
        all_types = [str(item) for item in gate.get("all_fact_types") or ()]
        if any_types and any(counts.get(item, 0) >= minimum for item in any_types):
            return True
        if all_types and all(counts.get(item, 0) >= minimum for item in all_types):
            return True
        return False

    return predicate


def describe_gate(gate: Mapping[str, Any]) -> str:
    """Human-readable form of a gate, shown by ``/playbook`` and the tool."""
    if gate.get("always") is True:
        return "sin hechos previos (fase inicial)"
    minimum = int(gate.get("min_count") or 1)
    parts: list[str] = []
    any_types = [str(item) for item in gate.get("any_fact_types") or ()]
    all_types = [str(item) for item in gate.get("all_fact_types") or ()]
    if any_types:
        parts.append(" o ".join(any_types))
    if all_types:
        parts.append(" y ".join(all_types))
    suffix = f" (>= {minimum})" if minimum > 1 else ""
    return f"hechos: {', '.join(parts)}{suffix}" if parts else "hechos desconocidos"


def _build_phase(document_playbook_id: str, raw: Mapping[str, Any]) -> LoadedPhase:
    phase_id = str(raw["phase_id"])
    steps: list[PlaybookStep] = []
    for item in raw["steps"]:
        assert isinstance(item, Mapping)  # guaranteed by the schema
        rationale = str(item["rationale"])
        verification = str(item.get("verification") or "")
        if verification:
            rationale = f"{rationale} [verificación: {verification}]"
        # The prompt carries one line per playbook, so the composed rationale is
        # bounded; the YAML keeps the long form for the operator.
        if len(rationale) > 400:
            rationale = rationale[:397].rstrip() + "..."
        steps.append(
            PlaybookStep(
                str(item["step_id"]),
                str(item["title"]),
                str(item["tool_id"]),
                produces=str(item["produces"]) if item.get("produces") else None,
                rationale=rationale,
            )
        )
    gate = dict(raw["gate"])
    playbook = Playbook(
        playbook_id=f"{document_playbook_id}.{phase_id}",
        title=str(raw["title"]),
        phase=str(raw["planner_phase"]),
        requires=describe_gate(gate),
        steps=tuple(steps),
    )
    return LoadedPhase(
        playbook=playbook,
        predicate=build_predicate(gate),
        phase_id=phase_id,
        planner_phase=str(raw["planner_phase"]),
        subagent=str(raw["subagent"]),
        objective=str(raw["objective"]),
    )


def load_package_text(text: str, *, source: str = "<memory>",
                      catalog: Mapping[str, Any] | None = None) -> LoadedPackage:
    """Parse and validate one YAML package, or raise :class:`PlaybookSchemaError`."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - declared dependency
        raise PlaybookSchemaError(
            "PyYAML is required to load declarative playbooks (pip install pyyaml)"
        ) from exc
    _require(len(text.encode("utf-8")) <= 262_144, f"{source}: package exceeds 256 KiB")
    try:
        depth = 0
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.AliasEvent):
                raise PlaybookSchemaError(f"{source}: YAML aliases are not permitted")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                _require(depth <= 32, f"{source}: YAML nesting exceeds 32")
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
        root = yaml.compose(text)
        pending = [root] if root is not None else []
        while pending:
            node = pending.pop()
            if isinstance(node, yaml.nodes.MappingNode):
                keys: set[str] = set()
                for key, value in node.value:
                    _require(isinstance(key, yaml.nodes.ScalarNode) and key.tag == "tag:yaml.org,2002:str",
                             f"{source}: mapping keys must be strings")
                    _require(key.value not in keys, f"{source}: duplicate YAML key {key.value}")
                    keys.add(key.value)
                    pending.append(value)
            elif isinstance(node, yaml.nodes.SequenceNode):
                pending.extend(node.value)
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PlaybookSchemaError(f"{source}: YAML inválido: {exc}") from exc
    _require(isinstance(document, Mapping), f"{source}: el documento debe ser un objeto YAML")
    assert isinstance(document, Mapping)  # narrowed for mypy
    try:
        validate(dict(document), DOCUMENT_SCHEMA)
    except SchemaValidationError as exc:
        raise PlaybookSchemaError(f"{source}: {exc}") from None

    playbook_id = str(document["playbook_id"])
    phases_raw = list(document["phases"])
    phases = tuple(_build_phase(playbook_id, phase) for phase in phases_raw)

    phase_ids = [phase.phase_id for phase in phases]
    _require(len(set(phase_ids)) == len(phase_ids), f"{source}: phase_id duplicado")
    step_ids = [step.step_id for phase in phases for step in phase.playbook.steps]
    _require(len(set(step_ids)) == len(step_ids), f"{source}: step_id duplicado")
    package = LoadedPackage(
        playbook_id=playbook_id,
        version=str(document["version"]),
        title=str(document["title"]),
        description=str(document["description"]),
        source=source,
        phases=phases,
    )
    if catalog is None:
        from nexus_core.tools.registry import durable_tool_definitions

        catalog = durable_tool_definitions()
    problems = validate_against_catalog((package,), catalog)
    _require(not problems, f"{source}: {'; '.join(problems)}")
    return package


def load_package(path: Path) -> LoadedPackage:
    """Load one package file from disk."""
    with path.open("rb") as stream:
        raw = stream.read(262_145)
    _require(len(raw) <= 262_144, f"{path}: package exceeds 256 KiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise PlaybookSchemaError(f"{path}: invalid UTF-8") from exc
    return load_package_text(text, source=str(path))


def package_paths(directory: Path | None = None) -> tuple[Path, ...]:
    """Every ``*.yaml``/``*.yml`` package in ``directory`` (sorted, deterministic)."""
    root = Path(directory) if directory is not None else PACKAGE_DIR
    if not root.is_dir():
        return ()
    found = sorted(
        (item for item in root.iterdir() if item.is_file() and item.suffix in {".yaml", ".yml"}),
        key=lambda item: item.name,
    )
    return tuple(found)


def _fingerprint(directory: Path | None) -> tuple[tuple[str, int, int], ...]:
    """Cheap change detector so the cache follows the files on disk."""
    rows: list[tuple[str, int, int]] = []
    for path in package_paths(directory):
        try:
            stat = path.stat()
        except OSError:  # pragma: no cover - file vanished mid-scan
            continue
        rows.append((str(path), stat.st_mtime_ns, stat.st_size))
    return tuple(rows)


@lru_cache(maxsize=8)
def _load_cached(
    directory: str | None, _fingerprint_rows: tuple[tuple[str, int, int], ...]
) -> tuple[LoadedPackage, ...]:
    root = Path(directory) if directory else None
    packages: list[LoadedPackage] = []
    for path in package_paths(root):
        packages.append(load_package(path))
    return tuple(packages)


def load_packages(
    directory: Path | None = None, *, strict: bool = False
) -> tuple[LoadedPackage, ...]:
    """All packages in ``directory`` (default: the packaged ones).

    With ``strict=False`` a broken package is skipped instead of killing a run;
    the caller that wants to know (tests, ``doctor``) asks for ``strict=True``.
    """
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions()
    packages: list[LoadedPackage] = []
    for path in package_paths(directory):
        try:
            # Bounded content key detects replacement even with unchanged mtime.
            with path.open("rb") as stream:
                raw = stream.read(262_145)
            _require(len(raw) <= 262_144, f"{path}: package exceeds 256 KiB")
            package = _parse_cached(raw.decode("utf-8"), str(path))
            problems = validate_against_catalog((package,), catalog)
            _require(not problems, f"{path}: {'; '.join(problems)}")
            packages.append(package)
        except (PlaybookSchemaError, OSError, UnicodeError):
            if strict:
                raise
    return tuple(packages)


@lru_cache(maxsize=16)
def _parse_cached(text: str, source: str) -> LoadedPackage:
    return load_package_text(text, source=source)


def validate_against_catalog(
    packages: Sequence[LoadedPackage], catalog: Mapping[str, Any]
) -> list[str]:
    """Problems that would make a package unusable against a real tool catalog.

    Empty means healthy: every step names a registered tool, and every phase's
    declared profile is allowed to call every tool of its steps (a chain the
    active subagent cannot execute is guidance into a denial).
    """
    from nexus_core.agent.subagents import SUBAGENTS_BY_ID, permits

    problems: list[str] = []
    for package in packages:
        for phase in package.phases:
            profile = SUBAGENTS_BY_ID.get(phase.subagent)
            if profile is None:
                problems.append(
                    f"{package.playbook_id}.{phase.phase_id}: unknown subagent '{phase.subagent}'"
                )
            for step in phase.playbook.steps:
                if step.tool_id not in catalog:
                    problems.append(
                        f"{package.playbook_id}.{phase.phase_id}: unknown tool '{step.tool_id}'"
                    )
                elif profile is not None and not permits(profile, step.tool_id, catalog[step.tool_id]):
                    problems.append(
                        f"{package.playbook_id}.{phase.phase_id}: subagent "
                        f"'{phase.subagent}' cannot call '{step.tool_id}'"
                    )
    return problems


__all__ = [
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
