"""The catalog the model reads must state the numeric limits of an argument.

A handler rejects an out-of-range value with a schema error and the model can
only avoid it if the published contract carries the bound.
"""

from __future__ import annotations

from types import SimpleNamespace

from nexus_core.agent.prompts import _required_arguments, _schema_arguments
from nexus_core.tools.registry import durable_tool_definitions


def _definition(properties: dict, required: tuple[str, ...] = ()) -> SimpleNamespace:
    return SimpleNamespace(
        input_schema={"type": "object", "properties": properties, "required": list(required)},
        description="tool",
        risk="read_only",
    )


def test_a_bounded_argument_shows_its_range():
    definition = _definition(
        {"timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 1800}},
        required=("timeout_seconds",),
    )
    assert _schema_arguments(definition) == "timeout_seconds:integer[10..1800]*"
    assert _required_arguments(definition) == "timeout_seconds:integer[10..1800]*"


def test_a_ceiling_or_a_floor_alone_is_published():
    ceiling = _definition({"retries": {"type": "integer", "maximum": 5}})
    floor = _definition({"port": {"type": "integer", "minimum": 1}})
    assert _schema_arguments(ceiling) == "retries:integer≤5"
    assert _schema_arguments(floor) == "port:integer≥1"


def test_an_unbounded_argument_keeps_its_plain_label():
    definition = _definition({"target": {"type": "string"}}, required=("target",))
    assert _schema_arguments(definition) == "target:string*"


def test_the_real_catalog_publishes_the_nmap_timeout():
    nmap = durable_tool_definitions()["nexus.recon.nmap"][0]
    assert "timeout_seconds:integer[10..1800]" in _schema_arguments(nmap)
