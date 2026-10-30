"""V1-10: every limit the catalog declares is enforced before the handler.

The hand-written validator implemented eight keywords and ignored the rest, so
``minimum``/``maximum``, ``minItems``/``maxItems``, ``minProperties``/
``maxProperties`` and ``pattern`` were decoration: a tool advertised bounds no
caller had to honour. These tests check the property, not the implementation:
for each limit class a real catalog schema declares, the invalid instance the
contract should reject *is* rejected, the valid one next to it is accepted, and
the handler is never reached.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.schema_validation import (
    SchemaValidationError,
    check_schema,
    validate,
)
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.registry import durable_tool_definitions

#: Keywords that constrain an instance and therefore must be enforced. Values
#: such as ``description``/``default`` annotate a schema and constrain nothing.
ASSERTION_KEYWORDS = frozenset(
    {
        "type",
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "required",
        "additionalProperties",
    }
)

def _recording_handler(calls: list[dict]):
    def handler(arguments: dict, _context) -> ToolResult:
        calls.append(arguments)
        return ToolResult({}, True, "probe", {})

    return handler


_TARGET = "10.0.0.5"
_PSEXEC = {"target": _TARGET, "username": "administrator", "command": "whoami"}

#: (keyword, tool id, instance the contract accepts, instance it must reject).
LIMIT_CASES = [
    (
        "minimum",
        "nexus.attack.impacket_psexec",
        {**_PSEXEC, "port": 445},
        {**_PSEXEC, "port": 0},
    ),
    (
        "maximum",
        "nexus.attack.impacket_psexec",
        {**_PSEXEC, "port": 445},
        {**_PSEXEC, "port": 70000},
    ),
    (
        "minimum",
        "nexus.recon.httpx",
        {"targets": [_TARGET], "timeout_seconds": 10},
        {"targets": [_TARGET], "timeout_seconds": 9},
    ),
    (
        "type",
        "nexus.attack.impacket_psexec",
        {**_PSEXEC, "port": 445},
        {**_PSEXEC, "port": "445"},
    ),
    (
        "minLength",
        "nexus.c2.sliver_exec",
        {"session_id": "abc-1", "command": "id"},
        {"session_id": "abc-1", "command": ""},
    ),
    (
        "maxLength",
        "nexus.attack.impacket_psexec",
        _PSEXEC,
        {**_PSEXEC, "username": "u" * 129},
    ),
    (
        "maxItems",
        "nexus.system.check_env",
        {"tools": [f"tool{i}" for i in range(50)]},
        {"tools": [f"tool{i}" for i in range(51)]},
    ),
    (
        "minItems",
        "nexus.recon.httpx",
        {"targets": [_TARGET]},
        {"targets": []},
    ),
    (
        "pattern",
        "nexus.c2.sliver_exec",
        {"session_id": "abc-1", "command": "id"},
        {"session_id": "bad id!!", "command": "id"},
    ),
    (
        "maxProperties",
        "nexus.post.pivot_http",
        {
            "target": _TARGET,
            "username": "u",
            "password": "p",
            "url": f"http://{_TARGET}/login",
            "headers": {f"H{i}": "v" for i in range(10)},
        },
        {
            "target": _TARGET,
            "username": "u",
            "password": "p",
            "url": f"http://{_TARGET}/login",
            "headers": {f"H{i}": "v" for i in range(11)},
        },
    ),
    (
        "additionalProperties",
        "nexus.web.request",
        {"url": f"http://{_TARGET}/", "headers": {"X-Probe": "1"}},
        {"url": f"http://{_TARGET}/", "headers": {"X-Probe": 1}},
    ),
    (
        "enum",
        "nexus.knowledge.record_fact",
        {"fact_type": "service", "key": "http"},
        {"fact_type": "service_version", "key": "http"},
    ),
]


@pytest.fixture(scope="module")
def catalog() -> dict:
    return durable_tool_definitions("system")


def _schema(catalog: dict, tool_id: str) -> dict:
    definition, _ = catalog[tool_id]
    return definition.input_schema


@pytest.mark.parametrize(
    ("keyword", "tool_id", "accepted", "rejected"),
    LIMIT_CASES,
    ids=[f"{case[0]}:{case[1]}" for case in LIMIT_CASES],
)
def test_all_declared_schema_keywords_are_enforced(
    catalog, keyword, tool_id, accepted, rejected
) -> None:
    schema = _schema(catalog, tool_id)
    # The valid instance proves the rejection below comes from the mutated
    # field and not from an unrelated keyword or an incomplete fixture.
    validate(accepted, schema)
    with pytest.raises(SchemaValidationError) as excinfo:
        validate(rejected, schema)
    # The rejection names the offending field so the operator can fix it.
    assert "$" in str(excinfo.value)


def test_the_catalog_declares_no_limit_without_a_case(catalog) -> None:
    """Guard against drift: a new constraint keyword must arrive with a case."""
    declared: set[str] = set()

    def walk(schema: object) -> None:
        if not isinstance(schema, dict):
            return
        declared.update(ASSERTION_KEYWORDS.intersection(schema))
        for sub in (schema.get("properties") or {}).values():
            walk(sub)
        walk(schema.get("items"))
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            walk(additional)

    for definition, _ in catalog.values():
        walk(definition.input_schema)
    covered = {case[0] for case in LIMIT_CASES} | {"required", "additionalProperties"}
    assert declared <= covered | {"required"}


def test_every_catalog_schema_is_a_valid_draft_2020_12_contract(catalog) -> None:
    """A malformed contract declares limits nobody can enforce (V1-10)."""
    for tool_id, (definition, _) in catalog.items():
        check_schema(definition.input_schema)


def test_an_unknown_property_lists_what_the_contract_accepts() -> None:
    """A rejection has to be actionable, not just correct.

    Measured in run_1052d63f9bba4838902b3aa21bd27d21 (2026-10-19): the model sent
    ``options`` to the sqlmap handler, read "Additional properties are not
    allowed ('options' was unexpected)", and had no way to know the accepted
    keys; its next attempt ran for 500 s without the intended flag.
    """
    schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}, "level": {"type": "integer"}},
        "additionalProperties": False,
    }
    with pytest.raises(SchemaValidationError) as excinfo:
        validate({"url": "http://x/?id=1", "options": {}}, schema)
    message = str(excinfo.value)
    assert "'options' was unexpected" in message
    assert "allowed: level, url" in message


def test_a_rejected_enum_carries_the_guidance_of_its_property() -> None:
    """The catalog already says *why*; the rejection has to say it too.

    hijack_v7 (2026-10-30) sent ``protocol="rpc"`` to ``nexus.recon.netexec``
    five times: the error listed ``['smb', 'ldap']`` and nothing about the
    rpcbind/mountd the run was actually looking at, so the model kept guessing.
    """
    from nexus_core.tools.handlers.netexec import netexec_definition

    schema = netexec_definition().input_schema
    with pytest.raises(SchemaValidationError) as excinfo:
        validate({"protocol": "rpc", "target": "203.0.113.10"}, schema)
    message = str(excinfo.value)
    assert "$.protocol" in message
    assert "rpcbind" in message


def test_a_rejected_enum_without_a_description_stays_short() -> None:
    schema = {
        "type": "object",
        "properties": {"mode": {"type": "string", "enum": ["a", "b"]}},
    }
    with pytest.raises(SchemaValidationError) as excinfo:
        validate({"mode": "c"}, schema)
    assert str(excinfo.value) == "$.mode: 'c' is not one of ['a', 'b']"


def test_malformed_schema_is_rejected_at_registration() -> None:
    with pytest.raises(SchemaValidationError):
        ToolDefinition(
            name="broken",
            tenant_id="system",
            tool_id="broken",
            input_schema={"type": "object", "properties": {"a": {"type": "nope"}}},
        )
    # The error is a ValueError, so existing callers that catch it keep working.
    assert issubclass(SchemaValidationError, ValueError)


def test_invalid_arguments_never_reach_the_handler(tmp_path) -> None:
    """Validation runs before approval and before the handler (positive control)."""
    store = ControlStore(tmp_path / "db")
    store.initialize()
    ctx = RunContext(
        "system",
        Identity("agent", "system", kind="agent", roles=("operator",)),
        run_id="run-v1-10",
        session_id="s-v1-10",
    )
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    calls: list[dict] = []
    gateway.register(
        # Active effect: without validation this call would raise
        # ApprovalRequired instead, so passing proves the order.
        ToolDefinition(
            "probe",
            "system",
            _schema(durable_tool_definitions("system"), "nexus.attack.impacket_psexec"),
            tool_id="probe",
            effect="execution",
        ),
        _recording_handler(calls),
    )
    with pytest.raises(SchemaValidationError):
        asyncio.run(gateway.invoke("probe", {**_PSEXEC, "port": 70000}, ctx))
    assert calls == []
    asyncio.run(gateway.invoke("probe", {**_PSEXEC, "port": 445}, ctx))
    assert calls and calls[0]["port"] == 445


def test_declared_defaults_satisfy_their_own_contract(catalog) -> None:
    """A default the contract itself rejects is a value that can never be used."""
    for tool_id, (definition, _) in catalog.items():
        properties = definition.input_schema.get("properties", {})
        for name, subschema in properties.items():
            if "default" in subschema:
                validate(subschema["default"], subschema, path=f"{tool_id}.{name}")
