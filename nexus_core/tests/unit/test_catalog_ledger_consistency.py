"""V1-8: the inventory, the ledger and the artifacts must describe one version.

The audit counted 55 ``tool_id`` literals with a regex while the runtime
registered 64 (nine definitions build the id from a module constant). Same story
for ``BACKLOG.md``: two ids had no row at all. These tests make the three sources
agree, so a count can no longer depend on how you grep.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from nexus_core.cli.tool import list_tools
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.parsers import PARSERS_VERSION
from nexus_core.tools.registry import tool_catalog

REPO_ROOT = Path(__file__).resolve().parents[3]
HANDLERS_DIR = REPO_ROOT / "nexus_core" / "tools" / "handlers"
CATALOG_PATH = REPO_ROOT / "docs" / "missions" / "audit-v1" / "catalog.json"
BACKLOG_PATH = REPO_ROOT / "BACKLOG.md"

#: Ledger ids that were never opened as a debt. Declared so the numbering is
#: continuous and a gap cannot be mistaken for a deleted row.
DECLARED_GAPS = ("V0-8", "V0-23")


def _module_constants(tree: ast.Module) -> dict[str, str]:
    """Map module-level ``NAME = "literal"`` assignments to their value."""
    constants: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = node.value.value
    return constants


def _ast_tool_ids() -> set[str]:
    """Every ``tool_id`` a handler declares, literal or via a constant."""
    found: set[str] = set()
    for path in sorted(HANDLERS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        constants = _module_constants(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name != "ToolDefinition":
                continue
            for keyword in node.keywords:
                if keyword.arg != "tool_id":
                    continue
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    found.add(keyword.value.value)
                elif isinstance(keyword.value, ast.Name):
                    resolved = constants.get(keyword.value.id)
                    if resolved is None:
                        raise AssertionError(
                            f"{path.name}: tool_id={keyword.value.id} is not a module constant"
                        )
                    found.add(resolved)
    return found


def test_handlers_ast_runtime_cli_and_json_agree():
    ast_ids = _ast_tool_ids()
    catalog = tool_catalog()
    runtime_ids = {entry["tool_id"] for entry in catalog["tools"]}

    assert ast_ids == runtime_ids, ast_ids.symmetric_difference(runtime_ids)
    assert catalog["tool_count"] == len(runtime_ids) == 82

    committed = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    assert committed == catalog, "catalog.json is stale: run scripts/omni_catalog.py"


def test_cli_listing_matches_the_catalog(capsys):
    assert list_tools("system") == 0
    printed = [line.split("\t", 1)[0] for line in capsys.readouterr().out.splitlines() if line]
    assert printed == sorted(entry["tool_id"] for entry in tool_catalog()["tools"])


def test_ledger_gaps_are_declared():
    backlog = BACKLOG_PATH.read_text(encoding="utf-8")
    for gap in DECLARED_GAPS:
        assert re.search(rf"^\| {re.escape(gap)} \|", backlog, re.MULTILINE), gap


def test_audit_ledger_catalog_and_result_versions_consistent(capsys):
    """The acceptance test of V1-8: one version across inventory, ledger, results."""
    # 1. 64 ids coincide across AST, CLI and JSON (the original 55-vs-64 defect).
    ast_ids = _ast_tool_ids()
    catalog = tool_catalog()
    runtime_ids = {entry["tool_id"] for entry in catalog["tools"]}
    assert ast_ids == runtime_ids and len(runtime_ids) == 82
    list_tools("system")
    cli_ids = {line.split("\t", 1)[0] for line in capsys.readouterr().out.splitlines() if line}
    assert cli_ids == runtime_ids
    assert json.loads(CATALOG_PATH.read_text(encoding="utf-8")) == catalog

    # 2. The ledger numbering has no undeclared hole.
    backlog = BACKLOG_PATH.read_text(encoding="utf-8")
    for gap in DECLARED_GAPS:
        assert re.search(rf"^\| {re.escape(gap)} \|", backlog, re.MULTILINE), gap


async def _echo_handler(arguments, context):
    return ToolResult(output={"target": arguments.get("target")}, verified=True,
                      verification_method="echo")


async def test_result_records_the_contract_version_that_produced_it(tmp_path):
    """A recorded result carries the versions a replay must use (V1-8)."""
    store = ControlStore(Path(tmp_path) / "versions.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    definition = ToolDefinition(
        tool_id="nexus.test.versioned",
        name="Versioned echo",
        tenant_id="system",
        description="test",
        version="2.3.1",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=(),
        scope_required=False,
    )
    gateway.register(definition, _echo_handler)
    context = RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        run_id="run-versions",
        trace_id="run-versions",
    )
    result = await gateway.invoke("nexus.test.versioned", {"target": "10.0.0.5"}, context)

    assert result["tool_id"] == "nexus.test.versioned"
    assert result["contract_version"] == definition.version == "2.3.1"
    assert result["parser_version"] == PARSERS_VERSION
    # The assertions derived for that version travel with it, so a replay can be
    # compared instead of re-derived with whatever is installed today.
    assert "assertions" in result
