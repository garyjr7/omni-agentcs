"""V1-3: ``effect`` es un contrato verificado, no una etiqueta heredada.

Regla del contrato: ``read_only`` significa **no modifica el objetivo ni el
estado del engagement**. Los escaneos de recon/DAST que solo leen la superficie
siguen siendo ``read_only``; ejecutar comandos, escribir en el objetivo o mutar
el blackboard no lo son.

El gate es binario (``effect != read_only`` ⇒ operación activa), así que un
``read_only`` falso convertía una acción activa en algo permitido en plan mode y
sin aprobación en exec mode. Estos tests cierran las tres puertas: que cada tool
**declare** su efecto, que el valor esté en la taxonomía, y que plan mode
rechace al 100 % de las operaciones activas **antes** de llegar al handler.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import (
    EFFECT_TAXONOMY,
    Identity,
    RunContext,
    ToolDefinition,
)
from nexus_core.kernel.operator_mode import OperatorMode
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.registry import durable_tool_definitions, tool_catalog

HANDLERS_DIR = Path(__file__).resolve().parents[3] / "nexus_core" / "tools" / "handlers"

#: Catálogo activo revisado a mano en V1-3. Es un trinquete: si una tool nueva
#: hereda el default ``read_only`` o alguien reetiqueta una existente, este
#: conjunto cambia y el test falla hasta que se revise la decisión.
EXPECTED_ACTIVE = frozenset({
    "nexus.attack.impacket_changepasswd",
    "nexus.attack.impacket_getuserspns",
    "nexus.attack.impacket_psexec",
    "nexus.attack.impacket_secretsdump",
    "nexus.attack.nopac",
    "nexus.c2.sliver_deploy",
    "nexus.c2.sliver_exec",
    "nexus.c2.sliver_generate",
    "nexus.c2.sliver_loot",
    "nexus.c2.sliver_pivot",
    "nexus.cred.bruteforce",
    "nexus.post.crack_hash",
    "nexus.exploit.msf_auxiliary",
    "nexus.exploit.msf_exploit",
    "nexus.knowledge.record_fact",
    # PLAN MODE: they write ``loot/ENGAGEMENT_PLAN.md``, which is engagement
    # state (exactly what ``read_only`` forbids), so ``state_write`` is the
    # honest label. They are never a target action; the PLAN-FIRST gate is what
    # keeps them ahead of the attack.
    "nexus.orchestrator.create_plan",
    "nexus.orchestrator.update_plan",
    "nexus.post.dns_update",
    "nexus.post.dpapi",
    "nexus.post.enum_system",
    "nexus.post.listener",
    "nexus.post.job",
    "nexus.post.shell_exec",
    "nexus.post.ntlm_capture",
    "nexus.post.pivot_bruteforce",
    "nexus.post.pivot_http",
    "nexus.post.smb_upload",
    "nexus.post.ssh_exec",
    "nexus.post.ssh_upload",
    "nexus.post.tftp",
    "nexus.pwn.analyze",
    "nexus.pwn.ret2libc",
    "nexus.recon.bloodhound_python",
    "nexus.recon.netexec",
    "nexus.report.generate",
    "nexus.session.interact",
    "nexus.session.kill",
    "nexus.session.pty",
    "nexus.shell.exec",
    "nexus.system.install_tool",
    "nexus.web.request",
    "nexus.web.upload",
    "nexus.web.sqlmap",
    "nexus.web.wp_bruteforce",
    "nexus.web.wp_exec",
    "nexus.win.winrm_exec",
})

#: Las 14 tools que declaraban ``read_only`` (o lo heredaban) siendo activas.
FORMERLY_READ_ONLY = {
    "nexus.cred.bruteforce": "credential_access",
    "nexus.knowledge.record_fact": "state_write",
    "nexus.post.enum_system": "post_exploitation",
    "nexus.post.pivot_bruteforce": "pivoting",
    "nexus.post.pivot_http": "pivoting",
    "nexus.post.ssh_exec": "post_exploitation",
    "nexus.pwn.analyze": "post_exploitation",
    "nexus.pwn.ret2libc": "exploit",
    "nexus.web.request": "target_write",
    "nexus.web.sqlmap": "exploit",
    "nexus.web.wp_bruteforce": "credential_access",
    "nexus.web.wp_exec": "exploit",
    "nexus.c2.sliver_loot": "state_write",
    "nexus.session.kill": "post_exploitation",
}


def _module_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    return constants


def _definitions_missing_effect() -> list[str]:
    """Tool ids whose ``ToolDefinition(...)`` call omits ``effect=``."""
    missing: list[str] = []
    for path in sorted(HANDLERS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        constants = _module_constants(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name != "ToolDefinition":
                continue
            keywords = {keyword.arg: keyword for keyword in node.keywords}
            if "effect" in keywords:
                continue
            value = keywords.get("tool_id")
            tool_id = "?"
            if value is not None:
                if isinstance(value.value, ast.Constant):
                    tool_id = str(value.value.value)
                else:
                    tool_id = constants.get(getattr(value.value, "id", ""), "?")
            missing.append(f"{path.name}:{node.lineno} {tool_id}")
    return missing


def test_every_handler_definition_declares_its_effect():
    """Prohibido heredar el default: cada definición declara su efecto."""
    assert _definitions_missing_effect() == []


def test_effect_values_are_in_the_taxonomy():
    catalog = tool_catalog()
    unknown = {entry["tool_id"]: entry["effect"] for entry in catalog["tools"]
               if entry["effect"] not in EFFECT_TAXONOMY}
    assert unknown == {}
    with pytest.raises(ValueError):
        ToolDefinition("x", "system", {}, effect="made_up")


def test_active_catalog_matches_the_reviewed_expectation():
    catalog = tool_catalog()
    active = frozenset(entry["tool_id"] for entry in catalog["tools"]
                       if entry["effect"] != "read_only")
    assert active == EXPECTED_ACTIVE
    read_only = [entry["tool_id"] for entry in catalog["tools"]
                 if entry["effect"] == "read_only"]
    # WP4 adds two read-only tools (nexus.skill.list/load): 73 - 44 active = 29.
    # PLAN MODE adds one read-only tool (get_plan_status) and two active
    # writers: 76 - 46 active = 30.
    assert len(read_only) == catalog["tool_count"] - len(EXPECTED_ACTIVE) == 30


def test_the_mislabelled_tools_now_declare_their_real_effect():
    live = {entry["tool_id"]: entry["effect"] for entry in tool_catalog()["tools"]}
    assert {tool_id: live[tool_id] for tool_id in FORMERLY_READ_ONLY} == FORMERLY_READ_ONLY


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_ACTIVE))
def test_plan_denies_every_active_catalog_operation(tmp_path, tool_id):
    """100 % de las operaciones activas se rechazan antes del handler.

    Se parametriza sobre la lista **revisada**, no sobre la etiqueta viva: así el
    test es rojo si alguien devuelve una de estas tools a ``read_only``.
    """
    definition, _real_handler = durable_tool_definitions()[tool_id]
    assert definition.active, f"{tool_id} debe declararse como operación activa"

    store = ControlStore(tmp_path / "plan.db")
    store.initialize()
    context = RunContext(
        "system",
        Identity("agent", "system", kind="agent", roles=("operator",)),
        run_id="plan-run",
        session_id="plan-session",
    )
    modes = OperatorMode(store)
    modes.plan(context, "revisar el objetivo antes de tocar nada")

    calls: list[str] = []
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    gateway.register(definition, lambda arguments, ctx: calls.append(tool_id))
    with pytest.raises(PermissionError, match="plan"):
        asyncio.run(gateway.invoke(tool_id, {}, context))
    assert calls == [], f"{tool_id} llegó al handler en plan mode"
    denied = [row for row in AuditWriter(store).export("system")
              if row["action"] == "mode.denied"]
    assert denied and denied[-1]["payload"]["tool_id"] == tool_id


@pytest.mark.parametrize("tool_id", sorted(set(t["tool_id"] for t in tool_catalog()["tools"])
                                             - EXPECTED_ACTIVE))
def test_plan_allows_every_read_only_catalog_operation(tmp_path, tool_id):
    """El gate de plan no rechaza los read_only (schema y scope sí pueden)."""
    definition, _real_handler = durable_tool_definitions()[tool_id]
    assert not definition.active
    store = ControlStore(tmp_path / "plan.db")
    store.initialize()
    context = RunContext(
        "system",
        Identity("agent", "system", kind="agent", roles=("operator",)),
        run_id="plan-run",
        session_id="plan-session",
    )
    OperatorMode(store).plan(context, "solo lectura")
    assert OperatorMode(store).constrain(context, definition) is None
