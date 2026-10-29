"""FIX 1: aviso y bloqueo por vector ``(tool, subcommand, target)``.

El run de la sala easy del 2026-10-29 (10.66.171.37, Apache/PHP en el 80) gastó
12+ turnos en ``pyNfsClient`` por ``nexus.shell.exec`` con el mismo error y nunca
visitó HTTP. Estas pruebas fijan el contrato nuevo: a los 2 fallos consecutivos
del mismo vector el loop inyecta un aviso en el historial, a los 3 rechaza la
llamada, y un éxito de otra tool sobre el mismo target o un ``barrier``
registrado por el modelo devuelven el vector al juego.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from nexus_core.agent import memory
from nexus_core.agent.react import ReActConfig
from nexus_core.agent.react_coordinator import (
    ReActCoordinator,
    _is_vector_failure,
    _shell_subcommand,
    _vector_key,
    _vector_target,
)
from nexus_core.agent.react_types import (
    VECTOR_LOCKED_EVENT_TYPE,
    VECTOR_LOCK_SKIPPED_EVENT_TYPE,
    VECTOR_LOCK_WARNING_KIND,
    VECTOR_UNLOCKED_EVENT_TYPE,
)
from nexus_core.kernel.models import RiskLevel, ToolDefinition
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.tests.unit.test_hooks_lifecycle import context

TENANT = "system"
TARGET = "10.0.0.5"
CLARIFY = json.dumps(
    {"thought": "fin", "action": "request_clarification", "question": "¿Sigo?"}
)


# --------------------------------------------------------------------- helpers
def _call(tool_id: str, **arguments) -> str:
    return json.dumps(
        {"thought": "probando el vector", "action": "tool_call", "tool_id": tool_id,
         "arguments": arguments}
    )


def _nfs(marker: str) -> str:
    """Un intento *distinto* sobre el mismo vector (target), como en el log real.

    Las variaciones importan: una repetición byte-idéntica la intercepta antes el
    guard de V1-26 (``repeated_action``), no cuenta y el run nunca llega al
    umbral. En el log de la sala easy el modelo también variaba los argumentos
    del script en cada intento sobre NFS.
    """
    return _call("nexus.recon.nfs", target=TARGET, path=f"/{marker}")


class ScriptedLLM:
    """Modelo guionizado que recuerda el prompt exacto de cada turno."""

    supports_streaming = False

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[list[str]] = []

    async def complete(self, messages, **kwargs):
        self.prompts.append([str(getattr(message, "content", "")) for message in messages])
        answer = self.answers[min(len(self.prompts) - 1, len(self.answers) - 1)]
        return LLMResponse(content=answer, model="scripted", provider=LLMProvider.FAKE)


class ScriptedService:
    """ToolExecutionService guionizado: cada llamada devuelve el outcome pedido."""

    def __init__(self, *outcomes: str) -> None:
        self.outcomes = list(outcomes) or ["success"]
        self.calls: list[str] = []

    async def execute(self, payload, context, *, timeout, cancel_event):
        tool_id = str(payload["tool_id"])
        self.calls.append(tool_id)
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        return _invocation(tool_id, outcome), False


def _invocation(tool_id: str, outcome: str = "success") -> dict:
    return {
        "output": {
            "success": outcome == "success",
            "outcome": outcome,
            "output": {"tool": tool_id},
            "verification_method": "unit",
            "invocation_id": f"inv-{tool_id}",
            "assertions": [],
        }
    }


def _catalog(*specs: tuple[str, str | None]) -> dict:
    return {
        tool_id: (
            ToolDefinition(
                name=tool_id,
                tenant_id=TENANT,
                input_schema={},
                tool_id=tool_id,
                description=f"stub {tool_id}",
                risk=RiskLevel.LOW,
                effect="read_only",
                effects=("read",),
                scope_target_field=field,
            ),
            lambda arguments, ctx: None,
        )
        for tool_id, field in specs
    }


def _loop_context(tmp_path, monkeypatch) -> ExecutionContext:
    ctx = context(tmp_path, monkeypatch)
    run = ctx.store.create_run(TENANT, {})
    return ExecutionContext(
        ctx.store,
        {
            "id": "task",
            "tenant_id": TENANT,
            "run_id": run["id"],
            "task_type": "react.run",
            "payload": {
                "objective": "comprometer el objetivo",
                "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            },
        },
        "worker-test",
    )


def _coordinator(exec_ctx, llm, catalog, service, *, max_iterations: int = 10):
    return ReActCoordinator(
        context=exec_ctx,
        objective="comprometer el objetivo",
        engagement_id=None,
        llm_client=llm,
        tool_catalog=catalog,
        config=ReActConfig(max_iterations=max_iterations, enforce_completion_gates=False),
        tool_execution=service,
    )


def _messages(exec_ctx, coordinator, kind: str) -> list[dict]:
    history = memory.load_history(
        exec_ctx.store, TENANT, coordinator.conversation_id, limit=500
    )
    return [message for message in history if memory.message_kind(message) == kind]


def _events(exec_ctx, event_type: str) -> list[dict]:
    return [
        event
        for event in exec_ctx.store.list_run_events(TENANT, exec_ctx.run_id)
        if event.get("event_type") == event_type
    ]


def _observations(exec_ctx, coordinator) -> list[dict]:
    return [
        json.loads(str(message["content"]))
        for message in _messages(exec_ctx, coordinator, "react.observation")
    ]


NFS = ("nexus.recon.nfs", "target")
WEB = ("nexus.web.request", "url")
RECORD_FACT = ("nexus.knowledge.record_fact", None)
SHELL = ("nexus.shell.exec", None)


# ------------------------------------------------------------------- threshold 2
def test_two_failures_inject_warning(tmp_path, monkeypatch):
    """Dos fallos del mismo vector avisan en el turno siguiente, no en el quinto."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    llm = ScriptedLLM(_nfs("share"), _nfs("export"), CLARIFY)
    # ``partial`` es justo el outcome del handler NFS cuando el cliente falla.
    service = ScriptedService("partial", "partial", "success")
    coordinator = _coordinator(exec_ctx, llm, _catalog(NFS), service)

    asyncio.run(coordinator.run())

    warnings = _messages(exec_ctx, coordinator, VECTOR_LOCK_WARNING_KIND)
    assert len(warnings) == 1, "un aviso por vector, no uno por turno"
    content = str(warnings[0]["content"])
    assert "AVISO DEL SISTEMA" in content
    assert "`nexus.recon.nfs`" in content and TARGET in content
    assert "barrier" in content and "nexus.knowledge.record_fact" in content
    # El aviso llega al prompt del turno 3: el historial se reconstruye cada turno.
    assert len(llm.prompts) >= 3
    assert any("AVISO DEL SISTEMA" in text for text in llm.prompts[2])
    assert not any("AVISO DEL SISTEMA" in text for text in llm.prompts[1])

    event = _events(exec_ctx, VECTOR_LOCK_WARNING_KIND)
    assert len(event) == 1
    assert event[0]["payload"]["fail_count"] == 2
    assert event[0]["payload"]["tool_id"] == "nexus.recon.nfs"
    assert event[0]["payload"]["target"] == TARGET
    assert not _events(exec_ctx, VECTOR_LOCKED_EVENT_TYPE)


# ------------------------------------------------------------------- threshold 3
def test_three_failures_reject_call(tmp_path, monkeypatch):
    """La cuarta llamada al vector muerto no llega a ejecutarse."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    llm = ScriptedLLM(_nfs("a"), _nfs("b"), _nfs("c"), _nfs("d"), CLARIFY)
    service = ScriptedService("failed", "failed", "failed", "success")
    catalog = _catalog(NFS, WEB)
    coordinator = _coordinator(exec_ctx, llm, catalog, service)

    result = asyncio.run(coordinator.run())

    assert service.calls == ["nexus.recon.nfs"] * 3, "el 4º intento fue rechazado"
    refusal = _observations(exec_ctx, coordinator)[-1]
    assert refusal["error"] == "vector_locked"
    assert refusal["outcome"] == "vector_locked"
    assert TARGET in refusal["reason"]
    assert refusal["hint"] and "barrier" in refusal["hint"]
    assert refusal["failures"] == 3

    # Dos líneas distinguibles: el bloqueo que se arma (fail_count=3) y el
    # rechazo de la llamada siguiente (refused=true). Un run real necesita ambas
    # para saber qué cerró el vector y qué intentó el modelo después.
    locked = _events(exec_ctx, VECTOR_LOCKED_EVENT_TYPE)
    assert len(locked) == 2
    armed = next(item for item in locked if not item["payload"].get("refused"))
    refused = next(item for item in locked if item["payload"].get("refused"))
    assert armed["payload"]["fail_count"] == 3
    assert refused["payload"]["target"] == TARGET

    audit = [
        entry
        for entry in __import__(
            "nexus_core.kernel.audit", fromlist=["AuditWriter"]
        ).AuditWriter(exec_ctx.store).export(TENANT)
        if entry.get("payload", {}).get("reason") == "vector_locked"
        or entry.get("payload", {}).get("tool_id") == "nexus.recon.nfs"
    ]
    assert any(
        entry.get("decision") == "deny"
        and entry.get("payload", {}).get("reason") == "vector_locked"
        for entry in audit
    ), "el rechazo tiene que quedar auditado como deny/vector_locked"
    assert result.status == "clarification"


# ------------------------------------------------------------------------ resets
def test_different_tool_resets_counter(tmp_path, monkeypatch):
    """Un éxito HTTP sobre el mismo host devuelve el contador de NFS a cero."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    web = _call("nexus.web.request", url=f"http://{TARGET}/index.php")
    llm = ScriptedLLM(_nfs("a"), _nfs("b"), web, _nfs("c"), _nfs("d"), _nfs("e"), CLARIFY)
    service = ScriptedService("failed", "failed", "success", "failed", "failed", "success")
    coordinator = _coordinator(exec_ctx, llm, _catalog(NFS, WEB), service)

    asyncio.run(coordinator.run())

    assert service.calls == [
        "nexus.recon.nfs",
        "nexus.recon.nfs",
        "nexus.web.request",
        "nexus.recon.nfs",
        "nexus.recon.nfs",
        "nexus.recon.nfs",
    ], "tras el reset los dos fallos vuelven a ejecutarse, y el 6º no está bloqueado"
    assert not _events(exec_ctx, VECTOR_LOCKED_EVENT_TYPE)
    unlocked = _events(exec_ctx, VECTOR_UNLOCKED_EVENT_TYPE)
    assert [item["payload"]["reason"] for item in unlocked] == ["other_tool_success"]
    assert unlocked[0]["payload"]["target"] == TARGET


def test_barrier_resets_counter(tmp_path, monkeypatch):
    """``record_fact(barrier)`` reconoce el vector: lo desbloquea y lo reinicia."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    barrier = _call(
        "nexus.knowledge.record_fact",
        fact_type="barrier",
        key=f"{TARGET}:2049:tcp",
        value={"reason": "NFS sin exports útiles"},
    )
    llm = ScriptedLLM(_nfs("a"), _nfs("b"), barrier, _nfs("c"), _nfs("d"), _nfs("e"), CLARIFY)
    service = ScriptedService("failed", "failed", "success", "failed", "failed", "success")
    coordinator = _coordinator(exec_ctx, llm, _catalog(NFS, RECORD_FACT), service)

    asyncio.run(coordinator.run())

    assert service.calls[-3:] == ["nexus.recon.nfs"] * 3
    assert not _events(exec_ctx, VECTOR_LOCKED_EVENT_TYPE)
    unlocked = _events(exec_ctx, VECTOR_UNLOCKED_EVENT_TYPE)
    assert [item["payload"]["reason"] for item in unlocked] == ["barrier"]
    assert unlocked[0]["payload"]["target"] == TARGET


# ----------------------------------------------------------- target extraction
@pytest.mark.parametrize(
    "arguments,expected",
    [
        ({"target": TARGET}, TARGET),
        ({"url": f"https://{TARGET}:8443/admin.php?x=1"}, TARGET),
        ({"targets": [f"{TARGET}:80"]}, TARGET),
        ({"host": "Host.Example.COM"}, "host.example.com"),
        ({"command": f"mount -t nfs {TARGET}:/share /mnt"}, TARGET),
    ],
)
def test_target_extraction_from_arguments(arguments, expected):
    assert _vector_target(None, arguments)[0] == expected


def test_shell_exec_counts_per_binary_not_per_tool():
    """``shell.exec`` es un cajón de sastre: el lock es por binario, no por tool."""
    python, _ = _vector_key(
        "nexus.shell.exec", None, {"command": f"python3 -c 'import pynfs' {TARGET}:/share"}
    )
    curl, _ = _vector_key("nexus.shell.exec", None, {"command": f"curl -s http://{TARGET}/"})
    mount, _ = _vector_key("nexus.shell.exec", None, {"command": f"mount -t nfs {TARGET}:/x /mnt"})

    assert python == ("nexus.shell.exec", "python3", TARGET)
    assert curl == ("nexus.shell.exec", "curl", TARGET)
    assert mount == ("nexus.shell.exec", "mount", TARGET)
    assert _shell_subcommand(f"sudo -u root bash -c 'curl http://{TARGET}'") == ""


def test_ambiguous_command_is_logged_and_not_counted(tmp_path, monkeypatch):
    """Dos IPs en el comando: no se atribuye el fallo a un vector."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    first = _call("nexus.shell.exec", command=f"nmap {TARGET}; curl http://10.0.0.6/a")
    second = _call("nexus.shell.exec", command=f"nmap {TARGET}; curl http://10.0.0.6/b")
    llm = ScriptedLLM(first, second, CLARIFY)
    service = ScriptedService("failed", "failed")
    coordinator = _coordinator(exec_ctx, llm, _catalog(SHELL), service)

    asyncio.run(coordinator.run())

    skipped = _events(exec_ctx, VECTOR_LOCK_SKIPPED_EVENT_TYPE)
    assert len(skipped) == 2
    assert set(skipped[0]["payload"]["detected_targets"]) == {TARGET, "10.0.0.6"}
    assert not _events(exec_ctx, VECTOR_LOCK_WARNING_KIND)


def test_unattributable_shell_command_is_warned_but_never_locked(tmp_path, monkeypatch):
    """Fallback A: ``bash -c`` no se puede atribuir, así que solo avisa."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    commands = [
        _call("nexus.shell.exec", command=f"bash -c 'curl http://{TARGET}/{marker}'")
        for marker in ("a", "b", "c", "d")
    ]
    llm = ScriptedLLM(*commands, CLARIFY)
    service = ScriptedService("failed", "failed", "failed", "success")
    coordinator = _coordinator(exec_ctx, llm, _catalog(SHELL), service)

    asyncio.run(coordinator.run())

    assert service.calls == ["nexus.shell.exec"] * 4, "sin atribución no hay lock"
    assert _events(exec_ctx, VECTOR_LOCK_WARNING_KIND)
    assert not _events(exec_ctx, VECTOR_LOCKED_EVENT_TYPE)


# ------------------------------------------------------------- open vectors

def test_open_vectors_include_endpoints_without_state(tmp_path, monkeypatch):
    """El aviso tiene que nombrar HTTP: un endpoint no lleva ``state``."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    board = __import__(
        "nexus_core.kernel.blackboard", fromlist=["Blackboard"]
    ).Blackboard(exec_ctx.store)
    base = dict(tenant_id=TENANT, engagement_id="eng-1", source="unit", created_by="unit")
    board.record(
        fact_type="service", key=f"{TARGET}:2049:tcp",
        value={"state": "open", "port": 2049, "protocol": "tcp", "service": "nfs"}, **base
    )
    board.record(
        fact_type="service", key=f"{TARGET}:22:tcp",
        value={"state": "closed", "port": 22, "protocol": "tcp", "service": "ssh"}, **base
    )
    board.record(
        fact_type="endpoint", key=f"http://{TARGET}/",
        value={"status_code": 200, "url": f"http://{TARGET}/", "tech": ["Apache"]}, **base
    )
    board.record(
        fact_type="endpoint", key=f"http://{TARGET}/boom",
        value={"status_code": 500, "url": f"http://{TARGET}/boom"}, **base
    )
    coordinator = _coordinator(exec_ctx, ScriptedLLM(CLARIFY), _catalog(NFS), ScriptedService())
    coordinator.store = exec_ctx.store
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = "eng-1"

    vectors = coordinator._open_vectors()

    suggested = {item["key"]: item["suggested_tool"] for item in vectors}
    assert suggested[f"{TARGET}:2049:tcp"] == "nexus.recon.nfs"
    assert suggested[f"http://{TARGET}/"] == "nexus.web.request", (
        "un endpoint 200 sin ``state`` es un vector abierto y su tool es web.request"
    )
    assert f"{TARGET}:22:tcp" not in suggested, "un puerto cerrado no es un vector"
    assert f"http://{TARGET}/boom" not in suggested, "un 5xx no es un vector abierto"


# --------------------------------------------------------------- outcome rules
def test_partial_counts_as_a_failure_even_with_success_true():
    """El contador no depende de ``success``: ``partial`` es veredicto del vector."""
    assert _is_vector_failure({"success": True, "outcome": "partial"})
    assert _is_vector_failure({"success": False, "outcome": "failed"})
    assert _is_vector_failure({"success": False, "outcome": ""})
    # Ni la gobernanza ni el comando fallido son veredictos sobre el vector.
    assert not _is_vector_failure({"success": False, "outcome": "scope_denied"})
    assert not _is_vector_failure({"success": False, "outcome": "command_failed"})
    assert not _is_vector_failure({"success": False, "outcome": "governance_denial"})
