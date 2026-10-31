"""FIX 3: resurrección de una tool retirada por *insistencia*, no por avería.

Medido en hijack_v4 (``run_83a6185d8c5240f9948beae31b837454``): las iteraciones
27, 28 y 29 repitieron el mismo POST sobre ``login.php``; los tres turnos fueron
rechazos (``repeated_barren_action``), la llamada nunca se ejecutó, y aun así el
contador de fallos de ``nexus.web.request`` llegó a 3 y la retiró para el resto
del run. En la iteración 30 la credencial apareció, y era inutilizable: la única
tool que consume un ``session_ref`` estaba apagada.

El contrato que fijan estas pruebas: una tool retirada por rechazo vuelve **una
vez** cuando el tablero cambia (llega ``credential``/``session``/``vulnerability``);
una tool ausente del entorno (``binary_missing``) o rota de verdad no vuelve
nunca; y no hay ping-pong entre rechazo y hecho nuevo.
"""

from __future__ import annotations

import asyncio

from nexus_core.agent.react import ReActConfig
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.react_types import TOOL_RESURRECTED_EVENT_TYPE
from nexus_core.tests.unit.test_react_pivot_forcing import (
    CLARIFY,
    ScriptedLLM,
    ScriptedService,
    _call,
    _catalog,
    _events,
    _loop_context,
    _observations,
)

WEB = ("nexus.web.request", "url")
RECORD_FACT = ("nexus.knowledge.record_fact", None)
NFS = ("nexus.recon.nfs", "target")
LOGIN_URL = "http://10.0.0.5/login.php"


def _coordinator(exec_ctx, llm, catalog, service, **kwargs):
    return ReActCoordinator(
        context=exec_ctx,
        objective="comprometer el objetivo",
        engagement_id=None,
        llm_client=llm,
        tool_catalog=catalog,
        config=ReActConfig(max_iterations=len(llm.answers) + 1, enforce_completion_gates=False),
        tool_execution=service,
        **kwargs,
    )


# ------------------------------------- hijack_v7: registrar lo que ya está escrito
def test_a_record_fact_the_verifier_already_proved_never_reaches_the_tool(
    tmp_path, monkeypatch
):
    """Nine turns re-recording the nmap services, refused before they run."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    catalog = _catalog(RECORD_FACT)
    llm = ScriptedLLM(
        _call(
            "nexus.knowledge.record_fact",
            fact_type="service",
            key="10.0.0.5:21:tcp",
            value={"port": "21", "service": "ftp", "state": "open"},
        ),
        CLARIFY,
    )
    service = ScriptedService("success")
    coordinator = _coordinator(exec_ctx, llm, catalog, service)
    coordinator._blackboard_facts = lambda: [
        {
            "fact_type": "service",
            "key": "10.0.0.5:21:tcp",
            "value": {"port": "21", "service": "ftp", "state": "open"},
            "verified": True,
        }
    ]

    asyncio.run(coordinator.run())

    assert service.calls == []
    observations = _observations(exec_ctx, coordinator)
    refused = [obs for obs in observations if obs.get("outcome") == "redundant_fact"]
    assert refused and "YA está en la pizarra" in refused[0]["guidance"]


def _credential_fact() -> str:
    return _call(
        "nexus.knowledge.record_fact",
        fact_type="credential",
        key="cred:http-post-form:admin@10.0.0.5",
        value={"username": "admin", "secret_ref": "vault:" + "a" * 32},
    )


# ------------------------------------------------------------------ resurrección
def test_refusal_retirement_resurrects_on_new_credential(tmp_path, monkeypatch):
    """Tres rechazos retiran la tool; la credencial siguiente la devuelve."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    llm = ScriptedLLM(
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _credential_fact(),
        _call("nexus.web.request", url=LOGIN_URL),
        CLARIFY,
    )
    service = ScriptedService("failed", "success", "success")
    coordinator = _coordinator(exec_ctx, llm, _catalog(WEB, RECORD_FACT), service)

    asyncio.run(coordinator.run())

    # El primer POST falló de verdad; los tres siguientes fueron rechazos que no
    # llegaron al servicio y armaron la retirada (el contador de rechazos empieza
    # en cero: el fallo del primer POST no lo mueve). El último POST sí se ejecutó:
    # la tool volvió.
    assert service.calls == ["nexus.web.request", "nexus.knowledge.record_fact",
                             "nexus.web.request"], "solo 3 llamadas ejecutadas"
    assert "nexus.web.request" not in coordinator.unavailable_tools
    resurrected = _events(exec_ctx, TOOL_RESURRECTED_EVENT_TYPE)
    assert len(resurrected) == 1
    payload = resurrected[0]["payload"]
    assert payload["tools"] == ["nexus.web.request"]
    assert payload["reason"] == "new_context"
    assert payload["fact_types"] == ["credential"]
    # La observación del hecho nuevo ya anuncia la tool devuelta: el prompt del
    # turno siguiente la ofrece sin esperar a otro evento.
    fact_result = [
        item for item in _observations(exec_ctx, coordinator)
        if "nexus.web.request" in (item.get("available_tools") or [])
    ]
    assert fact_result, "la observación del credential debe listar la tool devuelta"


class _CredentialAssertingService:
    """Como el verifier real: ``cred.bruteforce`` asserta el ``credential``.

    En hijack_v4 la credencial no entró por ``record_fact`` sino por la assertion
    que el verifier adjunta a la invocación de la tool, así que ese es el camino
    que hay que cubrir.
    """

    def __init__(self, *outcomes: str) -> None:
        self.scripted = ScriptedService(*outcomes)

    @property
    def calls(self) -> list[str]:
        return self.scripted.calls

    async def execute(self, payload, context, *, timeout, cancel_event):
        invocation, awaited = await self.scripted.execute(
            payload, context, timeout=timeout, cancel_event=cancel_event
        )
        if str(payload["tool_id"]) == "nexus.cred.bruteforce":
            invocation["output"]["assertions"] = [
                {
                    "asserted_by": "verifier",
                    "fact_type": "credential",
                    "key": "cred:http-post-form:admin@10.0.0.5",
                    "value": {"secret_ref": "vault:" + "b" * 32},
                    "verified": True,
                }
            ]
        return invocation, awaited


def test_credential_assertion_resurrects_the_tool(tmp_path, monkeypatch):
    """La assertion del verifier (no solo ``record_fact``) devuelve la tool."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    llm = ScriptedLLM(
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.cred.bruteforce", target="10.0.0.5", username="admin"),
        _call("nexus.web.request", url=LOGIN_URL),
        CLARIFY,
    )
    service = _CredentialAssertingService("failed", "success", "success")
    coordinator = _coordinator(
        exec_ctx, llm, _catalog(WEB, ("nexus.cred.bruteforce", "target")), service
    )

    asyncio.run(coordinator.run())

    assert service.calls == [
        "nexus.web.request", "nexus.cred.bruteforce", "nexus.web.request"
    ]
    payload = _events(exec_ctx, TOOL_RESURRECTED_EVENT_TYPE)[0]["payload"]
    assert payload["tools"] == ["nexus.web.request"]
    assert payload["fact_types"] == ["credential"]


def test_binary_missing_tool_is_never_resurrected(tmp_path, monkeypatch):
    """Una tool que no existe no vuelve porque llegue una credencial."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    llm = ScriptedLLM(
        _credential_fact(),
        _call("nexus.recon.nfs", target="10.0.0.5", action="list"),
        CLARIFY,
    )
    service = ScriptedService("success")
    coordinator = _coordinator(
        exec_ctx, llm, _catalog(NFS, RECORD_FACT), service,
        initial_unavailable_tools={"nexus.recon.nfs"},
    )

    asyncio.run(coordinator.run())

    assert service.calls == ["nexus.knowledge.record_fact"], "nfs nunca se ejecutó"
    assert not _events(exec_ctx, TOOL_RESURRECTED_EVENT_TYPE)
    assert "nexus.recon.nfs" in coordinator.unavailable_tools


def test_resurrection_is_granted_once_per_run(tmp_path, monkeypatch):
    """Tras volver una vez, otra racha de rechazos ya no la devuelve."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    llm = ScriptedLLM(
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url=LOGIN_URL),
        _credential_fact(),
        _call("nexus.web.request", url=LOGIN_URL),
        _call("nexus.web.request", url="http://10.0.0.5/admin.php"),
        _call("nexus.web.request", url="http://10.0.0.5/admin.php"),
        _call("nexus.web.request", url="http://10.0.0.5/admin.php"),
        _call("nexus.web.request", url="http://10.0.0.5/admin.php"),
        _credential_fact(),
        CLARIFY,
    )
    service = ScriptedService("failed", "success", "success", "failed", "success")
    coordinator = _coordinator(exec_ctx, llm, _catalog(WEB, RECORD_FACT), service)

    asyncio.run(coordinator.run())

    assert len(_events(exec_ctx, TOOL_RESURRECTED_EVENT_TYPE)) == 1
    assert "nexus.web.request" in coordinator.unavailable_tools, "la segunda racha la retira"
