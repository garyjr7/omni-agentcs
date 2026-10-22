"""Dos muros medidos en DeadDrop P10 (2026-10-22), y qué hace el loop con ellos.

* **El barrido sin ruta** - con SSH probado en ``192.168.11.200`` y sin túnel, el
  ``nmap`` contra el DC ``192.168.11.100`` gastó sus 600 s y no devolvió nada; la
  orden de pivote llegó *después*, porque ``pivot_hint`` lee el historial. El gate
  evalúa la llamada pendiente: con una sonda TCP de un segundo, niega el barrido y
  entrega la orden del túnel en vez de pagar el timeout.
* **El replay cercado** - un ``ssh_exec`` que expiró quedó ``unknown`` en el
  journal, y el reintento idéntico recibió ``unknown invocation requires human
  approval``. La negativa es correcta; cerrar el run con la sala aún arriba (exit
  2) no lo es. La negativa es una observación, y la insistencia es lo que cierra el
  run -como ya pasaba con una denegación de alcance-.

Los dos se prueban con el loop real, el store real y la capa de tools espiada: lo
que importa es si el run sobrevive y qué lee el modelo, no el texto de una función.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from nexus_core.agent import reachability
from nexus_core.agent.react import STATUS_BLOCKED, STATUS_COMPLETED, run_react_loop
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ReplayApprovalRequired
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.tests.unit.test_phase3b_fixes import (
    ScriptedLLM,
    _config,
    _create_scope,
    _observations,
)
from nexus_core.tests.unit.test_phase3g_fixes import (
    _PayloadSpy,
    _task_complete,
    mock_execute_tool,
)

pytestmark = [pytest.mark.usefixtures("lab_scope")]

#: The measured shape: a DMZ host the operator reached, and the DC behind it.
ACCESS_HOST = "10.0.0.200"
DC = "10.0.0.5"


def _call(tool_id: str, **arguments: Any) -> str:
    return json.dumps(
        {
            "thought": "Siguiente paso del reconocimiento.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments,
            "expected_outcome": "datos del objetivo",
        }
    )


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "routing.db")
    store.initialize()
    _create_scope(store, "eng-1")
    run = store.create_run("system", {})
    task = {
        "id": "task-routing-gates",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Llega al DC desde el host de acceso",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [
                "execute:tool:nexus.recon.nmap",
                "execute:tool:nexus.post.ssh_exec",
            ],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _no_route(monkeypatch) -> None:
    """The operator has no route: the probe answers False, as the measured run did."""

    async def unreachable(host: str, ports=None, **kwargs: Any) -> bool:
        return False

    monkeypatch.setattr(reachability, "host_reachable", unreachable)


def _events(store, run_id: str, event_type: str) -> list[dict]:
    return [
        event
        for event in store.list_run_events("system", run_id)
        if event.get("event_type") == event_type
    ]


# ------------------------------------------------------------------ pivot gate


async def test_a_sweep_without_a_route_is_refused_before_it_spends_its_timeout(
    harness, monkeypatch
):
    """P10: 600 s de ``nmap`` contra el DC y la orden del túnel solo al final.

    El gate lee la llamada pendiente, no el historial: la sonda no encuentra
    ningún puerto abierto, así que el barrido no puede devolver nada y se niega con
    la orden exacta (``ssh -D`` + ``proxychains4``). El ``nmap`` contra el DC nunca
    llega a la capa de tools.
    """
    store, context_ = harness
    _no_route(monkeypatch)
    llm = ScriptedLLM(
        [
            _call("nexus.recon.nmap", target=ACCESS_HOST, flags=["-Pn"]),
            _call(
                "nexus.post.ssh_exec",
                target=ACCESS_HOST,
                username="svc-drop",
                command="id",
            ),
            _call("nexus.recon.nmap", target=DC, flags=["-Pn"]),
            _task_complete(),
        ]
    )
    spy = _PayloadSpy({})

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Llega al DC desde el host de acceso",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=8),
        )

    assert result.status == STATUS_COMPLETED
    # Two calls ran (the DMZ sweep and the shell); the sweep of the DC did not.
    assert len(spy.payloads) == 2
    assert all(DC not in json.dumps(payload) for payload in spy.payloads)

    observations = _observations(store, result.conversation_id)
    order = [item for item in observations if "PIVOTE NECESARIO" in item]
    assert order, "the model must read the tunnel order on the next prompt"
    assert "ssh -f -N -D 1080" in order[0]
    assert "proxychains4" in order[0]
    assert "unroutable_target" in order[0]
    assert "refused_before_execution" in order[0]

    gates = _events(store, context_.run_id, "react.pivot_gate")
    assert len(gates) == 1
    assert gates[0]["payload"]["target"] == DC
    assert gates[0]["payload"]["aborted"] is False


async def test_insisting_on_the_unroutable_sweep_closes_the_run_as_blocked(
    harness, monkeypatch
):
    """Un aviso no cierra el run; tres barridos negados seguidos sí.

    Y cierra como ``blocked`` sobre el túnel, que es lo que el operador tiene que
    abrir: no se disfraza de fallo del run ni de éxito parcial.
    """
    store, context_ = harness
    _no_route(monkeypatch)
    llm = ScriptedLLM(
        [
            _call("nexus.recon.nmap", target=ACCESS_HOST, flags=["-Pn"]),
            _call(
                "nexus.post.ssh_exec",
                target=ACCESS_HOST,
                username="svc-drop",
                command="id",
            ),
            _call("nexus.recon.nmap", target=DC),
            _call("nexus.recon.nmap", target="10.0.0.6"),
            _call("nexus.recon.nmap", target="10.0.0.7"),
        ]
    )
    spy = _PayloadSpy({})

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Llega al DC desde el host de acceso",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=10),
        )

    assert result.status == STATUS_BLOCKED
    assert "pivot" in result.final_summary
    assert len(spy.payloads) == 2
    gates = _events(store, context_.run_id, "react.pivot_gate")
    assert [gate["payload"]["aborted"] for gate in gates] == [False, False, True]


# ------------------------------------------------------------------ replay fence


# ------------------------------------------------------- the probe itself
# The gate is only as good as the measurement under it. Measured against the live
# room (2026-10-22): the DMZ answers 22 in 0.18 s and 80 in 0.40 s, the DC stays
# silent on every port. The first version of the probe shared one deadline between
# the ports and the ceiling, so the gather always expired first and the fail-open
# branch called the black hole reachable -the gate could never fire-.


@pytest.fixture(autouse=True)
def _empty_probe_cache():
    reachability.clear_cache()
    yield
    reachability.clear_cache()


def test_the_per_port_deadline_lands_inside_the_ceiling():
    assert reachability.PROBE_PORT_TIMEOUT_SECONDS < reachability.PROBE_TIMEOUT_SECONDS


async def test_a_silent_host_is_unreachable(monkeypatch):
    asked: list[tuple[str, int, float]] = []

    async def silent(host: str, port: int, timeout: float) -> bool:
        asked.append((host, port, timeout))
        return False

    monkeypatch.setattr(reachability, "_probe_port", silent)

    assert await reachability.host_reachable(DC, (22, 445)) is False
    assert [port for _, port, _ in asked] == [22, 445]
    assert all(timeout <= reachability.PROBE_TIMEOUT_SECONDS for _, _, timeout in asked)


async def test_one_open_port_is_enough(monkeypatch):
    async def http_only(host: str, port: int, timeout: float) -> bool:
        return port == 80

    monkeypatch.setattr(reachability, "_probe_port", http_only)
    assert await reachability.host_reachable(ACCESS_HOST, (22, 80)) is True


async def test_a_broken_probe_fails_open(monkeypatch):
    """A probe that broke must never be the reason a valid sweep is denied."""

    async def broken(host: str, port: int, timeout: float) -> bool:
        raise RuntimeError("no se pudo abrir el socket")

    monkeypatch.setattr(reachability, "_probe_port", broken)
    assert await reachability.host_reachable(DC, (22,)) is True


async def test_the_verdict_is_cached_for_the_next_turn(monkeypatch):
    calls = {"count": 0}

    async def silent(host: str, port: int, timeout: float) -> bool:
        calls["count"] += 1
        return False

    monkeypatch.setattr(reachability, "_probe_port", silent)

    assert await reachability.host_reachable(DC, (22, 445)) is False
    assert await reachability.host_reachable(DC, (22, 445)) is False
    assert calls["count"] == 2, "the second turn must not probe again"


async def test_a_fenced_replay_is_an_observation_and_the_run_continues(harness):
    """P10 iteración 47: la negativa era correcta, cerrar el run no.

    El journal sigue negando el reintento idéntico de una invocación cuyo efecto
    es desconocido; lo que cambia es la consecuencia: el modelo lee qué hacer en su
    lugar (cambiar los argumentos, que es otra intención) y el run sigue.
    """
    store, context_ = harness
    refusal = ReplayApprovalRequired(
        "unknown invocation requires human approval: ssh_exec id"
    )
    llm = ScriptedLLM(
        [_call("nexus.recon.nmap", target=ACCESS_HOST), _task_complete()]
    )

    class _RefusingSpy:
        def __init__(self) -> None:
            self.payloads: list[dict] = []

        async def __call__(self, payload, context):
            self.payloads.append(payload)
            raise refusal

    spy = _RefusingSpy()

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Reconoce el host de acceso",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    assert result.status != STATUS_BLOCKED
    assert "requires human approval" not in result.final_summary

    observations = _observations(store, result.conversation_id)
    correction = [item for item in observations if "replay_refused" in item]
    assert correction, "the model must read the replay correction"
    assert "no se ha vuelto a ejecutar" in correction[0]
    assert "DESCONOCIDO" in correction[0]
    assert "cambia los argumentos" in correction[0]

    refused = _events(store, context_.run_id, "react.replay_refused")
    assert len(refused) == 1
    assert refused[0]["payload"]["aborted"] is False


async def test_three_fenced_replays_close_the_run_as_blocked(harness):
    """Un modelo que solo sabe repetir la misma invocación sí cierra el run.

    La negativa no se convierte en un bucle infinito: tres replays negados seguidos
    dejan el run ``blocked`` sobre la aprobación que falta, con la causa escrita.
    """
    store, context_ = harness
    llm = ScriptedLLM(
        [
            _call("nexus.recon.nmap", target=ACCESS_HOST),
            _call("nexus.recon.nmap", target="10.0.0.6"),
            _call("nexus.recon.nmap", target="10.0.0.7"),
        ]
    )

    class _RefusingSpy:
        def __init__(self) -> None:
            self.payloads: list[dict] = []

        async def __call__(self, payload, context):
            self.payloads.append(payload)
            raise ReplayApprovalRequired("unknown invocation requires human approval")

    spy = _RefusingSpy()

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Reconoce el host de acceso",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=8),
        )

    assert result.status == STATUS_BLOCKED
    assert "unconfirmed" in result.final_summary
    refused = _events(store, context_.run_id, "react.replay_refused")
    assert [event["payload"]["aborted"] for event in refused] == [False, False, True]
