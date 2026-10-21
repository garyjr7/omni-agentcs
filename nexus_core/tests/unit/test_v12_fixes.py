"""HackPark V12 walls (``run_66db1fce65b2465eb799a53d0f9299b2``), as regressions.

Five measured defects are pinned here, each with the number that proved it:

* **R1** — ``--max-iterations 50`` bought 21 turns: the token ceiling was a fixed
  250 000 while a turn costs ~12 000 (252 294 spent, status ``budget_exceeded``).
* **R2** — an operator-activated skill sent its whole body on every turn.
* **R4** — one ``URLError: timed out`` aborted the 5 000-password CSRF sweep after
  75 attempts (55 s) and was reported as ``unavailable``.
* **R6** — a barrier the model wrote after two *argument* rejections closed the
  only working branch (``sweep_attempted: false``).
* **R7** — those two rejections fed ``consecutive_no_progress`` until
  ``react.stuck_detected`` pivoted the run to RDP.

No test here touches a real target: the sweeps run against a local HTTP server.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.coverage import (
    STATUS_CLOSED,
    barrier_is_conclusive,
    build_coverage,
)
from nexus_core.agent.react import ReActConfig, _budget_tokens, run_react_loop
from nexus_core.agent.react_coordinator import MAX_FREE_ARGUMENT_REJECTIONS
from nexus_core.agent.react_support import (
    DEFAULT_RUN_BUDGET_TOKENS,
    MEASURED_TOKENS_PER_TURN,
    budget_tokens_for_iterations,
)
from nexus_core.agent.skills import Skill, render_skills
from nexus_core.cli.headless import token_accounting
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers.cred_bruteforce import cred_bruteforce_handler
from nexus_core.tools.handlers.knowledge_facts import record_fact_handler

TENANT = "system"
ENGAGEMENT = "eng-v12"

# The loop tests build an unsigned engagement scope, which the lab mode accepts
# (same convention as ``test_run_budget.py``/``test_react_degradation.py``).
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id=ENGAGEMENT,
        tenant_id=TENANT,
        name="v12",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("10.0.0.0/24",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


# --------------------------------------------------------------------------- R1


def test_the_budget_follows_the_iteration_ceiling(monkeypatch):
    """50 turns must buy 50 turns, not the 21 a fixed 250k bought in V12."""
    monkeypatch.delenv("NEXUS_RUN_BUDGET_TOKENS", raising=False)
    budget = budget_tokens_for_iterations(50)
    assert budget >= 50 * MEASURED_TOKENS_PER_TURN
    assert budget == int(50 * MEASURED_TOKENS_PER_TURN * 1.2 + 0.999)
    assert _budget_tokens({}, None, max_iterations=50) == budget


def test_the_default_iteration_count_keeps_the_reviewed_ceiling(monkeypatch):
    """A 12-turn run still gets 250k: the derivation may only grow the budget."""
    monkeypatch.delenv("NEXUS_RUN_BUDGET_TOKENS", raising=False)
    assert budget_tokens_for_iterations(12) == DEFAULT_RUN_BUDGET_TOKENS
    assert _budget_tokens({}, None) == DEFAULT_RUN_BUDGET_TOKENS


def test_an_explicit_budget_still_wins(monkeypatch):
    monkeypatch.delenv("NEXUS_RUN_BUDGET_TOKENS", raising=False)
    assert _budget_tokens({}, 900, max_iterations=50) == 900
    assert _budget_tokens({"budget_tokens": 0}, None, max_iterations=50) == 0
    monkeypatch.setenv("NEXUS_RUN_BUDGET_TOKENS", "700")
    assert _budget_tokens({}, None, max_iterations=50) == 700


def test_the_run_publishes_tokens_per_turn_and_budget_turns():
    """``run.complete`` must say whether the ceiling or the model was the limit."""
    turns = [{"total_tokens": 12_000}, {"total_tokens": 10_000}]
    result = SimpleNamespace(
        status="budget_exceeded", iterations=2, final_summary="", findings=[],
        subagent_id=None, conversation_id="", plan=None, turns=turns,
        budget_tokens=141_600, budget_used=22_000,
    )
    payload = token_accounting(result)
    assert payload["tokens_per_turn"] == 11_000
    assert payload["budget_turns"] == 141_600 // 11_000
    assert payload["tokens_spent"] == 22_000


# --------------------------------------------------------------------------- R2


def _skill(body: str = "cuerpo", name: str = "demo") -> Skill:
    return Skill(
        name=name,
        path=f".agents/skills/{name}/SKILL.md",
        sha256="a" * 64,
        content=body,
        trust="unsigned",
        signals=(),
        signed=False,
    )


def test_a_skill_body_is_rendered_only_when_it_is_due():
    body = "# Demo\n\nIntroduce la receta.\n\nBODY-MARKER\n" + ("paso\n" * 200)
    skill = _skill(body)

    first = render_skills([skill], bodies={skill.name})
    assert "BODY-MARKER" in first
    assert "Introduce la receta." in first

    later = render_skills([skill], bodies=set())
    assert "BODY-MARKER" not in later
    assert "demo" in later
    assert "ya entregada en este run" in later

    # ``bodies=None`` keeps the historical contract for other callers.
    assert "BODY-MARKER" in render_skills([skill])


# --------------------------------------------------------------------------- R4


class _FlakyLoginHandler(http.server.BaseHTTPRequestHandler):
    """ASP.NET-shaped login that drops one POST in every ``drop_every`` ones.

    ``drop_after`` makes the server drop *everything* from that request on, which
    is how the partial/abort path is exercised without waiting for a socket
    timeout.
    """

    viewstate = "VS-v12"
    eventvalidation = "EV-v12"
    drop_every = 0
    drop_after = 10**9
    posts_seen = 0

    def _send(self, status: int, body: str, *, cookie: str | None = None) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def _drop(self) -> bool:
        return type(self).posts_seen > type(self).drop_after

    def do_GET(self):  # noqa: N802 - stdlib naming
        if not self.path.startswith("/Account/login.aspx"):
            self._send(404, "not found")
            return
        self._send(
            200,
            (
                '<form method="post" action="/Account/login.aspx">'
                f'<input type="hidden" name="__VIEWSTATE" value="{self.viewstate}">'
                f'<input type="hidden" name="__EVENTVALIDATION" value="{self.eventvalidation}">'
                "</form>"
            ),
            cookie="ASP.NET_SessionId=v12-session; path=/; HttpOnly",
        )

    def do_POST(self):  # noqa: N802 - stdlib naming
        type(self).posts_seen += 1
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        every = type(self).drop_every
        if self._drop() or (every and type(self).posts_seen % every == 5):
            # Cut the connection without a response: the client sees a transport
            # failure, exactly like the ``URLError: timed out`` of the V12 run.
            self.close_connection = True
            return
        from urllib.parse import parse_qs

        fields = parse_qs(body)
        cookie = self.headers.get("Cookie") or ""
        tokens_ok = (
            fields.get("__VIEWSTATE") == [self.viewstate]
            and fields.get("__EVENTVALIDATION") == [self.eventvalidation]
        )
        password = (fields.get("ctl00$MainContent$LoginUser$Password") or [""])[0]
        if tokens_ok and "ASP.NET_SessionId=v12-session" in cookie and password == "hackpark":
            self._send(200, "Welcome admin")
        else:
            self._send(200, "Login failed")

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def _csrf_arguments(server: http.server.HTTPServer, wordlist: str) -> dict:
    return {
        "target": "127.0.0.1",
        "port": server.server_address[1],
        "service": "http-post-form",
        "username": "admin",
        "password_file": wordlist,
        "form_url": "/Account/login.aspx",
        "form_params": (
            "ctl00$MainContent$LoginUser$UserName=^USER^"
            "&ctl00$MainContent$LoginUser$Password=^PASS^"
        ),
        "failure_string": "Login failed",
        "csrf_mode": True,
    }


def _ctx() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _serve(handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _stop(server) -> None:
    server.shutdown()
    server.server_close()


def test_a_cut_request_does_not_abort_the_sweep(tmp_path, monkeypatch):
    """V12: one ``URLError`` at attempt 75 of 5 000 ended the whole slice.

    The wordlist is the room's own size (1 420 entries, ``1qaz2wsx`` last) and one
    POST in every ten is cut: the sweep must still reach the last entry.
    """
    entries = [f"wrong{i}" for i in range(1419)] + ["hackpark"]
    (tmp_path / "rockyou.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    _FlakyLoginHandler.posts_seen = 0
    _FlakyLoginHandler.drop_every = 10
    _FlakyLoginHandler.drop_after = 10**9
    server = _serve(_FlakyLoginHandler)
    try:
        result = asyncio.run(
            cred_bruteforce_handler(_csrf_arguments(server, "rockyou.txt"), _ctx())
        )
    finally:
        _stop(server)

    assert result.verified is True
    assert result.verification_method == "cred_bruteforce_csrf_completed"
    # Every cut connection is retried for the *same* entry, so nothing is lost
    # and the whole wordlist is really tested: before R4 the first cut ended the
    # run at attempt 75 with 4 925 passwords never tried.
    assert result.evidence["tested"] == 1_420
    assert result.evidence["request_timeouts"] == 0
    assert result.evidence["attempts_per_second"] > 0
    credential = result.output["valid_credentials"][0]
    assert credential["username"] == "admin"


def test_a_client_that_tested_something_is_partial_not_unavailable(tmp_path, monkeypatch):
    """V12 reported ``unavailable`` after 75 attempts: the model read "tool broken".

    A client that ran and then lost the target is ``partial`` with the offset to
    resume from, never ``unavailable`` (which the loop treats as a broken tool).
    """
    (tmp_path / "words.txt").write_text(
        "\n".join(f"wrong{i}" for i in range(20)) + "\n", encoding="utf-8"
    )
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    _FlakyLoginHandler.posts_seen = 0
    _FlakyLoginHandler.drop_every = 0
    # The probe POST is #1; attempts #2 and #3 run, then everything is cut.
    _FlakyLoginHandler.drop_after = 3
    server = _serve(_FlakyLoginHandler)
    try:
        result = asyncio.run(
            cred_bruteforce_handler(_csrf_arguments(server, "words.txt"), _ctx())
        )
    finally:
        _stop(server)

    assert result.outcome == "partial"
    assert result.verification_method == "cred_bruteforce_csrf_aborted"
    tested = int(result.output["tested"])
    assert tested >= 1
    assert result.output["next_start_at"] == tested
    assert result.evidence["request_timeouts"] >= 10
    assert "start_at=" in result.output["message"]


# --------------------------------------------------------------------------- R6


def _service_fact() -> dict:
    """The ``service`` fact exactly as ``nmap`` writes it (``host:port:proto``)."""
    return {
        "fact_type": "service",
        "key": "10.65.170.171:80:tcp",
        "value": {"port": "80", "protocol": "tcp", "service": "http", "state": "open"},
        "verified": True,
        "recorded_at": "2026-10-21T19:57:00+00:00",
    }


def test_the_v12_barrier_does_not_close_the_branch():
    """Iteration 17: "bruteforce returned no session" with ``sweep_attempted: false``."""
    barrier = {
        "fact_type": "barrier",
        "key": "10.65.170.171:80",
        "value": {
            "service": "http",
            "reason": "el bruteforce no ha devuelto sesión",
            "sweep_attempted": False,
            "outcome": "invalid_failure_string",
        },
        "verified": False,
        "recorded_at": "2026-10-21T20:03:07+00:00",
    }
    coverage = build_coverage([_service_fact(), barrier])
    entry = coverage.find("10.65.170.171:80")
    assert entry is not None
    assert entry.status != STATUS_CLOSED
    assert entry.status in {"pendiente", "sondeado"}


def test_a_finished_sweep_still_closes_its_branch():
    barrier = {
        "fact_type": "barrier",
        "key": "10.65.170.171:80",
        "value": {"reason": "5000 intentos sin acierto", "sweep_attempted": True,
                  "outcome": "negative"},
        "verified": False,
        "recorded_at": "2026-10-21T20:03:07+00:00",
    }
    coverage = build_coverage([_service_fact(), barrier])
    assert coverage.find("10.65.170.171:80").status == STATUS_CLOSED


@pytest.mark.parametrize(
    "value",
    [
        {"sweep_attempted": False},
        {"outcome": "invalid_failure_string"},
        {"outcome": "invalid_csrf"},
        {"outcome": "unavailable"},
        {"outcome": "rejected"},
        {"outcome": "partial"},
        {"outcome": "timeout"},
    ],
)
def test_an_inconclusive_barrier_never_closes_a_branch(value):
    assert barrier_is_conclusive({"value": value}) is False


def test_a_legacy_barrier_without_provenance_keeps_closing():
    assert barrier_is_conclusive({"value": {"reason": "ftp anónimo denegado"}}) is True


def test_record_fact_stamps_the_provenance_of_a_model_barrier(tmp_path):
    """The engine, not the model, decides whether an attempt happened."""
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = SimpleNamespace(engagement_id=ENGAGEMENT)
    context = RunContext(
        TENANT, Identity("operator-1", TENANT, roles=("operator",)), scope=scope, store=store
    )
    asyncio.run(
        record_fact_handler(
            {"fact_type": "barrier", "key": "10.65.170.171:80",
             "value": {"reason": "sin sesión", "service": "http"}},
            context,
        )
    )
    facts = Blackboard(store).list_facts(TENANT, ENGAGEMENT, fact_type="barrier")
    assert facts[0]["value"]["sweep_attempted"] is False
    assert facts[0]["value"]["provenance"] == "model_claim"


# --------------------------------------------------------------------------- R7


def _tool_call(tool_id: str, **arguments) -> str:
    return json.dumps(
        {
            "thought": "siguiente paso",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments,
            "expected_outcome": "evidencia",
        }
    )


def _task_complete() -> str:
    return json.dumps(
        {"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []}
    )


class _ScriptedLLM:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.calls = 0
        self.messages: list[list] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        self.messages.append(list(messages))
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index], model="scripted", provider=LLMProvider.FAKE
        )


class _RejectAll:
    """Every call fails the way a refused argument does (``ValueError``)."""

    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.payloads: list[dict] = []

    async def __call__(self, *_args, **_kwargs):
        raise self.error


def _loop_harness(tmp_path, **payload_extra):
    store = ControlStore(tmp_path / "budget.db")
    store.initialize()
    EngagementStore(store).create(_scope())
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {"objective": "objetivo", "engagement_id": ENGAGEMENT, **payload_extra},
    }
    return store, ExecutionContext(store, task, "worker")


def _loop_config(**kwargs) -> ReActConfig:
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


async def _run_rejections(store, context, count: int):
    llm = _ScriptedLLM(
        [_tool_call("nexus.recon.nmap", target=f"10.0.0.{i}", profile="service")
         for i in range(1, count + 1)]
        + [_task_complete()]
    )
    spy = _RejectAll(ValueError("nmap flag is forbidden"))
    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=count + 2),
        )
    stuck = [
        event
        for event in store.list_run_events(TENANT, context.run_id)
        if event.get("event_type") == "react.stuck_detected"
    ]
    return result, stuck


async def test_two_argument_rejections_do_not_move_the_pivot(tmp_path):
    """V12 iterations 13-14: two refused arguments, zero statements about the target.

    With the free budget of :data:`MAX_FREE_ARGUMENT_REJECTIONS` the no-progress
    counter must stay at zero, so the pivot never fires on a model typo.
    """
    store, context = _loop_harness(tmp_path)
    result, stuck = await _run_rejections(store, context, MAX_FREE_ARGUMENT_REJECTIONS)
    assert stuck == []
    progress = [
        int(turn.get("consecutive_no_progress") or 0) for turn in result.turns
    ]
    # The two refused turns are free; only the closing turn is barren.
    assert progress[:MAX_FREE_ARGUMENT_REJECTIONS] == [0, 0]
    assert max(progress) <= 1


async def test_rejections_past_the_free_budget_still_count(tmp_path):
    """A model guessing at the same door must not be able to burn the run."""
    store, context = _loop_harness(tmp_path)
    count = 7  # 2 free + 5 counted: exactly one stuck signal.
    _, stuck = await _run_rejections(store, context, count)
    assert len(stuck) == 1
    assert stuck[0]["payload"]["iterations_stuck"] == 5


# ------------------------------------------------- R2: the prompt, end to end


async def test_the_prompt_carries_an_active_skill_body_only_once(tmp_path, monkeypatch):
    """The measured cost: an 18 KB recipe paid on every turn of the run."""
    project = tmp_path / "project"
    skill_dir = project / ".agents" / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "# Demo\n\nReceta de prueba.\n\nBODY-MARKER\n" + ("paso\n" * 900),
        encoding="utf-8",
    )
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(project))
    store, context = _loop_harness(
        tmp_path,
        project_root=str(project),
        active_skills=["demo"],
    )
    llm = _ScriptedLLM(
        [
            _tool_call("nexus.recon.nmap", target="10.0.0.5", profile="service"),
            _tool_call("nexus.recon.nmap", target="10.0.0.6", profile="service"),
            _task_complete(),
        ]
    )
    ok = {"success": True, "output": {"stdout": "22/tcp open"}}
    with mock.patch.object(
        runtime_module, "execute_tool", mock.AsyncMock(return_value=ok)
    ):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=6),
        )
    assert result.status == "completed"
    prompts = [str(messages[0].content) for messages in llm.messages]
    assert len(prompts) >= 3
    assert "BODY-MARKER" in prompts[0]
    assert "BODY-MARKER" not in prompts[1]
    assert "BODY-MARKER" not in prompts[2]
    # The index line stays: the model still knows the skill exists and can reload it.
    assert "demo" in prompts[1]
