"""Tanda D: the harness tells the model what it is looking at.

Measured origin: DeadDrop P12 (2026-10-22,
``run_45103fbc0e6d4a9caf76496932777d55``), 59 iterations, ``budget_exceeded``,
0 findings. The fixes of Tandas A/B/C worked; the model lost thirty turns to
three readings of its own:

* ``{}`` from ``/preview/x.js`` read as "the server does not execute JS" when it
  means "the module ran and exported nothing";
* a ``barrier`` written after that single payload, closing the only web branch;
* ``react.branch_closed`` firing at iteration 44 and the model calling
  ``web.*`` against the same host:port for fifteen more turns.

Nothing here touches a network or DeadDrop: synthetic IPs (``10.10.10.x``) and
hand-built action histories.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from nexus_core.agent.branch_discipline import (
    BARRIER_ATTEMPT_WINDOW,
    BARRIER_TOO_EARLY,
    CLOSED_BRANCH_BLOCK_TURNS,
    barrier_refusal,
    closed_branch_refusal,
    distinct_attempts,
    redundant_fact_refusal,
)
from nexus_core.agent.coverage import STATUS_CLOSED, STATUS_PROBED, build_coverage
from nexus_core.agent.prompts import (
    CREDENTIAL_FAMILIES_RULE_PROMPT,
    PREVIEW_MODULE_RULE_PROMPT,
    render_available_credentials,
    render_system_prompt,
)
from nexus_core.kernel.credentials import credential_family
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers.http_request import http_request_handler
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.unit

HOST = "10.10.10.5"
WEB = f"{HOST}:80"
SSH = f"{HOST}:22"


# --------------------------------------------------------------------- fixtures
def _service(port: int, name: str) -> dict:
    return {
        "fact_type": "service",
        "key": f"{HOST}:{port}:tcp",
        "value": {
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": name,
            "product": "",
            "version": "",
        },
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "nmap_xml_parsed",
        "invocation_id": "inv-nmap",
    }


def _barrier(recorded_at: str = "2026-10-22T20:00:00+00:00") -> dict:
    return {
        "fact_type": "barrier",
        "key": WEB,
        "value": {"reason": "sin vector", "sweep_attempted": True},
        "verified": False,
        "asserted_by": "agent",
        "recorded_at": recorded_at,
    }


def _vulnerability(recorded_at: str = "2026-10-22T21:00:00+00:00") -> dict:
    return {
        "fact_type": "vulnerability",
        "key": WEB,
        "value": {"title": "preview ejecuta módulos", "cve": "n/a"},
        "verified": False,
        "asserted_by": "agent",
        "recorded_at": recorded_at,
    }


def _coverage(*facts: dict):
    return build_coverage([_service(80, "http"), _service(22, "ssh"), *facts])


def _action(
    tool_id: str,
    arguments: dict,
    *,
    iteration: int = 1,
    output: dict | None = None,
) -> dict:
    return {
        "iteration": iteration,
        "action": "tool_call",
        "tool_id": tool_id,
        "arguments": arguments,
        "tool_result": {
            "success": True,
            "outcome": "",
            "output": output or {},
        },
    }


def _barrier_arguments(key: str = WEB) -> dict:
    return {"fact_type": "barrier", "key": key, "value": {"reason": "probado"}}


# ------------------------------------------- hijack_v7: a barrier that was tried
def test_a_barrier_after_a_conclusive_answer_is_accepted():
    """``nexus.recon.ftp`` answering 530 is a verdict, not a guess."""
    denied = _action("nexus.web.request", {"url": f"http://{HOST}/"}, output={})
    denied["tool_result"].update(success=False, outcome="denied")
    assert barrier_refusal([denied], _coverage(), _barrier_arguments(WEB)) is None


def test_a_barrier_after_a_broken_tool_is_still_refused():
    broken = _action("nexus.web.request", {"url": f"http://{HOST}/"}, output={})
    broken["tool_result"].update(success=False, outcome="")
    assert barrier_refusal([broken], _coverage(), _barrier_arguments(WEB)) is not None


def test_a_stalled_branch_accepts_the_barrier_the_pivot_asks_for():
    """The loop's own verdict and the model's barrier agree after the window."""
    neutral = _action("nexus.web.request", {"url": f"http://{HOST}/"}, output={})
    assert (
        barrier_refusal(
            [neutral], _coverage(), _barrier_arguments(WEB), no_progress=BARRIER_ATTEMPT_WINDOW
        )
        is None
    )


# ------------------------------------- hijack_v7: re-recording the verifier's work
def test_a_service_the_verifier_already_proved_is_refused():
    guidance = redundant_fact_refusal(
        [_service(80, "http")],
        {
            "fact_type": "service",
            "key": f"{HOST}:80:tcp",
            "value": {"port": 80, "service": "http", "state": "open"},
        },
        next_branch=f"{HOST}:22/tcp ssh",
    )
    assert guidance is not None
    assert "YA está en la pizarra" in guidance
    assert f"Siguiente rama abierta: {HOST}:22/tcp ssh" in guidance


def test_a_service_with_a_new_detail_is_allowed():
    # A product/version is something the model learned, not bookkeeping.
    assert (
        redundant_fact_refusal(
            [_service(80, "http")],
            {
                "fact_type": "service",
                "key": f"{HOST}:80:tcp",
                "value": {"product": "Apache httpd 2.4.18"},
            },
        )
        is None
    )


def test_a_credential_or_barrier_is_never_refused():
    facts = [_service(80, "http")]
    for fact_type in ("credential", "barrier", "hint"):
        assert (
            redundant_fact_refusal(
                facts,
                {"fact_type": fact_type, "key": f"{HOST}:80:tcp", "value": {}},
            )
            is None
        )


# ----------------------------------------------------------------- D-2: the `{}`
class _FakeSandbox:
    def __init__(self, payload: dict) -> None:
        self.result = SandboxResult(0, json.dumps(payload) + "\n", "")

    async def run(self, argv, *, timeout_seconds: float = 30):
        return self.result


def _http_payload(url: str, body: str) -> dict:
    return {
        "ok": True,
        "url": url,
        "method": "GET",
        "status": 200,
        "reason": "OK",
        "headers": {"content-type": "application/json"},
        "content_type": "application/json",
        "body_bytes": len(body),
        "body_sha256": "b" * 64,
        "body_preview": body,
        "preview_truncated": False,
        "elapsed_ms": 4,
        "uploaded": None,
    }


def _run_http(url: str, body: str):
    context = RunContext("system", Identity("operator-1", "system", roles=("operator",)))
    sandbox = _FakeSandbox(_http_payload(url, body))
    from unittest import mock

    with mock.patch.object(
        http_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        return asyncio.run(http_request_handler({"url": url}, context))


def test_an_empty_preview_body_is_annotated_as_executed() -> None:
    result = _run_http(f"http://{HOST}/preview/pwn.js", "{}")

    assert result.verified is True
    assert result.output["preview_executed"] is True
    note = result.output["preview_note"]
    # The exact correction of the measured false verdict: executed, not text.
    assert "SE EJECUTÓ" in note
    assert "execSync" in note
    assert "barrier" in note


def test_a_text_plain_preview_is_not_annotated() -> None:
    result = _run_http(
        f"http://{HOST}/preview/pwn.js",
        "<html><body>module.exports = 1;</body></html>",
    )

    assert "preview_executed" not in result.output
    assert "preview_note" not in result.output


def test_a_body_outside_the_preview_path_is_not_annotated() -> None:
    # A real JSON API that answers ``{}`` is data, not an executed module.
    result = _run_http(f"http://{HOST}/api/status", "{}")

    assert "preview_executed" not in result.output


# ------------------------------------------- D-2.2 / D-3.1: the barrier gate
def test_a_barrier_after_an_executed_preview_is_rejected() -> None:
    coverage = _coverage()
    actions = [
        _action(
            "nexus.web.request",
            {"url": f"http://{HOST}/preview/pwn.js"},
            output={"preview_executed": True, "body_preview": "{}"},
        )
    ]

    refusal = barrier_refusal(actions, coverage, _barrier_arguments())

    assert refusal is not None
    assert "SE EJECUTÓ" in refusal
    assert "execSync" in refusal


def test_a_single_attempt_is_not_enough_to_close_a_branch() -> None:
    coverage = _coverage()
    actions = [_action("nexus.web.upload", {"url": f"http://{HOST}/upload"})]

    refusal = barrier_refusal(actions, coverage, _barrier_arguments())

    assert refusal == BARRIER_TOO_EARLY.format(
        ref=WEB,
        count=1,
        window=3,
        tools="`nexus.web.upload`",
        minimum=2,
    )


def test_two_attempts_allow_the_barrier() -> None:
    coverage = _coverage()
    actions = [
        _action("nexus.web.upload", {"url": f"http://{HOST}/upload"}),
        _action("nexus.web.request", {"url": f"http://{HOST}/login"}),
    ]

    assert distinct_attempts(actions, coverage, WEB) == [
        "nexus.web.upload",
        "nexus.web.request",
    ]
    assert barrier_refusal(actions, coverage, _barrier_arguments()) is None


def test_bookkeeping_calls_do_not_count_as_attempts() -> None:
    # A model could otherwise satisfy the two-attempt rule with query_facts.
    coverage = _coverage()
    actions = [
        _action("nexus.knowledge.query_facts", {"target": WEB}),
        _action("nexus.workspace.read", {"path": "loot/notes.txt"}),
    ]

    assert distinct_attempts(actions, coverage, WEB) == []
    assert barrier_refusal(actions, coverage, _barrier_arguments()) is not None


def test_a_vulnerability_opens_the_branch_before_the_barrier() -> None:
    coverage = _coverage()
    actions = [
        _action(
            "nexus.knowledge.record_fact",
            {"fact_type": "vulnerability", "key": WEB, "value": {"title": "RCE"}},
        )
    ]

    assert barrier_refusal(actions, coverage, _barrier_arguments()) is None


def test_a_barrier_outside_the_ledger_is_left_to_the_handler() -> None:
    # No service fact for that host: the gate has no branch to close and must
    # not turn into a global ban on the fact.
    coverage = _coverage()
    assert barrier_refusal([], coverage, _barrier_arguments("10.10.10.99:80")) is None


# ------------------------------------------------ D-3.2: the closed branch gate
def _closed(*facts: dict, iteration: int = 44):
    coverage = _coverage(*facts)
    return coverage, {WEB: iteration}


def test_a_closed_branch_rejects_further_web_calls() -> None:
    coverage, closed_at = _closed(_barrier())

    assert coverage.find(WEB).status == STATUS_CLOSED
    refusal = closed_branch_refusal(
        tool_id="nexus.web.request",
        arguments={"url": f"http://{HOST}/dashboard"},
        coverage=coverage,
        closed_at=closed_at,
        iteration=45,
    )

    assert refusal is not None
    assert "RAMA CERRADA" in refusal
    assert f"durante {CLOSED_BRANCH_BLOCK_TURNS} turno(s)" in refusal
    # The refusal names the way out: another open branch.
    assert SSH in refusal


def test_a_closed_branch_reopens_after_n_turns() -> None:
    coverage, closed_at = _closed(_barrier())

    # Closed at 44: turns 45..49 are refused (five turns) and 50 runs again.
    allowed_at = 44 + CLOSED_BRANCH_BLOCK_TURNS + 1
    assert (
        closed_branch_refusal(
            tool_id="nexus.web.request",
            arguments={"url": f"http://{HOST}/dashboard"},
            coverage=coverage,
            closed_at=closed_at,
            iteration=allowed_at,
        )
        is None
    )


def test_a_closed_branch_does_not_affect_other_branches() -> None:
    coverage, closed_at = _closed(_barrier())

    assert (
        closed_branch_refusal(
            tool_id="nexus.post.ssh_exec",
            arguments={"target": HOST, "username": "svc"},
            coverage=coverage,
            closed_at=closed_at,
            iteration=45,
        )
        is None
    )


def test_a_closed_branch_is_reopened_by_a_newer_vulnerability() -> None:
    coverage, closed_at = _closed(_barrier(), _vulnerability())

    assert coverage.find(WEB).status == STATUS_PROBED
    assert (
        closed_branch_refusal(
            tool_id="nexus.web.request",
            arguments={"url": f"http://{HOST}/preview/x.js"},
            coverage=coverage,
            closed_at=closed_at,
            iteration=45,
        )
        is None
    )


# ------------------------------------------------------- D-1 / D-5: the prompt
@pytest.fixture()
def catalog():
    return durable_tool_definitions("system")


def _prompt(catalog) -> str:
    return render_system_prompt(
        catalog=catalog, objective="x", engagement_id="eng-1", scope_summary="s"
    )


def test_the_preview_module_rule_is_offered_to_web_profiles(catalog) -> None:
    prompt = _prompt(catalog)
    assert "- PREVIEW DE .js (Node):" in prompt
    assert "SE EJECUTÓ" in prompt
    assert "execSync" in prompt
    # Methodology sits before the response contract, like every other order.
    assert prompt.index("PREVIEW DE .js") < prompt.index("RESPONDE SIEMPRE")


def test_the_preview_module_rule_needs_the_upload_tool(catalog) -> None:
    gated = {
        tool_id: entry
        for tool_id, entry in catalog.items()
        if tool_id != "nexus.web.upload"
    }
    prompt = _prompt(gated)
    assert PREVIEW_MODULE_RULE_PROMPT not in prompt
    assert "- PREVIEW DE .js" not in prompt


def test_the_credential_family_rule_is_offered_to_ssh_profiles(catalog) -> None:
    prompt = _prompt(catalog)
    assert "- FAMILIAS DE CREDENCIALES:" in prompt
    assert "family" not in prompt.split("- FAMILIAS DE CREDENCIALES:")[0][-200:]


def test_the_credential_family_rule_travels_only_with_a_remote_auth_tool(catalog) -> None:
    gated = {
        tool_id: entry
        for tool_id, entry in catalog.items()
        if tool_id
        not in {
            "nexus.post.ssh_exec",
            "nexus.win.winrm_exec",
            "nexus.recon.netexec",
        }
    }
    prompt = _prompt(gated)
    assert CREDENTIAL_FAMILIES_RULE_PROMPT not in prompt
    assert "- FAMILIAS DE CREDENCIALES:" not in prompt


def test_the_prompt_shows_credential_families() -> None:
    assert credential_family("http") == "web"
    assert credential_family("https") == "web"
    assert credential_family("ssh") == "ssh"
    assert credential_family("smb") == "smb"
    assert credential_family("") == "unknown"


def test_available_credentials_shows_two_families() -> None:
    block = render_available_credentials(
        [
            {
                "host": HOST,
                "handle": "vault:" + "a" * 32,
                "username": "admin",
                "protocol": "http",
                "family": "web",
            },
            {
                "host": HOST,
                "handle": "vault:" + "b" * 32,
                "username": "svc-drop",
                "protocol": "ssh",
                "family": "ssh",
            },
        ]
    )

    assert "family=`web`" in block
    assert "family=`ssh`" in block
    assert block.count(f"- `{HOST}`:") == 2
