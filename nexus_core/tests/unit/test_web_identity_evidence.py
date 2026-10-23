"""End to end: one HTML response becomes an identity lead, and a fact.

The chain closed here is the one measured as broken on HackPark: the handler
downloads a page whose footer prints ``j.doe@services.local`` and whose staff
list names ``Jack Rock - IT Staff``; the observation must carry both, and the
verifier must record the printed address as a fact while leaving ``j.rock`` a
ranked hypothesis (a convention guess is not an account).
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest import mock

from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers.http_request import http_request_handler

TEAM_PAGE = """<html><head><meta name="generator" content="WordPress 5.4"></head>
<body>
<nav><a href="/index.html">Home</a><a href="/about.html">About</a></nav>
<div class="team">
  <div><h4>Joanne Doe</h4><p>Sales</p></div>
  <div><h4>Jack Rock</h4><p>IT Staff</p></div>
  <div><h4>Will Masters</h4><p>CEO</p></div>
</div>
<footer><a href="mailto:j.doe@services.local">j.doe@services.local</a></footer>
</body></html>"""

URL = "http://203.0.113.10/index.html"


class _FakeSandbox:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
        return SandboxResult(0, json.dumps(self.payload) + "\n", "")


def _payload(**overrides) -> dict:
    payload = {
        "ok": True,
        "url": URL,
        "method": "GET",
        "status": 200,
        "reason": "OK",
        "headers": {"content-type": "text/html"},
        "content_type": "text/html; charset=utf-8",
        "body_bytes": len(TEAM_PAGE),
        "body_sha256": "a" * 64,
        "body_preview": TEAM_PAGE,
        "preview_truncated": False,
        "elapsed_ms": 5,
        "uploaded": None,
    }
    payload.update(overrides)
    return payload


def _run(arguments: dict, payload: dict):
    sandbox = _FakeSandbox(payload)
    with mock.patch.object(
        http_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        return asyncio.run(
            http_request_handler(arguments, RunContext("system", Identity("op", "system")))
        )


def test_the_observation_carries_the_address_the_people_and_the_links():
    result = _run({"url": URL}, _payload())
    extracted = result.output["extracted"]
    assert extracted["emails"] == ["j.doe@services.local"]
    roles = {person["name"]: person["title"] for person in extracted["people"]}
    assert roles["Jack Rock"] == "IT Staff"
    assert extracted["identities"]["convention"] == "initial.last"
    assert result.evidence["emails_found"] == 1
    assert result.evidence["people_found"] == 3


def test_the_observation_names_the_page_nobody_asked_for():
    result = _run({"url": URL}, _payload())
    steps = " ".join(result.output["next_steps"])
    assert "/about.html" in steps
    assert "nexus.web.request" in steps
    assert "j.rock" in steps
    assert "antes de probar contraseñas" in steps


def test_a_json_response_carries_no_extraction():
    result = _run(
        {"url": URL},
        _payload(content_type="application/json", body_preview='{"ok": true}'),
    )
    assert result.output["extracted"] is None
    assert "next_steps" not in result.output


def test_the_verifier_asserts_the_printed_address_and_the_local_part():
    result = _run({"url": URL}, _payload())
    context = SimpleNamespace(invocation_id="inv-1", run_id="run-1")
    facts = derive_assertions("nexus.web.request", {"url": URL}, result, context)
    by_type = {fact["fact_type"]: fact for fact in facts}
    assert by_type["email"]["key"] == "j.doe@services.local"
    assert by_type["email"]["value"]["confidence"] == "observed"
    assert by_type["user"]["key"] == "j.doe"
    assert by_type["user"]["value"]["domain"] == "services.local"
    # The convention guess is a candidate, never a fact: a run that sprayed
    # j.rock because a regex approved it would be the same failure as before.
    assert "j.rock" not in {fact["key"] for fact in facts}


def test_a_page_with_names_but_no_address_asserts_no_identity():
    page = "<html><body><h4>Jack Rock</h4><p>IT Staff</p></body></html>"
    result = _run({"url": URL}, _payload(body_preview=page))
    context = SimpleNamespace(invocation_id="inv-2", run_id="run-2")
    facts = derive_assertions("nexus.web.request", {"url": URL}, result, context)
    assert {fact["fact_type"] for fact in facts} == set()
