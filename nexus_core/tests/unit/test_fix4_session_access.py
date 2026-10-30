"""FIX 4: el motor dice si la sesión entró y deja de castigar al vector.

Medido en hijack_v5 (``run_bc2ff878a44641afa8f04dc90168f22f``, 2026-10-29): la
credencial de ``admin`` se validó en la iteración 18, ``nexus.web.request``
recibió un ``session_ref`` del vault y lo usó contra ``/administration.php`` en la
19 con un 200. El handler devolvió ``success`` **sin assertions**, así que el
tablero no supo nada, el Planner siguió en *Acceso inicial* y el modelo gastó las
27 iteraciones siguientes repitiendo el login (con ``credential_ref``, un campo
que no existe), marcando un ``barrier`` falso y quemando ``cred.bruteforce`` por
tres fallos hasta el ``budget_exceeded``.

El contrato que fijan estas pruebas:

* una respuesta que sólo se sirve con sesión (``logout`` en el body o una ruta
  privada, sin formulario de login y sin denegación) es un hecho ``access``;
* una respuesta que **deniega** la sesión es un veredicto ``denied`` explícito,
  no un silencio: el modelo tiene que poder distinguir "entré" de "me rechazó";
* un rechazo de argumentos (``credential_ref``, ``--script``) no cuenta como
  fallo del vector.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.planner import build_plan
from nexus_core.agent.react_coordinator import _is_vector_failure
from nexus_core.kernel.errors import ToolInputError
from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.schema_validation import SchemaValidationError, validate
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers.http_request import (
    http_request_definition,
    http_request_handler,
)
from nexus_core.tools.handlers.nmap import validate_and_canonicalize_flags

pytestmark = pytest.mark.unit

SESSION_REF = "vault:" + "a" * 32
HOST = "10.0.0.5"

#: A panel behind a login: no ``input type=password`` and a logout affordance.
PANEL = (
    "<html><body><h1>Administration</h1>"
    "<a href='/logout.php'>Cerrar sesión</a>"
    "<form action='/upload.php' method='post' enctype='multipart/form-data'>"
    "<input type='file' name='file'><input type='submit'></form></body></html>"
)
#: The same page refusing the session -the shape the model itself recorded as
#: "administration.php responde Access denied".
DENIED = (
    "<html><body><h2>Access denied</h2>"
    "<p>You are not allowed to view this page.</p></body></html>"
)
LOGIN_FORM = (
    "<html><body><form method='post' action='/login.php'>"
    "<input name='username'><input type='password' name='password'>"
    "<input type='submit'></form></body></html>"
)
PUBLIC_PAGE = "<html><body><h1>Welcome</h1><p>Public news feed</p></body></html>"


# --------------------------------------------------------------------- helpers
def _assertions(url: str, body: str, *, status: int = 200, arguments=None):
    result = ToolResult(
        output=dict(url=url, status=status, body_preview=body),
        verified=True,
        verification_method="http_response_received",
    )
    payload = arguments if arguments is not None else {"url": url, "session_ref": SESSION_REF}
    return derive_assertions(
        "nexus.web.request", payload, result, SimpleNamespace(invocation_id="inv-1", run_id="run-1")
    )


def _access(rows):
    return [row for row in rows if row["fact_type"] == "access"]


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


class FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result

    async def run(self, argv, *, timeout_seconds: float = 30):
        return self.result


@contextlib.contextmanager
def _fake_sandbox(payload: dict):
    sandbox = FakeSandbox(SandboxResult(0, json.dumps(payload) + "\n", ""))
    with mock.patch.object(
        http_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _payload(body: str, *, url: str) -> dict:
    return {
        "ok": True,
        "url": url,
        "method": "GET",
        "status": 200,
        "reason": "OK",
        "headers": {"content-type": "text/html; charset=utf-8"},
        "content_type": "text/html; charset=utf-8",
        "body_bytes": len(body.encode()),
        "body_sha256": "b" * 64,
        "body_preview": body,
        "preview_truncated": False,
        "elapsed_ms": 4,
        "uploaded": None,
        "set_cookie": [],
    }


def _stored_session(tmp_path, monkeypatch) -> str:
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    return default_secret_store().put("PHPSESSID=abc123", kind="session")


def _run_handler(arguments: dict):
    return asyncio.run(http_request_handler(arguments, _context()))


# ------------------------------------------------- 4.1 la sesión que sí entra
def test_web_request_with_session_ref_asserts_access():
    url = f"http://{HOST}/administration.php"
    access = _access(_assertions(url, PANEL))

    assert len(access) == 1
    assert access[0]["target"] == HOST
    assert access[0]["value"]["authenticated"] is True
    assert access[0]["value"]["session_ref"] == SESSION_REF
    assert access[0]["value"]["path"] == "/administration.php"
    assert access[0]["value"]["signal"] == "logout_affordance"
    assert access[0]["verification_method"] == "http_session_authenticated"
    assert access[0]["verified"] is True
    assert access[0]["asserted_by"] == "verifier"


def test_a_private_route_without_a_logout_link_still_proves_the_session():
    url = f"http://{HOST}/dashboard"
    access = _access(_assertions(url, "<html><body><h1>Reports</h1></body></html>"))

    assert len(access) == 1
    assert access[0]["value"]["signal"] == "protected_path"


def test_a_cookie_header_sent_by_hand_also_counts_as_a_session():
    url = f"http://{HOST}/admin"
    rows = _assertions(
        url, "<html><body><h1>Panel</h1></body></html>",
        arguments={"url": url, "cookie": "PHPSESSID=abc123"},
    )

    assert len(_access(rows)) == 1


def test_web_request_without_a_session_asserts_no_access():
    """A panel body alone proves nothing: the request must carry the session."""
    url = f"http://{HOST}/administration.php"
    assert _access(_assertions(url, PANEL, arguments={"url": url})) == []


def test_a_public_page_opened_with_a_session_is_not_access():
    url = f"http://{HOST}/index.php"
    assert _access(_assertions(url, PUBLIC_PAGE)) == []


def test_a_panel_that_denies_the_session_is_not_access():
    """The run's own note said "administration.php responde Access denied".

    Asserting ``access`` there would be the exact lie this verifier exists to
    prevent: a 200 with a denial page is a rejected session, not a login.
    """
    url = f"http://{HOST}/administration.php"
    assert _access(_assertions(url, DENIED)) == []


def test_a_login_form_served_to_a_session_is_not_access():
    url = f"http://{HOST}/admin"
    assert _access(_assertions(url, LOGIN_FORM)) == []


def test_a_redirect_to_the_login_is_not_access():
    url = f"http://{HOST}/admin"
    assert _access(_assertions(url, "<html><body>Redirecting…</body></html>", status=302)) == []


# ------------------------------------- 4.1b el handler publica el veredicto
def test_the_handler_reports_the_authenticated_verdict(tmp_path, monkeypatch):
    ref = _stored_session(tmp_path, monkeypatch)
    url = f"http://{HOST}/administration.php"
    with _fake_sandbox(_payload(PANEL, url=url)):
        result = _run_handler({"url": url, "session_ref": ref})

    assert result.output["session_state"] == "authenticated"
    assert "NO repitas el login" in result.output["guidance"]
    assert result.evidence["session_state"] == "authenticated"
    assert result.verified is True


def test_the_handler_reports_a_denied_session_as_a_verdict(tmp_path, monkeypatch):
    ref = _stored_session(tmp_path, monkeypatch)
    url = f"http://{HOST}/administration.php"
    with _fake_sandbox(_payload(DENIED, url=url)):
        result = _run_handler({"url": url, "session_ref": ref})

    assert result.output["session_state"] == "denied"
    assert result.evidence["session_state"] == "denied"
    assert result.verified is False
    assert result.outcome == "partial"
    assert result.verification_method == "http_session_denied"
    assert "cambia de vector" in result.output["guidance"]


# ------------------------------------------- 4.2 el schema dice qué campo es
def test_schema_error_suggests_session_ref():
    schema = http_request_definition().input_schema
    with pytest.raises(SchemaValidationError) as excinfo:
        validate({"url": f"http://{HOST}/login.php", "credential_ref": SESSION_REF}, schema)

    message = str(excinfo.value)
    assert "credential_ref" in message
    assert "session_ref" in message
    assert "no existe" in message
    # The value is a vault handle: the hint says it travels as-is.
    assert "vault:" in message


def test_schema_error_does_not_invent_a_field():
    schema = http_request_definition().input_schema
    with pytest.raises(SchemaValidationError) as excinfo:
        validate({"url": f"http://{HOST}/", "flavour": "x"}, schema)

    message = str(excinfo.value)
    assert "flavour" in message
    assert "el campo" not in message


# ------------------------------------------ 4.3 nmap: la salida de un rechazo
def test_nmap_forbidden_flag_names_the_way_out():
    with pytest.raises(ToolInputError) as excinfo:
        validate_and_canonicalize_flags(["-Pn", "--script", "ssh-auth-methods"])

    message = str(excinfo.value)
    assert "--script" in message
    assert "nexus.shell.exec" in message


def test_an_unknown_nmap_flag_points_at_the_profiles():
    with pytest.raises(ToolInputError) as excinfo:
        validate_and_canonicalize_flags(["--flood"])

    assert "profile" in str(excinfo.value)


def test_a_rejected_call_never_counts_against_the_vector():
    """``credential_ref``/``--script`` are the model's mistakes, not the target's.

    hijack_v5: the two ``--script`` rejections locked ``nexus.recon.nmap`` for
    the rest of the run and ``invalid_failure_string`` counted as a failure of
    ``cred.bruteforce``.
    """
    assert _is_vector_failure({"success": False, "input_rejected": True}) is False
    assert _is_vector_failure({"success": False, "outcome": "invalid_failure_string"}) is False
    assert _is_vector_failure({"success": False, "outcome": "failed"}) is True
    assert _is_vector_failure({"success": True, "outcome": "partial"}) is True


# ------------------------------- 4.4 (ya implementado) el plan avanza con access
def test_access_fact_moves_the_plan_to_privilege_escalation():
    """No second mechanism is needed: the phase was waiting for the fact.

    ``PHASES`` closes *Acceso inicial* on ``access``/``session``
    (``nexus_core/agent/planner.py``); what hijack_v5 never produced was the
    fact, because ``derive_assertions`` asserted nothing from a 200.
    """
    plan = build_plan(
        counts={"host": 1, "service": 1, "endpoint": 1, "credential": 1, "access": 1}
    )

    statuses = {phase.id: phase.status for phase in plan.phases}
    assert statuses["exploitation"] == "done"
    assert plan.current == "privilege_escalation"
    assert "escalada" in plan.next_hint.lower()


def test_the_assertion_reaches_the_board_and_the_plan_advances(tmp_path, monkeypatch):
    """End to end inside the engine: assertion → blackboard → plan.

    The report of hijack_v5 says the agent was "inside" and the plan stayed on
    *Acceso inicial*. This is the loop that has to close: the verifier's row is
    written as a verified fact by the gateway and the next plan reads it.
    """
    from dataclasses import replace as replace_dataclass

    from nexus_core.cli.engage import build_scope
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.fact_verification import persist_assertions
    from nexus_core.scope import EngagementStore

    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", "test-signing-secret")
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(
        build_scope("panel", f"{HOST}/32", "test-signing-secret")
    )
    context = replace_dataclass(
        RunContext("system", Identity("operator-1", "system", roles=("operator",))),
        store=store,
        scope=scope,
        run_id="run-access",
        invocation_id="inv-panel",
    )

    url = f"http://{HOST}/administration.php"
    persist_assertions(_assertions(url, PANEL), context, "nexus.web.request")

    facts = Blackboard(store).list_facts("system", scope.engagement_id)
    access = [fact for fact in facts if fact["fact_type"] == "access"]
    assert len(access) == 1
    assert access[0]["verified"] is True
    assert access[0]["asserted_by"] == "verifier"
    statuses = {phase.id: phase.status for phase in build_plan(facts=facts).phases}
    assert statuses["exploitation"] == "done"
    assert build_plan(facts=facts).current == "privilege_escalation"
