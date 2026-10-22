"""Unit tests for the deterministic multi-phase engagement planner."""

from __future__ import annotations

import pytest

from nexus_core.agent.planner import (
    ENUMERATION_ENDPOINT_CEILING,
    PHASE_IDS,
    SMART_BUDGET_MIN_ITERATION,
    STATUS_CURRENT,
    WEBSHELL_STALL_TURNS,
    STATUS_DONE,
    STATUS_PENDING,
    active_phase,
    build_plan,
    endpoint_ceiling,
    enumeration_budget_hint,
    normalize_counts,
    login_probe_hint,
    plan_from_summary,
    robots_paths_hint,
    webshell_stall_hint,
)

pytestmark = pytest.mark.unit


def test_empty_blackboard_starts_at_recon():
    plan = build_plan()
    assert plan.current == "recon"
    assert plan.progress == (0, 6)


def test_services_close_recon_and_open_enumeration():
    plan = build_plan(counts={"service": 3, "host": 1})
    assert plan.current == "enumeration"
    assert plan.progress == (1, 6)
    statuses = {item.id: item.status for item in plan.phases}
    assert statuses["recon"] == STATUS_DONE
    assert statuses["enumeration"] == STATUS_CURRENT


def test_users_and_credentials_close_enumeration():
    plan = build_plan(counts={"service": 1, "user": 1, "credential": 1})
    assert plan.current == "exploitation"


def test_access_closes_exploitation():
    plan = build_plan(counts={"service": 1, "user": 1, "access": 1})
    assert plan.current == "privilege_escalation"


def test_privilege_closes_escalation():
    plan = build_plan(counts={"service": 1, "user": 1, "access": 1, "privilege": 1})
    assert plan.current == "post_exploitation"


def test_loot_closes_post_exploitation_and_reaches_reporting():
    plan = build_plan(
        counts={"service": 1, "user": 1, "access": 1, "privilege": 1, "loot": 1}
    )
    assert plan.current == "reporting"
    assert plan.progress == (5, 6)


def test_reporting_is_never_auto_completed():
    for phase in PHASE_IDS:
        plan = build_plan(counts={phase: 5})
        reporting = next(item for item in plan.phases if item.id == "reporting")
        assert reporting.status != STATUS_DONE


def test_lateral_movement_is_optional_and_never_current():
    # Two sessions satisfy the optional lateral phase, but it is never current.
    plan = build_plan(
        counts={"service": 1, "user": 1, "access": 1, "privilege": 1, "loot": 1, "session": 2}
    )
    assert plan.current == "reporting"
    lateral = next(item for item in plan.phases if item.id == "lateral_movement")
    assert lateral.optional is True
    assert lateral.status == STATUS_DONE


def test_single_session_does_not_close_lateral():
    plan = build_plan(counts={"service": 1, "user": 1, "access": 1, "privilege": 1, "loot": 1, "session": 1})
    lateral = next(item for item in plan.phases if item.id == "lateral_movement")
    assert lateral.status == STATUS_PENDING


def test_render_marks_current_phase_and_hint():
    plan = build_plan(counts={"service": 1})
    text = plan.render()
    assert "PLAN DE ENGAGEMENT" in text
    assert "fase actual: Enumeración" in text
    assert "[>] Enumeración" in text
    assert "SIGUIENTE PASO DEL PLAN:" in text


def test_pipeline_is_single_line():
    plan = build_plan(counts={"service": 1})
    assert "\n" not in plan.pipeline()
    assert "Enumeración ▶" in plan.pipeline()


def test_to_dict_roundtrip_fields():
    plan = build_plan(counts={"service": 2}, engagement_id="eng-1")
    payload = plan.to_dict()
    assert payload["current"] == "enumeration"
    assert payload["current_label"] == "Enumeración"
    assert payload["done"] == 1 and payload["total"] == 6
    assert payload["counts"] == {"service": 2}
    assert len(payload["phases"]) == len(PHASE_IDS)


def test_normalize_counts_from_fact_records():
    counts = normalize_counts(
        facts=[dict(fact_type=kind, verified=True, asserted_by="verifier",
                    verification_method="test-parser", invocation_id="fixture-invocation")
               for kind in ("service", "service", "user")]
    )
    assert counts == {"service": 2, "user": 1}


def test_normalize_ignores_bad_values():
    assert normalize_counts(counts={"service": "x", "user": 3, "host": 0}) == {"user": 3}


def test_plan_from_summary_uses_blackboard_summary():
    plan = plan_from_summary(
        {"engagement_id": "eng-1", "total": 4, "counts": {"service": 2, "user": 1, "credential": 1}},
        engagement_id="eng-1",
    )
    assert plan.current == "exploitation"
    assert plan.facts_total == 4


def test_the_endpoint_ceiling_closes_enumeration_by_decision():
    """Five mapped endpoints are enough surface: pick one, stop enumerating.

    Leads are counted because the rule is an explicit hand-off, not a claim of
    evidence; a plan that still reports ``enumeration`` with that surface is the
    shape the Simple CTF run of 2026-10-18 got stuck in.
    """
    plan = build_plan(counts={"host": 1, "service": 3}, leads={"endpoint": 5})
    assert plan.current == "enumeration"

    closed = endpoint_ceiling(plan)

    assert closed is not None
    assert closed.current == "exploitation"
    statuses = {item.id: item.status for item in closed.phases}
    assert statuses["enumeration"] == STATUS_DONE
    # Below the ceiling nothing is forced.
    assert endpoint_ceiling(build_plan(
        counts={"host": 1, "service": 3}, leads={"endpoint": ENUMERATION_ENDPOINT_CEILING - 1}
    )) is None
    # A plan already past enumeration is untouched.
    assert endpoint_ceiling(build_plan(counts={"service": 3, "endpoint": 5})) is None


def test_the_smart_budget_hint_fires_only_after_ten_turns_with_a_wide_surface():
    plan = build_plan(counts={"host": 1, "service": 3, "endpoint": 2})

    hint = enumeration_budget_hint(plan, iteration=SMART_BUDGET_MIN_ITERATION + 1)

    assert "demasiado presupuesto en enumeración" in hint
    assert "3 servicios" in hint and "2 endpoints" in hint
    # The contract is "more than 10 turns".
    assert enumeration_budget_hint(plan, iteration=SMART_BUDGET_MIN_ITERATION) == ""
    # A narrow surface, or something already usable, does not trigger it.
    assert enumeration_budget_hint(
        build_plan(counts={"service": 2, "endpoint": 2}), iteration=11
    ) == ""
    assert enumeration_budget_hint(
        build_plan(counts={"service": 3, "endpoint": 2, "access": 1}), iteration=11
    ) == ""
    # It also fires on exploitation-with-no-access: in the measured run the plan
    # had advanced at iteration 5 and the model kept enumerating anyway.
    assert enumeration_budget_hint(plan, iteration=29) != ""


def test_the_webshell_stall_hint_fires_after_ten_build_turns_without_progress():
    """Measured in Vulnversity: 35 turns compiling pwnkit through ``curl``."""
    build = {
        "tool_id": "nexus.shell.exec",
        "arguments": {
            "command": (
                "cd /tmp/pwnkit && gcc -static -o pwnkit pwnkit.c && "
                "base64 -w0 pwnkit | curl -s -G \"$U\" --data-urlencode cmd=@-"
            )
        },
    }
    actions = [build] * WEBSHELL_STALL_TURNS

    hint = webshell_stall_hint(actions, no_progress=WEBSHELL_STALL_TURNS)

    assert "Estás atascado en un webshell" in hint
    assert "nexus.session.pty" in hint and "nexus.post.listener" in hint
    assert "reverse shell" in hint and "bash, nc, python" in hint
    # Nine build turns (or nine barren turns) are not the measured stall.
    assert webshell_stall_hint(actions[:-1], no_progress=9) == ""
    assert webshell_stall_hint(actions, no_progress=9) == ""
    # A run that is still learning something is not stuck.
    assert webshell_stall_hint(actions, no_progress=0) == ""


def test_the_webshell_stall_hint_ignores_light_and_non_shell_work():
    light = {"tool_id": "nexus.shell.exec", "arguments": {"command": "ls -la /var/www"}}
    recon = {
        "tool_id": "nexus.shell.exec",
        "arguments": {"command": "curl -s -o /dev/null -w '%{http_code}' http://10.0.0.5/"},
    }
    other_tool = {"tool_id": "nexus.recon.nmap", "arguments": {"command": "gcc -o x x.c"}}
    build = {"tool_id": "nexus.shell.exec", "arguments": {"command": "chmod +x /tmp/rev"}}
    limit = WEBSHELL_STALL_TURNS

    # Plain recon, a light command and another tool are not a build loop.
    for action in (light, recon, other_tool):
        assert webshell_stall_hint([action] * limit, no_progress=limit) == ""
    # A run that already pivoted keeps its last word: no stale hint.
    assert webshell_stall_hint([build] * (limit - 1) + [light], no_progress=limit) == ""
    # The same build turn in the shell channel does fire.
    assert webshell_stall_hint([build] * limit, no_progress=limit) != ""


def test_the_webshell_stall_hint_survives_an_inspection_turn():
    """Measured in Vulnversity: the run ended on ``cat pwnkit.c`` after 35 stalls.

    The build loop interleaves ``cat``/``ls``/``wc`` between transfers; requiring
    the *very last* action to be a build turn made the hint unreachable in the
    run it was written for. Two clean turns in a row still mean a real pivot.
    """
    limit = WEBSHELL_STALL_TURNS
    build = {"tool_id": "nexus.shell.exec", "arguments": {"command": "chmod +x /tmp/pwnkit"}}
    inspect = {"tool_id": "nexus.shell.exec", "arguments": {"command": "cat /tmp/pwnkit/pwnkit.c"}}

    assert webshell_stall_hint([build] * limit + [inspect], no_progress=limit) != ""
    assert webshell_stall_hint([build] * limit + [inspect, inspect], no_progress=limit) == ""


def _http_action(url: str, body: str = "") -> dict:
    """One persisted action the way the loop stores it (arguments + tool_result)."""
    return {
        "tool_id": "nexus.web.request",
        "arguments": {"url": url},
        "tool_result": {"output": {"body_preview": body}} if body else {},
    }


LOGIN_HTML = (
    '<form method="POST" action="/login">'
    '<input type="text" name="username"><input type="password" name="password">'
    "</form>"
)


def _post_action(url: str, data: str) -> dict:
    return {
        "tool_id": "nexus.web.request",
        "arguments": {"url": url, "method": "POST", "data": data},
        "tool_result": {"output": {"status": 200}},
    }


def test_the_login_hint_orders_the_three_probes_on_a_form_read():
    """DeadDrop P1/P3 (2026-10-22): el login aceptaba `admin'-- -`."""
    actions = [
        _http_action("http://192.168.11.200/"),
        _http_action("http://192.168.11.200/login", LOGIN_HTML),
    ]

    hint = login_probe_hint(actions)

    assert "http://192.168.11.200/login" in hint
    assert "admin'-- -" in hint and "[$ne]" in hint
    assert "Set-Cookie" in hint and "nexus.cred.bruteforce" in hint


def test_a_plain_credential_attempt_does_not_silence_the_login_hint():
    """`admin/admin` es la adivinación que la regla sustituye, no una sonda."""
    actions = [
        _http_action("http://192.168.11.200/login", LOGIN_HTML),
        _post_action("http://192.168.11.200/login", "username=admin&password=admin"),
    ]
    assert login_probe_hint(actions) != ""


def test_an_injection_probe_silences_the_login_hint():
    actions = [
        _http_action("http://192.168.11.200/login", LOGIN_HTML),
        _post_action("http://192.168.11.200/login", "username=admin'-- -&password=x"),
    ]
    assert login_probe_hint(actions) == ""


def test_a_page_without_a_password_field_never_asks_for_probes():
    actions = [_http_action("http://192.168.11.200/", "<html><body>hola</body></html>")]
    assert login_probe_hint(actions) == ""


def test_the_robots_hint_orders_the_paths_the_index_lists():
    """Measured in Brute It: ``/robots.txt`` read at 22, branch closed at 23."""
    body = "User-agent: *\nDisallow: /secret/\nAllow: /pub/\n"
    actions = [
        _http_action("http://10.67.136.239/"),
        _http_action("http://10.67.136.239/robots.txt", body),
    ]

    hint = robots_paths_hint(actions)

    assert "robots.txt" in hint and "http://10.67.136.239/secret/" in hint
    assert "http://10.67.136.239/pub/" in hint
    assert "nexus.workspace.read" in hint and "nexus.knowledge.record_fact" in hint
    # An index that is already followed has nothing to order.
    visited = actions + [
        _http_action("http://10.67.136.239/secret/"),
        _http_action("http://10.67.136.239/pub/"),
    ]
    assert robots_paths_hint(visited) == ""
    # ``/admin`` and ``/admin/`` are the same route.
    assert robots_paths_hint(
        actions + [_http_action("http://10.67.136.239/secret")]
    ).count("/secret/") == 0


def test_a_relative_disallow_rule_becomes_an_absolute_url():
    """The v3 run read ``Disallow: /whatever`` and the hint never fired.

    A robots.txt lists *relative* paths, so the parser has to resolve them
    against the host that served the file: the order names the URL the model
    must GET, not the bare route it cannot request.
    """
    body = "User-agent: *\nDisallow: /admin\n"
    actions = [_http_action("http://target/robots.txt", body)]

    hint = robots_paths_hint(actions)

    assert "http://target/admin" in hint
    assert "Disallow" not in hint  # the order carries URLs, not the raw rule


def test_a_realistic_robots_file_is_parsed_line_by_line():
    """TryHackMe-style file: comments, CRLF, indentation and no space after ':'.

    The v4 run (``run_6fef3c1ba9384ee79acee2bd09e8890c``) never fired the hint.
    Its ``/robots.txt`` was a 404, but the parser was the other half of the
    gap: ``^(?:Disallow|Allow)\\s*:\\s*(\\S+)\\s*$`` rejected the shapes a real
    file uses -``Disallow:/admin`` (no space), an indented rule, a trailing
    inline comment- so a served index could name paths and still order none.
    """
    body = (
        "# robots.txt de la sala\r\n"
        "# Los comentarios no son reglas\r\n"
        "\r\n"
        "User-agent: *\r\n"
        "Disallow: /admin/\r\n"
        "Disallow:/backups\r\n"
        "   Disallow: /secret/   \r\n"
        "# Disallow: /commented-out\r\n"
        "Allow: /pub/\r\n"
        "Allow:\r\n"
        "Disallow: /*.php$\r\n"
        "Disallow: /admin/panel.php # el panel\r\n"
    )
    hint = robots_paths_hint([_http_action("http://10.67.149.76/robots.txt", body)])

    for url in (
        "http://10.67.149.76/admin/",
        "http://10.67.149.76/backups",
        "http://10.67.149.76/secret/",
        "http://10.67.149.76/pub/",
        "http://10.67.149.76/admin/panel.php",
    ):
        assert url in hint
    # A commented rule is not a rule, and a wildcard is not a route.
    assert "commented-out" not in hint
    assert "*.php" not in hint and "el panel" not in hint


def test_the_robots_hint_reads_a_sitemap_and_ignores_non_indexes():
    sitemap = (
        '<?xml version="1.0"?><urlset>'
        "<url><loc>http://10.0.0.5/hidden/panel.php</loc></url>"
        "<url><loc>http://10.0.0.5/</loc></url></urlset>"
    )
    actions = [_http_action("http://10.0.0.5/sitemap.xml", sitemap)]
    hint = robots_paths_hint(actions)
    assert "sitemap.xml" in hint
    assert "http://10.0.0.5/hidden/panel.php" in hint

    # A 404 page or any other route is not an index: no hint, no invented paths.
    assert robots_paths_hint([_http_action("http://10.0.0.5/login.php", "<html>")]) == ""
    # Wildcards are a fuzzing pattern, not routes the agent can request.
    wildcard = _http_action("http://10.0.0.5/robots.txt", "Disallow: /*.php$\n")
    assert robots_paths_hint([wildcard]) == ""
    # No history at all is not a stall.
    assert robots_paths_hint([]) == "" and robots_paths_hint(None) == ""


def test_active_phase_matches_build_plan():
    counts = {"service": 1, "user": 1}
    assert active_phase(counts) == build_plan(counts=counts).current
