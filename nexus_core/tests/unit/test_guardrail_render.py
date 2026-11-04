"""Guardrails read as orchestrator corrections, never as tool failures."""

import pytest

from nexus_core.cli.tui.stream import render_tool_result

GUIDANCE = (
    "El plan no ha cambiado desde la última consulta. No vuelvas a llamar a "
    "get_plan_status: usa la evidencia actual y elige una tool que produzca "
    "información nueva."
)


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(
            {
                "success": False,
                "tool_id": "nexus.orchestrator.get_plan_status",
                "outcome": "plan_status_unchanged",
                "guidance": GUIDANCE,
            },
            id="plan-status",
        ),
        pytest.param(
            {
                "success": False,
                "tool_id": "nexus.recon.nmap",
                "failure_kind": "repeated_action",
                "error": "llamada repetida",
                "guidance": GUIDANCE,
            },
            id="repeated-action",
        ),
        pytest.param(
            {
                "success": False,
                "tool_id": "nexus.web.upload",
                "refused_before_execution": True,
                "guidance": GUIDANCE,
            },
            id="refused-before-execution",
        ),
        pytest.param(
            {
                "success": False,
                "tool_id": "nexus.recon.nmap",
                "outcome": "scope_denied",
                "guidance": GUIDANCE,
            },
            id="scope-denied",
        ),
        pytest.param(
            {
                "success": False,
                "tool_id": "nexus.web.ffuf",
                "outcome": "branch_closed_recent",
                "guidance": GUIDANCE,
            },
            id="branch-closed-recent",
        ),
    ],
)
def test_guardrails_show_the_full_guidance_and_never_a_tool_failure(result):
    text = render_tool_result(result, no_color=True, width=100)
    assert "⚠" in text
    assert f"⚠ {result['tool_id']} · corrección del orquestador" in text
    assert "No vuelvas a llamar" in text
    assert "información nueva" in text
    assert "× failed" not in text and "× falló" not in text


def test_the_guardrail_is_amber_in_truecolor():
    result = {
        "success": False,
        "tool_id": "nexus.recon.nmap",
        "outcome": "scope_denied",
        "guidance": GUIDANCE,
    }
    colored = render_tool_result(result, width=100)
    # WARN_STYLE / GUARDRAIL_STYLE is #ffc950.
    assert "38;2;255;201;80" in colored
    assert "38;2;255;64;84" not in colored


def test_a_real_failure_keeps_the_error_colour():
    text = render_tool_result(
        {"success": False, "tool_id": "nexus.recon.nmap", "error": "timeout 120s"},
        width=100,
    )
    # RESULT_ERROR_STYLE is #ff4054.
    assert "38;2;255;64;84" in text
    assert "38;2;255;201;80" not in text


def test_a_real_tool_failure_names_the_tool_once():
    text = render_tool_result(
        {"success": False, "tool_id": "nexus.recon.nmap", "error": "timeout 120s"},
        no_color=True,
    )
    assert "nexus.recon.nmap" in text
    assert text.count("nexus.recon.nmap") == 1
    assert text.count("×") == 1


def test_a_failure_without_a_specific_error_still_names_the_tool():
    text = render_tool_result(
        {"success": False, "tool_id": "nexus.web.request"}, no_color=True
    )
    assert "nexus.web.request" in text
    assert "falló" in text
    assert text.count("×") == 1


def test_a_real_tool_failure_stays_red_with_a_single_mark():
    text = render_tool_result(
        {"success": False, "tool_id": "nexus.recon.nmap",
         "error": "timeout 120s"},
        no_color=True,
    )
    assert text.startswith("  × nexus.recon.nmap · timeout 120s")
    assert text.count("×") == 1
    assert "corrección" not in text
