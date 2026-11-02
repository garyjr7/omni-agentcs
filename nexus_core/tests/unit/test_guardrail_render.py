"""Guardrails read as orchestrator corrections, never as tool failures."""

from nexus_core.cli.tui.stream import render_tool_result

GUIDANCE = (
    "El plan no ha cambiado desde la última consulta. No vuelvas a llamar a "
    "get_plan_status: usa la evidencia actual y elige una tool que produzca "
    "información nueva."
)


def test_plan_status_unchanged_shows_full_guidance_in_amber():
    result = {
        "success": False,
        "tool_id": "nexus.orchestrator.get_plan_status",
        "outcome": "plan_status_unchanged",
        "guidance": GUIDANCE,
    }
    text = render_tool_result(result, no_color=True, width=100)
    assert "⚠ nexus.orchestrator.get_plan_status · corrección del orquestador" in text
    assert "No vuelvas a llamar" in text
    assert "información nueva" in text
    assert "× failed" not in text and "× falló" not in text


def test_repeated_action_with_guidance_and_error_keeps_the_correction():
    result = {
        "success": False,
        "tool_id": "nexus.recon.nmap",
        "failure_kind": "repeated_action",
        "error": "llamada repetida",
        "guidance": GUIDANCE,
    }
    text = render_tool_result(result, no_color=True)
    assert "corrección del orquestador" in text
    assert "No vuelvas a llamar" in text
    assert "× failed" not in text


def test_a_real_tool_failure_stays_red_with_a_single_mark():
    text = render_tool_result(
        {"success": False, "tool_id": "nexus.recon.nmap",
         "error": "timeout 120s"},
        no_color=True,
    )
    assert text.startswith("  × timeout 120s")
    assert text.count("×") == 1
    assert "corrección" not in text
