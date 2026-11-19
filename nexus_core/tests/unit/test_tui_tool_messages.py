"""Conversational tool lines and human errors in the transcript (Wreath UX).

The TUI used to answer a bookkeeping payload with ``resultado estructurado ·
N campo(s)`` and a raw exception with the Python class name. These are the
messages the operator reads in the Wreath run, so they are pinned here.
"""

from __future__ import annotations

from nexus_core.cli.tui.stream import summarize_tool_result


def _result(tool_id: str, *, output=None, evidence=None, success=True, error=""):
    return {
        "tool_id": tool_id,
        "success": success,
        "output": output or {},
        "evidence": evidence or {},
        "error": error,
    }


def test_discover_tools_names_the_count_instead_of_its_json() -> None:
    result = _result(
        "nexus.system.discover_tools",
        output={"tools": ["a", "b", "c", "d", "e"], "activated": ["a"]},
        evidence={"tools_total": 5, "activated_total": 1},
    )
    assert summarize_tool_result(result) == "5 herramientas descubiertas"


def test_subfinder_zero_is_a_negative_answer_not_a_structured_body() -> None:
    result = _result(
        "nexus.recon.subfinder",
        output={"domain": "wreath.example", "count": 0, "subdomains": []},
        evidence={"count": 0},
    )
    assert summarize_tool_result(result) == "0 subdominios encontrados"


def test_record_fact_names_the_type_and_key() -> None:
    result = _result(
        "nexus.knowledge.record_fact",
        output={
            "recorded": {"fact_type": "credential", "key": "cred:ssh:user@host"},
            "verified": False,
        },
        evidence={"fact_type": "credential", "key": "cred:ssh:user@host"},
    )
    assert summarize_tool_result(result) == (
        "Hecho registrado: credential - cred:ssh:user@host"
    )


def test_web_request_reports_status_and_body_size() -> None:
    result = _result(
        "nexus.web.request",
        output={
            "status": 200,
            "reason": "OK",
            "body_bytes": 12_800,
            "body_preview": "<html>…</html>",
        },
        evidence={"status": 200, "body_bytes": 12_800},
    )
    assert summarize_tool_result(result) == "200 OK (12.5 KB)"


def test_an_ssl_failure_is_a_sentence_not_a_traceback() -> None:
    result = _result(
        "nexus.web.request",
        success=False,
        output={"url": "https://10.10.10.10/login"},
        error=(
            "SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] "
            "certificate verify failed: self-signed certificate"
        ),
    )
    line = summarize_tool_result(result)
    assert line.startswith("⚠️ Error SSL: certificado no verificable")
    assert "https://10.10.10.10/login" in line


def test_a_reset_ftp_channel_is_a_sentence() -> None:
    result = _result(
        "nexus.recon.ftp",
        success=False,
        error="ConnectionResetError: [Errno 104] Connection reset by peer",
    )
    assert summarize_tool_result(result) == "⚠️ Conexión FTP reiniciada por el objetivo."


def test_a_post_condition_failure_names_the_parser() -> None:
    result = _result(
        "nexus.recon.nmap",
        success=False,
        error="tool post-condition was not verified (method=nmap_xml_parsed)",
    )
    line = summarize_tool_result(result)
    assert "parser no pudo verificar el resultado" in line
    assert "host filtrado" in line


def test_an_unknown_skill_points_at_the_slash_command() -> None:
    result = _result(
        "nexus.skill.load",
        success=False,
        error="unknown skill 'sqlmap' (available: nmap, web)",
    )
    assert summarize_tool_result(result) == (
        "⚠️ Skill 'sqlmap' no encontrado. Usa /skills para ver disponibles."
    )
