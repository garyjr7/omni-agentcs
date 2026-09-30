"""Unit tests for nexus_core.tools.parsers.sqlmap (no network, no binary)."""

from __future__ import annotations

import hashlib

import pytest

from nexus_core.tools.parsers.sqlmap import parse_sqlmap_output

VULNERABLE_REPORT = (
    "[18:30:48] [INFO] testing connection to the target URL\n"
    "[18:30:48] [INFO] the back-end DBMS is MySQL\n"
    "[18:30:49] [INFO] GET parameter 'id' is vulnerable. Do you want to keep "
    "testing the others (if any)? [y/N]\n"
    "[18:30:49] [INFO] sqlmap identified the following injection point(s)\n"
    "---\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
    "    Payload: id=1 AND 1234=1234\n"
    "---\n"
)

NOT_INJECTABLE = (
    "[18:31:00] [INFO] testing for SQL injection on GET parameter 'id'\n"
    "[18:31:00] [WARNING] GET parameter 'id' does not seem to be injectable\n"
    "[18:31:00] [ERROR] all tested parameters do not appear to be injectable.\n"
)


def test_parse_vulnerable_report_block():
    result = parse_sqlmap_output(VULNERABLE_REPORT, target_url="http://x/?id=1")
    assert result.vulnerable is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.parameter == "id"
    assert finding.method == "GET"
    assert finding.injection_type == "boolean-based blind"
    assert finding.payload == "id=1 AND 1234=1234"
    assert finding.dbms == "MySQL"
    assert finding.severity == "high"


def test_parse_vulnerable_dedupes_line_and_report_block():
    result = parse_sqlmap_output(VULNERABLE_REPORT)
    assert len(result.findings) == 1


def test_parse_dbms_detected():
    result = parse_sqlmap_output(VULNERABLE_REPORT)
    assert result.dbms_detected == "MySQL"


def test_parse_is_vulnerable_line_without_report_block():
    text = "[INFO] POST parameter 'user' is vulnerable. Do you want to keep testing?\n"
    result = parse_sqlmap_output(text, target_url="http://x/")
    assert result.vulnerable is True
    assert result.findings[0].parameter == "user"
    assert result.findings[0].method == "POST"
    assert result.findings[0].injection_type == "SQL injection"


def test_parse_not_injectable_is_a_clean_negative():
    result = parse_sqlmap_output(NOT_INJECTABLE, target_url="http://x/?id=1")
    assert result.vulnerable is False
    assert result.findings == ()
    assert result.target_url == "http://x/?id=1"


def test_parse_empty_output_returns_empty_result():
    result = parse_sqlmap_output("")
    assert result.vulnerable is False
    assert result.findings == ()
    assert result.to_dict()["count"] == 0


def test_parse_unrelated_output_raises_value_error():
    with pytest.raises(ValueError):
        parse_sqlmap_output("this is not sqlmap output at all\njust text")


def test_parse_handles_crlf_and_ansi_sequences():
    text = (
        "\x1b[1m[18:31:00] \x1b[0m[INFO] the back-end DBMS is PostgreSQL\r\n"
        "\r[18:31:01] [INFO] GET parameter 'q' is vulnerable\r\n"
    )
    result = parse_sqlmap_output(text)
    assert result.dbms_detected == "PostgreSQL"
    assert result.findings[0].parameter == "q"


def test_parse_backend_dbms_colon_format():
    text = "[INFO] back-end DBMS: Microsoft SQL Server\n[INFO] GET parameter 'x' is vulnerable\n"
    result = parse_sqlmap_output(text)
    assert result.dbms_detected is not None
    assert "SQL Server" in result.dbms_detected


def test_parse_preserves_raw_sha256_of_the_payload():
    result = parse_sqlmap_output(VULNERABLE_REPORT)
    expected = hashlib.sha256(VULNERABLE_REPORT.encode("utf-8")).hexdigest()
    assert result.raw_log_sha256 == expected


def test_parse_missing_optional_payload_is_empty():
    text = "[INFO] GET parameter 'id' is vulnerable\n"
    result = parse_sqlmap_output(text)
    assert result.findings[0].payload == ""
