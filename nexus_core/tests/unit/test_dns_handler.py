"""Unit tests for the durable DNS handler and its parser (sandbox mocked).

The positive cases use real ``dig`` output captured from the RUN_sala10 target
(an AD DC whose domain TXT record carried the room's flag): the parser must not
invent anything, and a well-formed answer — including ``NXDOMAIN`` — is the
post-condition, while a server that does not answer is not.
"""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import dns as dns_module
from nexus_core.tools.handlers.dns import (
    dns_query_definition,
    dns_query_handler,
    validate_dns_name,
    validate_record_type,
)
from nexus_core.tools.parsers.dns import parse_dig_output

FLAG = ("flag{fake_flag}")

TXT_OUTPUT = f"""; <<>> DiG 9.20.15 <<>> +noquestion @10.64.147.184 windcorp.thm TXT
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2592
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1

;; ANSWER SECTION:
windcorp.thm.		86400	IN	TXT	"{FLAG}"

;; Query time: 98 msec
;; SERVER: 10.64.147.184#53(10.64.147.184) (UDP)
"""

SRV_OUTPUT = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11

;; ANSWER SECTION:
_ldap._tcp.dc._msdcs.windcorp.thm. 600 IN SRV 0 100 389 fire.windcorp.thm.
"""

NXDOMAIN_OUTPUT = """;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42

;; AUTHORITY SECTION:
windcorp.thm.		3600	IN	SOA	fire.windcorp.thm. hostmaster.windcorp.thm. 294 900 600 86400 3600
"""

TIMEOUT_OUTPUT = """; <<>> DiG 9.20.15 <<>> @10.0.0.1 example.test A
;; global options: +cmd
;; connection timed out; no servers could be reached
"""


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(dns_module, "ad_sandbox", lambda *args, **kwargs: sandbox):
        with mock.patch.object(
            dns_module, "resolve_ad_binary", lambda *args, **kwargs: "/usr/bin/dig"
        ):
            yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(dns_query_handler(arguments, _context()))


def _result(stdout: str = "", exit_code: int = 0, stderr: str = "") -> SandboxResult:
    return SandboxResult(exit_code, stdout, stderr)


# ------------------------------------------------------------------ definition
def test_definition_is_scoped_read_only_and_sandboxed():
    definition = dns_query_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert definition.sandbox_required is True
    assert definition.effect == "read_only"
    assert definition.input_schema["properties"]["record_type"]["enum"] == list(
        dns_module.DNS_RECORD_TYPES
    )


# --------------------------------------------------------------------- parser
def test_parser_extracts_txt_records_and_the_flag():
    payload = parse_dig_output(
        TXT_OUTPUT, server="10.64.147.184", name="windcorp.thm", record_type="TXT"
    )
    assert payload["status"] == "NOERROR"
    assert payload["count"] == 1
    assert payload["records"][0]["type"] == "TXT"
    assert payload["flags"] == [FLAG]
    assert payload["error"] is None


def test_parser_handles_srv_values_with_spaces():
    payload = parse_dig_output(
        SRV_OUTPUT, server="10.64.147.184", name="_ldap._tcp.dc._msdcs.windcorp.thm",
        record_type="SRV",
    )
    assert payload["count"] == 1
    assert payload["records"][0]["value"] == "0 100 389 fire.windcorp.thm."
    assert payload["flags"] == []


def test_parser_reports_network_failure_as_error_without_status():
    payload = parse_dig_output(
        TIMEOUT_OUTPUT, server="10.0.0.1", name="example.test", record_type="A"
    )
    assert payload["status"] is None
    assert payload["error"] == "dns server did not answer"


# --------------------------------------------------------------------- handler
def test_handler_runs_dig_through_the_sandbox():
    with _fake_sandbox(_result(TXT_OUTPUT)) as sandbox:
        result = _run({"target": "10.64.147.184", "name": "windcorp.thm", "record_type": "TXT"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "/usr/bin/dig"
    assert "@10.64.147.184" in argv and "windcorp.thm" in argv and "TXT" in argv
    assert result.verified is True
    assert result.verification_method == "dns_response_parsed"
    assert result.output["flags"] == [FLAG]
    assert result.evidence["noise_level"] == "low"


def test_handler_never_spawns_subprocess_directly():
    with _fake_sandbox(_result(TXT_OUTPUT)):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "10.64.147.184", "name": "windcorp.thm", "record_type": "TXT"})


def test_nxdomain_is_a_valid_negative_answer_not_a_failure():
    with _fake_sandbox(_result(NXDOMAIN_OUTPUT)):
        result = _run({"target": "10.64.147.184", "name": "nope.windcorp.thm"})
    assert result.verified is True
    assert result.verification_method == "dns_response_parsed"
    assert result.output["status"] == "NXDOMAIN"
    assert result.output["records"] == []


def test_unanswered_query_is_not_verified():
    with _fake_sandbox(_result(TIMEOUT_OUTPUT)):
        result = _run({"target": "10.0.0.1", "name": "example.test"})
    assert result.verified is False
    assert result.verification_method == "dns_unavailable"
    assert result.evidence["error"] == "dns server did not answer"


def test_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "10.0.0.1", "name": "example.test"})
    assert result.verified is False
    assert result.verification_method == "dns_timeout"


def test_record_type_defaults_to_a_and_is_case_insensitive():
    with _fake_sandbox(_result(SRV_OUTPUT)) as sandbox:
        _run({"target": "10.64.147.184", "name": "windcorp.thm", "record_type": "srv"})
    assert sandbox.calls[0][0][-1] == "SRV"


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("bad", ["", " ", "a b", "exa mple.test", "..bad", "a..b", "*.sub.*.test"])
def test_invalid_names_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_dns_name(bad)


def test_valid_names_include_srv_labels_and_wildcards():
    assert validate_dns_name("_ldap._tcp.dc._msdcs.windcorp.thm") == "_ldap._tcp.dc._msdcs.windcorp.thm"
    assert validate_dns_name("*.windcorp.thm") == "*.windcorp.thm"
    assert validate_dns_name("windcorp.thm.") == "windcorp.thm"


def test_unsupported_record_types_are_rejected():
    with pytest.raises(ValueError):
        validate_record_type("HINFO")
    with pytest.raises(ValueError):
        validate_record_type("A; rm -rf /")
