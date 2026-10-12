"""Unit tests for the durable dynamic-DNS-update (ADIDNS) handler.

The shipped client is exercised for real: a local UDP server records the packet
and answers with a RCODE, so the *wire format* (RFC 2136 opcode, zone section
typed SOA/IN, update RR, delete semantics) is asserted instead of assumed.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import struct
import subprocess
import sys
import threading
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import dns_update as update_module
from nexus_core.tools.handlers.dns_update import (
    DNS_UPDATE_SCRIPT,
    dns_update_definition,
    dns_update_handler,
    validate_update_name,
    validate_update_value,
)


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
    with mock.patch.object(update_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(dns_update_handler(arguments, _context()))


def _sandbox_for(payload: dict) -> SandboxResult:
    return SandboxResult(0, json.dumps(payload) + "\n", "")


# --------------------------------------------------- real wire-format harness
def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), offset


class _UdpDnsServer:
    """One-shot UDP server: records the update and answers with ``rcode``."""

    def __init__(self, rcode: int = 0):
        self.rcode = rcode
        self.received: bytes | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(20)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        try:
            data, peer = self.sock.recvfrom(4096)
        except OSError:
            return
        self.received = data
        ident = struct.unpack_from("!H", data, 0)[0]
        reply = struct.pack("!HHHHHH", ident, 0x8000 | self.rcode, 1, 0, 0, 0)
        self.sock.sendto(reply, peer)

    def close(self) -> None:
        self.sock.close()


def _run_client(port: int, *, action: str = "add", rtype: str = "A",
                value: str = "127.0.0.1", name: str = "omniproof.windcorp.thm") -> dict:
    argv = [
        sys.executable, "-c", DNS_UPDATE_SCRIPT, "127.0.0.1", str(port),
        "windcorp.thm", name, rtype, value, "60", action, "10",
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    payloads = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert payloads, proc.stdout + proc.stderr
    return json.loads(payloads[-1])


def test_shipped_client_sends_a_well_formed_update_and_reports_noerror():
    server = _UdpDnsServer(rcode=0)
    try:
        payload = _run_client(server.port, value="203.0.113.7")
    finally:
        server.close()
    assert payload["ok"] is True
    assert payload["rcode_name"] == "NOERROR"

    packet = server.received
    assert packet is not None
    ident, flags, zocount, prcount, upcount, adcount = struct.unpack_from("!HHHHHH", packet, 0)
    assert flags >> 11 == 5  # opcode UPDATE
    assert (zocount, prcount, upcount, adcount) == (1, 0, 1, 0)
    zone, offset = _read_name(packet, 12)
    assert zone == "windcorp.thm"
    zone_type, zone_class = struct.unpack_from("!HH", packet, offset)
    assert (zone_type, zone_class) == (6, 1)  # SOA / IN
    owner, offset = _read_name(packet, offset + 4)
    assert owner == "omniproof.windcorp.thm"
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
    assert (rtype, rclass, ttl) == (1, 1, 60)
    assert struct.unpack("!4s", packet[offset + 10:offset + 14])[0] == socket.inet_aton("203.0.113.7")
    assert rdlength == 4


def test_shipped_client_marks_a_refused_update_as_not_ok():
    server = _UdpDnsServer(rcode=5)
    try:
        payload = _run_client(server.port)
    finally:
        server.close()
    assert payload["ok"] is False
    assert payload["rcode_name"] == "REFUSED"
    assert payload["id_matched"] is True


def test_shipped_client_deletes_with_class_any_and_no_rdata():
    server = _UdpDnsServer(rcode=0)
    try:
        _run_client(server.port, action="delete", value="203.0.113.7")
    finally:
        server.close()
    packet = server.received
    assert packet is not None
    _zone, offset = _read_name(packet, 12)
    _owner, offset = _read_name(packet, offset + 4)
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
    assert (rtype, rclass, ttl, rdlength) == (1, 255, 0, 0)


# ------------------------------------------------------------------ definition
def test_definition_is_scoped_and_declares_the_active_effect():
    definition = dns_update_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert definition.sandbox_required is True
    assert definition.effect == "exploit"
    assert definition.idempotent is False
    assert definition.input_schema["properties"]["action"]["enum"] == ["add", "delete"]


# --------------------------------------------------------------------- handler
def test_handler_runs_the_client_in_the_sandbox():
    payload = {"ok": True, "rcode": 0, "rcode_name": "NOERROR", "id_matched": True,
               "action": "add", "update_bytes": 60, "reply_bytes": 12}
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run({"target": "10.64.147.184", "zone": "windcorp.thm",
                       "name": "omniproof.windcorp.thm", "value": "10.64.147.184"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "10.64.147.184" and argv[4] == "53"
    assert argv[5] == "windcorp.thm" and argv[6] == "omniproof.windcorp.thm"
    assert argv[7] == "A" and argv[8] == "10.64.147.184"
    assert argv[9] == "60" and argv[10] == "add"
    assert result.verified is True
    assert result.verification_method == "dns_update_accepted"
    assert result.evidence["unauthenticated"] is True
    assert result.evidence["rcode_name"] == "NOERROR"


def test_handler_never_spawns_subprocess_directly():
    payload = {"ok": True, "rcode": 0, "rcode_name": "NOERROR", "id_matched": True}
    with _fake_sandbox(_sandbox_for(payload)):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "10.64.147.184", "zone": "windcorp.thm",
                  "name": "omniproof.windcorp.thm", "value": "10.64.147.184"})


def test_refused_update_is_a_legitimate_negative():
    payload = {"ok": False, "rcode": 5, "rcode_name": "REFUSED", "id_matched": True}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "10.64.147.184", "zone": "windcorp.thm",
                       "name": "x.windcorp.thm", "value": "10.0.0.1"})
    assert result.verified is False
    assert result.verification_method == "dns_update_refused"
    assert result.evidence["rcode_name"] == "REFUSED"


def test_unanswered_update_is_not_verified():
    payload = {"ok": False, "rcode": 0, "rcode_name": "NOERROR", "id_matched": False}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "10.64.147.184", "zone": "windcorp.thm",
                       "name": "x.windcorp.thm", "value": "10.0.0.1"})
    assert result.verified is False
    assert result.verification_method == "dns_update_unanswered"


def test_client_error_is_not_verified():
    with _fake_sandbox(_sandbox_for({"ok": False, "error": "OSError: timed out"})):
        result = _run({"target": "10.64.147.184", "zone": "windcorp.thm",
                       "name": "x.windcorp.thm", "value": "10.0.0.1"})
    assert result.verified is False
    assert result.verification_method == "dns_update_failed"


def test_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "10.64.147.184", "zone": "windcorp.thm",
                       "name": "x.windcorp.thm", "value": "10.0.0.1"})
    assert result.verified is False
    assert result.verification_method == "dns_update_timeout"


# ---------------------------------------------------------------- validation
def test_zone_apex_is_refused():
    with pytest.raises(ValueError):
        validate_update_name("windcorp.thm", "windcorp.thm")


def test_names_outside_the_zone_are_refused():
    with pytest.raises(ValueError):
        validate_update_name("evil.other.thm", "windcorp.thm")


@pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.256", ""])
def test_bad_address_values_are_refused(bad):
    with pytest.raises(ValueError):
        validate_update_value("A", bad)


def test_aaaa_and_txt_values_are_validated_per_type():
    assert validate_update_value("AAAA", "fd00::1") == "fd00::1"
    assert validate_update_value("TXT", "proof-of-dynamic-update") == "proof-of-dynamic-update"
    with pytest.raises(ValueError):
        validate_update_value("TXT", "line\nbreak")


def test_unsupported_action_and_type_are_refused():
    with pytest.raises(ValueError):
        _run({"target": "10.64.147.184", "zone": "windcorp.thm", "name": "x.windcorp.thm",
              "value": "10.0.0.1", "action": "replace"})
    with pytest.raises(ValueError):
        _run({"target": "10.64.147.184", "zone": "windcorp.thm", "name": "x.windcorp.thm",
              "value": "10.0.0.1", "record_type": "MX"})
