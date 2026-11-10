"""Unit tests for the durable nmap handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nmap as nmap_module
from nexus_core.tools.handlers.nmap import (
    degrade_unprivileged_flags,
    nmap_definition,
    nmap_handler,
    validate_and_canonicalize_flags,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nmap"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


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
    with mock.patch.object(
        nmap_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nmap_handler(arguments, _context()))


# --------------------------------------------------------------- flag allowlist
def test_validate_flags_rejects_forbidden_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["--script=vuln"])
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["-A"])


def test_validate_flags_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["--malicious"])


def test_validate_flags_accepts_allowed_and_canonicalizes():
    flags, noise, _ = validate_and_canonicalize_flags(["-sV", "-p", "22,80"])
    assert flags == ["-sV", "-p", "22,80"]
    assert noise == "medium"


def test_validate_flags_calculates_high_noise():
    _, noise, _ = validate_and_canonicalize_flags(["-T4"])
    assert noise == "high"


def test_validate_flags_calculates_low_noise():
    _, noise, _ = validate_and_canonicalize_flags(["-Pn", "-n"])
    assert noise == "low"


# --------------------------------------------------------------------- handler
def test_handler_always_appends_oX_dash():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "flags": ["-Pn", "-p", "22,80"]})
    argv = sandbox.calls[0][0]
    assert argv[:4] == ["nmap", "-Pn", "-p", "22,80"]
    assert "-oX" in argv and "-" in argv
    assert argv[-1] == "203.0.113.10"


def test_handler_uses_sandbox_not_subprocess():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "203.0.113.10"})
    assert sandbox.calls


def test_handler_returns_verified_true_on_exit_zero():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")):
        result = _run({"target": "203.0.113.10", "flags": ["-sV"]})
    assert result.verified is True
    assert result.success is True
    assert result.verification_method == "nmap_xml_parsed"


def test_handler_returns_verified_false_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is False
    assert result.verification_method == "nmap_timeout"


def test_handler_returns_verified_false_on_malformed_xml():
    with _fake_sandbox(SandboxResult(0, _read("scan_malformed.xml"), "")):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is False
    assert result.verification_method == "nmap_xml_parse_failed"


def test_handler_includes_noise_level_in_evidence():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")):
        result = _run({"target": "203.0.113.10", "flags": ["-sV"]})
    assert result.evidence["noise_level"] == "medium"


def test_handler_includes_raw_xml_sha256_in_evidence():
    xml_text = _read("scan_single_host.xml")
    with _fake_sandbox(SandboxResult(0, xml_text, "")):
        result = _run({"target": "203.0.113.10"})
    assert result.evidence["raw_xml_sha256"] == hashlib.sha256(
        xml_text.encode("utf-8")
    ).hexdigest()
    assert result.evidence["hosts_up"] == 1
    assert result.evidence["ports_open_total"] == 2


# ------------------------------------------------------------------- H1 stdout
def _inflate(xml_text: str, target_bytes: int = 30_000) -> str:
    """Grow the fixture with an XML comment so the raw scan exceeds 30 KB."""
    padding = "<!--" + ("A" * target_bytes) + "-->"
    head, separator, tail = xml_text.partition("?>")
    if not separator:  # no XML declaration: just lead with the comment
        return padding + xml_text
    return head + separator + padding + tail


def test_handler_truncates_raw_xml_stdout_when_scan_is_parsed():
    xml_text = _inflate(_read("scan_single_host.xml"))
    assert len(xml_text.encode("utf-8")) > 30_000
    with _fake_sandbox(SandboxResult(0, xml_text, "")):
        result = _run({"target": "203.0.113.10", "profile": "service"})
    assert result.verified is True
    assert len(result.stdout.encode("utf-8")) <= 500
    assert result.output["stdout_truncated"] is True
    assert result.evidence["stdout_truncated"] is True
    # The parsed scan is untouched, and the digest still covers the full XML.
    assert result.output["scan"]["hosts"]
    assert result.evidence["raw_xml_sha256"] == hashlib.sha256(
        xml_text.encode("utf-8")
    ).hexdigest()


SMALL_XML = (
    '<?xml version="1.0"?>'
    '<nmaprun scanner="nmap" args="nmap">'
    '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80"><state state="open"/>'
    '<service name="http"/></port></ports></host>'
    '<runstats><hosts up="1" down="0"/></runstats></nmaprun>'
)


def test_handler_keeps_small_stdout_intact():
    assert len(SMALL_XML.encode("utf-8")) <= 500
    with _fake_sandbox(SandboxResult(0, SMALL_XML, "")):
        result = _run({"target": "10.0.0.1"})
    assert result.stdout == SMALL_XML
    assert "stdout_truncated" not in result.output
    assert result.evidence["stdout_truncated"] is False


def test_truncate_stdout_is_byte_safe():
    from nexus_core.tools.handlers.nmap import truncate_stdout

    text, truncated = truncate_stdout("á" * 400, limit=500)
    assert truncated is True
    assert len(text.encode("utf-8")) <= 500
    same, untouched = truncate_stdout("short", limit=500)
    assert same == "short" and untouched is False


def test_nmap_definition_declares_scope_requirements():
    definition = nmap_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert definition.tenant_id == "system"


def test_nmap_definition_exposes_profile_enum():
    definition = nmap_definition()
    profile = definition.input_schema["properties"]["profile"]
    assert "full_tcp" in profile["enum"]
    assert "service" in profile["enum"]


# ---------------------------------------------------------------------- profiles
def test_full_tcp_profile_scans_all_ports_with_its_own_timeout():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run({"target": "203.0.113.10", "profile": "full_tcp"})
    argv, timeout = sandbox.calls[0]
    assert "-p-" in argv
    # 600 s menos el rescate top-1000 (180 s) y un margen: con el presupuesto
    # entero el gateway cancelaba el reintento antes de que corriera (P6).
    assert timeout == 600 - 180 - 15
    assert result.output["profile"] == "full_tcp"
    assert result.evidence["profile"] == "full_tcp"


def test_explicit_timeout_overrides_profile_timeout():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "profile": "full_tcp", "timeout_seconds": 90})
    assert sandbox.calls[0][1] == 90


def test_the_profile_description_asks_for_ports_only_where_they_narrow():
    # `service` ahora acota cuando se le pasa `-p`; `full_tcp` no. El texto del
    # contrato tiene que decir las dos cosas o el modelo seguirá barriendo los
    # 65535 puertos para pedir la versión de dos (medido en DeadDrop P1/P3).
    definition = nmap_definition()
    properties = definition.input_schema["properties"]
    profile = properties["profile"]["description"]
    assert "no pases '-p'" in profile
    assert "Con 'service' pásalos" in profile
    flags = properties["flags"]["description"]
    assert "'-p <puertos>'" in flags
    assert "sin '-p' el -sV -sC recorre los 65535" in definition.description


def test_profile_flags_combine_with_explicit_flags():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "profile": "full_tcp", "flags": ["-sV"]})
    argv = sandbox.calls[0][0]
    assert "-p-" in argv and "-sV" in argv


def test_profiles_disable_reverse_dns():
    # ``-n`` is a pure speed win on IP targets (no reverse DNS) and was missing
    # from every profile; the RootMe scan measured 43.8 s without it.
    for profile in ("quick", "full_tcp", "service"):
        with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
            _run({"target": "203.0.113.10", "profile": profile})
        assert "-n" in sandbox.calls[0][0]


def test_min_rate_flag_is_allowed():
    flags, noise, _ = validate_and_canonicalize_flags(["--min-rate", "5000"])
    assert flags == ["--min-rate", "5000"]
    assert noise == "medium"


def test_min_rate_requires_a_value():
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["--min-rate"])


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "profile": "does-not-exist"})


def test_profile_all_ports_ignores_an_explicit_port_list():
    # Simple CTF: the model sent profile="service" + flags=["-p", "-p", ...];
    # raising here cost the run an iteration and the scan never happened. The
    # profile already means -p-, so the port selection is dropped, not fatal.
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run(
            {"target": "203.0.113.10", "profile": "full_tcp", "flags": ["-p", "22,80"]}
        )
    argv = sandbox.calls[0][0]
    assert "-p-" in argv
    assert "22,80" not in argv and "-p" not in argv
    assert result.output["ignored_flags"] == ["-p", "22,80"]
    assert any("ignored redundant port flags" in warning for warning in result.evidence["warnings"])


def test_service_profile_narrows_to_the_ports_the_model_named():
    # DeadDrop (2026-10-22): tras un full_tcp con 22/80 abiertos, el modelo pidió
    # profile="service" + -p 22,80 -sV -sC y el handler volvió a barrer 65 535
    # puertos con -sV: 600 s de timeout y cero hechos. El fingerprint de los
    # puertos descubiertos es el paso siguiente correcto, así que acota.
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run(
            {"target": "203.0.113.10", "profile": "service", "flags": ["-p", "22,80", "-sV"]}
        )
    argv = sandbox.calls[0][0]
    assert "-p-" not in argv
    assert "-p" in argv and "22,80" in argv and "-sV" in argv
    assert "ignored_flags" not in result.output
    assert any("narrowed" in warning for warning in result.evidence["warnings"])


def test_service_profile_narrows_an_inline_port_selection():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run(
            {"target": "203.0.113.10", "profile": "service", "flags": ["-p=21,80", "-sV"]}
        )
    argv = sandbox.calls[0][0]
    assert "-p-" not in argv
    assert "-p" in argv and "21,80" in argv and "-sV" in argv
    assert "ignored_flags" not in result.output


def test_service_profile_without_a_port_selection_still_sweeps_every_port():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "profile": "service", "flags": ["-sV"]})
    argv = sandbox.calls[0][0]
    assert "-p-" in argv and "-sV" in argv


def test_profiles_leave_the_port_selection_alone_without_all_ports():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run({"target": "203.0.113.10", "profile": "quick", "flags": ["-p", "21,80"]})
    argv = sandbox.calls[0][0]
    assert "-p" in argv and "21,80" in argv
    assert "ignored_flags" not in result.output


def test_explicit_all_ports_with_port_list_is_still_a_conflict():
    # Without a profile there is no server-side expansion to fall back on: the
    # two port selectors are genuinely ambiguous, so the guard stays.
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "flags": ["-p-", "-p", "22,80"]})


# -------------------------------------------------------- port-sweep fallback
# Simple CTF (2026-10-17): ``-p- -T4`` reported 65 533 ports as ``filtered`` and
# missed 2222/tcp -- the only way into the room -- while ``--top-ports 1000``
# found it in 9,65 s. A sweep that comes back that empty is retried.


class SequenceSandbox:
    """A sandbox that answers each call with the next queued result."""

    def __init__(self, results: list[SandboxResult]):
        self.results = list(results)
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        index = min(len(self.calls) - 1, len(self.results) - 1)
        return self.results[index]


@contextlib.contextmanager
def _sequence_sandbox(*results: SandboxResult):
    sandbox = SequenceSandbox(list(results))
    with mock.patch.object(
        nmap_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _scan_xml(ports: list[str], filtered: int = 0) -> str:
    entries = "".join(
        f'<port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="svc"/></port>'
        for port in ports
    )
    extra = f'<extraports state="filtered" count="{filtered}"/>' if filtered else ""
    return (
        '<?xml version="1.0"?>'
        '<nmaprun scanner="nmap" args="nmap -p-">'
        '<host><status state="up"/><address addr="10.64.128.102" addrtype="ipv4"/>'
        f"<ports>{entries}{extra}</ports></host>"
        '<runstats><hosts up="1" down="0"/><finished elapsed="180"/></runstats>'
        "</nmaprun>"
    )


def test_needs_port_fallback_only_for_an_empty_or_blind_full_sweep():
    from nexus_core.tools.handlers.nmap import needs_port_fallback

    # Empty: fewer open ports than the threshold.
    assert needs_port_fallback(["-p-"], 2) is True
    assert needs_port_fallback(["-p-"], 3) is False
    # Blind: it found some ports but cannot tell closed from dropped.
    assert needs_port_fallback(["-p-"], 3, 65_533) is True
    assert needs_port_fallback(["-p-"], 12, 1_000) is True
    assert needs_port_fallback(["-p-"], 12, 999) is False
    # An explicit short list is the operator's contract, not a false negative.
    assert needs_port_fallback(["-p", "21,80"], 2) is False
    assert needs_port_fallback(["-p", "21,80"], 2, 65_533) is False


def test_a_timed_out_full_sweep_is_retried_with_top_ports():
    """DeadDrop P5 (2026-10-22): ``-p- -T4`` agotó los 600 s y el run quedó a cero.

    Un barrido que expira es el mismo fallo que uno vacío (el host o el enlace se
    auto-limitaron), así que se reintenta top-1000 con tasa explícita en vez de
    devolver un timeout sin hechos que dejó sin superficie a todas las fases.
    """
    primary = SandboxResult(124, "", "timed out", timed_out=True)
    fallback = SandboxResult(0, _scan_xml(["22", "80"]), "")
    with _sequence_sandbox(primary, fallback) as sandbox:
        result = _run({"target": "10.64.128.102", "profile": "full_tcp"})

    assert result.verified is True
    assert len(sandbox.calls) == 2
    second = sandbox.calls[1][0]
    assert "--top-ports" in second and "1000" in second
    assert "-p-" not in second
    assert any("timed out" in warning for warning in result.evidence["warnings"])
    # The primary sweep must leave room for the rescue inside the tool's own
    # budget: with 600 s it was cancelled before the retry started (P6).
    assert sandbox.calls[0][1] <= 600 - 180 - 15


def test_a_blind_full_sweep_is_retried_even_when_it_found_ports():
    # 21/80/3306 open and 65 532 filtered: nmap cannot tell whether 2222 was
    # closed or dropped, so the cheap top-1000 pass runs anyway.
    primary = SandboxResult(0, _scan_xml(["21", "80", "3306"], filtered=65532), "")
    fallback = SandboxResult(0, _scan_xml(["21", "80", "2222", "3306"]), "")
    with _sequence_sandbox(primary, fallback) as sandbox:
        result = _run({"target": "10.64.128.102", "profile": "full_tcp"})

    assert len(sandbox.calls) == 2
    assert result.evidence["fallback"]["recovered_ports"] == ["2222/tcp"]
    assert result.evidence["ports_open_total"] == 4
    assert "65532 filtered" in result.evidence["fallback"]["reason"]


def test_empty_full_sweep_triggers_a_top_1000_fallback_that_recovers_the_port():
    primary = SandboxResult(0, _scan_xml(["21", "80"], filtered=65533), "")
    fallback = SandboxResult(0, _scan_xml(["21", "80", "2222"]), "")
    with _sequence_sandbox(primary, fallback) as sandbox:
        result = _run({"target": "10.64.128.102", "profile": "full_tcp"})

    assert len(sandbox.calls) == 2
    argv = sandbox.calls[1][0]
    for expected in ("-sS", "-Pn", "--top-ports", "1000", "--min-rate", "1000"):
        assert expected in argv
    # nmap accepts --top-ports with a value, so the value must travel with it.
    assert argv[argv.index("--top-ports") + 1] == "1000"
    assert argv[argv.index("--min-rate") + 1] == "1000"
    ports = [port["port"] for host in result.output["scan"]["hosts"] for port in host["ports"]]
    assert ports == ["21", "80", "2222"]
    assert result.evidence["ports_open_total"] == 3
    assert result.evidence["fallback"]["recovered_ports"] == ["2222/tcp"]
    assert any("recovered ports" in warning for warning in result.evidence["warnings"])
    assert result.verified is True


def test_a_full_sweep_with_enough_ports_is_not_retried():
    # Enough open ports and a trustworthy sweep: no second scan is paid for.
    with _sequence_sandbox(SandboxResult(0, _scan_xml(["21", "22", "80"], filtered=500), "")) as sandbox:
        result = _run({"target": "10.64.128.102", "profile": "full_tcp"})
    assert len(sandbox.calls) == 1
    assert "fallback" not in result.evidence


def test_an_explicit_port_list_never_triggers_the_fallback():
    with _sequence_sandbox(SandboxResult(0, _scan_xml(["21", "80"]), "")) as sandbox:
        result = _run({"target": "10.64.128.102", "flags": ["-Pn", "-p", "21,80"]})
    assert len(sandbox.calls) == 1
    assert "fallback" not in result.evidence


def test_a_failed_fallback_keeps_the_primary_scan():
    primary = SandboxResult(0, _scan_xml(["21", "80"], filtered=65533), "")
    with _sequence_sandbox(primary, SandboxResult(1, "", "nmap: no such device")) as sandbox:
        result = _run({"target": "10.64.128.102", "profile": "full_tcp"})

    assert len(sandbox.calls) == 2
    assert result.evidence["fallback"]["error"]
    assert result.evidence["ports_open_total"] == 2
    ports = [port["port"] for host in result.output["scan"]["hosts"] for port in host["ports"]]
    assert ports == ["21", "80"]


def test_a_timed_out_fallback_keeps_the_primary_scan():
    primary = SandboxResult(0, _scan_xml(["21", "80"], filtered=65533), "")
    with _sequence_sandbox(primary, SandboxResult(-1, "", "", timed_out=True)) as sandbox:
        result = _run({"target": "10.64.128.102", "profile": "full_tcp"})
    assert len(sandbox.calls) == 2
    assert result.evidence["fallback"]["timed_out"] is True
    assert result.evidence["fallback"]["error"] == "fallback scan failed"
    assert result.verified is True


# ------------------------------------- privilegios: el sandbox OCI no tiene root
PRIVILEGE_STDERR = (
    "You requested a scan type which requires root privileges.\nQUITTING!\n"
)


def test_unprivileged_flags_replace_syn_scan_and_drop_os_detection():
    flags, warnings = degrade_unprivileged_flags(
        ["-sS", "-O", "-Pn", "-p-"], unprivileged=True
    )
    assert flags == ["-sT", "-Pn", "-p-"]
    assert any("CAP_NET_RAW" in warning for warning in warnings)


def test_privileged_flags_are_left_untouched():
    flags, warnings = degrade_unprivileged_flags(["-sS"], unprivileged=False)
    assert flags == ["-sS"] and warnings == set()


def test_oci_sandbox_never_asks_nmap_for_a_syn_scan():
    xml_text = _scan_xml(["22"])
    with (
        mock.patch.object(nmap_module, "OCISandbox", FakeSandbox),
        _fake_sandbox(SandboxResult(0, xml_text, "")) as sandbox,
    ):
        result = _run({"target": "10.64.128.102", "flags": ["-sS", "-O"]})
    argv = sandbox.calls[0][0]
    assert "-sS" not in argv and "-sT" in argv and "-O" not in argv
    assert result.verified is True
    assert any("-sT" in warning for warning in result.evidence["warnings"])


def test_oci_sandbox_refuses_udp_instead_of_returning_empty_xml():
    with (
        mock.patch.object(nmap_module, "OCISandbox", FakeSandbox),
        _fake_sandbox(SandboxResult(0, "", "")) as sandbox,
    ):
        result = _run({"target": "10.64.128.102", "flags": ["-sU"]})
    assert result.verified is False
    assert result.verification_method == "nmap_privileges_required"
    assert "CAP_NET_RAW" in result.output["error"]
    assert sandbox.calls == []


def test_a_syn_scan_without_privileges_is_retried_as_a_connect_scan():
    # The local nmap may lack the setuid helper too: the empty stdout must not be
    # reported as "the host has no ports".
    with _sequence_sandbox(
        SandboxResult(1, "", PRIVILEGE_STDERR), SandboxResult(0, _scan_xml(["22"]), "")
    ) as sandbox:
        result = _run({"target": "10.64.128.102", "flags": ["-sS", "-Pn"]})
    assert result.verified is True
    assert "-sS" not in sandbox.calls[1][0] and "-sT" in sandbox.calls[1][0]
    assert any("-sT" in warning for warning in result.evidence["warnings"])


def test_xml_parse_failure_reports_the_stderr_that_explains_it():
    with _fake_sandbox(SandboxResult(1, "", PRIVILEGE_STDERR)):
        result = _run({"target": "10.64.128.102"})
    assert result.verification_method == "nmap_xml_parse_failed"
    assert "requires root privileges" in result.output["error"]
    assert "requires root privileges" in result.output["stderr"]
