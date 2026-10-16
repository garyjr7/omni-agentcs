"""Local contract regressions: no tool binary, RPC service or target required."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.output_capture import StreamManifest
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.provisioner.binaries import BINARY_IDENTITIES_BY_NAME, check_binary_identity
from nexus_core.provisioner.detector import check_tool, verify_tool_in_sandbox
from nexus_core.provisioner.readiness import assess_environment
from nexus_core.provisioner.recipes import load_recipes, validate_recipes
from nexus_core.tools.execution_contract import record_capture, with_execution_contract
from nexus_core.tools.handlers._exec import normalize_targets
from nexus_core.tools.handlers.nmap import nmap_definition
from nexus_core.tools.parsers._jsonl import loads_object, to_int
from nexus_core.tools.parsers.ffuf import parse_ffuf_output
from nexus_core.tools.parsers.metasploit import parse_msf_exploit
from nexus_core.tools.parsers.nuclei import parse_nuclei_jsonl
from nexus_core.tools.parsers.sliver import parse_sliver_exec, parse_sliver_version
from nexus_core.tools.registry import durable_tool_definitions

FIXTURES = Path(__file__).parents[1] / "fixtures"


def context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def captured(text: str, *, truncated: bool = False) -> SandboxResult:
    size = len(text.encode())
    sha = hashlib.sha256(text.encode()).hexdigest()
    manifest = StreamManifest(
        size + int(truncated), size, int(truncated), sha, sha, truncated, True, None
    )
    return SandboxResult(0, text, "", stdout_manifest=manifest)


@pytest.mark.parametrize("code", [1, 124, 127])
def test_identity_signature_does_not_override_failed_exit(code: int) -> None:
    verdict = check_binary_identity(
        BINARY_IDENTITIES_BY_NAME["nmap"],
        which=lambda _: "/bin/nmap",
        run=lambda _: (code, "Nmap 7.9"),
    )
    assert not verdict.ok


def test_identity_lookup_exception_is_data() -> None:
    def broken(_: str) -> str:
        raise OSError("secret diagnostic")

    verdict = check_binary_identity(BINARY_IDENTITIES_BY_NAME["nmap"], which=broken)
    assert not verdict.ok and "secret" not in verdict.detail


def test_unknown_recipe_has_explicit_state() -> None:
    assert check_tool("missing-tool-fixture").state == "unsupported"


def test_oci_verification_never_uses_host_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("NEXUS_NMAP_IMAGE", raising=False)
    monkeypatch.setattr(
        "nexus_core.provisioner.detector.check_tool",
        lambda _: pytest.fail("OCI must not probe host"),
    )
    result = asyncio.run(
        verify_tool_in_sandbox("nmap", sandbox_mode="oci", workspace_root=tmp_path)
    )
    assert result.sandbox_mode == "oci" and not result.runnable


def test_oci_verification_uses_selected_image(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from nexus_core.kernel.sandbox import OCISandbox

    monkeypatch.setenv("NEXUS_NMAP_IMAGE", "fixture/nmap")
    runner = AsyncMock(return_value=captured("Nmap version 7.99"))
    monkeypatch.setattr(OCISandbox, "run", runner)
    result = asyncio.run(
        verify_tool_in_sandbox("nmap", sandbox_mode="oci", workspace_root=tmp_path)
    )
    assert result.runnable
    assert runner.call_args.args[:2] == ("fixture/nmap", ["nmap", "--version"])


def test_readiness_uses_runtime_rpc_url_and_wordlists() -> None:
    calls: list[tuple[str, int]] = []

    def port(host: str, number: int) -> bool:
        calls.append((host, number))
        return True

    report = assess_environment(
        which=lambda _: None,
        port_open=port,
        path_exists=lambda value: value == "/fixture/words",
        env={
            "MSF_RPC_URL": "https://rpc.fixture:5443/api",
            "MSF_RPC_PASSWORD": "fixture",
            "NEXUS_WORDLIST_DIRS": "/fixture/words",
        },
    )
    assert calls == [("rpc.fixture", 5443)]
    assert next(c for c in report.components if c.component_id == "wordlists").ready


def test_recipe_catalog_rejects_ambiguous_alias_and_string_command() -> None:
    recipes = load_recipes()
    recipes["nmap"]["aliases"] = ["httpx"]
    with pytest.raises(ValueError):
        validate_recipes(recipes)
    with pytest.raises(ValueError):
        validate_recipes({"bad": {"verify": "nmap --version", "recipes": {}}})


@pytest.mark.parametrize("targets", ["host.fixture", ["--help"], ["host\nother"], [42]])
def test_batch_targets_reject_ambiguous_values(targets: Any) -> None:
    with pytest.raises(ValueError):
        normalize_targets(targets)


@pytest.mark.parametrize("payload", ['{"x":NaN}', '{"x":1,"x":2}'])
def test_jsonl_rejects_ambiguous_json(payload: str) -> None:
    assert loads_object(payload) is None


def test_parser_edge_cases_are_explicit() -> None:
    assert to_int(float("inf")) == 0
    assert parse_ffuf_output('{"results":[]}').matches == ()
    for raw in ("{}", '{"unrelated":true}'):
        with pytest.raises(ValueError):
            parse_nuclei_jsonl(raw)
    with pytest.raises(ValueError):
        parse_msf_exploit({"status": []}, "fixture", "host")
    with pytest.raises(ValueError):
        parse_sliver_exec({"status": "ok", "duration_seconds": float("nan")}, "s", "id")
    with pytest.raises(ValueError):
        parse_sliver_version({})


def test_concurrent_capture_isolation_and_incomplete_results() -> None:
    async def handler(arguments: dict[str, Any], ctx: RunContext) -> ToolResult:
        record_capture(captured(arguments["target"], truncated=arguments["target"] == "partial"))
        await asyncio.sleep(0)
        return ToolResult(verified=True, outcome="negative")

    invoke = with_execution_contract(nmap_definition(), handler)

    async def run() -> list[ToolResult]:
        return list(
            await asyncio.gather(
                *(invoke({"target": name}, context()) for name in ("full", "partial"))
            )
        )

    full, partial = asyncio.run(run())
    assert full.success and not partial.success and not partial.completed
    for result, text in ((full, "full"), (partial, "partial")):
        records = result.evidence["execution_capture"]["executions"]
        assert len(records) == 1
        assert records[0]["stdout"]["retained_sha256"] == hashlib.sha256(text.encode()).hexdigest()


@pytest.mark.parametrize(
    "tool,module_name,fixture,args",
    [
        ("nexus.recon.nmap", "nmap", "nmap/scan_single_host.xml", {"target": "203.0.113.10"}),
        (
            "nexus.web.ffuf",
            "ffuf",
            "ffuf/ndjson.jsonl",
            {"url": "https://scanme.example/FUZZ", "wordlist": "words.txt"},
        ),
        (
            "nexus.web.nuclei",
            "nuclei",
            "nuclei/findings.jsonl",
            {"targets": ["https://scanme.example"]},
        ),
    ],
)
@pytest.mark.parametrize("truncated", [False, True])
def test_mock_cli_to_persistence_and_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tool: str,
    module_name: str,
    fixture: str,
    args: dict[str, Any],
    truncated: bool,
) -> None:
    import importlib
    from nexus_core.tests import report_support as support
    from nexus_core.report.extractor import build_report
    from nexus_core.report.markdown import render_markdown

    module = importlib.import_module(f"nexus_core.tools.handlers.{module_name}")
    raw = (FIXTURES / fixture).read_text()
    sandbox = AsyncMock()
    sandbox.run.return_value = captured(raw, truncated=truncated)
    monkeypatch.setattr(module, "sandbox_for_environment", lambda *a, **kw: sandbox)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "words.txt").write_text("admin\n")
    monkeypatch.setenv("NEXUS_NUCLEI_TEMPLATES", str(tmp_path))
    result = asyncio.run(durable_tool_definitions()[tool][1](args, context()))
    assert result.success is not truncated
    capture = result.evidence["execution_capture"]["executions"][0]
    assert capture["stdout"]["retained_bytes"] == len(raw.encode())
    store = support.make_store(tmp_path)
    scope = support.seed_engagement(store)
    run_id = support.add_run(store)
    support.record(store, run_id, tool, args, result.to_dict(), engagement_id=scope.engagement_id)
    report = asyncio.run(build_report(store, "system", scope.engagement_id, enrich_cves=False))
    assert any(entry.tool_id == tool for entry in report.timeline)
    if not truncated:
        assert report.findings
    else:
        assert not report.findings
    assert tool in render_markdown(report)


@pytest.mark.parametrize("kind", ["metasploit", "sliver"])
def test_mock_rpc_to_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str) -> None:
    from nexus_core.tests import report_support as support
    from nexus_core.report.extractor import build_report
    from nexus_core.tools.handlers import msf_search
    from nexus_core.tests import msf_support, sliver_support

    if kind == "metasploit":
        msf_support.fake_client(monkeypatch, msf_search)
        tool = "nexus.exploit.msf_search"
    else:
        sliver_support.fake_client(monkeypatch)
        tool = "nexus.c2.sliver_server"
    result = asyncio.run(durable_tool_definitions()[tool][1]({}, context()))
    assert result.success and result.evidence["raw_sha256"]
    store = support.make_store(tmp_path)
    scope = support.seed_engagement(store)
    run_id = support.add_run(store)
    support.record(store, run_id, tool, {}, result.to_dict(), engagement_id=scope.engagement_id)
    report = asyncio.run(build_report(store, "system", scope.engagement_id, enrich_cves=False))
    assert any(entry.tool_id == tool for entry in report.timeline)
    assert not report.findings  # RPC catalog/server metadata is not a vulnerability.


def test_catalog_has_no_unmapped_builtins_or_missing_recipes() -> None:
    from nexus_core.provisioner.catalog import assess_tool_catalog

    assessment = assess_tool_catalog(which=lambda _: None)
    assert {item.tool_id for item in assessment} == set(durable_tool_definitions())
    assert not [item for item in assessment if item.state in {"misconfigured", "unassessed"}]
    assert (
        next(item for item in assessment if item.tool_id == "nexus.recon.nikto").recipe == "nikto"
    )


@pytest.mark.parametrize("chunks,expected", [([b"Nmap \xff", b""], 0), ([b"x" * 65537, b""], 125)])
def test_version_runner_bounds_and_decodes_mock_pipes(
    monkeypatch: pytest.MonkeyPatch, chunks: list[bytes], expected: int
) -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from nexus_core.provisioner.probe import bounded_probe

    process = MagicMock()
    process.__enter__.return_value = process
    process.wait.return_value = 0
    process.pid = 987654321
    selector = MagicMock()
    selector.__enter__.return_value = selector
    selector.get_map.side_effect = [True] * len(chunks) + [False]
    selector.select.return_value = [(SimpleNamespace(fd=123, fileobj=process.stdout), 1)]
    monkeypatch.setattr(
        "nexus_core.provisioner.probe.subprocess.Popen", MagicMock(return_value=process)
    )
    monkeypatch.setattr("nexus_core.provisioner.probe.selectors.DefaultSelector", lambda: selector)
    monkeypatch.setattr("nexus_core.provisioner.probe.os.read", MagicMock(side_effect=chunks))
    kill = MagicMock()
    monkeypatch.setattr("nexus_core.provisioner.probe.os.killpg", kill)
    code, output = bounded_probe(["fixture", "--version"])
    assert code == expected and len(output) <= 65536
    kill.assert_called_once()


def test_missing_binary_returns_explicit_tool_result() -> None:
    async def handler(arguments: dict[str, Any], ctx: RunContext) -> ToolResult:
        raise FileNotFoundError("sensitive file path")

    invoke = with_execution_contract(nmap_definition(), handler)
    result = asyncio.run(invoke({"target": "host.fixture"}, context()))
    assert not result.success and result.outcome == "unavailable"
    assert "sensitive" not in str(result.to_dict())


@pytest.mark.parametrize("case", ["oversized", "symlink", "missing"])
def test_file_parser_failure_cannot_be_hidden_by_handler(tmp_path: Path, case: str) -> None:
    from nexus_core.tools.output_files import read_output_text

    path = tmp_path / "output.json"
    if case == "oversized":
        path.write_text("x" * 11)
    elif case == "symlink":
        target = tmp_path / "secret"
        target.write_text("credential")
        path.symlink_to(target)

    async def handler(arguments: dict[str, Any], ctx: RunContext) -> ToolResult:
        try:
            read_output_text(path, limit=10)
        except OSError:
            pass  # Simulate an existing catch-and-continue handler.
        return ToolResult(verified=True)

    result = asyncio.run(
        with_execution_contract(nmap_definition(), handler)({"target": "host"}, context())
    )
    assert not result.success
    assert result.evidence["execution_capture"]["incomplete"]
    assert "credential" not in str(result.to_dict())


def test_impacket_detection_recovers_after_path_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    from nexus_core.tools.handlers._impacket_resolver import resolve_impacket_binary
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert resolve_impacket_binary("secretsdump") is None
    monkeypatch.setattr("shutil.which", lambda _: "/fixture/impacket-secretsdump")
    assert resolve_impacket_binary("secretsdump") == "/fixture/impacket-secretsdump"
