"""Offline regression for the Bounty Hacker run (2026-10-30) and its family.

The measured run got a map (FTP/SSH/HTTP), downloaded ``task.txt`` and
``locks.txt`` from anonymous FTP, read an artifact, and finished with
``max_iterations``/``findings_count=0``: the loot never became a next step, the
repository's skills were not found because the CLI ran from the engagement
directory, and the same dead ends were re-tried until the budget died.

Nothing here touches a target: the FTP client runs against a stub ``ftplib`` in a
temporary directory, the sandbox is a fake that returns the client's own JSON, and
the loop tests use a scripted model. No room is encoded -the assertions are about
the mechanism (a list of passwords becomes a ``password_file``, a missing skill
names the catalogue, a repeat is refused)- so a different engagement with the
same shape is covered by the same rules.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from nexus_core.agent.branch_discipline import unknown_skill_refusal
from nexus_core.agent.react import ReActConfig
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.skills import default_skills_root, discover_skills
from nexus_core.cli.engage import build_scope
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ToolInputError
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.tools.handlers import ftp as ftp_module
from nexus_core.tools.handlers._loot import looks_like_wordlist
from nexus_core.tools.handlers.cred_bruteforce import _resolve_wordlist
from nexus_core.tools.handlers.skill import skill_load_handler

TENANT = "system"
HOST = "203.0.113.10"
SECRET = "chain-test-secret"

#: Minimal FTP server: enough of ``ftplib.FTP`` for the handler's own client.
STUB_FTPLIB = '''
import io

DATA = {
    "/files/task.txt": b"user: lin\\nnote: read the locks list\\n",
    "/files/locks.txt": b"\\n".join(b"pw%d" % index for index in range(20)),
    "/files/crew.jpg": bytes(range(0, 32)) * 8,
}

class error_perm(Exception):
    pass

class FTP:
    def __init__(self):
        self.pasv = True

    def set_pasv(self, value):
        self.pasv = bool(value)

    def connect(self, host, port=21, timeout=None):
        self.host = host

    def login(self, user="", password=""):
        self.user = user

    def retrlines(self, command, callback):
        return None

    def nlst(self, path=None):
        return ["/files/task.txt", "/files/locks.txt", "/files/crew.jpg"]

    def size(self, name):
        return len(DATA[name])

    def retrbinary(self, command, callback):
        name = command.split(" ", 1)[1]
        callback(DATA[name])

    def quit(self):
        return None

    def close(self):
        return None
'''


# --------------------------------------------------------------------- helpers
def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RunContext:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    from nexus_core.scope.store import EngagementStore

    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("chain", f"{HOST}/32", SECRET))
    return RunContext(
        TENANT,
        Identity("operator-1", TENANT, roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(tmp_path / "ws"),
        run_id="run_chain_test",
    )


def _run_client(tmp_path: Path, action: str, remote: str) -> dict:
    """Execute the handler's real FTP client against the stub ``ftplib``."""
    workdir = tmp_path / "client"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "ftplib.py").write_text(STUB_FTPLIB, encoding="utf-8")
    local_dir = tmp_path / "ws" / "ftp_run_chain"
    argv = [
        sys.executable,
        "-c",
        ftp_module.FTP_CLIENT_SCRIPT,
        action,
        HOST,
        "21",
        "anonymous",
        "anonymous@",
        remote,
        str(local_dir),
    ]
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, cwd=workdir, capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result

    async def run(self, argv, *, timeout_seconds: float = 30):
        return self.result


def _run_handler(tmp_path, monkeypatch, payload: dict, context=None, **arguments):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path / "ws"))
    context = context or _context(tmp_path, monkeypatch)
    monkeypatch.setattr(
        ftp_module,
        "sandbox_for_environment",
        lambda *args, **kwargs: _FakeSandbox(
            SandboxResult(0, json.dumps(payload) + "\n", "")
        ),
    )
    base = {"target": HOST, "action": "list"}
    base.update(arguments)
    return asyncio.run(ftp_module.ftp_handler(base, context)), context


# ------------------------------------------------------- the client persists loot
def test_the_listing_persists_text_loot_with_hash_and_flags_binaries(tmp_path):
    payload = _run_client(tmp_path, "list", "/files")

    assert payload["ok"] is True
    files = {Path(item.get("remote", "")).name: item for item in payload["files"]}
    text = files["locks.txt"]
    assert text["content_kind"] == "text"
    assert text["saved"] is True
    assert len(text["sha256"]) == 64
    saved = Path(text["path"])
    assert saved.is_file(), "the preview alone is not a usable wordlist"
    assert saved.read_bytes() == b"\n".join(b"pw%d" % index for index in range(20))

    binary = files["crew.jpg"]
    assert binary["content_kind"] == "binary"
    assert "path" not in binary and "preview" not in binary, (
        "a binary artifact is reported, never read as text"
    )
    assert looks_like_wordlist(text["preview"]) is True
    assert looks_like_wordlist(binary.get("preview") or "") is False


# ------------------------------------------------- the chain: 21 -> 22 in one turn
def test_the_loot_becomes_a_wordlist_and_the_other_open_service(tmp_path, monkeypatch):
    payload = _run_client(tmp_path, "list", "/files")
    for item in payload["files"]:
        item.pop("workspace_path", None)
    result, context = _run_handler(tmp_path, monkeypatch, payload)

    chain = result.output["chain"]
    assert chain["tool"] == "nexus.cred.bruteforce"
    assert chain["username"] == "lin"
    assert chain["password_file"].endswith("locks.txt")
    assert chain["entries"] >= 8
    # The path the chain names is the one the sweep can read.
    resolved = _resolve_wordlist(
        str(tmp_path / "ws"), result.output["files"][1]["workspace_path"]
    )
    assert Path(resolved).is_file()

    # A second service on the same host is named only if the board proved it.
    assert "other_services" not in result.output
    Blackboard(context.store).record(
        tenant_id=TENANT,
        engagement_id=context.engagement_id,
        fact_type="service",
        key=f"{HOST}:21:tcp",
        value={"port": 21, "service": "ftp"},
        source="nexus.recon.nmap",
        created_by="nexus.recon.nmap",
    )
    Blackboard(context.store).record(
        tenant_id=TENANT,
        engagement_id=context.engagement_id,
        fact_type="service",
        key=f"{HOST}:22:tcp",
        value={"port": 22, "service": "ssh"},
        source="nexus.recon.nmap",
        created_by="nexus.recon.nmap",
    )
    for port, service in ((80, "http"), (445, "smb")):
        Blackboard(context.store).record(
            tenant_id=TENANT,
            engagement_id=context.engagement_id,
            fact_type="service",
            key=f"{HOST}:{port}:tcp",
            value={"port": port, "service": service},
            source="nexus.recon.nmap",
            created_by="nexus.recon.nmap",
        )
    result, context = _run_handler(tmp_path, monkeypatch, payload, context=context)
    services = result.output["other_services"]
    assert [(item["port"], item["service"]) for item in services] == [
        (22, "ssh"), (80, "http"), (445, "smb")
    ]
    # Only the directly supported credential modes become tool-call
    # suggestions. HTTP needs a verified form; SMB uses another tool.
    assert [item["service"] for item in result.output["chain"]["service_candidates"]] == [
        "ssh"
    ]
    assert result.output["chain"]["service_candidates"][0]["call"] == {
        "tool": "nexus.cred.bruteforce",
        "service": "ssh",
        "target": HOST,
        "port": 22,
    }
    assert any("nexus.cred.bruteforce" in step for step in result.output["next_steps"])


# ------------------------------------------------ evidence reaches the next prompt
def test_the_loot_is_recorded_on_the_board_with_provenance(tmp_path, monkeypatch):
    payload = _run_client(tmp_path, "list", "/files")
    result, context = _run_handler(tmp_path, monkeypatch, payload)

    board = Blackboard(context.store)
    loot = board.list_facts(TENANT, context.engagement_id, fact_type="loot", limit=50)
    users = board.list_facts(TENANT, context.engagement_id, fact_type="user", limit=50)
    assert {fact["key"] for fact in loot} >= {
        f"ftp:{HOST}:21:/files/locks.txt",
        f"ftp:{HOST}:21:/files/task.txt",
    }
    assert [fact["key"] for fact in users] == [f"user:{HOST}:lin"]
    locks = next(fact for fact in loot if fact["key"].endswith("locks.txt"))
    assert locks["value"]["sha256"] and locks["value"]["size"]
    assert locks["value"]["content_kind"] == "text"
    assert locks["value"]["via"] == "ftp-anonymous"
    # Leads, never proof: the phase cannot advance on them.
    assert all(fact["verified"] is False for fact in loot + users)
    # And the prompt-facing summary shows them as unverified work.
    summary = board.summary(TENANT, context.engagement_id)
    assert summary["leads"].get("loot") == len(loot)


def test_a_downloaded_binary_is_not_an_analysed_artifact(tmp_path, monkeypatch):
    payload = {
        "ok": True,
        "action": "download",
        "file": "crew.jpg",
        "path": str(tmp_path / "ws" / "ftp_run_chain" / "crew.jpg"),
        "size": 512,
        "sha256": "b" * 64,
        "preview": "",
        "preview_bytes": 256,
        "preview_truncated": True,
        "content_kind": "binary",
    }
    result, _ = _run_handler(
        tmp_path, monkeypatch, payload, action="download", remote_path="crew.jpg"
    )

    assert result.verified is True
    assert result.evidence["content_kind"] == "binary"
    assert result.output["artifact_status"] == "descargado, sin analizar"
    assert any("BINARIO" in step for step in result.output["next_steps"])
    assert "chain" not in result.output


# ------------------------------------------------------------- skills: the root
def test_the_engagement_directory_still_finds_the_shipped_catalogue(
    tmp_path, monkeypatch
):
    """The measured failure: the CLI ran from the engagement workspace."""
    monkeypatch.delenv("NEXUS_SKILLS_ROOT", raising=False)
    workspace = tmp_path / "engagement"
    workspace.mkdir()
    monkeypatch.chdir(workspace)

    root = default_skills_root()
    assert root != workspace / ".agents" / "skills", (
        "an empty workspace must fall back to the installation, not answer 'no skills'"
    )
    names = discover_skills()
    assert "web-recon-master" in names
    assert all(skill.trust != "signed" for skill in names.values()), (
        "repository skills are unsigned: untrusted data, never trusted guidance"
    )


# ----------------------------------------------- skills: the missing name is bounded
def test_an_unknown_skill_names_the_real_catalogue(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    with pytest.raises(ToolInputError) as caught:
        asyncio.run(
            skill_load_handler({"name": "web-recon-master-missing"}, context)
        )
    message = str(caught.value)
    assert "unknown skill" in message
    assert "available: " in message and "methodology-senior" in message


def _failed_load(name: str) -> dict:
    return {
        "tool_id": "nexus.skill.load",
        "arguments": {"name": name},
        "tool_result": {"success": False, "outcome": "invalid_input"},
    }


def test_the_same_missing_skill_is_not_requested_forever():
    actions = [_failed_load("ghost")]
    guidance = unknown_skill_refusal(
        actions, {"name": "ghost"}, known=["alpha"], catalogue="/inst/.agents/skills"
    )
    assert guidance and "ghost" in guidance and "alpha" in guidance

    # A different name, a first attempt, or a name the catalogue now holds is not
    # touched: the gate bounds the loop, it does not block the loader.
    assert unknown_skill_refusal(actions, {"name": "other"}, known=["alpha"]) is None
    assert unknown_skill_refusal([], {"name": "ghost"}, known=["alpha"]) is None
    assert unknown_skill_refusal(actions, {"name": "ghost"}, known=["ghost"]) is None
    assert (
        unknown_skill_refusal(
            [{"tool_id": "nexus.skill.load", "arguments": {"name": "ghost"},
              "tool_result": {"success": True}}],
            {"name": "ghost"},
            known=["alpha"],
        )
        is None
    )


def test_an_empty_catalogue_is_reported_as_such():
    guidance = unknown_skill_refusal(
        [_failed_load("ghost")],
        {"name": "ghost"},
        known=[],
        catalogue="/inst/.agents/skills",
    )
    assert guidance and "vacío" in guidance and "/inst/.agents/skills" in guidance


# ------------------------------------------------------- the loop refuses the repeat
class _ScriptedLLM:
    supports_streaming = False

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[list[str]] = []

    async def complete(self, messages, **kwargs):
        self.prompts.append([str(getattr(message, "content", "")) for message in messages])
        answer = self.answers[min(len(self.prompts) - 1, len(self.answers) - 1)]
        return LLMResponse(content=answer, model="scripted", provider=LLMProvider.FAKE)


class _ScriptedService:
    def __init__(self, *outcomes: str) -> None:
        self.outcomes = list(outcomes) or ["success"]
        self.calls: list[str] = []

    async def execute(self, payload, context, *, timeout, cancel_event):
        tool_id = str(payload["tool_id"])
        self.calls.append(tool_id)
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        return (
            {
                "output": {
                    "success": outcome == "success",
                    "outcome": outcome,
                    "output": {"tool": tool_id},
                    "verification_method": "unit",
                    "invocation_id": f"inv-{tool_id}",
                    "assertions": [],
                }
            },
            False,
        )


def _skill_call(name: str) -> str:
    return json.dumps(
        {
            "thought": "cargo la receta",
            "action": "tool_call",
            "tool_id": "nexus.skill.load",
            "arguments": {"name": name},
        }
    )


def _coordinator(exec_ctx, llm, service):
    catalog = {
        "nexus.skill.load": (
            ToolDefinition(
                name="nexus.skill.load",
                tenant_id=TENANT,
                input_schema={},
                tool_id="nexus.skill.load",
                description="stub skill loader",
                risk=RiskLevel.READ_ONLY,
                effect="read_only",
                effects=("read",),
            ),
            lambda arguments, ctx: None,
        )
    }
    return ReActCoordinator(
        context=exec_ctx,
        objective="comprometer el objetivo",
        engagement_id=None,
        llm_client=llm,
        tool_catalog=catalog,
        config=ReActConfig(max_iterations=6, enforce_completion_gates=False),
        tool_execution=service,
    )


def _react_context(tmp_path, monkeypatch):
    """A real ``ExecutionContext`` over a throwaway store (no network)."""
    from nexus_core.kernel.runtime import ExecutionContext
    from nexus_core.tests.unit.test_hooks_lifecycle import context

    ctx = context(tmp_path, monkeypatch)
    run = ctx.store.create_run(TENANT, {})
    exec_ctx = ExecutionContext(
        ctx.store,
        {
            "id": "task",
            "tenant_id": TENANT,
            "run_id": run["id"],
            "task_type": "react.run",
            "payload": {
                "objective": "comprometer el objetivo",
                "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            },
        },
        "worker-test",
    )
    return ctx, exec_ctx


def test_the_loop_refuses_the_second_load_of_a_missing_skill(tmp_path, monkeypatch):
    ctx, exec_ctx = _react_context(tmp_path, monkeypatch)
    # Alternating two names is the measured shape: an exact repeat is caught by
    # the older ``repeated_failed_action`` guard, but ``ghost`` -> ``beta`` ->
    # ``ghost`` is not adjacent and reaches the catalogue again.
    llm = _ScriptedLLM(_skill_call("ghost"), _skill_call("beta"), _skill_call("ghost"))
    service = _ScriptedService("failed")
    coordinator = _coordinator(exec_ctx, llm, service)

    asyncio.run(coordinator.run())

    # Two loads ran; the second request for ``ghost`` never reached the tool.
    assert service.calls == ["nexus.skill.load", "nexus.skill.load"]
    from nexus_core.agent import memory

    history = memory.load_history(ctx.store, TENANT, coordinator.conversation_id, limit=500)
    observations = [
        json.loads(str(message["content"]))
        for message in history
        if memory.message_kind(message) == "react.observation"
    ]
    refusal = next(
        item for item in observations if item.get("outcome") == "unknown_skill"
    )
    assert refusal["unknown_skill"] == "ghost"
    assert refusal["refused_before_execution"] is True
    assert refusal["skill_catalogue"], "the refusal names the real catalogue"
    assert refusal["skill_catalogue_root"]


def test_the_terminal_state_names_the_limit_the_findings_and_the_open_branches(
    tmp_path, monkeypatch
):
    """``max_iterations`` must end honestly, not with a bare budget number."""
    from types import SimpleNamespace

    from nexus_core.agent.react_types import STATUS_MAX_ITERATIONS

    _, exec_ctx = _react_context(tmp_path, monkeypatch)
    llm = _ScriptedLLM(_skill_call("ghost"))
    coordinator = _coordinator(exec_ctx, llm, _ScriptedService("failed"))

    result = asyncio.run(coordinator.run())

    assert result.status == STATUS_MAX_ITERATIONS
    assert "findings=0" in str(result.final_summary)
    assert "open branches:" in str(result.final_summary)
    # With a ledger image the summary names the work that is still open.
    coordinator.final_summary = ""
    coordinator.snapshot = SimpleNamespace(
        coverage=SimpleNamespace(
            open_work=[SimpleNamespace(label="203.0.113.10:22/tcp")]
        )
    )
    assert "203.0.113.10:22/tcp" in str(coordinator._result().final_summary)
