"""Elite startup: bind the workspace to cwd, resume explicitly with ``--continue``.

The two UX contracts: ``omni`` never blocks on an engagement menu (it silently
binds the current working directory as a local engagement) and resumption is an
explicit opt-in through ``--continue <engagement_id>``.
"""

import importlib
import sys
from typing import Any
from unittest.mock import patch

import omni

from nexus_core.cli.main import build_parser
from nexus_core.cli.session import OmniSession
from nexus_core.cli.workspace import bind_workspace, workspace_root
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementStore


def test_parser_exposes_continue_engagement_flag():
    assert build_parser().parse_args(["--continue", "eng-123"]).continue_engagement == "eng-123"
    assert build_parser().parse_args([]).continue_engagement is None


def test_bind_workspace_is_stable_local_and_reused(tmp_path):
    store = ControlStore(tmp_path / "workspace.db")
    store.initialize()
    first = bind_workspace(store, "system", tmp_path)
    assert first.engagement_id.startswith("local-")
    assert first.client == "local-workspace"
    assert first.notes == str(tmp_path.resolve())
    assert workspace_root(first) == tmp_path.resolve()
    # A second startup in the same directory reuses the same engagement.
    assert bind_workspace(store, "system", tmp_path).engagement_id == first.engagement_id
    assert len(EngagementStore(store).list_for_tenant("system")) == 1


def test_startup_without_flags_binds_cwd_and_never_prompts(
    onboarding_env, monkeypatch, tmp_path
):
    importlib.import_module("nexus_core.cli.main")
    main_module = sys.modules["nexus_core.cli.main"]

    def _fail(*args: Any, **kwargs: Any):  # pragma: no cover - never called
        raise AssertionError("startup must not prompt for an engagement")

    monkeypatch.setattr(main_module, "select_engagement", _fail)
    monkeypatch.setattr(main_module, "build_llm_client", lambda: object())
    monkeypatch.chdir(tmp_path)
    seen: dict[str, Any] = {}

    def _capture(self: OmniSession) -> None:
        seen["engagement"] = self.engagement
        seen["workspace"] = self.workspace_root

    monkeypatch.setattr(OmniSession, "run_repl", _capture)
    with patch("dotenv.load_dotenv"):
        code = omni.main(["--no-tui", "--no-wizard"])
    assert code == 0
    assert seen["engagement"] is not None
    assert seen["engagement"].client == "local-workspace"
    assert seen["workspace"] == tmp_path.resolve()


def test_continue_flag_resumes_the_requested_engagement(
    onboarding_env, monkeypatch, tmp_path
):
    from nexus_core.cli.engage import create_engagement
    from nexus_core.config.loader import effective_db_path, load_config
    from nexus_core.kernel.store_factory import get_control_store

    paths = onboarding_env.paths
    store = get_control_store(effective_db_path(load_config(paths), paths))
    store.initialize()
    created = create_engagement(
        store, "resume-lab", "203.0.113.0/24", secret="test-signing-secret"
    )

    importlib.import_module("nexus_core.cli.main")
    main_module = sys.modules["nexus_core.cli.main"]
    monkeypatch.setattr(main_module, "build_llm_client", lambda: object())
    # A different cwd makes the failure mode explicit: if the flag were ignored
    # the startup would bind this directory instead of resuming the engagement.
    monkeypatch.chdir(tmp_path)
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        OmniSession,
        "run_repl",
        lambda self: seen.update(engagement=self.engagement),
    )
    with patch("dotenv.load_dotenv"):
        code = omni.main(["--continue", created.engagement_id, "--no-tui", "--no-wizard"])
    assert code == 0
    assert seen["engagement"].engagement_id == created.engagement_id
    assert not seen["engagement"].engagement_id.startswith("local-")
