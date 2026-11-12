"""Presentation helpers: LLM summary, provider count, audit chain, msfrpcd."""

from __future__ import annotations

from unittest import mock

import pytest

from nexus_core.cli import llm_env
from nexus_core.cli import session as session_module
from nexus_core.cli.session import OmniSession, _detect_msfrpcd_version
from nexus_core.kernel.control_store import ControlStore


def _session(tmp_path=None) -> OmniSession:
    store = None
    if tmp_path is not None:
        store = ControlStore(tmp_path / "helpers.db")
        store.initialize()
    return OmniSession(store=store, engagement=None, operator_id="operator:tester")


@pytest.fixture()
def _llm_env(monkeypatch):
    """Start from a clean provider environment for each test."""
    for key in llm_env.PROVIDER_KEY_ENVS.values():
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv(llm_env.DEFAULT_PROVIDER_ENV, raising=False)
    monkeypatch.delenv(llm_env.LEGACY_PROVIDER_ENV, raising=False)


def test_llm_summary_with_groq_configured(monkeypatch, _llm_env):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-20b")
    assert _session()._llm_summary() == "groq/openai/gpt-oss-20b"
    # One probe feeds both the label and the provider count.
    assert _session()._llm_stats() == ("groq/openai/gpt-oss-20b", 1)


def test_llm_summary_honours_selected_provider(monkeypatch, _llm_env):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    monkeypatch.setenv("OPENAI_API_KEY", "sk_fixture")
    monkeypatch.setenv("NEXUS_LLM_DEFAULT_PROVIDER", "openai")
    assert _session()._llm_summary() == "openai/gpt-4o-mini"


def test_llm_summary_selected_without_key_falls_back_to_fake(monkeypatch, _llm_env):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    monkeypatch.setenv("NEXUS_LLM_DEFAULT_PROVIDER", "openai")
    # A selected provider without a key never silently picks another cloud.
    assert _session()._llm_summary() == "fake/nexus-fake-v1"


def test_llm_summary_with_fake_fallback(_llm_env):
    assert _session()._llm_summary() == "fake/nexus-fake-v1"


def test_llm_summary_is_side_effect_free(monkeypatch, _llm_env, capsys):
    """No LLM client is constructed: nothing is logged before the banner."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    with mock.patch(
        "nexus_core.llm.abstraction.LLMFactory.create_from_env",
        side_effect=AssertionError("the banner must not build LLM clients"),
    ):
        assert _session()._llm_summary() == "groq/qwen/qwen3.8-27b"
    assert capsys.readouterr().out == ""


def test_count_providers_excludes_fake(monkeypatch, _llm_env):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    monkeypatch.setenv("OPENAI_API_KEY", "sk_fixture")
    assert _session()._count_providers() == 2


def test_count_providers_zero_without_keys(_llm_env):
    assert _session()._count_providers() == 0
    assert _session()._llm_summary() == "fake/nexus-fake-v1"


def test_verify_audit_chain_valid(tmp_path):
    session = _session(tmp_path)
    assert session._verify_audit_chain() is True


def test_verify_audit_chain_fail_safe_on_exception():
    session = _session()
    with mock.patch(
        "nexus_core.cli.session.AuditWriter",
        side_effect=RuntimeError("no store"),
    ):
        assert session._verify_audit_chain() is False


def test_detect_msfrpcd_version_when_unavailable_returns_none(monkeypatch):
    monkeypatch.delenv("MSF_RPC_PASSWORD", raising=False)
    with mock.patch(
        "nexus_core.integrations.metasploit.client.MetasploitConfig.from_env",
        side_effect=ValueError("no password"),
    ):
        assert _detect_msfrpcd_version() is None


def test_detect_msfrpcd_version_when_daemon_dead_returns_none(monkeypatch):
    monkeypatch.setenv("MSF_RPC_PASSWORD", "test123")
    with mock.patch(
        "nexus_core.integrations.metasploit.client.MetasploitClient.__aenter__",
        side_effect=ConnectionRefusedError("msfrpcd down"),
    ):
        assert _detect_msfrpcd_version(timeout_seconds=0.2) is None


def test_supports_unicode_follows_stdout_encoding():
    class _Ascii:
        encoding = "ascii"

    class _Utf8:
        encoding = "utf-8"

    session = _session()
    with mock.patch.object(session_module.sys, "stdout", _Ascii()):
        assert session._supports_unicode() is False
    with mock.patch.object(session_module.sys, "stdout", _Utf8()):
        assert session._supports_unicode() is True


def test_describe_tool_call_variants():
    session = _session()
    assert session._describe_tool_call("nexus.recon.nmap", {"target": "scanme.nmap.org"}) == (
        "Ejecutando nmap contra scanme.nmap.org"
    )
    assert "ms17_010_eternalblue" in session._describe_tool_call(
        "nexus.exploit.msf_exploit",
        {"module": "exploit/windows/smb/ms17_010_eternalblue", "target": "10.0.0.5"},
    )
    session.active_session_uuid = "abcdef123456"
    assert session._describe_tool_call("nexus.session.interact", {}) == (
        "Enviando comando a sesión abcdef12"
    )
    assert session._describe_tool_call("nexus.custom.tool", {}) == "Ejecutando nexus.custom.tool"


def test_spinner_enabled_respects_env_opt_out(monkeypatch):
    session = _session()
    # _spinner_enabled also disables itself when CI is set; this test is about
    # the explicit opt-out, so the CI gate must not decide the result.
    monkeypatch.delenv("CI", raising=False)
    with mock.patch("nexus_core.cli.spinner.spinner_enabled", return_value=True):
        monkeypatch.delenv("NEXUS_NO_SPINNER", raising=False)
        assert session._spinner_enabled() is True
        monkeypatch.setenv("NEXUS_NO_SPINNER", "1")
        assert session._spinner_enabled() is False


def test_spinner_enabled_false_without_tty(monkeypatch):
    session = _session()
    monkeypatch.delenv("NEXUS_NO_SPINNER", raising=False)
    with mock.patch("nexus_core.cli.spinner.spinner_enabled", return_value=False):
        assert session._spinner_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "yes"])
def test_no_banner_env_truthy_variants(value, monkeypatch):
    session = _session()
    monkeypatch.setenv("NEXUS_NO_BANNER", value)
    with mock.patch.object(session_module, "_stdout_is_tty", return_value=True):
        with mock.patch("nexus_core.cli.banner.render_banner") as render_banner:
            session._show_banner()
    render_banner.assert_not_called()