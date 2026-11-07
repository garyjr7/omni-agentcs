"""SEC-05: a third-party tool plugin is not imported until a human trusts it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_core.cli import tools_cli
from nexus_core.kernel.models import Identity
from nexus_core.tools import registration
from nexus_core.tools import trust as trust_module

pytestmark = pytest.mark.unit

PLUGIN = "evil-plugin"
TARGET = "evil_plugin:register"


class _Dist:
    """Minimal distribution: one module file plus its metadata listing."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files = [Path("plugin.py")]

    def locate_file(self, member) -> Path:
        return self.root / Path(member)


class _Entry:
    def __init__(self, root: Path, *, name: str = PLUGIN, target: str = TARGET) -> None:
        self.name = name
        self.value = target
        self.dist = _Dist(root)
        self.loads = 0

    def load(self) -> None:
        self.loads += 1


def _human(tenant: str = "system") -> Identity:
    return Identity("alice", tenant, kind="human", roles=("operator",))


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    registration.clear_registrations()
    yield
    registration.clear_registrations()


def _plugin(tmp_path) -> tuple[_Entry, Path]:
    root = tmp_path / "site-packages"
    root.mkdir()
    module = root / "plugin.py"
    module.write_text("VALUE = 1\n")
    return _Entry(root), module


def test_an_untrusted_plugin_is_reported_and_never_loaded(tmp_path, monkeypatch):
    entry, _ = _plugin(tmp_path)
    monkeypatch.setattr(registration, "installed_entry_points", lambda: [entry])

    report = registration.discover(force=True)

    assert entry.loads == 0
    assert any("not trusted" in message for _, message in report.errors)


def test_a_trusted_plugin_is_loaded(tmp_path, monkeypatch):
    entry, _ = _plugin(tmp_path)
    monkeypatch.setattr(registration, "installed_entry_points", lambda: [entry])
    record = trust_module.approve_plugin(PLUGIN, entry, _human())
    assert record["target"] == TARGET

    report = registration.discover(force=True)

    assert entry.loads == 1
    assert report.errors == ()


def test_any_change_in_the_distribution_revokes_trust(tmp_path, monkeypatch):
    entry, module = _plugin(tmp_path)
    monkeypatch.setattr(registration, "installed_entry_points", lambda: [entry])
    trust_module.approve_plugin(PLUGIN, entry, _human())
    module.write_text("VALUE = 2\n")

    registration.discover(force=True)

    assert entry.loads == 0
    assert trust_module.is_trusted(entry) is False


def test_approval_requires_a_human_and_the_reviewed_hash(tmp_path):
    entry, _ = _plugin(tmp_path)
    agent = Identity("bot", "system", kind="agent", roles=("agent",))
    with pytest.raises(PermissionError):
        trust_module.approve_plugin(PLUGIN, entry, agent)
    with pytest.raises(ValueError, match="hash"):
        trust_module.approve_plugin(PLUGIN, entry, _human(), expected_hash="0" * 64)
    assert trust_module.trusted_plugins() == []


def test_a_record_cannot_be_reused_by_another_target(tmp_path):
    entry, _ = _plugin(tmp_path)
    trust_module.approve_plugin(PLUGIN, entry, _human())
    impostor = _Entry(entry.dist.root, name=PLUGIN, target="other:register")
    assert trust_module.is_trusted(impostor) is False


def test_cli_trust_list_revoke(tmp_path, monkeypatch, capsys):
    entry, _ = _plugin(tmp_path)
    monkeypatch.setattr(trust_module, "installed_entry_points", lambda: [entry])

    assert tools_cli.run_tools_command(["trust", PLUGIN, "--yes"], "system") == 0
    assert tools_cli.run_tools_command(["list"], "system") == 0
    listed = capsys.readouterr().out
    assert PLUGIN in listed and "sha256=" in listed
    path = trust_module.trust_path()
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())[PLUGIN]["sha256"]

    assert tools_cli.run_tools_command(["revoke", PLUGIN], "system") == 0
    assert tools_cli.run_tools_command(["revoke", PLUGIN], "system") == 1
    assert trust_module.trusted_plugins() == []


def test_cli_declined_confirmation_does_not_trust(tmp_path, monkeypatch):
    entry, _ = _plugin(tmp_path)
    monkeypatch.setattr(trust_module, "installed_entry_points", lambda: [entry])
    code = tools_cli.run_tools_command(
        ["trust", PLUGIN], "system", reader=lambda prompt: "n"
    )
    assert code == 1
    assert trust_module.trusted_plugins() == []
