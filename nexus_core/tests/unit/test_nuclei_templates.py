"""Unit tests for the stable nuclei templates directory (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nuclei as nuclei_module
from nexus_core.tools.handlers.nuclei import (
    NUCLEI_MAX_EXPLICIT_TEMPLATES,
    nuclei_handler,
    nuclei_templates_dir,
    validate_tags,
    validate_template_paths,
)

TECH_DETECT = "http/technologies/tech-detect.yaml"


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
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, allowed_programs=None):
        allowlists.append(tuple(allowed_programs or ()))
        return sandbox

    with mock.patch.object(nuclei_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


@pytest.fixture
def templates_dir(tmp_path, monkeypatch):
    """A real, host-independent templates directory used as the default."""
    root = tmp_path / "nuclei-templates"
    template = root / TECH_DETECT
    template.parent.mkdir(parents=True)
    template.write_text(
        "id: tech-detect\ninfo:\n  name: Tech Detect\n  severity: info\n", encoding="utf-8"
    )
    monkeypatch.delenv("NEXUS_NUCLEI_TEMPLATES", raising=False)
    monkeypatch.setattr(nuclei_module, "DEFAULT_NUCLEI_TEMPLATES", str(root))
    return root


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nuclei_handler(arguments, _context()))


def _argv_pairs(argv: list[str], flag: str) -> list[tuple[str, str]]:
    return [
        (argv[index], argv[index + 1])
        for index in range(len(argv) - 1)
        if argv[index] == flag
    ]


def test_nuclei_uses_default_templates_dir(templates_dir):
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        result = _run({"targets": ["https://scanme.example"]})
    resolved = str(templates_dir.resolve())
    assert ("-t", resolved) in _argv_pairs(sandbox.calls[0][0], "-t")
    assert result.evidence["templates_dir"] == resolved
    assert result.evidence["templates"] == [resolved]
    assert result.verified is True


def test_nuclei_honors_env_override(tmp_path, monkeypatch):
    override = tmp_path / "custom-templates"
    (override / "http").mkdir(parents=True)
    monkeypatch.setenv("NEXUS_NUCLEI_TEMPLATES", str(override))
    assert nuclei_templates_dir() == str(override)

    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        result = _run({"targets": ["https://scanme.example"]})
    assert ("-t", str(override.resolve())) in _argv_pairs(sandbox.calls[0][0], "-t")
    assert result.evidence["templates_dir"] == str(override.resolve())


def test_nuclei_fails_closed_when_templates_missing(tmp_path, monkeypatch):
    missing = tmp_path / "does-not-exist"
    monkeypatch.setenv("NEXUS_NUCLEI_TEMPLATES", str(missing))

    with _fake_sandbox(SandboxResult(0, "{\"template-id\":\"x\"}\n", "")) as (sandbox, allowlists):
        result = _run({"targets": ["https://scanme.example"]})

    assert result.verified is False
    assert result.success is False
    assert result.verification_method == "nuclei_templates_missing"
    assert result.output["templates_dir"] == str(missing)
    assert result.output["error"] == "nuclei templates directory not found"
    # Fail closed: nuclei is never executed without templates.
    assert sandbox.calls == []
    assert allowlists == []


def test_nuclei_fails_closed_when_is_dir_is_false(templates_dir):
    with mock.patch("pathlib.Path.is_dir", return_value=False):
        with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
            result = _run({"targets": ["https://scanme.example"]})
    assert result.verification_method == "nuclei_templates_missing"
    assert sandbox.calls == []


def test_nuclei_accepts_explicit_templates_list(templates_dir):
    selection = str(templates_dir / TECH_DETECT)
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        result = _run({"targets": ["https://scanme.example"], "templates": [selection]})
    pairs = _argv_pairs(sandbox.calls[0][0], "-t")
    assert pairs == [("-t", str(Path(selection).resolve()))]
    assert result.evidence["templates"] == [str(Path(selection).resolve())]


def test_nuclei_accepts_relative_template_selection(templates_dir):
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        result = _run({"targets": ["https://scanme.example"], "templates": [TECH_DETECT]})
    assert _argv_pairs(sandbox.calls[0][0], "-t") == [("-t", str((templates_dir / TECH_DETECT).resolve()))]
    assert result.evidence["templates"] == [str((templates_dir / TECH_DETECT).resolve())]


def test_nuclei_accepts_tags_argument(templates_dir):
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        result = _run({"targets": ["https://scanme.example"], "tags": ["tech", "misconfig"]})
    argv = sandbox.calls[0][0]
    assert _argv_pairs(argv, "-tags") == [("-tags", "tech,misconfig")]
    assert result.evidence["tags"] == ["tech", "misconfig"]


def test_nuclei_argv_includes_t_flag_always(templates_dir):
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        _run({"targets": ["https://scanme.example"]})
    assert "-t" in sandbox.calls[0][0]

    selection = str(templates_dir / TECH_DETECT)
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        _run({"targets": ["https://scanme.example"], "templates": [selection, selection]})
    # A duplicate selection never becomes a duplicate flag.
    assert len(_argv_pairs(sandbox.calls[0][0], "-t")) == 1


def test_nuclei_rejects_template_outside_the_templates_dir(templates_dir, tmp_path):
    outsider = tmp_path / "evil.yaml"
    outsider.write_text("id: evil\n", encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"targets": ["https://scanme.example"], "templates": [str(outsider)]})
    with pytest.raises(ValueError):
        validate_template_paths(["../../etc/passwd"], str(templates_dir))


def test_nuclei_rejects_missing_template_file(templates_dir):
    with pytest.raises(ValueError):
        validate_template_paths(["http/technologies/nope.yaml"], str(templates_dir))


def test_nuclei_rejects_too_many_templates(templates_dir):
    with pytest.raises(ValueError):
        validate_template_paths([TECH_DETECT] * (NUCLEI_MAX_EXPLICIT_TEMPLATES + 1), str(templates_dir))


@pytest.mark.parametrize("tag", ["tech,discovery", "-evil", "", "with space"])
def test_nuclei_rejects_invalid_tags(tag):
    with pytest.raises(ValueError):
        validate_tags([tag])


def test_nuclei_templates_dir_reads_the_environment(monkeypatch):
    monkeypatch.setenv("NEXUS_NUCLEI_TEMPLATES", "/srv/templates")
    assert nuclei_templates_dir() == "/srv/templates"
    monkeypatch.delenv("NEXUS_NUCLEI_TEMPLATES")
    assert nuclei_templates_dir() == nuclei_module.DEFAULT_NUCLEI_TEMPLATES


def test_nuclei_managed_flags_disable_the_update_check(templates_dir):
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        _run({"targets": ["https://scanme.example"]})
    argv = sandbox.calls[0][0]
    assert "-duc" in argv
    assert argv[:5] == ["nuclei", "-jsonl", "-silent", "-nc", "-no-interactsh"]


def test_nuclei_evidence_is_json_serializable(templates_dir):
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"targets": ["https://scanme.example"], "tags": ["tech"]})
    assert json.loads(json.dumps(result.evidence))["templates"]
