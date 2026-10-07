"""Binary *identity* verification, not just presence.

``shutil.which("httpx")`` is not enough to run a ProjectDiscovery tool: the
Python ``httpx`` HTTP client ships a ``/usr/bin/httpx`` console script with the
same name. The handler then expects ProjectDiscovery's JSONL, gets the Python
client's error output, and the run dies with an opaque
``post-condition was not verified`` instead of a message an operator can act on
(B1 of ``docs/missions/TEST_E2E_BOUNTY_HACKER.md``).

This module probes a binary's ``--version``/``-version`` output and checks for
the vendor's own signature. It is read-only and never raises: a probe failure is
just "not verified", never a crash.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable

#: Default timeout of one identity probe (seconds).
DEFAULT_PROBE_TIMEOUT_SECONDS = 10.0

#: A runner returns ``(returncode, combined_output)`` and must not raise.
VersionRunner = Callable[[list[str]], "tuple[int, str]"]


@dataclass(frozen=True)
class BinaryIdentity:
    """The signature that proves a binary is the one the handlers expect."""

    name: str
    purpose: str
    version_argv: tuple[str, ...]
    #: Lower-case substrings that must *all* appear in the version output.
    markers: tuple[str, ...]
    #: Lower-case substrings that prove this is a different binary entirely.
    wrong_markers: tuple[str, ...]
    #: Command that installs the expected binary.
    install: str
    #: True when the whole engagement cannot run without it.
    required: bool = False
    #: Durable tool that cannot work without this binary. When the binary is
    #: *absent* the tool is retired for the run (do not burn iterations on a
    #: ``FileNotFoundError``); see ``missing_tool_binaries`` (B6).
    tool_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "purpose": self.purpose,
            "version_argv": list(self.version_argv),
            "markers": list(self.markers),
            "wrong_markers": list(self.wrong_markers),
            "install": self.install,
            "required": self.required,
            "tool_id": self.tool_id,
        }


#: The critical binaries whose *wrong* variant silently poisons a run.
BINARY_IDENTITIES: tuple[BinaryIdentity, ...] = (
    BinaryIdentity(
        name="httpx",
        purpose="Sondeo HTTP (ProjectDiscovery)",
        version_argv=("-version",),
        markers=("projectdiscovery",),
        wrong_markers=("no such option", "usage: httpx [options]", "python"),
        install="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        tool_id="nexus.recon.httpx",
    ),
    BinaryIdentity(
        name="whatweb",
        purpose="Fingerprinting web",
        version_argv=("--version",),
        markers=("whatweb",),
        wrong_markers=(),
        install="sudo apt install whatweb",
        tool_id="nexus.recon.whatweb",
    ),
    BinaryIdentity(
        name="nmap",
        purpose="Descubrimiento de puertos y servicios",
        version_argv=("--version",),
        markers=("nmap",),
        wrong_markers=(),
        install="sudo apt install nmap",
        required=True,
        tool_id="nexus.recon.nmap",
    ),
    BinaryIdentity(
        name="rg",
        purpose="Búsqueda de texto en el workspace (ripgrep)",
        version_argv=("--version",),
        markers=("ripgrep",),
        wrong_markers=(),
        install="sudo apt install ripgrep",
        tool_id="nexus.workspace.search",
    ),
)

BINARY_IDENTITIES_BY_NAME: dict[str, BinaryIdentity] = {
    identity.name: identity for identity in BINARY_IDENTITIES
}


@dataclass(frozen=True)
class IdentityCheck:
    """Outcome of probing one binary's identity."""

    name: str
    present: bool
    ok: bool
    binary_path: str
    detail: str
    install: str = ""
    required: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "present": self.present,
            "ok": self.ok,
            "binary_path": self.binary_path,
            "detail": self.detail,
            "install": self.install,
            "required": self.required,
        }


def default_version_runner(
    argv: list[str], *, timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS
) -> tuple[int, str]:
    """Run a version probe, merging stdout/stderr; never raises.

    A missing binary, a permission error or a timeout all collapse to
    ``(returncode, text)`` so callers only ever inspect data.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    merged = f"{completed.stdout}\n{completed.stderr}".strip()
    return int(completed.returncode), merged


def classify_identity(
    identity: BinaryIdentity,
    *,
    path: str,
    present: bool,
    output: str,
) -> IdentityCheck:
    """Pure verdict from a version probe's output (no process spawn).

    Split from :func:`check_binary_identity` so handlers running inside a
    sandbox can reuse the exact same decision on the output they obtained.
    """
    if not present:
        return IdentityCheck(
            name=identity.name,
            present=False,
            ok=False,
            binary_path="",
            detail="no encontrado en PATH",
            install=identity.install,
            required=identity.required,
        )
    lowered = str(output or "").lower()
    if any(bad in lowered for bad in identity.wrong_markers):
        return IdentityCheck(
            name=identity.name,
            present=True,
            ok=False,
            binary_path=path,
            detail=f"binario equivocado en {path}: no es el {identity.name} esperado",
            install=identity.install,
            required=identity.required,
        )
    if not all(marker in lowered for marker in identity.markers):
        return IdentityCheck(
            name=identity.name,
            present=True,
            ok=False,
            binary_path=path,
            detail=(
                f"no se pudo confirmar la identidad de {path}: falta la firma "
                f"{', '.join(identity.markers)}"
            ),
            install=identity.install,
            required=identity.required,
        )
    return IdentityCheck(
        name=identity.name,
        present=True,
        ok=True,
        binary_path=path,
        detail=output.splitlines()[0].strip() if str(output or "").strip() else path,
        install="",
        required=identity.required,
    )


def check_binary_identity(
    identity: BinaryIdentity,
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: VersionRunner = default_version_runner,
) -> IdentityCheck:
    """Probe one binary and decide whether it is the expected one."""
    path = which(identity.name)
    if not path:
        return classify_identity(identity, path="", present=False, output="")
    _, output = run([path, *identity.version_argv])
    return classify_identity(identity, path=path, present=True, output=output)


def check_binary_identities(
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: VersionRunner = default_version_runner,
    identities: Iterable[BinaryIdentity] = BINARY_IDENTITIES,
) -> list[IdentityCheck]:
    """Probe every identity, in a stable order (never raises)."""
    return [check_binary_identity(item, which=which, run=run) for item in identities]


def identity_problems(checks: Iterable[IdentityCheck]) -> list[IdentityCheck]:
    """Return the binaries that are present but are *not* the expected ones."""
    return [check for check in checks if check.present and not check.ok]


def missing_tool_binaries(
    *,
    which: Callable[[str], str | None] = shutil.which,
    identities: Iterable[BinaryIdentity] = BINARY_IDENTITIES,
) -> tuple[str, ...]:
    """Durable tools whose binary is **absent** (no process is spawned).

    A missing binary is not a reason to refuse the run (it is an optional route,
    unlike a *wrong* binary which silently feeds garbage), but it is a reason to
    stop proposing that tool: the E2E run #2 spent iterations on
    ``nexus.workspace.search`` until ``rg`` raised ``FileNotFoundError`` (B6).
    Only a ``which`` lookup happens here, so this is cheap enough to call at the
    start of every run.
    """
    missing: list[str] = []
    for identity in identities:
        if not identity.tool_id or identity.tool_id in missing:
            continue
        if which(identity.name) is None:
            missing.append(identity.tool_id)
    return tuple(sorted(missing))


__all__ = [
    "BINARY_IDENTITIES",
    "BINARY_IDENTITIES_BY_NAME",
    "DEFAULT_PROBE_TIMEOUT_SECONDS",
    "BinaryIdentity",
    "IdentityCheck",
    "check_binary_identities",
    "check_binary_identity",
    "classify_identity",
    "default_version_runner",
    "identity_problems",
    "missing_tool_binaries",
]
