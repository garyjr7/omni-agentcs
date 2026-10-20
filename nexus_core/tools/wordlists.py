"""One resolver for every tool that reads a wordlist.

The path is attacker-influenced (it comes from the model), so it must stay
inside the workspace or a read-only system wordlist root; otherwise a tool that
copies the file becomes an arbitrary-file reader. That rule is identical for
``nexus.cred.bruteforce``, ``nexus.web.ffuf`` and ``nexus.recon.gobuster`` -only
the wording and the roots differ-, so the logic lives here once instead of once
per handler.

Measured in Brute It v6 (2026-10-20, iterations 11, 12 and 17): the model asked
for ``/usr/share/wordlists/fasttrack.txt`` -a symlink that *is* inside an
allowed root- and for ``/usr/share/seclists/...`` -a directory that does not
exist on that host-, and both got the same "must be inside the allowed roots"
answer. The first was a false refusal (Kali ships 12 of the 13 entries of
``/usr/share/wordlists`` as symlinks pointing outside the root), the second hid
the real problem (the file is not installed), so the model could not correct it
and retried the same path until the run closed as ``blocked``.

Two rules make that difference explicit:

* containment is decided on the **path the caller wrote** first (``abspath``,
  no symlinks resolved), and only then on the resolved target;
* a lexical path inside a *system* root is accepted even when it resolves
  outside it (that is how Kali installs its wordlists, and only root can plant a
  symlink there), while a lexical path inside the **workspace** must also
  resolve inside it: the model can create symlinks there with
  ``nexus.shell.exec``, so a workspace symlink pointing at ``/etc/shadow`` must
  keep being refused.

The two failures keep two names -:class:`WordlistNotFound` and
:class:`WordlistForbidden`- because they require two different reactions:
"pick another list" and "you may not read that one".
"""

from __future__ import annotations

import os
from typing import Iterable


class WordlistError(ValueError):
    """A wordlist path that cannot be used, with the piece that failed."""

    def __init__(self, label: str, path: str) -> None:
        self.label = str(label or "wordlist")
        self.path = str(path or "")
        super().__init__(f"{self.label} is not usable: {self.path}")


class WordlistNotFound(WordlistError):
    """The path does not name an existing file anywhere it was looked up."""

    def __init__(self, label: str, path: str) -> None:
        super().__init__(label, path)
        self.args = (f"{self.label} does not exist: {self.path}",)


class WordlistForbidden(WordlistError):
    """The path exists but lives outside every root the tool may read."""

    def __init__(self, label: str, path: str) -> None:
        super().__init__(label, path)
        self.args = (f"{self.label} is outside the allowed roots: {self.path}",)


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def _containing(path: str, roots: Iterable[str]) -> str | None:
    for root in roots:
        if _inside(path, root):
            return root
    return None


def existing_roots(roots: Iterable[str]) -> list[str]:
    """Resolved, de-duplicated roots that exist *now*.

    A root that is not installed on this host is not a root: keeping
    ``/usr/share/seclists`` in the list when the directory is absent only
    produces "not allowed" answers for paths that are simply missing.
    """
    found: list[str] = []
    for root in roots or ():
        text = str(root or "").strip()
        if not text:
            continue
        resolved = os.path.realpath(text)
        if os.path.isdir(resolved) and resolved not in found:
            found.append(resolved)
    return found


def resolve_wordlist(
    workspace_root: str,
    source: str,
    *,
    system_roots: Iterable[str] = (),
    label: str = "wordlist",
) -> str:
    """Return the readable path of ``source`` or raise a typed error.

    Absolute paths are accepted only when they are inside the workspace or a
    system root; a relative one is looked up in the workspace first and then in
    the system roots, so ``rockyou.txt`` finds ``/usr/share/wordlists/rockyou.txt``
    without the model having to guess where the operator installed it.

    ``WordlistNotFound`` means the file is not there (choose another list);
    ``WordlistForbidden`` means it exists somewhere the tool may not read.
    """
    text = str(source or "").strip()
    if not text:
        raise WordlistNotFound(label, text)
    workspace = os.path.realpath(workspace_root)
    roots = [workspace, *existing_roots(system_roots)]
    if os.path.isabs(text):
        candidates = [os.path.abspath(text)]
    else:
        candidates = [os.path.abspath(os.path.join(workspace, text))]
        candidates.extend(os.path.abspath(os.path.join(root, text)) for root in roots[1:])
    missing: list[str] = []
    forbidden: list[str] = []
    for candidate in candidates:
        root = _containing(candidate, roots)
        if not os.path.isfile(candidate):
            missing.append(candidate)
            continue
        resolved = os.path.realpath(candidate)
        if _containing(resolved, roots) is not None:
            return resolved
        if root is not None and root != workspace:
            # A symlink installed under a root-owned system directory: trusting
            # it is trusting root, which is the operator's own install.
            return resolved
        forbidden.append(candidate)
    if forbidden:
        raise WordlistForbidden(label, forbidden[0])
    raise WordlistNotFound(label, missing[0] if missing else os.path.abspath(text))
