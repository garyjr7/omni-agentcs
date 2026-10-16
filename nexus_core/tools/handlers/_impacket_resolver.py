"""Resolve the on-disk name of an impacket script.

Impacket is packaged differently depending on how it was installed:

* Kali/Debian packages expose console scripts named ``impacket-<name>``
  (for example ``impacket-secretsdump``);
* ``pip install --user impacket`` on PEP 668 systems drops plain ``.py``
  scripts into ``~/.local/bin`` (for example ``secretsdump.py``);
* some environments still provide the bare ``<name>``.

Handlers must work with whichever convention is present, so they resolve the
executable once via :func:`resolve_impacket_binary` instead of hard-coding a
name.
"""

from __future__ import annotations

import shutil
from functools import lru_cache


# Keep cache_clear compatibility, but never cache absence or a stale PATH.
@lru_cache(maxsize=0)
def resolve_impacket_binary(name: str) -> str | None:
    """Return the path to the impacket script ``name`` on the current PATH.

    Tries, in order: ``impacket-<name>`` (Kali/Debian), ``<name>.py`` (pip
    ``--user``) and ``<name>`` (compatibility). Returns ``None`` when none of
    the candidates is executable.
    """
    for candidate in (f"impacket-{name}", f"{name}.py", name):
        try:
            path = shutil.which(candidate)
        except OSError:
            continue
        if path:
            return path
    return None
