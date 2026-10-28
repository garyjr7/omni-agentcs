"""``omni auth login``: store a provider API key without touching ``.env``.

The operator names a provider, types the key twice-masked (``getpass``, or the
TUI's own concealed prompt), and the value goes straight to
:mod:`nexus_core.config.secrets` -- OS keyring when available, otherwise the
``0600`` file. Nothing is echoed, nothing is written to history, and the key is
never printed: the command only reports the provider and the variable it was
stored under.

The same flow backs the TUI's ``/auth`` meta command, so both entry points share
one implementation and one set of checks.
"""

from __future__ import annotations

import getpass
from collections.abc import Callable, Sequence

from nexus_core.config.secrets import (
    LOGIN_PROVIDERS,
    PROVIDER_ENV_VARS,
    SecretStore,
    provider_env_var,
    set_secret,
)

USAGE = "uso: omni auth login [openai|deepseek|gemini|anthropic]"

Reader = Callable[[str], str]


def _ask(reader: Reader | None, prompt: str, *, default: Reader) -> str:
    """Read one line, treating EOF/Ctrl-C as "the operator said nothing"."""
    try:
        return str((reader or default)(prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _choose_provider(text_reader: Reader | None, out: Callable[[str], None]) -> str:
    """Print the menu and return the chosen provider (``""`` when invalid)."""
    out("Proveedores disponibles:")
    for index, name in enumerate(LOGIN_PROVIDERS, start=1):
        out(f"  {index}) {name:10} ({PROVIDER_ENV_VARS[name]})")
    answer = _ask(text_reader, "Proveedor (nombre o número): ", default=input)
    if not answer:
        return ""
    if answer.isdigit():
        position = int(answer)
        if 1 <= position <= len(LOGIN_PROVIDERS):
            return LOGIN_PROVIDERS[position - 1]
        return ""
    return answer.lower()


def _login(
    args: Sequence[str],
    *,
    store: SecretStore | None,
    text_reader: Reader | None,
    secret_reader: Reader | None,
    out: Callable[[str], None],
) -> int:
    provider = str(args[0]).strip().lower() if args else ""
    if not provider:
        provider = _choose_provider(text_reader, out)
        if not provider:
            out(USAGE)
            return 2
    try:
        env_var = provider_env_var(provider)
    except ValueError as exc:
        out(f"✗ {exc}")
        out(USAGE)
        return 2

    key = _ask(secret_reader, f"API key de {provider} (no se mostrará): ", default=getpass.getpass)
    if not key:
        out(f"✗ valor vacío: {provider} no se modificó")
        return 1

    resolved_store = store or SecretStore()
    try:
        set_secret(provider, key, store=resolved_store)
    except Exception as exc:  # noqa: BLE001 - report it, never dump the value
        out(f"✗ no se pudo guardar la clave de {provider}: {type(exc).__name__}: {exc}")
        return 1

    out(f"✓ clave de {provider} guardada en el store ({resolved_store.backend_name})")
    out(f"  variable: {env_var} · el valor no se imprime ni se escribe en el historial")
    out("  si la clave estaba en .env, borra esa línea: el store tiene prioridad.")
    return 0


def run_auth_command(
    argv: Sequence[str],
    *,
    store: SecretStore | None = None,
    text_reader: Reader | None = None,
    secret_reader: Reader | None = None,
    out: Callable[[str], None] = print,
) -> int:
    """Entry point for ``omni auth ...``; returns the process exit code.

    ``text_reader``/``secret_reader``/``store`` are injected by the TUI (which
    must not call ``input()``/``getpass`` while it owns the terminal) and by the
    tests. With ``text_reader=None`` the provider menu reads stdin; with
    ``secret_reader=None`` the key is read with ``getpass``.
    """
    options = list(argv)
    action = str(options[0]).strip().lower() if options else "login"
    if action in {"login", "add"}:
        return _login(
            options[1:],
            store=store,
            text_reader=text_reader,
            secret_reader=secret_reader,
            out=out,
        )
    if action in {"list", "ls"}:
        resolved = store or SecretStore()
        out(f"backend de secretos: {resolved.backend_name}")
        names = resolved.names()
        if not names:
            out("  (sin secretos guardados)")
        for name in names:
            out(f"  {name}")
        return 0
    out(f"acción desconocida: {action}")
    out(USAGE)
    return 2


__all__ = ["USAGE", "run_auth_command"]
