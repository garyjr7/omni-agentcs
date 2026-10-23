"""SOCKS proxy plumbing for the AD handlers (Tanda F1).

The measured problem
--------------------
The DeadDrop run (2026-10-23) reached the domain controller only through a
``proxychains4`` wrapper typed into ``nexus.shell.exec``: ``netexec`` and
``impacket`` do not speak SOCKS natively, so the model was forced out of the
tools that parse their output. The command ran, the DC answered, and the
verifier recorded **nothing** -``shell.exec`` derives no AD fact- so a run that
had dumped NTDS closed with ``completion_verified: false`` and ``grounded: 0``.

This module keeps that wrapper *inside* the tool: the handler still resolves the
binary, still hands the sandbox an explicit allowlist, and still parses the
output. The proxy is a transport detail, never a second channel.

What it deliberately does not do
--------------------------------
* **No credentials in the proxy URL.** ``proxychains4`` writes its config to a
  file inside the workspace; a ``socks5://user:pass@host`` would leak the secret
  into a file the model can read. chisel/sliver tunnels do not need auth, so a
  URL with userinfo is refused with the reason.
* **No unchecked egress.** A loopback proxy is the tunnel the engagement already
  proved; any other address is an outbound destination and is validated against
  the signed scope with the same validator ``nexus.web.request`` and
  ``nexus.shell.exec`` use.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

#: Schemes accepted in ``proxy``. ``socks5h``/``socks4a`` resolve DNS at the
#: proxy; ``https`` is the same CONNECT tunnel as ``http`` for proxychains.
PROXY_SCHEMES: tuple[str, ...] = ("socks5", "socks5h", "socks4", "socks4a", "http", "https")

#: Port used when the URL omits it, per scheme (proxychains' own defaults).
DEFAULT_PROXY_PORTS: dict[str, int] = {
    "socks5": 1080,
    "socks5h": 1080,
    "socks4": 1080,
    "socks4a": 1080,
    "http": 8080,
    "https": 8080,
}

#: proxychains' name for each accepted scheme (``https`` is a CONNECT tunnel).
PROXYCHAINS_TYPES: dict[str, str] = {
    "socks5": "socks5",
    "socks5h": "socks5",
    "socks4": "socks4",
    "socks4a": "socks4",
    "http": "http",
    "https": "http",
}

#: Overrides the resolved binary (an operator whose proxychains lives elsewhere).
PROXYCHAINS_BINARY_ENV = "NEXUS_PROXYCHAINS_BINARY"

#: Directory (inside the workspace) that holds the generated configs.
PROXYCHAINS_CONFIG_DIRNAME = ".proxychains"

#: The tunnel a pilot normally has: chisel/sliver listen on loopback.
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})

_PROXY_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://"
    r"(?P<authority>[^/?#\s]+)"
    r"(?P<path>/[^\s?#]*)?$"
)


@dataclass(frozen=True)
class ProxySpec:
    """One validated ``scheme://host:port`` proxy."""

    scheme: str
    host: str
    port: int
    path: str = ""

    @property
    def chain_type(self) -> str:
        """The type name proxychains reads in ``[ProxyList]``."""
        return PROXYCHAINS_TYPES[self.scheme]

    @property
    def address(self) -> str:
        """``host:port`` as the operator wrote it (IPv6 without brackets)."""
        return f"{self.host}:{self.port}"

    def describe(self) -> dict:
        """Evidence form: what was used, never a secret (there is none)."""
        return {
            "type": self.chain_type,
            "host": self.host,
            "port": self.port,
            "via": "proxychains4",
        }


def _split_authority(authority: str) -> tuple[str, str]:
    """``(host, port)`` of a URL authority, tolerating ``[::1]:1080``."""
    text = authority.strip()
    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            raise ValueError("proxy host is not a valid address")
        host = text[1:close]
        rest = text[close + 1 :]
        if rest and not rest.startswith(":"):
            raise ValueError("proxy host is not a valid address")
        return host, rest[1:] if rest else ""
    host, separator, port = text.rpartition(":")
    if not separator:
        return text, ""
    if ":" in host:  # a bare IPv6 literal without brackets
        return text, ""
    return host, port


def parse_proxy(value: object) -> ProxySpec:
    """Validate ``proxy`` and return a :class:`ProxySpec`.

    Raises ``ValueError`` for anything that is not ``scheme://host[:port]``: a
    half-parsed destination is not a tunnel, and proxychains would either run
    direct (silently ignoring the pivot) or fail with its own message.
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError("proxy must be a scheme://host:port string")
    match = _PROXY_RE.match(text)
    if match is None:
        raise ValueError(
            "proxy must look like socks5://127.0.0.1:1080 (no path, no spaces)"
        )
    scheme = match.group("scheme").lower()
    if scheme not in PROXY_SCHEMES:
        raise ValueError(
            f"proxy scheme is not supported: {scheme!r} "
            f"(accepted: {', '.join(PROXY_SCHEMES)})"
        )
    if (match.group("path") or "") not in ("", "/"):
        raise ValueError("proxy must not carry a path")
    if "@" in match.group("authority"):
        # Never write a proxy password into a workspace file the model can read.
        raise ValueError(
            "proxy must not carry credentials: the tunnel has to accept the "
            "connection without auth (chisel/sliver default)"
        )
    host, raw_port = _split_authority(match.group("authority"))
    if not host or any(char.isspace() for char in host):
        raise ValueError("proxy host is not a valid address")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise ValueError("proxy host is not a valid address")
    if raw_port:
        if not raw_port.isdigit():
            raise ValueError("proxy port must be numeric")
        port = int(raw_port)
        if not 0 < port < 65536:
            raise ValueError("proxy port must be between 1 and 65535")
    else:
        port = DEFAULT_PROXY_PORTS[scheme]
    return ProxySpec(scheme=scheme, host=host.strip("[]"), port=port)


def is_loopback(host: str) -> bool:
    """Whether *host* never leaves the machine (the tunnel's own socket)."""
    text = str(host or "").strip().strip("[]").split("%", 1)[0].lower()
    if not text:
        return False
    if text in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def ensure_proxy_in_scope(proxy: ProxySpec, scope) -> None:
    """Refuse a proxy address the signed engagement does not cover.

    The tools' own ``target`` is checked by the gateway's scope validator; the
    proxy is a *second* destination and used to be unchecked (only the loopback
    tunnel is exempt, because nothing leaves the machine). Raises
    ``ScopeViolation`` for an out-of-scope address and ``ValueError`` when there
    is no signed scope to check against.
    """
    if is_loopback(proxy.host):
        return
    if scope is None:
        raise ValueError(
            "a non-loopback proxy needs a signed scope: "
            f"{proxy.address} cannot be validated"
        )
    from nexus_core.kernel.scope_loader import scope_signing_secret
    from nexus_core.scope import ScopeValidator

    ScopeValidator(scope, signing_secret=scope_signing_secret()).validate(proxy.host)


def resolve_proxychains() -> str | None:
    """Absolute path of ``proxychains4``/``proxychains``, or ``None``."""
    override = str(os.getenv(PROXYCHAINS_BINARY_ENV) or "").strip()
    if override:
        chosen = shutil.which(override) or (
            override if Path(override).is_file() else ""
        )
        return str(Path(chosen).resolve()) if chosen else None
    for candidate in ("proxychains4", "proxychains"):
        found = shutil.which(candidate)
        if found:
            return str(Path(found).resolve())
    return None


def proxychains_config(proxy: ProxySpec) -> str:
    """Body of the ``proxychains4`` config for one proxy.

    ``strict_chain`` keeps every connection inside the one tunnel the run
    proved; ``proxy_dns`` sends the names to the pivot instead of resolving them
    locally (the DC's FQDN does not exist on the operator's resolver).
    """
    return (
        "# generated by OMNI for this invocation (no credentials in this file)\n"
        "strict_chain\n"
        "proxy_dns\n"
        "remote_dns_subnet 224\n"
        "tcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n"
        "[ProxyList]\n"
        f"{proxy.chain_type} {proxy.host} {proxy.port}\n"
    )


def config_path(root: str | Path, run_id: str) -> tuple[Path, str]:
    """``(absolute, workspace-relative)`` config path for one run.

    The relative form is what the child receives: the sandbox runs with the
    workspace as its cwd (and, under OCI, bind-mounts it at ``/workspace``), so
    a relative path resolves in both backends while the absolute host path only
    resolves in one.
    """
    base = Path(root).resolve() / PROXYCHAINS_CONFIG_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    stamp = re.sub(r"[^A-Za-z0-9_-]", "", str(run_id or "run"))[:48] or "run"
    absolute = base / f"{stamp}.conf"
    return absolute, str(PurePosixPath(PROXYCHAINS_CONFIG_DIRNAME) / absolute.name)


def wrap_argv(
    argv: list[str],
    proxy: ProxySpec,
    *,
    binary: str,
    root: str | Path,
    run_id: str,
) -> tuple[list[str], dict]:
    """Return ``argv`` behind proxychains and the evidence to record.

    ``-q`` silences proxychains' own banner so the parser only sees the tool,
    and ``-f`` points at the generated config instead of the operator's
    ``/etc/proxychains4.conf`` (which may chain to a different tunnel).
    """
    absolute, relative = config_path(root, run_id)
    absolute.write_text(proxychains_config(proxy), encoding="utf-8")
    return [binary, "-q", "-f", relative, *argv], {
        "proxy": proxy.describe(),
        "proxychains_config": relative,
    }


__all__ = [
    "DEFAULT_PROXY_PORTS",
    "PROXYCHAINS_BINARY_ENV",
    "PROXYCHAINS_CONFIG_DIRNAME",
    "PROXY_SCHEMES",
    "ProxySpec",
    "config_path",
    "ensure_proxy_in_scope",
    "is_loopback",
    "parse_proxy",
    "proxychains_config",
    "resolve_proxychains",
    "wrap_argv",
]
