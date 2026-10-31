"""Read-only join between the agent registry and the installation catalog.

Binary presence is an inventory fact, never proof of parser compatibility,
network reachability or RPC authentication. Unknown plugins remain unassessed.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from .recipes import load_recipes

# Names are handler modules, not duplicated tool IDs. Multiple tools can share
# a dependency; RPC clients do not require a local server executable.
CLI_RECIPES = {
    "nmap": "nmap",
    "nfs": "nfs-common",
    "ffuf": "ffuf",
    "nuclei": "nuclei",
    "httpx": "httpx",
    "subfinder": "subfinder",
    "sqlmap": "sqlmap",
    "gobuster": "gobuster",
    "nikto": "nikto",
    "whatweb": "whatweb",
    "dalfox": "dalfox",
    "searchsploit": "searchsploit",
    # The PoC finder runs the same local Exploit-DB binary and copies the file
    # into the workspace; no network and no extra dependency.
    "exploit_prep": "searchsploit",
    "netexec": "netexec",
    "bloodhound": "bloodhound",
    "cred_bruteforce": "hydra",
    "smb": "impacket",
    "impacket_secretsdump": "impacket",
    "impacket_getuserspns": "impacket",
    # B1: the guaranteed oracle is GetNPUsers (impacket); kerbrute, when present,
    # only improves attribution from partial to full.
    "ad_user_enum": "impacket",
    "impacket_psexec": "impacket",
    "impacket_changepasswd": "impacket",
    # DACL read/write and owner change ship inside impacket
    # (``impacket-dacledit`` / ``impacket-owneredit``).
    "ad_acl": "impacket",
    "nopac": "impacket",
}
PYTHON_HANDLERS = frozenset(
    {
        "dns",
        "dns_update",
        # Tanda A: the route prober is pure Python sockets (TCP connect and a
        # SOCKS5 CONNECT). It runs no binary, so there is nothing to install.
        "verify_route",
        "tftp",
        "dpapi",
        "ftp",
        "ssh_post",
        "pivot",
        "http_request",
        "web_upload",
        # V11: prepares the PoC and delegates the multipart POST to web_upload,
        # so it needs python3 in the sandbox (plus mcs only for a plain .cs).
        "exploit_upload",
        "git_dump",
        "listener",
        "ntlm_capture",
        "winrm",
        "pwn",
        "wp",
        # Theseus: the SSTI engine driver sends HTTP with stdlib/httpx and the
        # PwnKit path runs CVE-2021-4034 over an owned SSH session via paramiko;
        # neither shells out to a pentest binary.
        "web_ssti",
        "pwnkit",
    }
)
INTERNAL_HANDLERS = frozenset(
    {
        "system_env",
        "system_install",
        "system",
        "privesc_hints",
        "knowledge_facts",
        "report_generate",
        "playbook",
        "jobs",
        "shell_exec",
        # WP4: the skill loader reads the project's own SKILL.md files in-process;
        # there is no binary, transport or target behind it.
        "skill",
        # PLAN MODE: create/update/status of ``loot/ENGAGEMENT_PLAN.md``. One
        # Markdown file in the engagement workspace, no binary behind it.
        "plan_engagement",
    }
)


@dataclass(frozen=True)
class CatalogCapability:
    tool_id: str
    handler: str
    transport: str
    recipe: str | None
    binaries: tuple[str, ...]
    state: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_tool_catalog(
    *, which: Callable[[str], str | None] = shutil.which
) -> tuple[CatalogCapability, ...]:
    """Build inventory without probing processes, sockets or installing packages."""
    from nexus_core.tools.registry import durable_tool_definitions

    recipes = load_recipes()
    results: list[CatalogCapability] = []
    for tool_id, (_, handler) in sorted(durable_tool_definitions().items()):
        module = handler.__module__.rsplit(".", 1)[-1]
        recipe_name = CLI_RECIPES.get(module)
        binaries: tuple[str, ...] = ()
        transport, state, detail = "unknown", "unassessed", "plugin or unmapped capability"
        if not handler.__module__.startswith("nexus_core.tools.handlers."):
            recipe_name = None
        elif recipe_name:
            recipe = recipes.get(recipe_name)
            transport = "cli"
            if recipe is None:
                state, detail = "misconfigured", "missing installation recipe"
            else:
                binaries = tuple(
                    dict.fromkeys(
                        [
                            recipe["verify"][0],
                            *[
                                spec["verify"][0]
                                for spec in recipe["recipes"].values()
                                if "verify" in spec
                            ],
                        ]
                    )
                )
                state, detail = (
                    "unverified",
                    "recipe mapped; per-tool binary and sandbox require verification",
                )
                # A package such as Impacket provides several independently named
                # scripts: its generic package probe cannot certify every handler.
                if recipe_name != "impacket":
                    try:
                        state = "detected" if any(which(name) for name in binaries) else "absent"
                    except Exception:
                        state = "failed"
        elif module.startswith("msf_"):
            transport, state, detail = (
                "rpc",
                "unverified",
                "requires configured Metasploit RPC authentication",
            )
        elif module.startswith("sliver_"):
            transport, state, detail = (
                "grpc",
                "unverified",
                "requires Sliver operator config, SDK and mTLS server",
            )
        elif module == "shell_exec":
            transport, state, detail = (
                "session-adapter", "unverified",
                "requires an owned session and its configured HTTP/MSF/Sliver transport",
            )
        elif module == "shell_exec_local":
            transport, state, detail = (
                "local-sandbox", "unverified",
                "requires bash/sh in the sandbox and a confined workspace",
            )
            binaries = ("bash", "sh")
        elif module == "session_pty":
            transport, state, detail = (
                "tmux", "unverified",
                "requires tmux and a run-owned socket in the sandbox",
            )
            binaries = ("tmux",)
        elif module == "http_server":
            # The stdlib file server lives in a tmux pane (the handler has no
            # other way to outlive the call that started it).
            transport, state, detail = (
                "tmux", "unverified",
                "requires tmux, python3 and a workspace directory to publish",
            )
            binaries = ("tmux", "python3")
        elif module == "crack_hash":
            # ``john`` is the cracker and ``ssh2john`` the key converter; the
            # handler reaches both through the stdlib client, so the transport
            # stays the python sandbox.
            transport, state, detail = (
                "python-sandbox",
                "unverified",
                "requires python3 plus john/ssh2john in the sandbox",
            )
            binaries = ("python3", "john")
        elif module in PYTHON_HANDLERS:
            transport, state, detail = (
                "python-sandbox",
                "unverified",
                "requires python3 and handler-specific modules in sandbox",
            )
            binaries = ("python3",)
        elif module == "workspace":
            transport, state, detail = (
                "local",
                "unverified",
                "read: filesystem; search: rg or grep in sandbox",
            )
            binaries = ("rg", "grep")
        elif module in INTERNAL_HANDLERS:
            transport, state, detail = (
                "internal",
                "unverified",
                "requires configured kernel services",
            )
        results.append(
            CatalogCapability(tool_id, module, transport, recipe_name, binaries, state, detail)
        )
    return tuple(results)
