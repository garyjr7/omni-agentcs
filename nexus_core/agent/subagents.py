"""Specialized subagents: isolated tool subsets, budgets and context.

A subagent is a *capability profile* for one phase of the kill chain. It never
executes anything itself; it narrows what the ReAct loop is allowed to propose:

* **Tool subset** - the loop intersects the durable catalog with the active
  profile's ``tools`` and denies anything outside it. The check is fail-closed:
  a tool that exists in the catalog but not in the subset is refused exactly
  like an invented tool, and the refusal is audited with the ``subagent_id``.
* **Budget isolation** - each profile owns a token and iteration budget, and the
  loop books its spend under ``subject_id = subagent_id`` so one phase can never
  drain another phase's allowance.
* **Context isolation** - the prompt frame of every iteration carries the active
  profile (id, focus, remaining budget, allowed tools), so the model reasons
  inside one phase instead of re-deriving the methodology each turn.

Selection is deterministic and blackboard-driven, mirroring the planner: the
kill-chain phase plus the facts registered so far fully determine the active
subagent. The model never picks its own profile, which keeps the choice cheap to
unit-test and impossible to steer through a prompt.

A subagent is **not** an execution boundary. It cannot widen its own authority:
the gateway keeps enforcing policy, the signed scope, durable approvals and the
deterministic post-condition. The profile only shrinks the surface.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Iterable, Mapping, Sequence

#: Per-subagent token budgets are tunable per engagement through env vars, e.g.
#: ``NEXUS_SUBAGENT_BUDGET_RECON=150000``. This is the escape hatch for a
#: target that legitimately needs more context than the calibrated default.
BUDGET_ENV_PREFIX = "NEXUS_SUBAGENT_BUDGET_"

#: Tools that only read durable memory or the local environment. They touch no
#: target, so every profile may use them without widening its blast radius.
#: ``nexus.workspace.read`` reads the *engagement's own* workspace (the loot the
#: recon handlers downloaded); it is confined to that directory, so it belongs
#: here next to the workspace search (B7).
COMMON_TOOLS: frozenset[str] = frozenset(
    {
        "nexus.knowledge.record_fact",
        "nexus.knowledge.query_facts",
        "nexus.workspace.search",
        "nexus.workspace.read",
        "nexus.system.status",
        "nexus.system.check_env",
        "nexus.orchestrator.playbook",
    }
)

#: Tools that change state on a target, a session or the local system. A profile
#: that declares itself read-only must not list any of them: two independent
#: classifications, so a mismatch is caught instead of failing open. Kept
#: deliberately explicit - a new durable tool must be triaged here on purpose.
ACTIVE_TOOLS: frozenset[str] = frozenset(
    {
        "nexus.cred.bruteforce",
        "nexus.exploit.msf_auxiliary",
        "nexus.exploit.msf_exploit",
        "nexus.attack.impacket_secretsdump",
        "nexus.attack.impacket_getuserspns",
        "nexus.attack.impacket_psexec",
        "nexus.post.ssh_exec",
        "nexus.recon.netexec",
        "nexus.recon.bloodhound_python",
        "nexus.web.sqlmap",
        "nexus.session.interact",
        "nexus.session.kill",
        "nexus.system.install_tool",
        "nexus.c2.sliver_server",
        "nexus.c2.sliver_implants",
        "nexus.c2.sliver_sessions",
        "nexus.c2.sliver_exec",
        "nexus.c2.sliver_pivot",
        "nexus.c2.sliver_generate",
        "nexus.c2.sliver_deploy",
        "nexus.c2.sliver_loot",
    }
)

#: Tool-id prefixes that are *operator-authorized extensions* rather than
#: kill-chain tools (currently the MCP bridge, ``mcp.<server>.<tool>``).
#:
#: Why they bypass the phase subset: they are not part of the kill chain, so they
#: cannot be assigned to one phase, and their authorization already happened
#: out-of-band — the operator allowlisted the server, policy approval-gates the
#: dangerous ones, the RoE gate still applies, and their output is wrapped as
#: untrusted data. Registration *is* the opt-in; nothing is registered otherwise.
EXTERNAL_TOOL_PREFIXES: tuple[str, ...] = ("mcp.",)

#: Hard ceiling on concurrent read-only fan-out. Defence in depth against a
#: profile or caller asking to stampede a target.
DEFAULT_MAX_PARALLEL = 4

#: Fallback profile when a phase is unknown or missing. It is the most
#: restrictive read-only profile, so an unrecognised phase fails *closed*.
DEFAULT_SUBAGENT_ID = "recon"


def _with_common(tools: Iterable[str]) -> frozenset[str]:
    return COMMON_TOOLS | frozenset(tools)


@dataclass(frozen=True)
class SubAgentDefinition:
    """One capability profile of the kill chain."""

    id: str
    label: str
    phase: str
    focus: str
    tools: frozenset[str]
    token_budget: int
    max_iterations: int
    #: True only when every listed tool reads the target without altering it.
    read_only: bool

    @property
    def parallel_safe(self) -> bool:
        """Read-only profiles may fan out; everything else stays sequential."""
        return self.read_only

    def allows(self, tool_id: str) -> bool:
        """Whether the tool is in this profile's own subset (not external)."""
        return tool_id in self.tools

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "phase": self.phase,
            "focus": self.focus,
            "tools": sorted(self.tools),
            "tools_count": len(self.tools),
            "token_budget": self.token_budget,
            "max_iterations": self.max_iterations,
            "read_only": self.read_only,
            "parallel_safe": self.parallel_safe,
        }

    def describe(self) -> str:
        """Compact, prompt-ready frame for the system message."""
        mode = "solo lectura (paralelizable)" if self.parallel_safe else "activo (secuencial)"
        return (
            f"SUBAGENTE ACTIVO: {self.id} ({self.label})\n"
            f"foco: {self.focus}\n"
            f"modo: {mode}\n"
            f"presupuesto: {self.token_budget} tokens · {self.max_iterations} iteraciones\n"
            "solo puedes invocar tools de tu subconjunto; cualquier otra será denegada "
            "y auditada."
        )


#: The eight profiles, in kill-chain order. Tool subsets are exact catalog ids
#: (a test asserts every id exists in the durable catalog).
SUBAGENTS: tuple[SubAgentDefinition, ...] = (
    SubAgentDefinition(
        id="recon",
        label="Reconocimiento",
        phase="recon",
        focus="descubrir hosts, puertos y servicios sin tocar el estado del objetivo",
        tools=_with_common(
            {
                "nexus.recon.nmap",
                "nexus.recon.subfinder",
                "nexus.recon.httpx",
                "nexus.recon.ftp",
                "nexus.recon.gobuster",
                "nexus.recon.whatweb",
            }
        ),
        # 5x the original 20k: each iteration re-sends ~7k tokens of system
        # prompt + schemas, so 20k only bought ~3 actions (B4).
        token_budget=100_000,
        max_iterations=8,
        read_only=True,
    ),
    SubAgentDefinition(
        id="web",
        label="Enumeración web",
        phase="enumeration",
        focus="enumerar endpoints, tecnologías y vulnerabilidades web",
        tools=_with_common(
            {
                "nexus.recon.httpx",
                "nexus.recon.gobuster",
                "nexus.recon.whatweb",
                "nexus.web.nuclei",
                "nexus.web.ffuf",
                "nexus.web.dalfox",
            }
        ),
        token_budget=80_000,
        max_iterations=10,
        read_only=True,
    ),
    SubAgentDefinition(
        id="cred",
        label="Credenciales",
        phase="enumeration",
        focus="validar credenciales halladas contra los servicios expuestos",
        tools=_with_common(
            {
                "nexus.cred.bruteforce",
                "nexus.recon.netexec",
                "nexus.recon.ftp",
            }
        ),
        token_budget=60_000,
        max_iterations=6,
        read_only=False,
    ),
    SubAgentDefinition(
        id="exploit",
        label="Acceso inicial",
        phase="exploitation",
        focus="convertir un hallazgo en acceso inicial (explotar o validar)",
        tools=_with_common(
            {
                "nexus.exploit.msf_search",
                "nexus.exploit.msf_auxiliary",
                "nexus.exploit.msf_exploit",
                "nexus.exploit.searchsploit",
                "nexus.recon.netexec",
            }
        ),
        token_budget=60_000,
        max_iterations=8,
        read_only=False,
    ),
    SubAgentDefinition(
        id="postexploit",
        label="Post-explotación",
        phase="post_exploitation",
        focus="ejecutar comandos, recolectar loot y registrar evidencia",
        tools=_with_common(
            {
                "nexus.post.ssh_exec",
                "nexus.post.enum_system",
                "nexus.session.list",
                "nexus.session.interact",
                "nexus.session.kill",
                "nexus.c2.sliver_sessions",
                "nexus.c2.sliver_exec",
                "nexus.c2.sliver_loot",
            }
        ),
        token_budget=60_000,
        max_iterations=8,
        read_only=False,
    ),
    SubAgentDefinition(
        id="privesc",
        label="Escalada de privilegios",
        phase="privilege_escalation",
        focus="enumerar sudo/SUID/capabilities y demostrar uid=0",
        tools=_with_common(
            {
                "nexus.post.enum_system",
                "nexus.post.privesc_hints",
                "nexus.post.ssh_exec",
            }
        ),
        token_budget=60_000,
        max_iterations=10,
        read_only=False,
    ),
    SubAgentDefinition(
        id="lateral",
        label="Movimiento lateral",
        phase="lateral_movement",
        focus="reutilizar el acceso para comprometer más hosts",
        tools=_with_common(
            {
                "nexus.recon.netexec",
                "nexus.recon.bloodhound_python",
                "nexus.attack.impacket_secretsdump",
                "nexus.attack.impacket_getuserspns",
                "nexus.attack.impacket_psexec",
                "nexus.cred.bruteforce",
                "nexus.post.ssh_exec",
                "nexus.session.list",
                "nexus.session.interact",
                "nexus.c2.sliver_sessions",
                "nexus.c2.sliver_pivot",
            }
        ),
        token_budget=60_000,
        max_iterations=8,
        read_only=False,
    ),
    SubAgentDefinition(
        id="reporter",
        label="Reporte",
        phase="reporting",
        focus="consolidar hallazgos verificados y cerrar el engagement",
        tools=_with_common({"nexus.report.generate"}),
        token_budget=30_000,
        max_iterations=4,
        read_only=True,
    ),
)

SUBAGENTS_BY_ID: Mapping[str, SubAgentDefinition] = {item.id: item for item in SUBAGENTS}
SUBAGENT_IDS: tuple[str, ...] = tuple(item.id for item in SUBAGENTS)

#: Deterministic phase -> profile table. Mirrors the planner's phase ids.
PHASE_SUBAGENT: Mapping[str, str] = {
    "recon": "recon",
    "enumeration": "web",
    "exploitation": "exploit",
    "privilege_escalation": "privesc",
    "post_exploitation": "postexploit",
    "lateral_movement": "lateral",
    "reporting": "reporter",
}


def budget_env_name(subagent_id: str) -> str:
    """Env var that overrides one profile's token budget for this engagement."""
    return f"{BUDGET_ENV_PREFIX}{str(subagent_id).upper()}"


def apply_budget_overrides(
    profile: SubAgentDefinition, *, env: Mapping[str, str] | None = None
) -> SubAgentDefinition:
    """Return ``profile`` with ``NEXUS_SUBAGENT_BUDGET_<ID>`` applied when set.

    A non-numeric or non-positive value is ignored so a typo cannot disable the
    budget entirely (fail safe towards the calibrated default).
    """
    raw = (os.environ if env is None else env).get(budget_env_name(profile.id))
    if raw is None or str(raw).strip() == "":
        return profile
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return profile
    if value <= 0:
        return profile
    if value == profile.token_budget:
        return profile
    return replace(profile, token_budget=value)


def select_subagent(
    phase: str | None = None,
    *,
    counts: Mapping[str, Any] | None = None,
    override: str | None = None,
    env: Mapping[str, str] | None = None,
) -> SubAgentDefinition:
    """Pick the active profile deterministically.

    ``override`` (an operator pin) wins when it names a real profile; an unknown
    override raises instead of silently falling back. Otherwise the kill-chain
    phase plus the blackboard counts decide, and an unknown phase fails closed to
    the most restrictive profile. The chosen profile's budget honours
    ``NEXUS_SUBAGENT_BUDGET_<ID>`` when present.
    """
    if override:
        profile = SUBAGENTS_BY_ID.get(str(override))
        if profile is None:
            raise ValueError(f"unknown subagent: {override}")
        return apply_budget_overrides(profile, env=env)
    normalized = {str(key): int(value or 0) for key, value in (counts or {}).items()}
    refined = _refine(str(phase or ""), normalized)
    subagent_id = refined or PHASE_SUBAGENT.get(str(phase or ""), DEFAULT_SUBAGENT_ID)
    return apply_budget_overrides(SUBAGENTS_BY_ID[subagent_id], env=env)


def _refine(phase: str, counts: Mapping[str, int]) -> str | None:
    """Blackboard-driven refinement of the default phase profile.

    Once credentials or users are on the board, enumeration is about *testing*
    them, so the credential profile takes over; endpoints alone keep it on web.
    """
    if phase == "enumeration":
        if counts.get("credential") or counts.get("user"):
            return "cred"
        if counts.get("endpoint") or counts.get("vulnerability"):
            return "web"
    return None


def select_for_plan(plan: Any, *, override: str | None = None) -> SubAgentDefinition:
    """Pick the profile for a planner :class:`~nexus_core.agent.planner.Plan`."""
    return select_subagent(
        getattr(plan, "current", None),
        counts=getattr(plan, "counts", None) or {},
        override=override,
    )


def is_external(tool_id: str) -> bool:
    """Whether ``tool_id`` is an operator-authorized extension (e.g. MCP)."""
    return str(tool_id).startswith(EXTERNAL_TOOL_PREFIXES)


def permits(subagent: SubAgentDefinition, tool_id: str) -> bool:
    """Whether the active profile may propose ``tool_id``.

    A profile's own subset plus every external (operator-authorized) tool. This
    is the single predicate the loop uses, so the prompt and the enforcement can
    never disagree.
    """
    return subagent.allows(tool_id) or is_external(tool_id)


def filter_catalog(
    subagent: SubAgentDefinition,
    catalog: Mapping[str, Any],
    *,
    include_external: bool = True,
) -> dict[str, Any]:
    """Intersect a durable catalog with a profile's subset (order-preserving)."""
    return {
        tool_id: entry
        for tool_id, entry in catalog.items()
        if (permits(subagent, tool_id) if include_external else subagent.allows(tool_id))
    }


def validate_registry(catalog: Mapping[str, Any] | None = None) -> list[str]:
    """Return the problems that would make the registry unsafe.

    Empty means healthy. Two invariants are checked: a read-only profile must
    list no active tool, and (when ``catalog`` is given) every listed tool must
    exist in the durable catalog. Exposed as a function so both tests and an
    operator can assert it without importing private state.
    """
    problems: list[str] = []
    seen: set[str] = set()
    for profile in SUBAGENTS:
        if profile.id in seen:
            problems.append(f"duplicate subagent id: {profile.id}")
        seen.add(profile.id)
        if profile.read_only:
            leaked = sorted(profile.tools & ACTIVE_TOOLS)
            if leaked:
                problems.append(
                    f"profile '{profile.id}' is read-only but lists active tools: {leaked}"
                )
        if profile.token_budget <= 0 or profile.max_iterations <= 0:
            problems.append(f"profile '{profile.id}' has a non-positive budget")
        if catalog is not None:
            missing = sorted(profile.tools - set(catalog))
            if missing:
                problems.append(
                    f"profile '{profile.id}' references unknown tools: {missing}"
                )
    return problems


async def gather_readonly(
    calls: Sequence[Callable[[], Awaitable[Any]]],
    *,
    subagent: SubAgentDefinition,
    limit: int = DEFAULT_MAX_PARALLEL,
    cancel_event: asyncio.Event | None = None,
) -> list[Any]:
    """Run read-only calls concurrently: bounded, cancellable and fail-closed.

    Only a profile flagged ``parallel_safe`` may fan out; anything else raises
    ``ValueError`` *before* a single call is scheduled, so an active phase can
    never be parallelised by accident. At most ``limit`` calls run at once, and
    setting ``cancel_event`` cancels every in-flight call. Exceptions are
    returned in place (like ``gather(return_exceptions=True)``) so one failing
    probe never discards its siblings' evidence.
    """
    if not subagent.parallel_safe:
        raise ValueError(
            f"subagent '{subagent.id}' is not read-only; refusing to parallelise"
        )
    if not calls:
        return []
    bound = max(1, min(int(limit), DEFAULT_MAX_PARALLEL))
    semaphore = asyncio.Semaphore(bound)
    results: list[Any] = []

    async def _run(call: Callable[[], Awaitable[Any]]) -> Any:
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError("read-only fan-out cancelled")
        async with semaphore:
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError("read-only fan-out cancelled")
            return await call()

    tasks = [asyncio.ensure_future(_run(call)) for call in calls]
    watcher: asyncio.Future | None = None
    if cancel_event is not None:

        async def _watch() -> None:
            await cancel_event.wait()
            for task in tasks:
                task.cancel()

        watcher = asyncio.ensure_future(_watch())
    try:
        results = list(await asyncio.gather(*tasks, return_exceptions=True))
    finally:
        if watcher is not None:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
    return results


__all__ = [
    "ACTIVE_TOOLS",
    "COMMON_TOOLS",
    "DEFAULT_MAX_PARALLEL",
    "DEFAULT_SUBAGENT_ID",
    "EXTERNAL_TOOL_PREFIXES",
    "PHASE_SUBAGENT",
    "SUBAGENTS",
    "SUBAGENTS_BY_ID",
    "SUBAGENT_IDS",
    "BUDGET_ENV_PREFIX",
    "SubAgentDefinition",
    "apply_budget_overrides",
    "budget_env_name",
    "filter_catalog",
    "gather_readonly",
    "is_external",
    "permits",
    "select_for_plan",
    "select_subagent",
    "validate_registry",
]
