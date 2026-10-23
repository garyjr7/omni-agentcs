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
        # PLAN MODE: the engagement's own contract (``ENGAGEMENT_PLAN.md``).
        # Every profile must be able to read it -it is what the run is held to-
        # and the two writers are here because a phase that discovers a new
        # vector is exactly who has to add its TODO. They write a file in the
        # engagement's workspace (``scope_required=False``), never the target.
        "nexus.orchestrator.create_plan",
        "nexus.orchestrator.update_plan",
        "nexus.orchestrator.get_plan_status",
        # WP4: the skill catalogue. Read-only local files, no target, so every
        # profile (including the read-only ones) may consult and load a recipe.
        "nexus.skill.list",
        "nexus.skill.load",
    }
)

#: The WP1 execution substrate: available to **every** profile, including the
#: read-only ones. This is the deliberate product decision of the plan -a shell
#: and a persistent session are not a kill-chain tool, they are the substrate
#: every phase needs- and it fixes the measured failure where the planner moved
#: the run to ``reporter`` and the profile then denied ``ssh_exec`` with root
#: already on the board (rerun 13).
#:
#: They are *active* tools (``ACTIVE_TOOLS``) and remain governed by the
#: gateway, the signed engagement and the audit chain. ``validate_registry``
#: excludes exactly this overlay from the read-only subset invariant; the
#: read-only *kill-chain* subset still cannot acquire an active tool.
UNIVERSAL_TOOLS: frozenset[str] = frozenset(
    {"nexus.shell.exec", "nexus.session.pty"}
)

#: Tools that change state on a target, a session or the local system. A profile
#: that declares itself read-only must not list any of them: two independent
#: classifications, so a mismatch is caught instead of failing open. Kept
#: deliberately explicit - a new durable tool must be triaged here on purpose.
ACTIVE_TOOLS: frozenset[str] = frozenset(
    {
        # The application-boundary pair of the declarative red_team_base chain
        # (staging_and_interaction): staging a component and triggering it change
        # the target, so both are active by classification.
        "nexus.web.request",
        "nexus.web.upload",
        # V11: uploading a PoC writes to the target (a BlogEngine theme control
        # or a compiled binary), so it is active by the same classification.
        "nexus.exploit.compile_and_upload",
        # Owned-session command execution and its durable handoff. Both were in
        # the catalog but reachable from no profile, which made the
        # command_execution / local_elevation_heuristics phases unimplementable.
        "nexus.post.shell_exec",
        "nexus.post.job",
        # WP1 universal substrate (available to every profile).
        "nexus.shell.exec",
        "nexus.session.pty",
        "nexus.cred.bruteforce",
        # Offline cracking of what the engagement already holds: a hash from a
        # config or a passphrase-protected key from an exposed panel. Without
        # it a validated artifact stops being usable at the last step.
        "nexus.post.crack_hash",
        "nexus.exploit.msf_auxiliary",
        "nexus.exploit.msf_exploit",
        "nexus.attack.impacket_secretsdump",
        "nexus.attack.impacket_getuserspns",
        "nexus.attack.impacket_psexec",
        "nexus.post.ssh_exec",
        "nexus.post.ssh_upload",
        "nexus.post.pivot_bruteforce",
        "nexus.post.pivot_http",
        "nexus.post.ntlm_capture",
        # Tanda G: hosting the payload the victim has to fetch back (SSRF).
        # A network service on the operator's side, so active by classification.
        "nexus.post.http_server",
        "nexus.attack.impacket_changepasswd",
        "nexus.attack.ad_acl",
        "nexus.attack.nopac",
        "nexus.win.winrm_exec",
        "nexus.pwn.ret2libc",
        "nexus.web.wp_bruteforce",
        "nexus.web.wp_exec",
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
        # PLAN MODE writers (COMMON_TOOLS): they mutate the engagement's own
        # plan file, not the target, so a read-only profile may keep them. See
        # ``ORCHESTRATOR_PLAN_TOOLS`` for why the invariant excludes them.
        "nexus.orchestrator.create_plan",
        "nexus.orchestrator.update_plan",
    }
)

#: The plan tools are the one active pair every profile carries. The invariant
#: "a read-only profile lists no active tool" exists to stop a *capability* leak
#: (a recon profile acquiring sqlmap); a profile that can read the contract it is
#: held to but cannot fix it would deadlock the run on iteration 0 (recon is
#: read-only and the plan is mandatory before any attack). They write one file in
#: the engagement workspace and never touch the objective, which is why they are
#: excluded exactly like the universal execution overlay.
ORCHESTRATOR_PLAN_TOOLS: frozenset[str] = frozenset(
    {
        "nexus.orchestrator.create_plan",
        "nexus.orchestrator.update_plan",
        "nexus.orchestrator.get_plan_status",
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

#: WP2 (Loop v2): the single default profile. It is deliberately **not** part of
#: ``SUBAGENTS``: the legacy profiles stay intact for ``--subagent`` pins, the
#: TUI and the regression suite behind ``NEXUS_LEGACY_PROFILES=1``.
OMNI_SUBAGENT_ID = "omni"

#: Operator escape hatch to the old phase-gated loop. Truthy values enable it.
LEGACY_PROFILES_ENV = "NEXUS_LEGACY_PROFILES"


def legacy_profiles() -> bool:
    """Whether the phase-gated loop (one tool subset per phase) is requested.

    WP2 declares the phase model a *hint*. The flag exists so a regression can
    still reproduce the old behaviour exactly, with the same tool intersections
    and the same per-profile budgets; it is read per call, so a process can flip
    it only through its own environment.
    """
    raw = os.getenv(LEGACY_PROFILES_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}

#: Tools of the web-enumeration subset. ``web`` (the refinement) is exactly
#: these; ``services`` (the enumeration entry profile) adds the non-web ones on
#: top, so enumerating a target that exposes both HTTP and, say, FTP never needs
#: a phase change to reach either (P0, Fase 3.7).
WEB_ENUM_TOOLS: frozenset[str] = frozenset(
    {
        "nexus.recon.httpx",
        "nexus.recon.gobuster",
        "nexus.recon.whatweb",
        # Web scan with the evasion knobs of RUN_sala12 (-Tuning/-evasion/-Pause).
        "nexus.recon.nikto",
        "nexus.web.nuclei",
        "nexus.web.ffuf",
        "nexus.web.dalfox",
        "nexus.web.wp_enum",
        # Recovering a repository the target itself is serving is read-only
        # reconnaissance of the application surface (red_team_base phase 2).
        "nexus.web.git_dump",
    }
)

#: Iterations at the start of a new profile during which the previous profile's
#: read-only tools stay available (P1, Fase 3.7). The planner closes ``recon``
#: with the first ``service`` fact, so without this grace the agent loses in the
#: very iteration it needs them the tools that are meant to enumerate that
#: service - which is what made the FTP chain unreachable in the E2E #3.
PHASE_GRACE_ITERATIONS = 2


def _with_common(tools: Iterable[str]) -> frozenset[str]:
    """Profile subset plus the shared tools and the universal execution overlay."""
    return COMMON_TOOLS | UNIVERSAL_TOOLS | frozenset(tools)


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
    #: Optional, profile-specific line for the prompt (V1-44): the correction a
    #: measured run needed, stated where the model reads the active profile.
    hint: str | None = None
    #: WP2: ``True`` for the single ``omni`` profile, which may invoke every tool
    #: in the durable catalog. It is not a permission grant - the gateway keeps
    #: governing every call - it only removes the *subset* intersection.
    unrestricted: bool = False

    @property
    def parallel_safe(self) -> bool:
        """Read-only profiles may fan out; everything else stays sequential."""
        return self.read_only

    def allows(self, tool_id: str) -> bool:
        """Whether the tool is in this profile's own subset (not external)."""
        return self.unrestricted or tool_id in self.tools

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
            "hint": self.hint,
            "unrestricted": self.unrestricted,
        }

    def describe(self) -> str:
        """Compact, prompt-ready frame for the system message."""
        mode = "solo lectura (paralelizable)" if self.parallel_safe else "activo (secuencial)"
        lines = [
            (
                f"PERFIL ACTIVO: {self.id} ({self.label})"
                if self.unrestricted
                else f"SUBAGENTE ACTIVO: {self.id} ({self.label})"
            ),
            f"foco: {self.focus}",
            f"modo: {mode}",
        ]
        if self.unrestricted:
            lines.extend(
                [
                    "catálogo: TODAS las tools del catálogo están disponibles en todas las fases.",
                    "límites: presupuesto y presupuesto de iteraciones son *soft* (telemetría); "
                    "solo el presupuesto global del run puede detenerlo.",
                ]
            )
        else:
            lines.append(
                f"presupuesto: {self.token_budget} tokens · {self.max_iterations} iteraciones"
            )
        if self.hint:
            lines.append(f"pista: {self.hint}")
        if not self.unrestricted:
            lines.append(
                "solo puedes invocar tools de tu subconjunto; cualquier otra será denegada "
                "y auditada."
            )
        return "\n".join(lines)


#: The nine profiles, in kill-chain order. Tool subsets are exact catalog ids
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
                "nexus.recon.dns",
                "nexus.recon.subfinder",
                "nexus.recon.httpx",
                "nexus.recon.ftp",
                "nexus.recon.nfs",
                "nexus.recon.gobuster",
                "nexus.recon.whatweb",
                "nexus.recon.nikto",
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
        tools=_with_common(WEB_ENUM_TOOLS),
        token_budget=80_000,
        max_iterations=10,
        read_only=True,
    ),
    # P0 (Fase 3.7): the enumeration entry profile is *service*-aware, not
    # web-only. It carries every read-only enumeration tool the catalog has -
    # FTP and SMB (netexec) next to the web trio - so a target whose first fact is
    # a non-web ``service`` can still be enumerated. ``web`` stays as the
    # refinement once web-specific evidence (``endpoint``/``vulnerability``)
    # exists, which tightens the subset back to just the web surface.
    # ``nexus.recon.netexec`` is classified active, so this profile is not
    # read-only: it therefore never fans out. Governance is untouched - a subset
    # can only shrink the surface, never widen authority.
    SubAgentDefinition(
        id="services",
        label="Enumeración de servicios",
        phase="enumeration",
        focus="enumerar cada servicio hallado (FTP, SMB, HTTP…) y registrar usuarios y pistas",
        tools=_with_common(
            WEB_ENUM_TOOLS
            | {"nexus.recon.ftp", "nexus.recon.nfs", "nexus.recon.netexec", "nexus.pwn.analyze"}
            # Enumerating the *application boundary* includes touching it: probing
            # a panel and staging a component against it are part of phase 2 of
            # red_team_base, which starts while the phase is still `enumeration`.
            | {"nexus.web.request", "nexus.web.upload"}
        ),
        token_budget=80_000,
        max_iterations=10,
        read_only=False,
    ),
    SubAgentDefinition(
        id="cred",
        label="Credenciales",
        phase="enumeration",
        focus="validar credenciales halladas contra los servicios expuestos",
        tools=_with_common(
            {
                "nexus.cred.bruteforce",
                "nexus.web.wp_bruteforce",
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
                # The PoC itself, not just the lookup: V10 found CVE-2019-6714
                # and the profile had no way to copy/read/adapt the exploit.
                "nexus.exploit.find_and_prepare",
                # V11: and the way to *ship* it. The PoC is a BlogEngine theme
                # control: uploading it as .ascx through the CMS panel is the
                # step that turns the CVE into access.
                "nexus.exploit.compile_and_upload",
                "nexus.recon.netexec",
                # Tanda G: the SSRF PoC (Dell OpenManage) only works once the
                # target can download the payload from us.
                "nexus.post.http_server",
                "nexus.pwn.analyze",
                "nexus.pwn.ret2libc",
                "nexus.web.wp_bruteforce",
                "nexus.web.wp_exec",
                # Application-boundary staging/triggering (red_team_base phase 2)
                # and the web-repository recovery that feeds it.
                "nexus.web.request",
                "nexus.web.upload",
                "nexus.web.git_dump",
                # V1-34 part B: the profile that owns initial access must be able
                # to *consume* the credential the board already validated, not
                # just find one. Measured in rerun 9: the verified credential
                # reached the plan but no ``exploit`` tool could open a session
                # with it (``ssh_exec``/``winrm_exec`` were absent and
                # ``session.*`` could only be reached from ``postexploit``).
                "nexus.post.ssh_exec",
                "nexus.win.winrm_exec",
                "nexus.session.list",
                "nexus.session.interact",
            }
        ),
        token_budget=60_000,
        # 2026-10-15 (experimento rerun 5): 8 → 15. Razón: el run4 gastó sus 8
        # iteraciones en 3 turnos de relleno y 2 rechazos evitables antes de
        # poder probar alternativas tras el fallo de MS17-010. Se mide si con más
        # espacio el agente pivota. Si no pivota, el problema NO es presupuesto.
        max_iterations=15,
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
                "nexus.post.ssh_upload",
                "nexus.post.enum_system",
                # The session→post hand-over (V1-25) lands here, so this profile
                # needs the elevation heuristics too: it is the only profile that
                # both owns a session and can look for the vector (measured in
                # rerun 6: `exploit` opened a SYSTEM Meterpreter with no tool to
                # use it, and `privesc` was never reached).
                "nexus.post.privesc_hints",
                # Stable command handling on an owned session: interactive execution
                # plus the durable handoff for long-running commands (phase 3).
                "nexus.post.shell_exec",
                "nexus.post.job",
                "nexus.post.pivot_bruteforce",
                "nexus.post.pivot_http",
                # The verification step of any tunnel this profile builds: without
                # it the pivot is a claim (DeadDrop P11 burned twenty turns on
                # tunnels nobody could prove).
                "nexus.post.verify_route",
                "nexus.post.crack_hash",
                "nexus.post.ntlm_capture",
                "nexus.post.dns_update",
                "nexus.post.tftp",
                # Tanda G: the same governed way to hand a file to the target
                # over HTTP when TFTP/SMB are not the vector an SSRF needs.
                "nexus.post.http_server",
                "nexus.post.dpapi",
                "nexus.attack.impacket_changepasswd",
                "nexus.attack.ad_acl",
                "nexus.attack.nopac",
                "nexus.win.winrm_exec",
                "nexus.web.wp_exec",
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
                # A PE-assist script has to be pushed when the target has no
                # outbound network (RUN_sala12: the host could not fetch it).
                "nexus.post.ssh_upload",
                # red_team_base phases 3 and 4 run in this profile: inventory the
                # owned sessions, execute one verified command per hypothesis and
                # hand a long verification routine to a durable job.
                "nexus.session.list",
                "nexus.post.shell_exec",
                "nexus.post.job",
            }
        ),
        token_budget=60_000,
        max_iterations=10,
        read_only=False,
        # V1-44 (rerun 12): the model saw `sudo -n -l` answer "a password is
        # required", read it as "sudo is unusable", and spent its 8 iterations on
        # the SUID template of the same binary -which does not elevate- and on a
        # hand-built PwnKit, dying at 63465/60000 tokens without root. The tool
        # that resolves exactly that dead end was in its own subset: this profile
        # has `nexus.post.enum_system`, and it is the only tool that answers
        # `sudo -l` by feeding the vault credential to `sudo -S`.
        hint=(
            "Cuando ssh_exec devuelva 'sudo: a password is required', invoca "
            "nexus.post.enum_system — no reintentes sudo -l por ssh_exec."
        ),
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
                "nexus.attack.impacket_changepasswd",
                "nexus.attack.ad_acl",
                "nexus.attack.nopac",
                "nexus.cred.bruteforce",
                "nexus.post.ssh_exec",
                "nexus.post.pivot_bruteforce",
                "nexus.post.pivot_http",
                "nexus.post.verify_route",
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
        # V1-41: measured in rerun 11 (`run_30bfde08…`), the reporter spent its 4
        # iterations on one denied attempt, `report.generate`, a `task_complete`
        # the gate rejected and the recovery turn that fetched the right evidence
        # -and died just before it could retry with it. The gate itself is not
        # relaxed (that is V1-45 territory): the profile gets the margin the
        # reject-and-retry loop costs. `token_budget` is untouched (V1-21 stays
        # closed).
        max_iterations=6,
        read_only=True,
    ),
)

#: WP2: the default profile of the loop. One profile, every tool. The phase
#: labels remain as prompt hints (the plan block), never as a tool intersection.
#: Its budgets are soft: they only produce telemetry and can never stop the run.
OMNI_PROFILE = SubAgentDefinition(
    id=OMNI_SUBAGENT_ID,
    label="Agente único",
    phase="",
    focus="resolver el engagement de principio a fin con todo el catálogo disponible",
    tools=frozenset(),
    token_budget=250_000,
    max_iterations=10_000,
    read_only=False,
    unrestricted=True,
    hint=(
        "La fase del plan es una pista, no una puerta: si la evidencia pide otra "
        "herramienta, úsala aunque la fase diga otra cosa."
    ),
)

SUBAGENTS_BY_ID: Mapping[str, SubAgentDefinition] = {item.id: item for item in SUBAGENTS}
SUBAGENT_IDS: tuple[str, ...] = tuple(item.id for item in SUBAGENTS)

#: Operator-facing vocabulary for the specialization "jobs" a caller may ask
#: for, bound to the canonical kill-chain profile that implements them. The
#: alias never creates a new execution path: it only resolves to an existing
#: capability profile, so the tool subset and capability boundary are unchanged.
#: - ``target-mapper`` maps hosts/services (read-only recon).
#: - ``tactical-planner`` analyses the blackboard read-only to propose the next
#:   phase (the deterministic planner, not a model, owns the phase itself).
#: - ``exploit-scripter`` turns a finding into initial access.
#: - ``stealth-validator`` reviews evidence and formats deliverables.
#: - ``c2-operator`` drives owned sessions, jobs and C2.
#: - ``deep-reasoning`` is the largest read-only analysis budget.
SUBAGENT_ALIASES: Mapping[str, str] = {
    "target-mapper": "recon",
    "tactical-planner": "recon",
    "exploit-scripter": "exploit",
    "stealth-validator": "reporter",
    "c2-operator": "postexploit",
    "deep-reasoning": "recon",
}


def resolve_subagent_id(identifier: str | None) -> str | None:
    """Resolve a profile id or an alias to a canonical profile id.

    Returns ``None`` for an unknown/empty identifier so callers fail closed
    (the same contract :func:`select_subagent` enforces on an override).
    """
    if not identifier:
        return None
    value = str(identifier).strip()
    if not value:
        return None
    canonical = SUBAGENT_ALIASES.get(value.lower())
    if canonical is not None:
        return canonical
    return value if value in SUBAGENTS_BY_ID else None

#: Deterministic phase -> profile table. Mirrors the planner's phase ids.
#: ``enumeration`` enters through ``services`` (any service), and ``_refine``
#: narrows to ``web``/``cred`` as the blackboard gains web or credential facts.
PHASE_SUBAGENT: Mapping[str, str] = {
    "recon": "recon",
    "enumeration": "services",
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
        resolved = resolve_subagent_id(override)
        if resolved is None:
            raise ValueError(f"unknown subagent: {override}")
        return apply_budget_overrides(SUBAGENTS_BY_ID[resolved], env=env)
    normalized = {str(key): int(value or 0) for key, value in (counts or {}).items()}
    refined = _refine(str(phase or ""), normalized)
    subagent_id = refined or PHASE_SUBAGENT.get(str(phase or ""), DEFAULT_SUBAGENT_ID)
    return apply_budget_overrides(SUBAGENTS_BY_ID[subagent_id], env=env)


def _refine(phase: str, counts: Mapping[str, int]) -> str | None:
    """Blackboard-driven refinement of the default phase profile.

    Once credentials or users are on the board, enumeration is about *testing*
    them, so the credential profile takes over; web-specific evidence
    (endpoints/vulnerabilities) narrows enumeration to the web profile. With no
    such evidence the phase keeps the default ``services`` profile, which can
    enumerate whatever service was found (P0, Fase 3.7).
    """
    if phase == "enumeration":
        if counts.get("credential") or counts.get("user"):
            return "cred"
        if counts.get("endpoint") or counts.get("vulnerability"):
            return "web"
    return None


def with_phase_grace(
    subagent: SubAgentDefinition,
    previous: SubAgentDefinition | None,
    *,
    iterations: int = 1,
) -> SubAgentDefinition:
    """Return ``subagent`` widened with the previous profile's read-only tools.

    Only during the first ``PHASE_GRACE_ITERATIONS`` iterations of a profile, and
    only with tools that are themselves read-only (``ACTIVE_TOOLS`` are never
    inherited, so the grace can never widen authority). The result is a *derived
    profile*, not a second permission check: the prompt the model sees and the
    subset the loop enforces stay the same object (P1, Fase 3.7).
    """
    if previous is None or previous.id == subagent.id:
        return subagent
    if iterations > PHASE_GRACE_ITERATIONS:
        return subagent
    inherited = frozenset(previous.tools - ACTIVE_TOOLS)
    if inherited <= subagent.tools:
        return subagent
    return replace(subagent, tools=subagent.tools | inherited)


def select_for_plan(plan: Any, *, override: str | None = None) -> SubAgentDefinition:
    """Pick the profile for a planner :class:`~nexus_core.agent.planner.Plan`.

    The phase (``plan.current``) comes from verified evidence only, but profile
    refinement also reads the plan's *leads* (agent-recorded, unverified facts):
    a user the agent found but no parser attested still has to reach the
    credential profile, otherwise the loop enumerates forever with no tool that
    can test what it found. Leads can only choose among existing profiles, so
    they never widen the tool surface.
    """
    counts = {str(key): int(value or 0) for key, value in (getattr(plan, "counts", None) or {}).items()}
    for fact_type, amount in (getattr(plan, "leads", None) or {}).items():
        name = str(fact_type)
        counts[name] = max(counts.get(name, 0), int(amount or 0))
    return select_subagent(
        getattr(plan, "current", None),
        counts=counts,
        override=override,
    )


def is_external(tool_id: str) -> bool:
    """Whether ``tool_id`` is an operator-authorized extension (e.g. MCP)."""
    return str(tool_id).startswith(EXTERNAL_TOOL_PREFIXES)


def permits(subagent: SubAgentDefinition, tool_id: str, definition: Any = None) -> bool:
    """External tools require known effects, restricted by the active profile."""
    if not is_external(tool_id):
        return subagent.allows(tool_id)
    if isinstance(definition, tuple):
        definition = definition[0]
    effects = set(getattr(definition, "effects", ()))
    if not effects or not effects <= {"read", "write", "exec", "network"}:
        return False
    return not subagent.read_only or effects == {"read"}


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
        if (permits(subagent, tool_id, entry) if include_external else subagent.allows(tool_id))
    }


def select_run_profile(plan: Any, *, override: str | None = None) -> SubAgentDefinition:
    """Pick the profile the *loop* runs with (WP2).

    New default: one ``omni`` profile with every tool, so the phase can never
    remove the tool the engagement needs. ``NEXUS_LEGACY_PROFILES=1`` restores
    the old phase-driven selection, and an explicit operator pin still wins in
    both modes (it is the debug/escape hatch, not the product default).
    """
    if override:
        resolved = resolve_subagent_id(override)
        if resolved is None:
            raise ValueError(f"unknown subagent: {override}")
        return apply_budget_overrides(SUBAGENTS_BY_ID[resolved])
    if legacy_profiles():
        return select_for_plan(plan)
    return OMNI_PROFILE


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
        if profile.unrestricted:
            # The single omni profile is not a subset; its authority is the
            # gateway's, not a list. Nothing to validate against the catalog.
            continue
        if profile.read_only:
            # The universal execution substrate is profile-independent and is
            # never counted as a leak (WP1); every other active tool is.
            leaked = sorted(
                profile.tools
                & (ACTIVE_TOOLS - UNIVERSAL_TOOLS - ORCHESTRATOR_PLAN_TOOLS)
            )
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
    watcher: asyncio.Future[None] | None = None
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
    "LEGACY_PROFILES_ENV",
    "OMNI_PROFILE",
    "OMNI_SUBAGENT_ID",
    "PHASE_GRACE_ITERATIONS",
    "PHASE_SUBAGENT",
    "SUBAGENT_ALIASES",
    "SUBAGENTS",
    "SUBAGENTS_BY_ID",
    "SUBAGENT_IDS",
    "UNIVERSAL_TOOLS",
    "BUDGET_ENV_PREFIX",
    "SubAgentDefinition",
    "WEB_ENUM_TOOLS",
    "apply_budget_overrides",
    "budget_env_name",
    "filter_catalog",
    "gather_readonly",
    "is_external",
    "legacy_profiles",
    "permits",
    "resolve_subagent_id",
    "select_for_plan",
    "select_run_profile",
    "select_subagent",
    "validate_registry",
    "with_phase_grace",
]
