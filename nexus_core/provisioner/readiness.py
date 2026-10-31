"""Operational-environment bootstrap for OmniAgentCS.

``omni`` is a penetration-testing tool, so its first run must leave the whole
offensive environment ready, not just the LLM configuration. This module models
every operational component — binaries (``nmap``, ``hydra``, ``sliver-server``,
...), services (``msfrpcd``, the Sliver team server) and configurations (the
Sliver operator config, nuclei templates, wordlists, the scope signing secret,
the LLM provider) — assesses which are ready, and returns a concrete setup plan
for the ones that are not.

It is read-only: it never installs or starts anything. Installation reuses the
existing approved ``nexus.system.install_tool`` flow; service setup is reported
as an actionable command.
"""

from __future__ import annotations

import os
import shutil
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .binaries import (
    BINARY_IDENTITIES_BY_NAME,
    BinaryIdentity,
    IdentityCheck,
)
from .recipes import load_recipes

#: Binary components: (component_id, binary, purpose, required).
BINARY_COMPONENTS: tuple[tuple[str, str, str, bool], ...] = (
    ("nmap", "nmap", "Descubrimiento de puertos y servicios", True),
    ("hydra", "hydra", "Prueba de credenciales (ssh/ftp)", True),
    ("ripgrep", "rg", "Búsqueda en el workspace (nexus.workspace.search)", False),
    ("gobuster", "gobuster", "Descubrimiento de contenido web", False),
    ("whatweb", "whatweb", "Fingerprinting web", False),
    ("nikto", "nikto", "Escaneo web con tuning/evasión", False),
    ("sqlmap", "sqlmap", "Verificación de inyección SQL", False),
    ("ffuf", "ffuf", "Fuzzing web", False),
    ("nuclei", "nuclei", "Escaneo por plantillas", False),
    ("httpx", "httpx", "Sondeo HTTP (ProjectDiscovery)", False),
    ("subfinder", "subfinder", "Enumeración de subdominios", False),
    ("searchsploit", "searchsploit", "Exploit-DB offline", False),
    ("msfconsole", "msfconsole", "Metasploit Framework", False),
    ("netexec", "nxc", "Enumeración SMB/LDAP", False),
    ("bloodhound", "bloodhound-python", "Grafo de Active Directory", False),
    ("impacket", "impacket-smbclient", "Auditoría de protocolos", False),
    ("dalfox", "dalfox", "Detección de XSS", False),
    ("minisign", "minisign", "Verificación de firmas (Sliver)", False),
    ("sliver-server", "sliver-server", "C2 Sliver (team server)", False),
)

SLIVER_DEFAULT_CONFIG = "~/.config/omni/sliver/operator.cfg"


@dataclass(frozen=True)
class ComponentStatus:
    component_id: str
    kind: str  # "binary" | "service" | "config"
    purpose: str
    required: bool
    ready: bool
    detail: str
    setup: str = ""
    #: Identity verdict for binary components (``None`` when not probed, the
    #: binary is absent, or the component is not a binary). ``False`` means the
    #: binary exists but is the *wrong* one (e.g. Python ``httpx``).
    identity_ok: bool | None = None

    @property
    def capability_state(self) -> str:
        if not self.ready:
            return "failed" if self.identity_ok is False else "unavailable"
        return "detected" if self.kind == "binary" and self.identity_ok is None else "verified"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.component_id,
            "kind": self.kind,
            "purpose": self.purpose,
            "required": self.required,
            "ready": self.ready,
            "detail": self.detail,
            "setup": self.setup,
            "identity_ok": self.identity_ok,
            "capability_state": self.capability_state,
        }


@dataclass
class EnvironmentReport:
    components: list[ComponentStatus] = field(default_factory=list)

    @property
    def ready(self) -> list[ComponentStatus]:
        return [c for c in self.components if c.ready]

    @property
    def missing(self) -> list[ComponentStatus]:
        return [c for c in self.components if not c.ready]

    @property
    def missing_required(self) -> list[ComponentStatus]:
        return [c for c in self.missing if c.required]

    def to_dict(self) -> dict[str, object]:
        return {
            "components": [c.to_dict() for c in self.components],
            "ready": len(self.ready),
            "missing": len(self.missing),
            "missing_required": [c.component_id for c in self.missing_required],
        }


def _default_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def sliver_operator_plan(
    *, lhost: str, name: str = "omni", save_path: str = SLIVER_DEFAULT_CONFIG
) -> str:
    """Return the command that generates a Sliver operator config."""
    return (
        f"sliver-server operator --name {name} --lhost {lhost} --permissions all --save {save_path}"
    )


def assess_environment(
    *,
    which: Callable[[str], str | None] = shutil.which,
    port_open: Callable[[str, int], bool] | None = None,
    env: dict[str, str] | None = None,
    path_exists: Callable[[str], bool] | None = None,
    lhost: str = "127.0.0.1",
    probe_binary: Callable[[BinaryIdentity], IdentityCheck] | None = None,
) -> EnvironmentReport:
    """Assess the operational environment. Fully injectable for tests.

    ``probe_binary`` is opt-in: when given, the critical binaries (those in
    :data:`nexus_core.provisioner.binaries.BINARY_IDENTITIES`) are checked for
    *identity*, so a same-named wrong binary is reported as not ready instead of
    "present". The default is ``None`` to keep the assessment free of process
    spawns for callers that only need presence.
    """
    env = dict(os.environ if env is None else env)
    port_open = port_open or _default_port_open
    path_probe = path_exists or (lambda p: Path(p).expanduser().exists())

    def safe_path_exists(path: str) -> bool:
        try:
            return path_probe(path)
        except (OSError, ValueError):
            return False

    path_exists = safe_path_exists
    identities = BINARY_IDENTITIES_BY_NAME if probe_binary is not None else {}

    components: list[ComponentStatus] = []
    recipe_names = set(load_recipes())

    # ---- binaries ---------------------------------------------------------
    for component_id, binary, purpose, required in BINARY_COMPONENTS:
        try:
            path = which(binary)
        except Exception:
            path = None
        present = path is not None
        identity: IdentityCheck | None = None
        identity_spec = identities.get(binary)
        if present and identity_spec is not None and probe_binary is not None:
            try:
                identity = probe_binary(identity_spec)
            except Exception:
                identity = IdentityCheck(
                    binary, True, False, path or "", "probe failed", identity_spec.install, required
                )
        if identity is not None and not identity.ok:
            # A wrong binary is worse than a missing one: it silently feeds
            # garbage to the handler. Fail it closed with actionable guidance.
            components.append(
                ComponentStatus(
                    component_id,
                    "binary",
                    purpose,
                    required,
                    False,
                    f"binario equivocado en {identity.binary_path or path}",
                    identity.install,
                    False,
                )
            )
            continue
        if component_id == "sliver-server":
            setup = (
                "Ejecuta `omni --setup --install --yes`: descarga la release "
                "fijada, verifica la firma minisign, instala el binario, levanta "
                "el team server y genera el operator config con "
                f"`{sliver_operator_plan(lhost=lhost)}`."
            )
        elif component_id in recipe_names:
            setup = (
                f"Instala con la tool durable nexus.system.install_tool (receta: {component_id})."
            )
        else:
            setup = f"Instala {binary} con el gestor de paquetes de tu distro."
        components.append(
            ComponentStatus(
                component_id,
                "binary",
                purpose,
                required,
                present,
                path or "no encontrado en PATH",
                "" if present else setup,
                True if (identity is not None and identity.ok) else None,
            )
        )

    # ---- services / configs ----------------------------------------------
    msf_pass = bool(env.get("MSF_RPC_PASSWORD") or env.get("MSFRPC_PASSWORD"))
    try:
        rpc_url = urlsplit(env.get("MSF_RPC_URL", "http://127.0.0.1:55552"))
        msf_up = bool(rpc_url.scheme in {"http", "https"} and rpc_url.hostname) and port_open(
            rpc_url.hostname or "127.0.0.1",
            rpc_url.port or (443 if rpc_url.scheme == "https" else 80),
        )
    except (OSError, ValueError, OverflowError):
        msf_up = False
    components.append(
        ComponentStatus(
            "msfrpcd",
            "service",
            "Daemon RPC de Metasploit",
            False,
            msf_up and msf_pass,
            f"listening={msf_up} credencial={'sí' if msf_pass else 'no'}",
            ""
            if (msf_up and msf_pass)
            else (
                "Configura MSF_RPC_PASSWORD y ejecuta "
                "`sudo bash scripts/install_msfrpcd_service.sh`."
            ),
        )
    )

    sliver_cfg = env.get("SLIVER_OPERATOR_CONFIG", "").strip()
    sliver_cfg_ready = bool(sliver_cfg) and path_exists(sliver_cfg)
    components.append(
        ComponentStatus(
            "sliver_operator_config",
            "config",
            "Config de operador Sliver (gRPC/mTLS)",
            False,
            sliver_cfg_ready,
            sliver_cfg or "SLIVER_OPERATOR_CONFIG sin definir",
            ""
            if sliver_cfg_ready
            else (
                f"Genera el config y exporta SLIVER_OPERATOR_CONFIG: "
                f"`{sliver_operator_plan(lhost=lhost)}`."
            ),
        )
    )

    from nexus_core.tools.handlers.nuclei import nuclei_templates_dir

    nuclei_templates = str(nuclei_templates_dir()).strip()
    nuclei_ready = bool(nuclei_templates) and path_exists(nuclei_templates)
    components.append(
        ComponentStatus(
            "nuclei_templates",
            "config",
            "Plantillas de nuclei",
            False,
            nuclei_ready,
            nuclei_templates or "NEXUS_NUCLEI_TEMPLATES sin definir",
            ""
            if nuclei_ready
            else (
                "Instala las plantillas (`nuclei -update-templates`) o configura "
                "NEXUS_NUCLEI_TEMPLATES al directorio."
            ),
        )
    )

    wordlists = next(
        (
            p
            for p in (
                *env.get("NEXUS_WORDLIST_DIRS", "").split(os.pathsep),
                env.get("NEXUS_WORDLISTS", ""),
                "/usr/share/wordlists",
            )
            if p and path_exists(p)
        ),
        None,
    )
    components.append(
        ComponentStatus(
            "wordlists",
            "config",
            "Diccionarios (gobuster/ftp/credenciales)",
            False,
            wordlists is not None,
            wordlists or "sin diccionarios detectados",
            ""
            if wordlists
            else (
                "Instala wordlists (p. ej. SecLists: `sudo apt install seclists`) "
                "o define NEXUS_WORDLISTS."
            ),
        )
    )

    components.append(
        ComponentStatus(
            "scope_signing_secret",
            "config",
            "Secreto de firma del alcance",
            True,
            bool(env.get("NEXUS_SCOPE_SIGNING_SECRET")),
            "definido" if env.get("NEXUS_SCOPE_SIGNING_SECRET") else "sin definir",
            ""
            if env.get("NEXUS_SCOPE_SIGNING_SECRET")
            else (
                "Crea un engagement con el wizard (define el secreto) o exporta "
                "NEXUS_SCOPE_SIGNING_SECRET."
            ),
        )
    )

    return EnvironmentReport(components)


def render_report(report: EnvironmentReport) -> str:
    """Human-readable readiness report (no ANSI)."""
    lines = ["Entorno operativo de OmniAgentCS", ""]
    for group, title in (
        (report.ready, "Listo"),
        ([c for c in report.missing if not c.required], "Opcional / no disponible"),
        (report.missing_required, "REQUERIDO y ausente"),
    ):
        if not group:
            continue
        lines.append(f"== {title} ({len(group)}) ==")
        for component in group:
            mark = "✓" if component.ready else "✗"
            lines.append(
                f"  {mark} [{component.kind}] {component.component_id}: "
                f"{component.purpose} — {component.detail}"
            )
            if component.setup:
                lines.append(f"      → {component.setup}")
        lines.append("")
    if not report.missing_required:
        lines.append(
            "Requeridos: OK en esta evaluación; detección no acredita ejecución en sandbox."
        )
    else:
        lines.append(
            "Faltan componentes requeridos: "
            + ", ".join(c.component_id for c in report.missing_required)
        )
    return "\n".join(lines)
