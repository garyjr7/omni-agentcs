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

from .recipes import load_recipes

#: Binary components: (component_id, binary, purpose, required).
BINARY_COMPONENTS: tuple[tuple[str, str, str, bool], ...] = (
    ("nmap", "nmap", "Descubrimiento de puertos y servicios", True),
    ("hydra", "hydra", "Prueba de credenciales (ssh/ftp)", True),
    ("gobuster", "gobuster", "Descubrimiento de contenido web", False),
    ("whatweb", "whatweb", "Fingerprinting web", False),
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

    def to_dict(self) -> dict:
        return {
            "id": self.component_id,
            "kind": self.kind,
            "purpose": self.purpose,
            "required": self.required,
            "ready": self.ready,
            "detail": self.detail,
            "setup": self.setup,
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

    def to_dict(self) -> dict:
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
        f"sliver-server operator --name {name} --lhost {lhost} "
        f"--permissions all --save {save_path}"
    )


def assess_environment(
    *,
    which: Callable[[str], str | None] = shutil.which,
    port_open: Callable[[str, int], bool] | None = None,
    env: dict | None = None,
    path_exists: Callable[[str], bool] | None = None,
    lhost: str = "127.0.0.1",
) -> EnvironmentReport:
    """Assess the operational environment. Fully injectable for tests."""
    env = dict(os.environ if env is None else env)
    port_open = port_open or _default_port_open
    path_exists = path_exists or (lambda p: Path(p).expanduser().exists())

    components: list[ComponentStatus] = []
    recipe_names = set(load_recipes())

    # ---- binaries ---------------------------------------------------------
    for component_id, binary, purpose, required in BINARY_COMPONENTS:
        present = which(binary) is not None
        if component_id == "sliver-server":
            setup = (
                "Ejecuta `omni --setup --install --yes`: descarga la release "
                "fijada, verifica la firma minisign, instala el binario, levanta "
                "el team server y genera el operator config con "
                f"`{sliver_operator_plan(lhost=lhost)}`."
            )
        elif component_id in recipe_names:
            setup = (
                "Instala con la tool durable nexus.system.install_tool "
                f"(receta: {component_id})."
            )
        else:
            setup = f"Instala {binary} con el gestor de paquetes de tu distro."
        components.append(
            ComponentStatus(
                component_id, "binary", purpose, required, present,
                which(binary) or "no encontrado en PATH", "" if present else setup,
            )
        )

    # ---- services / configs ----------------------------------------------
    msf_pass = bool(env.get("MSF_RPC_PASSWORD") or env.get("MSFRPC_PASSWORD"))
    msf_up = port_open("127.0.0.1", 55552)
    components.append(
        ComponentStatus(
            "msfrpcd", "service", "Daemon RPC de Metasploit", False, msf_up and msf_pass,
            f"listening={msf_up} credencial={'sí' if msf_pass else 'no'}",
            "" if (msf_up and msf_pass) else (
                "Configura MSF_RPC_PASSWORD y ejecuta "
                "`sudo bash scripts/install_msfrpcd_service.sh`."
            ),
        )
    )

    sliver_cfg = env.get("SLIVER_OPERATOR_CONFIG", "").strip()
    sliver_cfg_ready = bool(sliver_cfg) and path_exists(sliver_cfg)
    components.append(
        ComponentStatus(
            "sliver_operator_config", "config", "Config de operador Sliver (gRPC/mTLS)",
            False, sliver_cfg_ready,
            sliver_cfg or "SLIVER_OPERATOR_CONFIG sin definir",
            "" if sliver_cfg_ready else (
                f"Genera el config y exporta SLIVER_OPERATOR_CONFIG: "
                f"`{sliver_operator_plan(lhost=lhost)}`."
            ),
        )
    )

    nuclei_templates = env.get("NEXUS_NUCLEI_TEMPLATES", "").strip()
    nuclei_ready = bool(nuclei_templates) and path_exists(nuclei_templates)
    components.append(
        ComponentStatus(
            "nuclei_templates", "config", "Plantillas de nuclei", False, nuclei_ready,
            nuclei_templates or "NEXUS_NUCLEI_TEMPLATES sin definir",
            "" if nuclei_ready else (
                "Instala las plantillas (`nuclei -update-templates`) y exporta "
                "NEXUS_NUCLEI_TEMPLATES al directorio."
            ),
        )
    )

    wordlists = next(
        (p for p in (
            env.get("NEXUS_WORDLISTS", ""),
            "/usr/share/wordlists",
        ) if p and path_exists(p)),
        None,
    )
    components.append(
        ComponentStatus(
            "wordlists", "config", "Diccionarios (gobuster/ftp/credenciales)", False,
            wordlists is not None, wordlists or "sin diccionarios detectados",
            "" if wordlists else (
                "Instala wordlists (p. ej. SecLists: `sudo apt install seclists`) "
                "o define NEXUS_WORDLISTS."
            ),
        )
    )

    components.append(
        ComponentStatus(
            "scope_signing_secret", "config", "Secreto de firma del alcance",
            True, bool(env.get("NEXUS_SCOPE_SIGNING_SECRET")),
            "definido" if env.get("NEXUS_SCOPE_SIGNING_SECRET") else "sin definir",
            "" if env.get("NEXUS_SCOPE_SIGNING_SECRET") else (
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
        lines.append("Requeridos: OK. Puedes operar.")
    else:
        lines.append(
            "Faltan componentes requeridos: "
            + ", ".join(c.component_id for c in report.missing_required)
        )
    return "\n".join(lines)
