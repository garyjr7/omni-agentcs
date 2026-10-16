"""Pure access, session and identity capability extractors."""

from __future__ import annotations


from . import mitre, severity
from .models import (
    FailedAttempt,
    Finding,
    ReportItem,
)

from .extraction_support import (
    Observation,
    _Context,
    _evidence_for,
    _finding_id,
    _as_dict,
    _report_item,
    _dict_list,
)


def _exploit_findings(
    observation: Observation, context: _Context
) -> tuple[list[Finding], list[FailedAttempt]]:
    output = observation.output or {}
    status = str(output.get("status") or "")
    module = str(output.get("module") or "")
    target = str(output.get("target") or "")
    session = _as_dict(output.get("session"))
    if status == "session_opened":
        uuid = str((session or {}).get("uuid") or "")
        username = str((session or {}).get("username") or "")
        kind_session = str((session or {}).get("type") or "")
        finding = Finding(
            finding_id=_finding_id("session_opened", observation),
            title=f"Acceso obtenido vía {module or 'un exploit'}",
            description=(
                f"El módulo `{module}` abrió una sesión {kind_session or 'remota'} "
                f"({uuid or 'uuid n/d'}) sobre {target}"
                + (f" como `{username}`" if username else "")
                + ". El acceso está confirmado por el post-condition del handler, "
                "no por una afirmación del modelo."
            ),
            severity="critical",
            cvss_score=None,
            cvss_vector=None,
            cwe=None,
            cve=None,
            mitre_techniques=(),
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            affected_targets=tuple(filter(None, (target,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"Ejecutar `nexus.exploit.msf_exploit` con module=`{module}` y target=`{target}`",
                f"Comprobar la sesión con `nexus.session.list` (uuid {uuid or 'n/d'})",
            ),
            kind="session_opened",
        )
        return [finding], []
    if status in {"timeout", "failed", "no_session"}:
        reason = {
            "timeout": "el exploit terminó sin abrir sesión (dentro del tiempo concedido)",
            "failed": "el módulo no pudo ejecutarse contra el objetivo",
            "no_session": "el módulo completó y no abrió sesión",
        }[status]
        return [], [
            FailedAttempt(
                tool_id=observation.tool_id,
                target=target,
                reason=reason,
                attempted_at=observation.created_at,
                evidence=_evidence_for(observation, context, excerpt=output),
            )
        ]
    return [], []


def _session_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    command = str(output.get("command") or observation.arguments.get("command") or "")
    session_uuid = str(
        output.get("session_uuid") or observation.arguments.get("session_uuid") or ""
    )
    status = str(output.get("status") or "")
    if not command or status not in {"ok", "timeout"}:
        return []
    text = str(output.get("output") or "")
    level = severity.severity_for_command(command, status)
    return [
        Finding(
            finding_id=_finding_id("session_command", observation, command),
            title=f"Comando ejecutado en sesión: {command.strip()}",
            description=(
                f"Se ejecutó `{command.strip()}` en la sesión {session_uuid or 'n/d'} "
                f"(estado `{status}`) y devolvió {len(text)} bytes. "
                f"Salida: {text.strip()[:800] or '(vacía)'}"
            ),
            severity=level,
            cvss_score=None,
            cvss_vector=None,
            cwe=None,
            cve=None,
            mitre_techniques=mitre.techniques_for_command(command),
            owasp_category=None,
            affected_targets=tuple(filter(None, (session_uuid,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"Adjuntar la sesión {session_uuid or 'n/d'} (`/session attach {session_uuid}`)",
                f"Enviar `{command.strip()}` con `nexus.session.interact`",
            ),
            kind="session_command",
        )
    ]


def _searchsploit_reference(observation: Observation, context: _Context) -> list[ReportItem]:
    output = observation.output or {}
    exploits = _dict_list(output.get("exploits"))
    shellcodes = _dict_list(output.get("shellcodes"))
    if not exploits and not shellcodes:
        return []
    query = str(output.get("query") or "")
    entries = exploits + shellcodes
    return [
        _report_item(
            kind="reference",
            title=f"Exploits disponibles para «{query}» ({len(entries)})",
            detail={
                "query": query,
                "total": output.get("total"),
                "exploits": exploits,
                "shellcodes": shellcodes,
            },
            observation=observation,
            context=context,
            targets=(str(item.get("edb_id") or "") for item in entries),
        )
    ]


def _netexec_surface(observation: Observation, context: _Context) -> list[ReportItem]:
    output = observation.output or {}
    entries = _dict_list(output.get("entries"))
    if not entries:
        return []
    protocol = str(output.get("protocol") or "")
    targets = [str(item) for item in (output.get("targets") or []) if item]
    if not targets and output.get("target"):
        targets = [str(output["target"])]
    return [
        _report_item(
            kind="surface",
            title=f"Superficie {protocol or 'red'} observada ({len(entries)} línea(s))",
            detail={
                "protocol": protocol,
                "targets": targets,
                "entries": entries,
            },
            observation=observation,
            context=context,
            targets=targets,
        )
    ]


def _bloodhound_evidence(observation: Observation, context: _Context) -> list[ReportItem]:
    output = observation.output or {}
    files = _dict_list(output.get("files"))
    total_records = int(output.get("total_records") or 0)
    if not files and not total_records:
        return []
    dc = str(output.get("dc") or "")
    return [
        _report_item(
            kind="evidence",
            title=(
                f"Mapa de Active Directory recolectado "
                f"({len(files)} fichero(s), {total_records} registro(s))"
            ),
            detail={
                "domain": str(output.get("domain") or ""),
                "dc": dc,
                "total_records": total_records,
                "files": files,
            },
            observation=observation,
            context=context,
            targets=tuple(filter(None, (dc,))),
        )
    ]


def _secretsdump_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    entries = _dict_list(output.get("entries"))
    secrets = _dict_list(output.get("secrets"))
    if not entries and not secrets:
        return []
    target = str(output.get("target") or "")
    usernames = [str(item.get("username") or "") for item in entries]
    return [
        Finding(
            finding_id=_finding_id("credentials", observation),
            title=f"Credenciales volcadas ({len(entries)} cuenta(s))",
            description=(
                f"secretsdump extrajo material de autenticación de {target or 'el objetivo'}: "
                f"{len(entries)} cuenta(s) con hashes NTLM"
                + (f" ({', '.join(usernames[:20])})" if usernames else "")
                + (f" y {len(secrets)} secreto(s) LSA" if secrets else "")
                + f". Fuentes: {', '.join(str(source) for source in output.get('sources') or []) or 'n/d'}."
            ),
            severity="critical",
            cvss_score=None,
            cvss_vector=None,
            cwe="CWE-522",
            cve=None,
            mitre_techniques=("T1003.003",),
            owasp_category="A02:2021-Cryptographic Failures",
            affected_targets=tuple(filter(None, (target,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"secretsdump -target {target} (método {output.get('method') or 'n/d'})",
                "Confirmar el acceso con las credenciales obtenidas sin reutilizarlas fuera del alcance",
            ),
            kind="credentials",
        )
    ]


def _getuserspns_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    principals = _dict_list(output.get("service_principals"))
    hashes = _dict_list(output.get("hashes"))
    if not principals and not hashes:
        return []
    dc_ip = str(output.get("dc_ip") or "")
    names = [
        str(item.get("name") or item.get("service_principal_name") or "") for item in principals
    ]
    return [
        Finding(
            finding_id=_finding_id("kerberoast", observation),
            title=f"Cuentas kerberoastables ({len(principals)})",
            description=(
                f"GetUserSPNs enumeró {len(principals)} cuenta(s) de servicio con SPN en "
                f"{output.get('domain') or 'el dominio'}"
                + (f" ({', '.join(names[:20])})" if names else "")
                + (f" y solicitó {len(hashes)} ticket(s) TGS (hash Kerberoast)" if hashes else "")
                + ". Un atacante puede crackearlos offline para escalar privilegios."
            ),
            severity="high",
            cvss_score=None,
            cvss_vector=None,
            cwe="CWE-522",
            cve=None,
            mitre_techniques=("T1558.003",),
            owasp_category="A02:2021-Cryptographic Failures",
            affected_targets=tuple(filter(None, (dc_ip,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"GetUserSPNs -dc-ip {dc_ip} -request".strip(),
                "Crackear los hashes TGS offline y validar las cuentas afectadas",
            ),
            kind="kerberoast",
        )
    ]


def _psexec_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    if not output.get("connected"):
        return []
    target = str(output.get("target") or "")
    command = str(output.get("command") or "")
    lines = [str(line) for line in (output.get("lines") or [])]
    return [
        Finding(
            finding_id=_finding_id("remote_exec", observation),
            title="Ejecución remota confirmada con psexec",
            description=(
                f"psexec ejecutó `{command or 'el comando'}` en {target or 'el objetivo'} "
                f"y devolvió {len(lines)} línea(s) de salida. La conexión remota está "
                "confirmada por la post-condition del handler."
            ),
            severity="critical",
            cvss_score=None,
            cvss_vector=None,
            cwe="CWE-284",
            cve=None,
            mitre_techniques=("T1021.002",),
            owasp_category=None,
            affected_targets=tuple(filter(None, (target,))),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"psexec -target {target} `{command}`".strip(),
                "Revisar la salida del comando remoto en la evidencia",
            ),
            kind="remote_exec",
        )
    ]
