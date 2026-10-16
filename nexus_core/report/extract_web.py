"""Pure web finding extractors; no storage access."""

from __future__ import annotations


from . import severity
from .models import (
    Finding,
)

from .extraction_support import (
    Observation,
    _Context,
    _evidence_for,
    _finding_id,
    _as_list,
    _dict_list,
)


def _nuclei_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    findings = _as_list(output.get("findings"))
    results: list[Finding] = []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            continue
        template_id = str(item.get("template_id") or "")
        name = str(item.get("name") or template_id or "hallazgo de nuclei")
        target = str(item.get("matched_at") or item.get("host") or "")
        tags = [str(tag) for tag in (item.get("tags") or ())]
        cve = next((tag.upper() for tag in tags if tag.lower().startswith("cve-")), None)
        cwe = next(
            (tag.upper().replace("CWE-", "CWE-") for tag in tags if tag.lower().startswith("cwe-")),
            None,
        )
        results.append(
            Finding(
                finding_id=_finding_id("nuclei", observation, f"{index}:{template_id}"),
                # Severity is rendered from ``Finding.severity`` by every
                # renderer; promoting it into the title would duplicate it
                # ("### [HIGH] [HIGH] ...").
                title=name,
                description=(
                    f"Template `{template_id}` matcheó en {target or 'el objetivo'}. "
                    f"Tipo: {item.get('type') or 'n/d'}"
                    + (f". Matcher: {item.get('matcher_name')}" if item.get("matcher_name") else "")
                    + (
                        ". Extraído: " + ", ".join(str(x) for x in item.get("extracted") or ())
                        if item.get("extracted")
                        else ""
                    )
                ),
                severity=severity.severity_from_nuclei(item.get("severity")),
                cvss_score=None,
                cvss_vector=None,
                cwe=cwe,
                cve=cve,
                mitre_techniques=(),
                owasp_category=None,
                affected_targets=tuple(filter(None, (target,))),
                evidence=_evidence_for(observation, context, excerpt=item),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"nuclei -t {template_id} -u {target}".strip(),
                    f"Revisar la línea JSON del template {template_id} en la evidencia",
                ),
                kind="nuclei",
            )
        )
    return results


def _ffuf_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    matches = _as_list(output.get("matches"))
    base_url = str(output.get("url") or "")
    exposed: list[str] = []
    protected: list[str] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        url = str(match.get("url") or base_url)
        status = match.get("status")
        if severity.severity_for_ffuf(status) == "low":
            protected.append(f"{url} [{status}]")
        else:
            exposed.append(f"{url} [{status}]")
    results: list[Finding] = []
    if exposed:
        results.append(
            Finding(
                finding_id=_finding_id("http_surface", observation),
                title=f"Endpoints descubiertos ({len(exposed)})",
                description=(
                    f"El fuzzing de {base_url or 'la URL'} encontró {len(exposed)} "
                    "recurso(s) accesible(s) (200/30x). Es superficie publicada."
                ),
                severity="info",
                cvss_score=None,
                cvss_vector=None,
                cwe=None,
                cve=None,
                mitre_techniques=(),
                owasp_category=None,
                affected_targets=tuple(exposed[:50]),
                evidence=_evidence_for(observation, context, excerpt=output),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"ffuf -u {base_url}/FUZZ -w <wordlist>",
                    "Revisar cada endpoint y su contenido en la evidencia",
                ),
                kind="http_surface",
            )
        )
    if protected:
        results.append(
            Finding(
                finding_id=_finding_id("endpoint_protected", observation),
                title=f"Endpoints protegidos descubiertos ({len(protected)})",
                description=(
                    f"El fuzzing de {base_url or 'la URL'} reveló {len(protected)} "
                    "recurso(s) que responden 401/403: la enumeración ya confirmó su "
                    "existencia aunque exija credenciales."
                ),
                severity="low",
                cvss_score=None,
                cvss_vector=None,
                cwe="CWE-200",
                cve=None,
                mitre_techniques=(),
                owasp_category="A01:2021-Broken Access Control",
                affected_targets=tuple(protected[:50]),
                evidence=_evidence_for(observation, context, excerpt=output),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"ffuf -u {base_url}/FUZZ -w <wordlist>",
                    "Confirmar que el recurso exige autenticación sin revelar contenido",
                ),
                kind="endpoint_protected",
            )
        )
    return results


def _sqlmap_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    url = str(output.get("url") or "")
    results: list[Finding] = []
    for index, item in enumerate(_dict_list(output.get("findings"))):
        parameter = str(item.get("parameter") or "?")
        injection = str(item.get("injection_type") or "SQL injection")
        dbms = item.get("dbms")
        title = str(item.get("title") or f"SQL injection en parámetro `{parameter}`")
        results.append(
            Finding(
                finding_id=_finding_id("sqli", observation, f"{index}:{parameter}"),
                title=title,
                description=(
                    f"sqlmap confirmó una inyección SQL ({injection}) en el parámetro "
                    f"`{parameter}` ({str(item.get('method') or 'GET')}) de {url or 'el objetivo'}"
                    + (f", DBMS `{dbms}`" if dbms else "")
                    + f". Payload observado: `{str(item.get('payload') or '')[:300]}`"
                ),
                severity=severity.normalize_severity(item.get("severity"), default="high"),
                cvss_score=None,
                cvss_vector=None,
                cwe="CWE-89",
                cve=None,
                mitre_techniques=(),
                owasp_category="A03:2021-Injection",
                affected_targets=tuple(filter(None, (url,))),
                evidence=_evidence_for(observation, context, excerpt=item),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"sqlmap -u {url} --batch --flush-session".strip(),
                    f"Confirmar la inyección en el parámetro `{parameter}`",
                ),
                kind="sqli",
            )
        )
    return results


def _dalfox_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    target = str(output.get("target") or "")
    results: list[Finding] = []
    for index, item in enumerate(_dict_list(output.get("findings"))):
        url = str(item.get("url") or target)
        param = str(item.get("param") or "?")
        results.append(
            Finding(
                finding_id=_finding_id("xss", observation, f"{index}:{param}"),
                title=str(item.get("message") or f"XSS reflectido en parámetro `{param}`"),
                description=(
                    f"dalfox confirmó un XSS ({str(item.get('inject_type') or 'reflected')}) "
                    f"en el parámetro `{param}` de {url or 'el objetivo'}. Payload: "
                    f"`{str(item.get('payload') or '')[:300]}`. Evidencia: "
                    f"`{str(item.get('evidence') or '')[:300]}`"
                ),
                severity=severity.normalize_severity(item.get("severity"), default="medium"),
                cvss_score=None,
                cvss_vector=None,
                cwe=str(item.get("cwe") or "CWE-79"),
                cve=None,
                mitre_techniques=(),
                owasp_category="A03:2021-Injection",
                affected_targets=tuple(filter(None, (url,))),
                evidence=_evidence_for(observation, context, excerpt=item),
                discovered_by_tool=observation.tool_id,
                discovered_at=observation.created_at,
                reproduction_steps=(
                    f"dalfox url {url}".strip(),
                    f"Revisar el parámetro `{param}` y su vector de inyección",
                ),
                kind="xss",
            )
        )
    return results
