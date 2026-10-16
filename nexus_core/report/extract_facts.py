"""Map validated blackboard facts to report findings and inventory."""

from __future__ import annotations

import json
from typing import Any, Iterable

from nexus_core.kernel.blackboard import is_verified_fact

from .models import (
    Evidence,
    Finding,
    ReportItem,
)

from .extraction_support import (
    _excerpt,
    _as_dict,
    _FACT_SEVERITY,
    _FACT_META,
    FACT_RECORD_TOOL,
    matches_scope,
)

#: Fields of a ``loot`` value that recover the target it was taken from. The
#: *key* of a loot fact is the artifact itself (``flag{fake_flag}``, a loot id), never a
#: host, so it is deliberately not consulted here.
_LOOT_TARGET_FIELDS: tuple[str, ...] = ("target", "host", "ip", "url", "targets", "hosts")

#: Value fields that make a captured artifact a *credential exposure* rather than
#: a captured file: a vault handle, a plaintext, a hash or recovered key
#: material. It raises the loot finding to ``critical``.
_LOOT_SECRET_FIELDS: tuple[str, ...] = (
    "secret_ref",
    "password",
    "hash",
    "ntlm",
    "material_sha256",
)


def _fact_finding_id(fact_type: str, key: str) -> str:
    import hashlib

    seed = f"fact|{fact_type}|{key}"
    return "finding_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def _fact_targets(fact: dict[str, Any]) -> tuple[str, ...]:
    """Recover the target(s) a fact points at, from its key and value."""
    targets: list[str] = []
    key = str(fact.get("key") or "")
    if key:
        targets.append(key.split()[0])
    value = _as_dict(fact.get("value"))
    for field_name in ("target", "host", "hosts", "ip", "url", "dc", "targets"):
        candidate = value.get(field_name)
        if isinstance(candidate, str) and candidate.strip():
            targets.append(candidate.strip())
        elif isinstance(candidate, (list, tuple)):
            targets.extend(str(item) for item in candidate if str(item or "").strip())
    seen: list[str] = []
    for item in targets:
        if item and item not in seen:
            seen.append(item)
    return tuple(seen[:50])


def _loot_targets(value: dict[str, Any]) -> tuple[str, ...]:
    """Targets a ``loot`` fact can be attributed to (empty when it names none)."""
    targets: list[str] = []
    for field_name in _LOOT_TARGET_FIELDS:
        candidate = value.get(field_name)
        if isinstance(candidate, str) and candidate.strip():
            targets.append(candidate.strip())
        elif isinstance(candidate, (list, tuple)):
            targets.extend(str(item) for item in candidate if str(item or "").strip())
    seen: list[str] = []
    for item in targets:
        if item and item not in seen:
            seen.append(item)
    return tuple(seen[:50])


def _loot_finding(
    fact: dict[str, Any],
    *,
    key: str,
    value: dict[str, Any],
    scope: Any = None,
) -> Finding | None:
    """Turn one *verified* captured artifact into a confirmed finding (V1-37).

    Measured in rerun 10 (``run_179cef8b7b424b339caba3d2093eed9d``): ``root.txt``
    was captured and promoted as a verified ``loot`` fact, and the deliverable of
    the engagement reported ``findings: 0`` because nothing mapped that fact to a
    finding the way H3 maps the rest of the chain.

    Two limits keep it honest:

    * only a **verified** fact becomes a finding: an agent-recorded ``loot`` is a
      hypothesis and the blackboard already carries it as such in the inventory;
    * a loot attributed to a target outside the signed scope is not a finding of
      this engagement (the fact still exists; it just is not reported as impact).
      A loot that names no target at all is attributed to the engagement: the
      blackboard is engagement-scoped and every fact came from a scoped call.
    """
    if not is_verified_fact(fact):
        return None
    targets = _loot_targets(value)
    if scope is not None and targets and not any(matches_scope(item, scope) for item in targets):
        return None
    severity = (
        "critical"
        if any(value.get(field_name) for field_name in _LOOT_SECRET_FIELDS)
        else _FACT_SEVERITY.get("loot", "high")
    )
    # The deterministic CVSS of the level: the same one ``build_report`` resolves
    # for every other finding, made explicit here because a captured artifact
    # always has a level by construction (the ticket asks for the heuristic when
    # it applies, and this is exactly the case).
    from .cvss import heuristic_cvss

    score, vector = heuristic_cvss(severity)
    created_at = str(fact.get("recorded_at") or "")
    source = str(fact.get("source") or FACT_RECORD_TOOL)
    command = str(value.get("command") or "")
    return Finding(
        finding_id=_fact_finding_id("loot", key),
        title=f"Loot capturado: {key}" if key else "Loot capturado",
        description=(
            f"Artefacto con valor probatorio capturado en el engagement: `{key}`. "
            "Hecho `loot` verificado por el motor"
            + (f" tras ejecutar `{command[:300]}`" if command else "")
            + f". Valor observado: {json.dumps(value, ensure_ascii=False, sort_keys=True)}"
        ),
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cwe="CWE-522",
        cve=None,
        mitre_techniques=("T1005",),
        owasp_category="A01:2021-Broken Access Control",
        affected_targets=targets,
        evidence=(
            Evidence(
                kind="fact",
                ref_id=f"loot/{key}",
                sha256=_loot_sha256(value),
                excerpt=_excerpt(value),
                created_at=created_at,
            ),
        ),
        discovered_by_tool=source,
        discovered_at=created_at,
        reproduction_steps=(
            f"Recuperar el hecho con `nexus.knowledge.query_facts` (fact_type=loot, key={key})",
            "Repetir el canal verificado que lo capturó y comparar el valor",
        ),
        kind="fact_loot",
        verification_status="confirmed_finding",
    )


def _loot_sha256(value: dict[str, Any]) -> str | None:
    """Digest of the artifact, when the fact recorded one."""
    digest = str(value.get("sha256") or "").strip()
    return digest or None


def _fact_findings(
    facts: Iterable[dict[str, Any]], *, scope: Any = None
) -> list[Finding]:
    """Turn every recorded blackboard fact into one finding (H3).

    ``scope`` (optional) is the signed engagement scope: when given, a fact that
    names targets entirely outside it is not reported as impact.
    """
    results: list[Finding] = []
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        fact_type = str(fact.get("fact_type") or "hint")
        key = str(fact.get("key") or "")
        value = _as_dict(fact.get("value"))
        if fact_type == "loot":
            loot = _loot_finding(fact, key=key, value=value, scope=scope)
            if loot is not None:
                results.append(loot)
            continue
        severity = _FACT_SEVERITY.get(fact_type, "info")
        kind, cwe, owasp, techniques = _FACT_META.get(
            fact_type, (f"fact_{fact_type}", None, None, ())
        )
        created_at = str(fact.get("recorded_at") or "")
        source = str(fact.get("source") or FACT_RECORD_TOOL)
        evidence = (
            Evidence(
                kind="fact",
                ref_id=f"{fact_type}/{key}",
                sha256=None,
                excerpt=_excerpt(value),
                created_at=created_at,
            ),
        )
        results.append(
            Finding(
                finding_id=_fact_finding_id(fact_type, key),
                title=f"{key}" if key else f"Hecho registrado ({fact_type})",
                description=(
                    f"Hecho tipado `{fact_type}` registrado en el blackboard del "
                    f"engagement: `{key}`. Valor observado: "
                    f"{json.dumps(value, ensure_ascii=False, sort_keys=True)}"
                    + (" (verificado)" if is_verified_fact(fact) else " (sin verificar)")
                    + ". Procedencia: "
                    + str(fact.get("asserted_by", "agent"))
                ),
                severity=severity,
                cvss_score=None,
                cvss_vector=None,
                cwe=cwe,
                cve=None,
                mitre_techniques=techniques,
                owasp_category=owasp,
                affected_targets=_fact_targets(fact),
                evidence=evidence,
                discovered_by_tool=source,
                discovered_at=created_at,
                reproduction_steps=(
                    f"Consultar el hecho con `nexus.knowledge.query_facts` "
                    f"(fact_type={fact_type}, key={key})",
                    "Verificar el valor en la evidencia del blackboard",
                ),
                kind=kind,
                verification_status="confirmed_finding" if is_verified_fact(fact) else "hypothesis",
            )
        )
    return results


def _fact_inventory(facts: Iterable[dict[str, Any]]) -> list[ReportItem]:
    """One inventory item summarising every fact of the engagement (H3)."""
    facts = [fact for fact in facts if isinstance(fact, dict)]
    if not facts:
        return []
    counts: dict[str, int] = {}
    entries: list[dict[str, Any]] = []
    targets: list[str] = []
    latest = ""
    for fact in facts:
        fact_type = str(fact.get("fact_type") or "hint")
        counts[fact_type] = counts.get(fact_type, 0) + 1
        created_at = str(fact.get("recorded_at") or "")
        latest = max(latest, created_at)
        for target in _fact_targets(fact):
            if target not in targets:
                targets.append(target)
        entries.append(
            {
                "fact_type": fact_type,
                "key": str(fact.get("key") or ""),
                "value": fact.get("value") or {},
                "source": str(fact.get("source") or FACT_RECORD_TOOL),
                "verified": bool(fact.get("verified")),
                "recorded_at": created_at,
            }
        )
    return [
        ReportItem(
            kind="inventory",
            title=f"Inventario del engagement ({len(facts)} hecho(s))",
            detail={"total": len(facts), "counts": counts, "facts": entries},
            discovered_by_tool=FACT_RECORD_TOOL,
            discovered_at=latest,
            affected_targets=tuple(targets[:50]),
            mitre_techniques=(),
            evidence=(),
        )
    ]
