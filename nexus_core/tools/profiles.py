"""Perfiles de tools: el agente ve un puñado, no las 80 herramientas.

El catálogo durable es la superficie completa del kernel y debe seguir siéndolo
(el gateway, la auditoría y el inventario lo usan). Lo que *ve el modelo* es
otra cosa: un perfil. Por defecto solo viajan al prompt las cinco tools con las
que se trabaja de verdad —

* ``nexus.shell.exec`` (ejecución),
* ``nexus.system.execute_and_parse`` (ejecución + dato estructurado),
* ``nexus.workspace.read`` (leer lo ya capturado),
* ``nexus.skill.load`` (cargar una receta),
* ``nexus.orchestrator.create_plan`` (el contrato del engagement),

más el comando de descubrimiento (``nexus.system.discover_tools``). El resto se
activa **por run** cuando el agente carga una skill (los tools que la receta
declara, o el grupo que su nombre implica) o cuando descubre un grupo. Nada de
esto cambia la autoridad: el scope, el RoE, el riesgo y las aprobaciones siguen
gobernando cada llamada, y el catálogo durable no pierde ninguna tool.

``NEXUS_TOOL_PROFILE=open`` desactiva el ocultamiento (depuración, y lo que
esperan los tests que ejercitan el catálogo entero).
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterable, Mapping

DEFAULT_PROFILE = "default"
OPEN_PROFILE = "open"
PROFILE_ENV = "NEXUS_TOOL_PROFILE"

#: Las tools visibles sin descubrir nada. Es la lista del contrato del run.
DEFAULT_TOOL_IDS: tuple[str, ...] = (
    "nexus.shell.exec",
    "nexus.system.execute_and_parse",
    "nexus.workspace.read",
    "nexus.skill.load",
    "nexus.orchestrator.create_plan",
)

#: La tool que revela el resto (y que por eso no puede estar oculta).
DISCOVERY_TOOL_ID = "nexus.system.discover_tools"

#: Tools por run que un descubrimiento o una skill activaron.
_ACTIVE: dict[str, set[str]] = {}


def resolve_profile(profile: str | None = None) -> str:
    """``profile`` explícito, o ``NEXUS_TOOL_PROFILE``, o el perfil por defecto."""
    chosen = str(profile or os.getenv(PROFILE_ENV, "") or DEFAULT_PROFILE).strip().lower()
    return chosen or DEFAULT_PROFILE


def hiding_enabled(profile: str | None = None) -> bool:
    """``False`` for ``open``: the whole catalog goes to the model."""
    return resolve_profile(profile) != OPEN_PROFILE


def active_tool_ids(run_id: str) -> set[str]:
    """Tools this run activated through discovery or a skill."""
    if not str(run_id or "").strip():
        return set()
    return set(_ACTIVE.get(str(run_id), set()))


def activate_tools(run_id: str, tool_ids: Iterable[str]) -> list[str]:
    """Activate *tool_ids* for *run_id*; return the ones that were new."""
    key = str(run_id or "").strip()
    if not key:
        return []
    wanted = {str(tool_id) for tool_id in tool_ids if str(tool_id or "").strip()}
    before = _ACTIVE.setdefault(key, set())
    added = sorted(wanted - before)
    before.update(wanted)
    return added


def reset_tools(run_id: str | None = None) -> None:
    """Forget activations (one run, or every run when *run_id* is ``None``)."""
    if run_id is None:
        _ACTIVE.clear()
        return
    _ACTIVE.pop(str(run_id), None)


def group_of(tool_id: str) -> str:
    """``nexus.recon.nmap`` → ``recon`` (the family the catalog groups by)."""
    parts = str(tool_id or "").split(".")
    return parts[1] if len(parts) > 2 else "other"


def catalog_groups(catalog: Mapping[str, Any]) -> dict[str, list[str]]:
    """``{group: [tool_id, ...]}`` for a durable catalog, sorted."""
    groups: dict[str, list[str]] = {}
    for tool_id in sorted(catalog):
        groups.setdefault(group_of(tool_id), []).append(str(tool_id))
    return groups


def visible_tool_ids(
    catalog: Mapping[str, Any], *, run_id: str = "", profile: str | None = None
) -> set[str]:
    """Tool ids the model may see for this run."""
    available = {str(tool_id) for tool_id in catalog}
    if not hiding_enabled(profile):
        return available
    visible = {tool_id for tool_id in DEFAULT_TOOL_IDS if tool_id in available}
    if DISCOVERY_TOOL_ID in available:
        visible.add(DISCOVERY_TOOL_ID)
    visible |= active_tool_ids(run_id) & available
    return visible


def visible_catalog(
    catalog: Mapping[str, Any], *, run_id: str = "", profile: str | None = None
) -> dict[str, Any]:
    """The order-preserving subset of *catalog* the prompt should carry."""
    visible = visible_tool_ids(catalog, run_id=run_id, profile=profile)
    return {
        tool_id: entry for tool_id, entry in catalog.items() if str(tool_id) in visible
    }


def _search_terms(query: str) -> list[str]:
    """Words of *query* worth matching (short fillers such as ``a``/``de`` out)."""
    return [
        term
        for term in re.split(r"[^a-z0-9]+", str(query or "").lower())
        if len(term) >= 3
    ]


def search_tools(catalog: Mapping[str, Any], query: str) -> list[str]:
    """Tool ids that match *query*, tolerating a phrase or a near-miss.

    The measured call was ``discover_tools(query="nmap full_tcp scan")``: no tool
    id or description contains that whole sentence, so the old substring test
    answered ``no tool matches`` and the model was left without the tools it had
    just named. Now the phrase is matched word by word (``nmap`` finds
    ``nexus.recon.nmap``), and a typo falls back to a close match on the short
    names (``reconn`` -> ``recon``). Exact substring results still win, so a
    precise query keeps returning the same set as before.
    """
    needle = str(query or "").strip().lower()
    if not needle:
        return []
    haystacks: dict[str, str] = {}
    matches: list[str] = []
    for tool_id, entry in catalog.items():
        definition = entry[0] if isinstance(entry, tuple) else entry
        description = str(getattr(definition, "description", "") or "")
        haystack = f"{tool_id} {description}".lower()
        haystacks[str(tool_id)] = haystack
        if needle in str(tool_id).lower() or needle in description.lower():
            matches.append(str(tool_id))
    if matches:
        return sorted(matches)
    terms = _search_terms(needle)
    if terms:
        matches = [
            tool_id
            for tool_id, haystack in haystacks.items()
            if any(term in haystack for term in terms)
        ]
    if matches:
        return sorted(matches)
    from difflib import get_close_matches

    names = [term for tool_id in haystacks for term in _search_terms(tool_id)]
    close = {
        match
        for term in terms or [needle]
        for match in get_close_matches(term, names, n=3, cutoff=0.75)
    }
    return sorted(
        tool_id
        for tool_id, haystack in haystacks.items()
        if any(name in haystack for name in close)
    )


#: Token of a skill name → catalog group it unlocks. Ordered: the first match
#: wins, and an explicit ``tools:`` list in the skill always outranks this.
_SKILL_GROUP_HINTS: tuple[tuple[str, str], ...] = (
    ("privesc", "post"),
    ("pivot", "post"),
    ("socks", "post"),
    ("shell", "shell"),
    ("web", "web"),
    ("http", "web"),
    ("sqli", "web"),
    ("xss", "web"),
    ("sqlmap", "web"),
    ("recon", "recon"),
    ("nmap", "recon"),
    ("enum", "recon"),
    ("smb", "recon"),
    ("ldap", "recon"),
    ("dns", "recon"),
    ("exploit", "exploit"),
    ("c2", "c2"),
    ("sliver", "c2"),
    ("cred", "cred"),
    ("brute", "cred"),
    ("hash", "cred"),
    ("post", "post"),
)

_DECLARED_TOOLS_RE = re.compile(
    r"^tools\s*:\s*\[?(?P<value>[^\]\n]+)", re.IGNORECASE | re.MULTILINE
)


def declared_tools(skill_text: str) -> list[str]:
    """Tool ids a skill declares in its frontmatter ``tools:`` field."""
    match = _DECLARED_TOOLS_RE.search(str(skill_text or ""))
    if match is None:
        return []
    return [
        item.strip().strip("'\"")
        for item in match.group("value").split(",")
        if item.strip()
    ]


def skill_groups(skill_name: str) -> list[str]:
    """Catalog groups a skill name implies (``web-upload-webshell`` → web)."""
    tokens = re.split(r"[-_/\s.]+", str(skill_name or "").lower())
    groups: list[str] = []
    for token in tokens:
        for hint, group in _SKILL_GROUP_HINTS:
            if hint in token and group not in groups:
                groups.append(group)
    return groups


def tools_for_skill(
    skill_name: str, catalog: Mapping[str, Any], *, skill_text: str = ""
) -> list[str]:
    """Tools to reveal when *skill_name* is loaded.

    Explicit declarations win; otherwise the groups the name implies are
    revealed. Either way only ids that exist in *catalog* come back.
    """
    available = {str(tool_id) for tool_id in catalog}
    explicit = [tool_id for tool_id in declared_tools(skill_text) if tool_id in available]
    if explicit:
        return sorted(explicit)
    groups = set(skill_groups(skill_name))
    return sorted(
        tool_id for tool_id in available if group_of(tool_id) in groups
    )


__all__ = [
    "DEFAULT_PROFILE",
    "DEFAULT_TOOL_IDS",
    "DISCOVERY_TOOL_ID",
    "OPEN_PROFILE",
    "PROFILE_ENV",
    "activate_tools",
    "active_tool_ids",
    "catalog_groups",
    "declared_tools",
    "group_of",
    "hiding_enabled",
    "reset_tools",
    "resolve_profile",
    "search_tools",
    "skill_groups",
    "tools_for_skill",
    "visible_catalog",
    "visible_tool_ids",
]
