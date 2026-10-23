"""Deterministic reflection: what the board proved and the run never used.

The gap this closes is not "the model lacks methodology" (the skills carry it)
but "the model does not look back at its own board". Measured on HackPark
(V15 family): the run held the contract name, the account and the panel session
and spent its turns re-reading the same page; on DeadDrop P12 the run had the
hash and the SSH password in the facts and asked for credentials with them on
screen. A senior asks one question between observation and action -"what do I
already have that I have not spent?"- and this module makes that question
auditable instead of hoping the model asks it.

Two rules keep it honest:

* only *verified* facts of an actionable type count (identity, credential,
  vulnerability, session). Recon outputs (host/service/endpoint) are excluded:
  an endpoint URL lives in a tool's **output**, not in its arguments, so calling
  it "unused" would be a lie.
* "used" means the fact's own value appears in the arguments of some action of
  this run. No model judgment, no embeddings, no prose: a substring over the
  action history, bounded and cheap to unit-test.

The module never executes anything, never changes the plan and never authorizes
a tool. It returns one text block, and only after a barren streak: a fact created
this turn has not had a chance to be used yet.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from nexus_core.kernel.blackboard import is_verified_fact

#: Consecutive turns without a new verified fact before reflecting. Below this
#: the run is still making progress and the block would be noise.
REFLECTION_AFTER_TURNS = 3
MAX_REFLECTION_FACTS = 5
MAX_REFLECTION_CHARS = 900
#: Shortest value that can identify a fact in an action's arguments. Anything
#: shorter ("/", "80", "a") matches by accident.
MIN_NEEDLE_CHARS = 4

#: Fact types the model can *spend*. Ranked: a credential first, because it is
#: the shortest path to access; a session last, because a channel without a
#: target is rarely the blocker.
ACTIONABLE_TYPES: tuple[str, ...] = (
    "credential",
    "vulnerability",
    "user",
    "email",
    "session",
)

_SUGGESTION = {
    "credential": "úsalo como credential_ref/session_ref en el servicio correcto",
    "vulnerability": "conviértelo en la siguiente llamada (request, PoC o exploit)",
    "user": "confírmalo o valida una credencial suya (1 intento por cuenta)",
    "email": "deriva la cuenta y confírmala por Kerberos antes de una contraseña",
    "session": "úsala como session_ref en shell.exec en vez de abrir otra",
}


def _flatten(value: Any, depth: int = 0) -> Iterable[str]:
    """Yield the scalars of a nested argument structure (bounded)."""
    if depth > 4:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _flatten(item, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _flatten(item, depth + 1)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield str(value)


def _action_blob(actions: Iterable[Any]) -> str:
    """Every argument the run has sent, flattened and lowercased.

    Only ``arguments`` and the tool id are read: the outputs are what produced
    the facts, so counting them as "use" would silence every hint.
    """
    parts: list[str] = []
    for action in actions or ():
        if not isinstance(action, Mapping):
            continue
        parts.append(str(action.get("tool_id") or ""))
        arguments = action.get("arguments")
        if isinstance(arguments, Mapping):
            parts.extend(_flatten(arguments))
    blob = " ".join(parts).casefold()
    # A pathological history must not turn a cheap check into a memory sink.
    return blob[:200_000]


def _needles(fact: Mapping[str, Any]) -> tuple[str, ...]:
    """Values that identify the fact inside an action's arguments.

    The value is the anchor on purpose: an action that spends a credential
    passes its username or reference, not the board's key. The key is only a
    fallback for facts whose value carries no usable handle (an opaque session),
    so a key that merely shares a prefix with an action's text cannot silence a
    hint on its own.
    """
    value = fact.get("value")
    value = value if isinstance(value, Mapping) else {}
    raw: list[str] = []
    for name in ("username", "email", "address", "id", "cve", "path",
                 "secret_ref", "session_ref", "flag"):
        text = value.get(name)
        if isinstance(text, str):
            raw.append(text)
    url = value.get("url")
    if isinstance(url, str) and url:
        path = urlsplit(url).path
        if path and path != "/":
            raw.append(path)
    needles = {
        str(item).strip().casefold()
        for item in raw
        if len(str(item).strip()) >= MIN_NEEDLE_CHARS
    }
    if not needles:
        key = str(fact.get("key") or "").strip().casefold()
        if len(key) >= MIN_NEEDLE_CHARS:
            needles.add(key)
    return tuple(sorted(needles, key=len, reverse=True))


def _label(fact: Mapping[str, Any]) -> str:
    """One readable identifier for the fact."""
    value = fact.get("value")
    value = value if isinstance(value, Mapping) else {}
    fact_type = str(fact.get("fact_type") or "")
    key = str(fact.get("key") or "").strip()
    if fact_type == "vulnerability":
        name = str(value.get("id") or value.get("cve") or value.get("class") or key)
        url = str(value.get("url") or "")
        path = urlsplit(url).path if url else ""
        if path and path != "/" and path not in name:
            name = f"{name} ({path})"
        return " ".join(name.split())[:90]
    if fact_type == "credential":
        account = str(value.get("username") or key)
        domain = str(value.get("domain") or "")
        service = str(value.get("service") or "")
        principal = f"{account}@{domain}" if domain else account
        detail = " ".join(part for part in (principal, service and f"({service})") if part)
        return detail[:90]
    return " ".join(key.split())[:90]


def unused_facts(
    facts: Iterable[Any],
    actions: Iterable[Any],
    *,
    limit: int = MAX_REFLECTION_FACTS,
) -> tuple[dict[str, Any], ...]:
    """Verified, actionable facts whose value no action has used yet."""
    blob = _action_blob(actions)
    seen: set[tuple[str, str]] = set()
    found: list[dict[str, Any]] = []
    for fact in facts or ():
        if not isinstance(fact, Mapping) or not is_verified_fact(fact):
            continue
        fact_type = str(fact.get("fact_type") or "")
        if fact_type not in ACTIONABLE_TYPES:
            continue
        key = str(fact.get("key") or "").strip()
        identity = (fact_type, key.casefold())
        if not key or identity in seen:
            continue
        seen.add(identity)
        needles = _needles(fact)
        if not needles:
            continue
        if any(needle in blob for needle in needles):
            continue
        found.append(
            {
                "fact_type": fact_type,
                "key": key,
                "label": _label(fact),
                "suggestion": _SUGGESTION.get(fact_type, ""),
            }
        )
    rank = {name: index for index, name in enumerate(ACTIONABLE_TYPES)}
    found.sort(key=lambda item: (rank.get(item["fact_type"], 9), item["key"]))
    return tuple(found[:limit])


def render_reflection(
    facts: Iterable[Any],
    actions: Iterable[Any],
    *,
    no_progress: int = 0,
    threshold: int = REFLECTION_AFTER_TURNS,
    limit: int = MAX_REFLECTION_FACTS,
) -> str:
    """The reflection block, or ``""`` when the run is progressing or used up.

    It is an observation, not an order: the model still chooses the action and
    the gateway still governs it. The text names the facts and what each one can
    become, because "piensa en lo que tienes" is the kind of advice that changed
    nothing in the measured runs.
    """
    if int(no_progress or 0) < int(threshold or 0):
        return ""
    unused = unused_facts(facts, actions, limit=limit)
    if not unused:
        return ""
    lines = [
        f"REFLEXIÓN ({int(no_progress)} turnos sin hechos nuevos; hechos "
        "verificados que aún no has usado):"
    ]
    for item in unused:
        label = item["label"] or item["key"]
        suggestion = item["suggestion"]
        # No ``<secret term>: value`` shape here: the audit writer redacts those
        # by name and would erase the very fact the block is pointing at.
        lines.append(
            f"- [{item['fact_type']}] {label}"
            + (f" → {suggestion}" if suggestion else "")
        )
    lines.append(
        "No repitas la última acción: elige uno de estos hechos y conviértelo en "
        "la siguiente llamada (o documenta por qué no sirve)."
    )
    text = "\n".join(lines)
    return text[:MAX_REFLECTION_CHARS]
