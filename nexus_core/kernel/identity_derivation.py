"""Deterministic identity derivation: from what a page publishes to candidates.

The rule this module encodes is older than any room it was measured on: an
organisation that prints ``j.doe@services.local`` and lists ``Joanne Doe`` has
told you its account convention. Deriving ``j.rock`` for ``Jack Rock`` is
arithmetic, not intuition, and it must not depend on the model noticing it.

Two levels are kept strictly apart, because mixing them is how a run ends up
spraying five hundred invented accounts:

* **observed** - the address is printed on the page. It proves the *string*, not
  that the directory has the account.
* **derived** - the name plus the convention. It is a *hypothesis* with a
  confidence, and the caller must validate it cheaply (Kerberos enumeration,
  a login probe that does not consume an attempt) before spending a password.

The module is pure and stdlib-only: no model, no network, no store. Callers get
a ranked list they can put in an observation or assert as a fact, and the tests
pin the ranking so a future change cannot quietly make ``john`` outrank
``j.doe``.
"""

from __future__ import annotations

import unicodedata
from collections import Counter

#: Conventions in preference order. When two fit equally, the earlier one wins:
#: ``initial.last`` is the most common corporate convention and the one a
#: low-confidence guess should use.
CONVENTION_INITIAL_DOT_LAST = "initial.last"
CONVENTION_FIRST_DOT_LAST = "first.last"
CONVENTION_INITIAL_LAST = "initiallast"
CONVENTION_FIRST_LAST = "firstlast"
CONVENTION_FL_LAST = "flast"
CONVENTION_FIRST = "first"

CONVENTIONS: tuple[str, ...] = (
    CONVENTION_INITIAL_DOT_LAST,
    CONVENTION_FIRST_DOT_LAST,
    CONVENTION_INITIAL_LAST,
    CONVENTION_FIRST_LAST,
    CONVENTION_FL_LAST,
    CONVENTION_FIRST,
)

#: Confidence of each basis. ``observed`` is the printed local part; ``derived``
#: is a name plus a convention the page confirmed; ``guessed`` is a name plus the
#: most common convention when the page confirmed none.
CONFIDENCE_OBSERVED = 1.0
CONFIDENCE_CONFIRMED_NAME = 0.9
CONFIDENCE_CONFIRMED_CONVENTION = 0.6
CONFIDENCE_GUESSED = 0.3

#: Titles that make an account worth validating first. The list is a *ranking*
#: input, never an authorisation: "IT Staff" is a lead, not a privilege fact.
_HIGH_PRIORITY_TITLES: frozenset[str] = frozenset(
    {
        "admin", "administrator", "cio", "cto", "ceo", "ciso", "devops",
        "director", "engineer", "head", "infrastructure", "it", "lead",
        "manager", "officer", "operations", "owner", "security", "staff",
        "support", "sysadmin", "technician",
    }
)
_MEDIUM_PRIORITY_TITLES: frozenset[str] = frozenset(
    {"accountant", "analyst", "consultant", "finance", "hr", "human", "sales", "specialist"}
)

_PRIORITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _ascii(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(value or ""))
    return normalized.encode("ascii", "ignore").decode("ascii")


def _fold(value: str) -> str:
    """ASCII-fold a *name*: ``Núñez`` -> ``nunez``, ``O'Brien`` -> ``obrien``.

    Only letters and digits survive, because the name is an input to a pattern,
    not an account string.
    """
    return "".join(ch for ch in _ascii(value).casefold() if ch.isalnum())


def _normalize_username(value: str) -> str:
    """Normalize an *account string*: keep the separators, drop the rest.

    ``J.Doe`` -> ``j.doe`` and ``J.Doe@`` -> ``j.doe``: folding a username with
    ``_fold`` would turn ``j.doe`` into ``jdoe`` and silently invent a different
    account, which is exactly the class of error this module exists to avoid.
    """
    return "".join(
        ch for ch in _ascii(value).casefold() if ch.isalnum() or ch in "._-"
    ).strip("._-")


def split_name(name: str) -> tuple[str, str] | None:
    """Return ``(first, last)`` for a human name, or ``None`` if unusable.

    Middle tokens are dropped on purpose: ``Joanne M. Doe`` follows the same
    convention as ``Joanne Doe``, and a middle initial is not part of the account
    string in any convention worth guessing.
    """
    tokens = [token for token in str(name or "").replace("-", " ").split() if token]
    if len(tokens) < 2:
        return None
    first, last = _fold(tokens[0]), _fold(tokens[-1])
    if not first or not last:
        return None
    return first, last


def convention_username(first: str, last: str, convention: str) -> str:
    """Build the username a given convention would produce."""
    if convention == CONVENTION_INITIAL_DOT_LAST:
        return f"{first[:1]}.{last}"
    if convention == CONVENTION_FIRST_DOT_LAST:
        return f"{first}.{last}"
    if convention == CONVENTION_INITIAL_LAST:
        return f"{first[:1]}{last}"
    if convention == CONVENTION_FIRST_LAST:
        return f"{first}{last}"
    if convention == CONVENTION_FL_LAST:
        return f"{first[:1]}{last}"
    if convention == CONVENTION_FIRST:
        return first
    return f"{first[:1]}.{last}"


def _local_part(address: str) -> str:
    return _normalize_username(str(address).split("@", 1)[0])


def _domain(address: str) -> str:
    _, _, domain = str(address).partition("@")
    return domain.strip().casefold()


def detect_convention(emails, people) -> tuple[str | None, int, str]:
    """Return ``(convention, matches, sample)`` for the addresses and names.

    A convention is *detected* only when at least one printed address equals the
    pattern some person on the same page would produce. That is the ``j.doe`` +
    ``Joanne Doe`` case; one address without a matching name proves the domain,
    not the convention.
    """
    names = [pair for pair in (split_name(person.get("name", "")) for person in people or ()) if pair]
    if not emails or not names:
        return None, 0, ""
    counts: Counter[str] = Counter()
    samples: dict[str, str] = {}
    for address in emails:
        local = _local_part(address)
        if not local:
            continue
        for first, last in names:
            for convention in CONVENTIONS:
                if local == convention_username(first, last, convention):
                    counts[convention] += 1
                    samples.setdefault(convention, str(address))
    if not counts:
        return None, 0, ""
    best = max(counts, key=lambda item: (counts[item], -CONVENTIONS.index(item)))
    return best, counts[best], samples.get(best, "")


def _priority(title: str) -> str:
    words = {word.strip(".,;:()[]").casefold() for word in str(title or "").split()}
    if words & _HIGH_PRIORITY_TITLES:
        return "high"
    if words & _MEDIUM_PRIORITY_TITLES:
        return "medium"
    return "low"


def derive_identities(
    emails,
    people,
    *,
    max_candidates: int = 20,
) -> dict:
    """Rank every account the page suggests, best evidence first.

    Returns ``{"domain", "convention", "convention_matches", "convention_sample",
    "candidates", "priority_targets"}``. An empty page returns empty lists and a
    ``None`` domain; nothing here raises on malformed input.
    """
    email_list = [str(address).strip() for address in emails or () if "@" in str(address)]
    person_list = [person for person in people or () if isinstance(person, dict)]
    domain = ""
    if email_list:
        domain = Counter(_domain(address) for address in email_list).most_common(1)[0][0]
    convention, matches, sample = detect_convention(email_list, person_list)

    candidates: dict[str, dict] = {}

    def add(username: str, confidence: float, basis: str, person: dict | None = None) -> None:
        handle = _normalize_username(username)
        if not handle:
            return
        current = candidates.get(handle)
        if current is not None and current["confidence"] >= confidence:
            # Keep the stronger evidence, but a title is never lost: it is what
            # makes the candidate worth validating first.
            if person and person.get("title") and not current.get("title"):
                current["title"] = person["title"]
                current["priority"] = _priority(person["title"])
            return
        candidates[handle] = {
            "username": handle,
            "confidence": round(confidence, 2),
            "basis": basis,
            "person": (person or {}).get("name", ""),
            "title": (person or {}).get("title", ""),
            "priority": _priority((person or {}).get("title", "")),
            "domain": domain,
        }

    # Every printed address is a candidate on its own: the local part is what an
    # attacker would type. It is also the anchor the derived names are ranked
    # against.
    observed_names: dict[str, dict] = {}
    for address in email_list:
        handle = _local_part(address)
        add(handle, CONFIDENCE_OBSERVED, "observed_email")
        for person in person_list:
            pair = split_name(person.get("name", ""))
            if pair is None:
                continue
            if handle in {convention_username(pair[0], pair[1], item) for item in CONVENTIONS}:
                observed_names[handle] = person
                add(handle, CONFIDENCE_OBSERVED, "observed_email", person)

    # No published address means no domain, and an account without a domain is
    # not a lead: deriving one would be inventing a target. The people are still
    # ranked below (a role is worth knowing), but no username is produced.
    for person in (person_list if domain else ()):
        pair = split_name(person.get("name", ""))
        if pair is None:
            continue
        first, last = pair
        matching = ""
        if convention:
            matching = next(
                (handle for handle in observed_names
                 if handle == convention_username(first, last, convention)),
                "",
            )
        if matching:
            confidence = CONFIDENCE_CONFIRMED_NAME
            basis = "derived_from_confirmed_email"
        elif convention:
            confidence = CONFIDENCE_CONFIRMED_CONVENTION
            basis = f"derived_from_convention:{convention}"
        else:
            confidence = CONFIDENCE_GUESSED
            basis = "derived_without_confirmed_convention"
        conventions = (convention,) if convention else (CONVENTION_INITIAL_DOT_LAST, CONVENTION_FIRST_DOT_LAST)
        for item in conventions:
            add(convention_username(first, last, item), confidence, basis, person)
            if confidence >= CONFIDENCE_CONFIRMED_NAME:
                break

    ordered = sorted(
        candidates.values(),
        key=lambda item: (-item["confidence"], _PRIORITY_RANK.get(item["priority"], 3),
                          item["username"]),
    )[:max_candidates]
    priority_targets = [
        {"name": item["person"], "title": item["title"], "username": item["username"]}
        for item in ordered
        if item["priority"] == "high" and item["person"]
    ]
    if not priority_targets:
        # Without a domain there are no candidates to rank from, but "IT Staff"
        # is still the person to validate first once one appears.
        priority_targets = [
            {"name": person.get("name", ""), "title": person.get("title", ""), "username": ""}
            for person in person_list
            if _priority(person.get("title", "")) == "high"
        ][:5]
    return {
        "domain": domain,
        "convention": convention,
        "convention_matches": matches,
        "convention_sample": sample,
        "candidates": ordered,
        "priority_targets": priority_targets,
    }
