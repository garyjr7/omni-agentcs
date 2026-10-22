"""Board credentials resolved by the engine, not retyped by the model (Fix 2).

Why this module exists
----------------------
Every channel that authenticates had its own lookup. ``nexus.post.ssh_exec``
built one inside ``ssh_post.py`` (``_resolve_transport`` +
``_board_ssh_credential``) that matches a credential *structurally* —the same
secret under any of the keys the handlers and the verifier have written over
time— and resolves the plaintext from its vault handle in-process. ``winrm_exec``
and ``nexus.recon.netexec`` had nothing: without ``password``/``credential_ref``
they refused (winrm) or ran an anonymous session (netexec), even when the
engagement had already proved the credential one turn earlier.

Copying that lookup three times is how the two channels drift, so this module
owns it once: the ssh handler now delegates to :func:`resolve_credential_for`
instead of keeping its own scan, and the Windows channels call the same code.

Two rules that are not negotiable
---------------------------------
* The plaintext **never** leaves this process as a fact: the board keeps a
  ``vault:<hex>`` handle and the fact's key is the provenance record
  (:attr:`ResolvedCredential.source_fact_id`). That is what the observation
  cites when it says the engine resolved the credential.
* A credential-shaped fact **without** a handle (a hash somebody pasted, a
  redacted plaintext) is never injected. It is reported as a lead, never used.

Resolution is *strict* for the callers that cannot verify it cheaply
(``winrm_exec``, ``netexec``): exactly one candidate resolves, zero or several
are the caller's problem to disambiguate with ``credential_ref``. ``ssh_exec``
keeps "the newest usable one" because its channel verifies the credential on
every call —a wrong pick is a determinate ``denied`` the model reads— while a
Windows call spends a HIGH approval on a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: How many handles the prompt and the error messages list per host. Three is
#: what fits the per-tool token budget; more is a catalogue, not a hint.
MAX_CREDENTIALS_PER_HOST = 3

#: Protocols that share one credential corpus. A password proved on SMB is the
#: same AD account as WinRM/LDAP/RDP; a password proved by ``hydra`` against
#: ``ssh`` is not. An empty/unknown ``service`` on the fact matches any channel
#: (the provenance simply did not say), which keeps the historical ssh behaviour
#: -the CMS hash of the measured run was keyed without a host and without a
#: service- while narrowing the Windows channels to the accounts that can work.
_WINDOWS = frozenset({"winrm", "smb", "ldap", "rdp", "mssql", "wmi", "windows", "ntlm"})
_WEB = frozenset(
    {"http", "https", "http-post-form", "http-get-form", "http-pivot", "wordpress", "wp", "web"}
)
PROTOCOL_FAMILIES: dict[str, frozenset[str]] = {
    "ssh": frozenset({"ssh"}),
    "winrm": _WINDOWS,
    "smb": _WINDOWS,
    "ldap": _WINDOWS,
    "rdp": _WINDOWS,
    "mssql": _WINDOWS,
    "web": _WEB,
    "http": _WEB,
}

#: Fact fields that have carried the vault handle over time (V1-29 and before).
_REF_FIELDS = ("secret_ref", "credential_ref", "vault_ref", "password", "secret")

#: Fact fields that have carried the host over time.
_HOST_FIELDS = ("target", "host", "address")

#: Fact fields that have carried the account over time.
_USER_FIELDS = ("username", "user")


def normalize_protocol(protocol: Any) -> str:
    """Lower-case leaf of a protocol/service name (``http-post-form`` → itself)."""
    return str(protocol or "").strip().lower()


def protocol_matches(service: Any, protocol: Any) -> bool:
    """Whether a credential proved on ``service`` can be used over ``protocol``."""
    fact = normalize_protocol(service)
    wanted = normalize_protocol(protocol)
    if not fact:
        return True
    if not wanted or fact == wanted:
        return True
    return fact in PROTOCOL_FAMILIES.get(wanted, frozenset({wanted}))


def credential_family(protocol: Any) -> str:
    """The family label the prompt shows for one credential (``web``/``ssh``/…).

    It is the corpus the credential was proved in, not the channel the model
    happens to be using: a password hardcoded in the web app is ``web`` even
    when the model tries it over SSH, which is exactly the confusion measured in
    DeadDrop P12 (2026-10-22). ``http``/``https`` collapse to ``web``; the
    Windows channels keep their own name because each is a different login.
    """
    name = normalize_protocol(protocol)
    if not name:
        return "unknown"
    return "web" if name in _WEB else name


def key_names_target(key: str, target: str) -> bool:
    """Whether a fact key names exactly ``target`` (not a longer address)."""
    if not key or not target:
        return False
    if key == target:
        return True
    boundary = rf"(?<![0-9A-Za-z.]){re.escape(target)}(?![0-9A-Za-z.])"
    return re.search(boundary, key) is not None


def key_names_user(key: str, username: str) -> bool:
    """Whether a fact key carries ``username`` as its user part."""
    if not key or not username:
        return False
    if key == username:
        return True
    return re.search(rf"(?:^|[:/@]){re.escape(username)}(?=[@:/]|$)", key) is not None


def vault_reference(value: Any) -> str:
    """The vault handle a ``credential``/``access`` fact carries, or ``""``."""
    from .secret_store import is_secret_ref

    if not isinstance(value, dict):
        return ""
    for name in _REF_FIELDS:
        candidate = value.get(name)
        if isinstance(candidate, str) and is_secret_ref(candidate.strip()):
            return candidate.strip()
    return ""


def fact_names_host(fact: Mapping[str, Any], host: str) -> bool:
    """Whether *fact* is about ``host`` (value first, then the key)."""
    value = fact.get("value")
    if isinstance(value, dict):
        named = str(next((value.get(name) or "" for name in _HOST_FIELDS if value.get(name)), "")).strip()
        if named:
            return named == host
    return key_names_target(str(fact.get("key") or ""), host)


def fact_names_user(fact: Mapping[str, Any], username: str) -> bool:
    """Whether *fact* is about ``username`` (value first, then the key)."""
    value = fact.get("value")
    if isinstance(value, dict):
        named = str(next((value.get(name) or "" for name in _USER_FIELDS if value.get(name)), "")).strip()
        if named:
            return named == username
    return key_names_user(str(fact.get("key") or ""), username)


def fact_protocol(fact: Mapping[str, Any]) -> str:
    """Service of a credential fact: its ``service`` field, else its key prefix."""
    value = fact.get("value")
    if isinstance(value, dict):
        declared = normalize_protocol(value.get("service"))
        if declared:
            return declared
    match = re.match(r"^cred:([^:@]+):", str(fact.get("key") or ""))
    return normalize_protocol(match.group(1)) if match else ""


def board_facts_for(
    store: Any, tenant_id: str, engagement_id: str, fact_type: str
) -> list[dict[str, Any]]:
    """Facts of ``fact_type`` on the board (never raises)."""
    if store is None or not engagement_id:
        return []
    from .blackboard import Blackboard

    try:
        facts = Blackboard(store).list_facts(tenant_id, engagement_id, fact_type=fact_type)
    except Exception:  # noqa: BLE001 - an unreadable board never breaks a tool
        return []
    return [fact for fact in facts if isinstance(fact, dict)]


def board_facts(context: Any, fact_type: str) -> list[dict[str, Any]]:
    """``board_facts_for`` from a ``RunContext`` (the handler-facing form)."""
    return board_facts_for(
        getattr(context, "store", None),
        str(getattr(context, "tenant_id", "system") or "system"),
        str(getattr(context, "engagement_id", "") or ""),
        fact_type,
    )


def credential_entries_for(
    store: Any, tenant_id: str, engagement_id: str
) -> list[dict[str, Any]]:
    """Every handle-bearing credential fact, newest first.

    One entry per handle (the newest fact that produced it), so a fact re-recorded
    every turn does not fill the prompt with the same line. ``handle`` is the
    vault reference; the plaintext is never read here.
    """
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fact_type in ("credential", "access"):
        for fact in board_facts_for(store, tenant_id, engagement_id, fact_type):
            value = fact.get("value")
            handle = vault_reference(value)
            if not handle or handle in seen:
                continue
            host = ""
            if isinstance(value, dict):
                host = str(
                    next((value.get(name) or "" for name in _HOST_FIELDS if value.get(name)), "")
                ).strip()
            if not host:
                # ``cred:ssh:lin@10.0.0.5`` / ``pivot:tom@http://…``: the key is
                # the only place the host was written.
                key = str(fact.get("key") or "")
                host = re.sub(r"^[^:]*:", "", key).rsplit("@", 1)[-1].strip() if "@" in key else key
            seen.add(handle)
            entries.append(
                {
                    "host": host,
                    "handle": handle,
                    "username": str(
                        next(
                            (value.get(name) or "" for name in _USER_FIELDS if value.get(name)),
                            "",
                        )
                    ).strip()
                    if isinstance(value, dict)
                    else "",
                    "protocol": fact_protocol(fact),
                    "family": credential_family(fact_protocol(fact)),
                    "source_fact_id": str(fact.get("key") or ""),
                    "recorded_at": str(fact.get("recorded_at") or ""),
                    "verified": bool(fact.get("verified")),
                }
            )
    entries.sort(key=lambda entry: entry["recorded_at"], reverse=True)
    return entries


def credential_entries(context: Any) -> list[dict[str, Any]]:
    """``credential_entries_for`` from a ``RunContext``."""
    return credential_entries_for(
        getattr(context, "store", None),
        str(getattr(context, "tenant_id", "system") or "system"),
        str(getattr(context, "engagement_id", "") or ""),
    )


@dataclass(frozen=True)
class ResolvedCredential:
    """One usable credential: its handle, the plaintext and where it came from.

    ``(handle, source_fact_id)`` is the identity of the credential —what evidence
    cites— and ``password`` is carried so the calling handler runs without a
    second vault read. It never reaches an observation: the handlers cite the
    handle and the redaction layer removes the value.
    """

    handle: str
    password: str
    source_fact_id: str
    username: str
    protocol: str

    def evidence_note(self) -> str:
        """The exact sentence the observation uses when the engine resolved it."""
        return f"credential_ref resuelto por el motor: {self.handle}"


def _candidate(context: Any, fact: Mapping[str, Any], protocol: str) -> ResolvedCredential | None:
    """Resolve one fact's handle into a usable credential (``None`` when unusable)."""
    from .secret_store import default_secret_store

    value = fact.get("value")
    handle = vault_reference(value)
    if not handle:
        return None
    if not protocol_matches(fact_protocol(fact), protocol):
        return None
    tenant_id = str(getattr(context, "tenant_id", "system") or "system")
    try:
        plaintext = default_secret_store().get(handle, tenant_id=tenant_id).decode("utf-8")
    except Exception:  # noqa: BLE001 - an unreadable handle is not a credential
        return None
    if not plaintext:
        return None
    username = ""
    if isinstance(value, dict):
        username = str(
            next((value.get(name) or "" for name in _USER_FIELDS if value.get(name)), "")
        ).strip()
    return ResolvedCredential(
        handle=handle,
        password=plaintext,
        source_fact_id=str(fact.get("key") or ""),
        username=username,
        protocol=fact_protocol(fact) or normalize_protocol(protocol),
    )


def credential_candidates(
    host: str,
    username: str,
    protocol: str,
    *,
    context: Any,
) -> list[ResolvedCredential]:
    """Usable credentials for ``username@host`` over ``protocol``, newest first.

    A blank ``username`` matches every account on the host, which is what the
    prompt needs and what a caller without an identity asks for; a call that
    names an account only sees that account's credentials.
    """
    candidates: list[ResolvedCredential] = []
    seen: set[str] = set()
    for fact_type in ("credential", "access"):
        for fact in board_facts(context, fact_type):
            if not fact_names_host(fact, host):
                continue
            if username and not fact_names_user(fact, username):
                continue
            resolved = _candidate(context, fact, protocol)
            if resolved is None or resolved.handle in seen:
                continue
            seen.add(resolved.handle)
            candidates.append(resolved)
    return candidates


def best_credential_for(
    host: str,
    username: str,
    protocol: str,
    *,
    context: Any,
) -> ResolvedCredential | None:
    """Newest usable credential for the identity (verified facts first).

    Used by ``ssh_exec``, whose channel proves the credential on every call: a
    wrong pick is a determinate ``denied`` the model reads, not a silent guess
    that survives. ``credential_candidates`` keeps verified facts first because
    the board already merged them, and the board order is newest-first.
    """
    candidates = credential_candidates(host, username, protocol, context=context)
    return candidates[0] if candidates else None


def resolve_credential_for(
    host: str,
    username: str,
    protocol: str,
    *,
    context: Any,
) -> ResolvedCredential | None:
    """The single credential the engine may supply without asking, or ``None``.

    ``None`` also means "ambiguous": the caller distinguishes zero from several
    with :func:`credential_candidates` and refuses with
    :func:`credential_choice_message` instead of guessing which account to use.
    """
    candidates = credential_candidates(host, username, protocol, context=context)
    return candidates[0] if len(candidates) == 1 else None


def _describe(entry: Mapping[str, Any]) -> str:
    """One line of a handle: what the operator would read in the ledger."""
    username = str(entry.get("username") or "?").strip()
    protocol = str(entry.get("protocol") or "?").strip()
    return (
        f"`{entry['handle']}` (username=`{username}`, protocol=`{protocol}`, "
        f"fact=`{entry.get('source_fact_id') or '?'}`)"
    )


def _describe_candidate(candidate: ResolvedCredential) -> str:
    """The same line for a resolved candidate (a dataclass, not a board dict)."""
    return (
        f"`{candidate.handle}` (username=`{candidate.username or '?'}`, "
        f"protocol=`{candidate.protocol or '?'}`, "
        f"fact=`{candidate.source_fact_id or '?'}`)"
    )


def credential_choice_message(
    *,
    tool_id: str,
    host: str,
    username: str,
    protocol: str,
    context: Any,
    purpose: str = "autenticar",
) -> str:
    """Invalid-input text: no credential, or more than one to choose from.

    The two failures are the same turn to the model —it has to pass a handle or a
    secret— but they are not the same fact, so the message names which one it is
    and lists what the board actually holds. A refusal that does not name the way
    out costs a turn per retry (measured in DeadDrop P8 and in the Simple CTF
    credential loop).
    """
    identity = f"{username}@{host}" if username else host
    candidates = credential_candidates(host, username, protocol, context=context)
    if not candidates:
        elsewhere = [
            entry
            for entry in credential_entries(context)
            if (entry.get("host") or "") == host
        ]
        if elsewhere:
            listing = "; ".join(_describe(entry) for entry in elsewhere[:MAX_CREDENTIALS_PER_HOST])
            return (
                f"no {protocol} credential for {identity}: pass `credential_ref` (or "
                f"`password`) to {purpose}. The board holds {len(elsewhere)} handle(s) "
                f"for that host over other protocols: {listing}."
            )
        return (
            f"no {protocol} credential for {identity}: pass `credential_ref` (or "
            f"`password`) to {purpose}. The board holds no usable handle for that "
            "host yet, so prove one first (nexus.cred.bruteforce, or a manual "
            "login that the engine records)."
        )
    listing = "; ".join(_describe_candidate(candidate) for candidate in candidates)
    return (
        f"{len(candidates)} credentials on the board could authenticate "
        f"{identity} over {protocol}: {listing}. Pass the one to use as "
        "`credential_ref`; the engine does not guess between accounts."
    )


def available_credentials_for(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    *,
    per_host: int = MAX_CREDENTIALS_PER_HOST,
) -> list[dict[str, Any]]:
    """Handles the prompt may show: the newest ``per_host`` per host.

    Returns entries with an added ``extra`` count (how many more handles that host
    has) so the renderer does not need to re-read the board to say "… y N más".
    """
    limit = max(1, int(per_host))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in credential_entries_for(store, tenant_id, engagement_id):
        host = str(entry.get("host") or "").strip()
        if not host:
            continue
        grouped.setdefault(host, []).append(entry)
    shown: list[dict[str, Any]] = []
    for host, entries in grouped.items():
        kept = entries[:limit]
        extra = max(0, len(entries) - len(kept))
        if extra:
            kept = [dict(entry) for entry in kept]
            kept[-1]["extra"] = extra
        shown.extend(kept)
    return shown


def available_credentials(
    context: Any, *, per_host: int = MAX_CREDENTIALS_PER_HOST
) -> list[dict[str, Any]]:
    """``available_credentials_for`` from a ``RunContext``."""
    return available_credentials_for(
        getattr(context, "store", None),
        str(getattr(context, "tenant_id", "system") or "system"),
        str(getattr(context, "engagement_id", "") or ""),
        per_host=per_host,
    )


def credential_lines(entries: Iterable[Mapping[str, Any]]) -> list[str]:
    """The ``- <host>: <handle> (username=…, protocol=…)`` lines, nothing else."""
    lines: list[str] = []
    for entry in entries:
        line = (
            f"- `{entry.get('host') or '?'}`: `{entry.get('handle')}` "
            f"(username=`{entry.get('username') or '?'}`, "
            f"protocol=`{entry.get('protocol') or '?'}`, "
            f"family=`{entry.get('family') or credential_family(entry.get('protocol'))}`)"
        )
        if entry.get("extra"):
            line += f" … y {int(entry['extra'])} más"
        lines.append(line)
    return lines


__all__ = [
    "MAX_CREDENTIALS_PER_HOST",
    "PROTOCOL_FAMILIES",
    "ResolvedCredential",
    "available_credentials",
    "available_credentials_for",
    "best_credential_for",
    "board_facts",
    "board_facts_for",
    "credential_candidates",
    "credential_choice_message",
    "credential_entries",
    "credential_entries_for",
    "credential_family",
    "credential_lines",
    "fact_names_host",
    "fact_names_user",
    "fact_protocol",
    "key_names_target",
    "key_names_user",
    "normalize_protocol",
    "protocol_matches",
    "resolve_credential_for",
    "vault_reference",
]
