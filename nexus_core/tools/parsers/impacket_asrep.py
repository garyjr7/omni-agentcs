"""Parser for the two user-enumeration oracles this engine can run.

Two binaries answer "does this account exist?" without a password and without a
failed logon (so without a lockout): ``kerbrute userenum`` and Impacket's
``GetNPUsers -no-pass -usersfile``. They do not answer equally well:

* **kerbrute** prints a verdict per line (``VALID USERNAME`` / ``Invalid
  username``), so it can confirm existence *and* absence. ``attribution=full``.
* **GetNPUsers** prints a hash for an account with preauth disabled and
  ``User X doesn't have UF_DONT_REQUIRE_PREAUTH set`` for one that exists with
  preauth, but a *nonexistent* principal only produces
  ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` with **no username** (verified in the shipped
  Impacket source: ``request_multiple_TGTs`` logs only ``str(e)``). So the rest
  of the list is ``unknown``, never ``missing``. ``attribution=partial``.

The parser refuses to turn "the tool did not name it" into "the account does not
exist": that inference is exactly how a run ends up spraying a validated list of
nonexistent users, or closing a branch that was never probed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from ._jsonl import sha256_text

MODE_KERBRUTE = "kerbrute"
MODE_ASREP = "asrep"

_KERBRUTE_VALID = re.compile(r"VALID USERNAME:\s+(?P<user>[A-Za-z0-9][A-Za-z0-9._$-]*)")
_KERBRUTE_INVALID = re.compile(
    r"Invalid username:\s+(?P<user>[A-Za-z0-9][A-Za-z0-9._$-]*)", re.IGNORECASE
)
#: John format for etype 23: ``$krb5asrep$23$user@REALM:...``.
_ASREP_JOHN = re.compile(r"\$krb5asrep\$(?P<etype>\d+)\$(?P<body>[^$\s]+)\$(?P<rest>\S+)")
#: John format for etype 17/18 (no ``@``): ``$krb5asrep$18$REALMuser$...``.
_ASREP_ETYPE_1718 = re.compile(r"^\$krb5asrep\$(?:17|18)\$")
#: The "exists, preauth enabled" answer; it names the account.
_NO_PREAUTH = re.compile(
    r"User (?P<user>[A-Za-z0-9][A-Za-z0-9._$-]*) doesn't have UF_DONT_REQUIRE_PREAUTH set"
)


@dataclass(frozen=True)
class RoastableAccount:
    """An account whose AS-REP came back without preauthentication."""

    username: str
    domain: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation (hash included)."""
        return {"username": self.username, "domain": self.domain, "hash": self.hash}


@dataclass(frozen=True)
class UserEnumResult:
    """What the oracle proved, and what it merely did not mention."""

    mode: str
    existing: tuple[str, ...]
    missing: tuple[str, ...]
    unknown: tuple[str, ...]
    roastable: tuple[RoastableAccount, ...]
    raw_sha256: str

    @property
    def attribution(self) -> str:
        """``full`` when absence is proved too, ``partial`` otherwise."""
        return "full" if self.mode == MODE_KERBRUTE else "partial"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "mode": self.mode,
            "attribution": self.attribution,
            "existing": list(self.existing),
            "missing": list(self.missing),
            "unknown": list(self.unknown),
            "roastable": [item.to_dict() for item in self.roastable],
            "roastable_count": len(self.roastable),
            "raw_sha256": self.raw_sha256,
        }


def _local(value: str) -> str:
    """``jdoe@services.local`` -> ``jdoe`` (the sAMAccountName)."""
    return str(value or "").split("@", 1)[0].strip()


def _ordered(values: Iterable[str], requested: Iterable[str]) -> tuple[str, ...]:
    """Return ``values`` in the order the caller asked for them."""
    wanted = [str(item).strip() for item in requested if str(item).strip()]
    present = {str(item).casefold(): str(item) for item in values if str(item).strip()}
    ordered = [present[item.casefold()] for item in wanted if item.casefold() in present]
    seen = {item.casefold() for item in ordered}
    for item in present.values():
        if item.casefold() not in seen:
            ordered.append(item)
    return tuple(ordered)


def _asrep_account(line: str, requested: Iterable[str], domain: str) -> RoastableAccount | None:
    match = _ASREP_JOHN.search(line)
    if not match:
        return None
    body = match.group("body")
    account_domain = domain
    username = body
    if "@" in body:
        username, _, account_domain = body.partition("@")
    elif _ASREP_ETYPE_1718.match(line):
        # etype 17/18 john output concatenates the realm and the account name.
        for candidate in requested:
            name = str(candidate).strip()
            if name and body.casefold().endswith(name.casefold()) and len(body) > len(name):
                username = name
                account_domain = body[: -len(name)]
                break
    username = _local(username)
    if not username:
        return None
    return RoastableAccount(
        username=username,
        domain=account_domain or domain,
        hash=line.strip(),
    )


def parse_user_enum(
    text: str,
    requested: Iterable[str] = (),
    *,
    mode: str = MODE_ASREP,
    domain: str = "",
) -> UserEnumResult:
    """Parse kerbrute/GetNPUsers output into ``existing``/``missing``/``unknown``."""
    raw = str(text or "")
    requested_list = [str(item).strip() for item in requested if str(item).strip()]
    existing: list[str] = []
    missing: list[str] = []
    roastable: list[RoastableAccount] = []

    if mode == MODE_KERBRUTE:
        for match in _KERBRUTE_VALID.finditer(raw):
            existing.append(_local(match.group("user")))
        for match in _KERBRUTE_INVALID.finditer(raw):
            missing.append(_local(match.group("user")))
    else:
        for line in raw.splitlines():
            account = _asrep_account(line, requested_list, domain)
            if account is not None:
                roastable.append(account)
                existing.append(account.username)
        for match in _NO_PREAUTH.finditer(raw):
            existing.append(match.group("user"))

    existing_set = {item.casefold() for item in existing if item}
    missing_set = {item.casefold() for item in missing if item} - existing_set
    ordered_existing = _ordered([item for item in existing if item], requested_list)
    ordered_missing = _ordered(
        [item for item in missing if item and item.casefold() not in existing_set],
        requested_list,
    )
    if mode == MODE_KERBRUTE:
        unknown = [
            item for item in requested_list
            if item.casefold() not in existing_set and item.casefold() not in missing_set
        ]
    else:
        # Absence is not proved by this oracle: everything it did not name stays
        # an open question instead of becoming a false "does not exist".
        unknown = [item for item in requested_list if item.casefold() not in existing_set]
    return UserEnumResult(
        mode=mode,
        existing=ordered_existing,
        missing=ordered_missing,
        unknown=tuple(unknown),
        roastable=tuple(roastable),
        raw_sha256=sha256_text(raw),
    )
