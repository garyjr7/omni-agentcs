"""Parser de la salida de GetUserSPNs (Kerberoasting) → estructura estable.

``GetUserSPNs.py`` imprime una tabla de SPNs (``ServicePrincipalName  Name ...``)
y, con ``-request``, líneas de hash ``$krb5tgs$...``. El parser interpreta solo
esas dos formas documentadas; no reconstruye tickets ni inventa cuentas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text

_TABLE_HEADER = "serviceprincipalname"
_KERB_RE = re.compile(
    r"^\$krb5tgs\$\d+\$\*(?P<user>[^$]*)\$(?P<domain>[^$]*)\$(?P<spn>[^*]*)\*"
)
_KERB_MARK = "$krb5tgs$"


@dataclass(frozen=True)
class ServicePrincipal:
    """Una cuenta con SPN (kerberoasteable)."""

    service_principal_name: str
    name: str
    member_of: str
    password_last_set: str
    last_logon: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the SPN row."""
        return {
            "service_principal_name": self.service_principal_name,
            "name": self.name,
            "member_of": self.member_of,
            "password_last_set": self.password_last_set,
            "last_logon": self.last_logon,
        }


@dataclass(frozen=True)
class KerberoastHash:
    """Un hash de ticket de servicio (TGS) solicitado con ``-request``."""

    username: str
    domain: str
    service_principal_name: str
    ticket_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the hash."""
        return {
            "username": self.username,
            "domain": self.domain,
            "service_principal_name": self.service_principal_name,
            "ticket_hash": self.ticket_hash,
        }


@dataclass(frozen=True)
class GetUserSPNsResult:
    """Resultado normalizado de una ejecución de GetUserSPNs."""

    service_principals: tuple[ServicePrincipal, ...]
    hashes: tuple[KerberoastHash, ...]
    raw_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "spn_count": len(self.service_principals),
            "hash_count": len(self.hashes),
            "service_principals": [item.to_dict() for item in self.service_principals],
            "hashes": [item.to_dict() for item in self.hashes],
            "raw_sha256": self.raw_sha256,
        }


def _spn_from_line(line: str) -> ServicePrincipal | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("-"):
        return None
    if stripped.lower().startswith(_TABLE_HEADER):
        return None
    parts = re.split(r"\s{2,}", stripped)
    if len(parts) < 2:
        return None
    return ServicePrincipal(
        service_principal_name=parts[0].strip(),
        name=parts[1].strip(),
        member_of=parts[2].strip() if len(parts) > 2 else "",
        password_last_set=parts[3].strip() if len(parts) > 3 else "",
        last_logon=parts[4].strip() if len(parts) > 4 else "",
    )


def parse_getuserspns_output(text: str) -> GetUserSPNsResult:
    """Parse GetUserSPNs table and hash output.

    Empty output is a valid "nothing found" outcome.
    """
    if not isinstance(text, str) or not text.strip():
        return GetUserSPNsResult(
            service_principals=(), hashes=(), raw_sha256=sha256_text("")
        )

    principals: list[ServicePrincipal] = []
    hashes: list[KerberoastHash] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _KERB_MARK in line:
            match = _KERB_RE.match(line)
            hashes.append(
                KerberoastHash(
                    username=match.group("user").strip() if match else "",
                    domain=match.group("domain").strip() if match else "",
                    service_principal_name=match.group("spn").strip() if match else "",
                    ticket_hash=line.strip(),
                )
            )
            continue
        principal = _spn_from_line(line)
        if principal is not None:
            principals.append(principal)

    return GetUserSPNsResult(
        service_principals=tuple(principals),
        hashes=tuple(hashes),
        raw_sha256=sha256_text(text),
    )
