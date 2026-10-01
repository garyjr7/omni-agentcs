"""Parser de los ficheros de secretsdump de Impacket → estructura estable.

``secretsdump.py -outputfile PREFIJO`` trata el argumento como prefijo y añade
extensiones (``.sam``, ``.secrets``, ``.cached``, ``.ntds``). El parser lee
esos ficheros con su formato documentado: las líneas de hash
``usuario:rid:lmhash:nthash:::`` y las asignaciones de secretos LSA
``clave:valor``. No reconstruye hashes ni inventa cuentas.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text


@dataclass(frozen=True)
class SecretsDumpEntry:
    """Una cuenta con hashes NTLM extraída de SAM/NTDS/cached."""

    username: str
    rid: str
    lm_hash: str
    ntlm_hash: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the entry."""
        return {
            "username": self.username,
            "rid": self.rid,
            "lm_hash": self.lm_hash,
            "ntlm_hash": self.ntlm_hash,
            "source": self.source,
        }


@dataclass(frozen=True)
class SecretsDumpSecret:
    """Un secreto LSA (clave → valor) del fichero ``.secrets``."""

    key: str
    value: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the secret."""
        return {"key": self.key, "value": self.value, "source": self.source}


@dataclass(frozen=True)
class SecretsDumpResult:
    """Resultado normalizado de un volcado de secretsdump."""

    entries: tuple[SecretsDumpEntry, ...]
    secrets: tuple[SecretsDumpSecret, ...]
    sources: tuple[str, ...]
    raw_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "count": len(self.entries),
            "secret_count": len(self.secrets),
            "sources": list(self.sources),
            "entries": [entry.to_dict() for entry in self.entries],
            "secrets": [secret.to_dict() for secret in self.secrets],
            "raw_sha256": self.raw_sha256,
        }


def _hash_entry(line: str, source: str) -> SecretsDumpEntry | None:
    parts = line.split(":")
    if len(parts) < 4:
        return None
    rid = parts[1].strip()
    if not rid.isdigit():
        return None
    lm_hash = parts[2].strip()
    ntlm_hash = parts[3].strip()
    if not lm_hash and not ntlm_hash:
        return None
    return SecretsDumpEntry(
        username=parts[0].strip(),
        rid=rid,
        lm_hash=lm_hash,
        ntlm_hash=ntlm_hash,
        source=source,
    )


def _cached_entry(line: str, source: str) -> SecretsDumpEntry | None:
    # Cached domain credentials: $DCC2$10240#user#hash
    if not line.startswith("$DCC2$"):
        return None
    body = line[len("$DCC2$") :]
    parts = body.split("#")
    if len(parts) < 3:
        return None
    return SecretsDumpEntry(
        username=parts[1].strip(),
        rid="",
        lm_hash="",
        ntlm_hash=parts[2].strip(),
        source=source,
    )


def _secret_entry(line: str, source: str) -> SecretsDumpSecret | None:
    if ":" not in line:
        return None
    key, _, value = line.partition(":")
    key = key.strip()
    if not key:
        return None
    return SecretsDumpSecret(key=key, value=value.strip(), source=source)


def parse_secretsdump_file(
    text: str, source: str
) -> tuple[list[SecretsDumpEntry], list[SecretsDumpSecret]]:
    """Parse one secretsdump output file into entries and secrets."""
    entries: list[SecretsDumpEntry] = []
    secrets: list[SecretsDumpSecret] = []
    if not isinstance(text, str) or not text.strip():
        return entries, secrets
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if source == "secrets":
            secret = _secret_entry(line, source)
            if secret is not None:
                secrets.append(secret)
            continue
        entry = _hash_entry(line, source) or _cached_entry(line, source)
        if entry is not None:
            entries.append(entry)
    return entries, secrets


def parse_secretsdump_files(files: dict[str, str]) -> SecretsDumpResult:
    """Parse every secretsdump output file, keyed by extension/source."""
    all_entries: list[SecretsDumpEntry] = []
    all_secrets: list[SecretsDumpSecret] = []
    sources: list[str] = []
    combined: list[str] = []
    for source in sorted(files):
        text = files[source]
        sources.append(source)
        combined.append(text)
        entries, secrets = parse_secretsdump_file(text, source)
        all_entries.extend(entries)
        all_secrets.extend(secrets)
    return SecretsDumpResult(
        entries=tuple(all_entries),
        secrets=tuple(all_secrets),
        sources=tuple(sources),
        raw_sha256=sha256_text("\n".join(combined)),
    )
