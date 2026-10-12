"""Parser determinista de la salida de ``dig`` → estructura estable.

``dig`` no ofrece JSON. El parser reconoce la cabecera (``status:``), las líneas
de la sección de respuesta (``NAME TTL IN TYPE VALUE``) y los fallos de red
(``connection timed out``, ``communications error``). Nunca reconstruye datos:
guarda el valor observado tal cual, y separa **respuesta válida** (incluido un
``NXDOMAIN``, que es un negativo legítimo) de **servidor no disponible**.
"""

from __future__ import annotations

import re
from typing import Any

from ._jsonl import sha256_text

#: ``;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234``
_STATUS_RE = re.compile(r";;\s*->>HEADER<<-\s+opcode:\s*\w+,\s*status:\s*(?P<status>[A-Z]+)")

#: ``windcorp.thm. 86400 IN TXT "…"`` — la clase se acepta en sus formas habituales.
_RECORD_RE = re.compile(
    r"^(?P<name>[^\s;]+?)\s+(?P<ttl>\d+)\s+(?P<cls>IN|CH|HS)\s+"
    r"(?P<rtype>[A-Z0-9]+)\s+(?P<value>.+)$"
)

#: ``;; connection timed out; no servers could be reached`` / fallo de AXFR.
_NETWORK_FAILURE_RE = re.compile(
    r"connection timed out|communications error|no servers could be reached|"
    r"connection refused|Transfer failed",
    re.IGNORECASE,
)

#: Flag-shaped loot inside a record value (``TXT`` es el caso real medido).
#: A flag is brace-delimited, so the body may contain spaces: the RUN_sala10 flag
#: is a whole sentence (``flag{fake_flag}``). Excluding
#: braces and newlines keeps the shape strict without dropping real flags.
FLAG_RE = re.compile(r"(?:THM|HTB|FLAG|flag|CTF|ctf)\{[^{}\r\n\x00]{4,200}\}")

#: ``;; ANSWER SECTION:`` … until the next ``;;`` header. Records outside the
#: answer (an ``SOA`` in AUTHORITY, glue in ADDITIONAL) are **not** answers to
#: the question, so they must never be reported as one.
_ANSWER_HEADER = ";; ANSWER SECTION:"


def _answer_section(text: str) -> str:
    """Return only the records of the answer section ('' when there is none)."""
    lines: list[str] = []
    in_answer = False
    for line in (text or "").splitlines():
        if line.startswith(_ANSWER_HEADER):
            in_answer = True
            continue
        if in_answer and line.startswith(";;"):
            break
        if in_answer:
            lines.append(line)
    return "\n".join(lines)


def empty_dns_result(server: str, name: str, record_type: str) -> dict[str, Any]:
    """Return the shape of a DNS observation with no records yet."""
    return {
        "server": server,
        "name": name,
        "record_type": record_type,
        "status": None,
        "records": [],
        "count": 0,
        "flags": [],
        "error": None,
        "dig_sha256": sha256_text(""),
        "raw_lines": 0,
    }


def parse_dig_output(
    stdout: str,
    *,
    server: str,
    name: str,
    record_type: str,
    stderr: str = "",
) -> dict[str, Any]:
    """Parse ``dig`` output into a stable observation.

    A well-formed answer (``NOERROR``/``NXDOMAIN``/…, with or without records) is
    *not* an error: an empty answer is the correct observation for a name that is
    absent. ``error`` is reserved for a server that did not answer.
    """
    result = empty_dns_result(server, name, record_type)
    text = stdout or ""
    result["dig_sha256"] = sha256_text(text)
    result["raw_lines"] = len([line for line in text.splitlines() if line.strip()])

    status = _STATUS_RE.search(text)
    if status:
        result["status"] = status.group("status")

    records: list[dict[str, Any]] = []
    for line in _answer_section(text).splitlines():
        line = line.rstrip()
        if not line or line.startswith(";"):
            continue
        match = _RECORD_RE.match(line)
        if match is None:
            continue
        records.append(
            {
                "name": match.group("name").rstrip("."),
                "ttl": int(match.group("ttl")),
                "type": match.group("rtype").upper(),
                "value": match.group("value").strip(),
            }
        )
    result["records"] = records
    result["count"] = len(records)

    flags: list[str] = []
    for record in records:
        for flag in FLAG_RE.findall(record["value"]):
            if flag not in flags:
                flags.append(flag)
    result["flags"] = flags

    if result["status"] is None:
        if _NETWORK_FAILURE_RE.search(f"{text}\n{stderr or ''}"):
            result["error"] = "dns server did not answer"
        else:
            result["error"] = "dig produced no DNS header"
    return result
