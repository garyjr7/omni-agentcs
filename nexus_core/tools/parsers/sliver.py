"""Deterministic parsers for normalized Sliver gRPC responses.

The client turns protobuf messages into plain dicts (``MessageToDict`` with
``preserving_proto_field_name=True``), so the field names here are the proto
names (``ID``/``RemoteAddress``/``OS``...). Lookups are case-tolerant to keep
them stable against minor proto renames and easy to unit-test with fixtures.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import json
from dataclasses import asdict, dataclass
from typing import Any

SESSION_KINDS = ("session", "beacon")
LOOT_KINDS = ("file", "credential")
EXEC_STATUSES = ("ok", "timeout", "error")


def _sha(raw: Any) -> str:
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _pick(record: dict, *names: str, default: Any = "") -> Any:
    """Read the first present key, tolerating casing."""
    for name in names:
        for candidate in (name, name.upper(), name.lower()):
            if candidate in record and record[candidate] is not None:
                return record[candidate]
    return default


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _last_checkin(value: Any) -> str | None:
    text = _text(value)
    return None if text in {"", "0"} else text


@dataclass(frozen=True)
class SliverServerInfo:
    version: str
    operators: tuple[dict, ...]
    jobs_count: int
    raw_sha256: str

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "operators": [dict(item) for item in self.operators],
            "operators_count": len(self.operators),
            "jobs_count": self.jobs_count,
            "raw_sha256": self.raw_sha256,
        }


@dataclass(frozen=True)
class SliverSession:
    session_id: str
    name: str
    kind: str
    hostname: str
    username: str
    os: str
    arch: str
    remote_address: str
    process_name: str
    process_id: int
    transport: str
    last_checkin: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SliverExecResult:
    session_id: str
    command: str
    status: str
    stdout: str
    stderr: str
    duration_seconds: float
    raw_sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SliverLootInfo:
    """One loot entry, with a content hash for chain of custody."""

    loot_id: str
    name: str
    kind: str
    file_type: str
    size: int
    sha256: str
    username: str
    has_content: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SliverPivotInfo:
    forward_id: int
    bind_port: int
    remote_host: str
    remote_port: int
    kind: str

    def to_dict(self) -> dict:
        return asdict(self)


def _version_string(record: dict) -> str:
    major = _int(_pick(record, "Major"), 0)
    minor = _int(_pick(record, "Minor"), 0)
    patch = _int(_pick(record, "Patch"), 0)
    commit = _text(_pick(record, "Commit")).strip()
    base = f"{major}.{minor}.{patch}"
    return base if not commit else f"{base}-{commit}"


def parse_sliver_version(raw: dict) -> SliverServerInfo:
    """Parse the combined ``{version, operators, jobs_count}`` payload."""
    if not isinstance(raw, dict):
        raise ValueError("sliver server info must be an object")
    version_raw = raw.get("version")
    if not isinstance(version_raw, dict) or not version_raw:
        raise ValueError("sliver version must be an object")
    operators_raw = raw.get("operators") or ()
    if not isinstance(operators_raw, (list, tuple)):
        raise ValueError("sliver operators must be a list")
    jobs_raw = raw.get("jobs") if raw.get("jobs") is not None else raw.get("jobs_count", 0)
    if isinstance(jobs_raw, (list, tuple)):
        jobs_count = len(jobs_raw)
    else:
        jobs_count = _int(jobs_raw, 0)
    operators = tuple(
        {
            "name": _text(_pick(item, "Name", "name")),
            "online": bool(_pick(item, "Online", "online", default=False)),
        }
        for item in operators_raw
        if isinstance(item, dict)
    )
    return SliverServerInfo(
        version=_version_string(version_raw or {}),
        operators=operators,
        jobs_count=jobs_count,
        raw_sha256=_sha(raw),
    )


def _session_kind(record: dict, default: str) -> str:
    explicit = _text(_pick(record, "kind", "Kind")).lower()
    if explicit in SESSION_KINDS:
        return explicit
    return default if default in SESSION_KINDS else "session"


def parse_sliver_session(record: dict, *, kind: str = "session") -> SliverSession:
    """Build one session/beacon record; every field is optional but the id."""
    if not isinstance(record, dict):
        raise ValueError("session record must be an object")
    session_id = _text(_pick(record, "ID", "Id", "id", "session_id", "beacon_id"))
    if not session_id:
        raise ValueError("session record has no id")
    return SliverSession(
        session_id=session_id,
        name=_text(_pick(record, "Name", "name")),
        kind=_session_kind(record, kind),
        hostname=_text(_pick(record, "Hostname", "hostname")),
        username=_text(_pick(record, "Username", "username")),
        os=_text(_pick(record, "OS", "Os", "os")),
        arch=_text(_pick(record, "Arch", "arch")),
        remote_address=_text(_pick(record, "RemoteAddress", "remote_address")),
        process_name=_text(_pick(record, "Filename", "filename", "process_name")),
        process_id=_int(_pick(record, "PID", "Pid", "pid"), 0),
        transport=_text(_pick(record, "Transport", "transport")),
        last_checkin=_last_checkin(_pick(record, "LastCheckin", "last_checkin")),
    )


def parse_sliver_sessions(raw: Any, beacons: Any = None) -> tuple[SliverSession, ...]:
    """Parse sessions and/or beacons into an ordered tuple.

    Accepts either a ``{"sessions": [...], "beacons": [...]}`` mapping, a flat
    list (sessions by default, or mixed when each record carries its kind) or a
    sessions list plus a separate ``beacons`` argument.
    """
    if isinstance(raw, dict):
        sessions_list = raw.get("sessions") or []
        beacons_list = raw.get("beacons") if "beacons" in raw else (beacons or [])
    else:
        sessions_list = list(raw or [])
        beacons_list = list(beacons or [])
    if not isinstance(sessions_list, (list, tuple)) or not isinstance(beacons_list, (list, tuple)):
        raise ValueError("sliver sessions must be lists")
    parsed: list[SliverSession] = []
    for record in sessions_list:
        parsed.append(parse_sliver_session(record, kind="session"))
    for record in beacons_list:
        parsed.append(parse_sliver_session(record, kind="beacon"))
    parsed.sort(key=lambda item: (item.kind, item.session_id))
    return tuple(parsed)


def parse_sliver_exec(raw: dict, session_id: str, command: str) -> SliverExecResult:
    """Parse the outcome of one command sent to an interactive session."""
    if not isinstance(raw, dict):
        raise ValueError("exec result must be an object")
    explicit = _text(raw.get("status")).lower()
    if explicit and explicit not in EXEC_STATUSES:
        raise ValueError("unknown exec status")
    if not explicit and "status_code" not in raw:
        raise ValueError("exec result has no status")
    if explicit in EXEC_STATUSES:
        status = explicit
    else:
        status = "ok" if _int(raw.get("status_code", 0), 1) == 0 else "error"
    stdout = raw.get("stdout")
    stderr = raw.get("stderr")
    if stdout is not None and not isinstance(stdout, str):
        raise ValueError("stdout must be a string")
    if stderr is not None and not isinstance(stderr, str):
        raise ValueError("stderr must be a string")
    try:
        duration = round(float(raw.get("duration_seconds") or 0.0), 3)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("invalid duration_seconds") from None
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("invalid duration_seconds")
    return SliverExecResult(
        session_id=str(session_id),
        command=str(command),
        status=status,
        stdout=stdout or "",
        stderr=stderr or "",
        duration_seconds=duration,
        raw_sha256=_sha(raw),
    )


def _file_bytes(record: dict) -> bytes:
    """Decode the loot file payload (base64 from MessageToDict) if present."""
    file = _pick(record, "File", "file", default=None)
    if not isinstance(file, dict):
        return b""
    data = file.get("Data")
    if isinstance(data, str) and data:
        try:
            return base64.b64decode(data)
        except (binascii.Error, ValueError):
            return data.encode("utf-8", errors="replace")
    return b""


def parse_sliver_loot(raw: Any) -> tuple[SliverLootInfo, ...]:
    """Normalize Sliver loot entries (single object or ``AllLoot`` list).

    The custody hash is the SHA256 of the file payload when the server sends it
    (``LootContent``) and otherwise the SHA256 of the loot descriptor, so every
    entry carries a stable, comparable digest.
    """
    if isinstance(raw, dict):
        if "Loot" in raw or "loot" in raw:
            records = raw.get("Loot") or raw.get("loot") or []
        else:
            records = [raw]
    else:
        records = list(raw or [])
    result: list[SliverLootInfo] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("loot record must be an object")
        payload = _file_bytes(record)
        loot_type = _text(_pick(record, "Type", "type")).upper()
        credential = _pick(record, "Credential", "credential", default={})
        credential = credential if isinstance(credential, dict) else {}
        kind = "credential" if "CREDENTIAL" in loot_type else "file"
        result.append(
            SliverLootInfo(
                loot_id=_text(_pick(record, "LootID", "loot_id", "ID", "id")),
                name=_text(_pick(record, "Name", "name")),
                kind=kind,
                file_type=_text(_pick(record, "FileType", "file_type")),
                size=len(payload) if payload else _int(_pick(record, "FileSize", "size"), 0),
                sha256=hashlib.sha256(payload).hexdigest() if payload else _sha(record),
                username=_text(_pick(credential, "User", "user")),
                has_content=bool(payload),
            )
        )
    result.sort(key=lambda item: (item.kind, item.name, item.loot_id))
    return tuple(result)


def _split_host_port(value: str) -> tuple[str, int]:
    text = _text(value).strip()
    if not text:
        return "", 0
    if text.startswith("[") and "]" in text:  # [::1]:8080
        host, _, port = text.rpartition("]:")
        return host.lstrip("["), _int(port, 0)
    host, separator, port = text.rpartition(":")
    if separator and port.isdigit():
        return host, _int(port, 0)
    return text, 0


def parse_sliver_pivots(raw: Any) -> tuple[SliverPivotInfo, ...]:
    """Normalize pivot listeners / forwards / SOCKS tunnels into one shape."""
    if isinstance(raw, dict):
        records = raw.get("listeners") or raw.get("Listeners") or raw.get("pivots") or []
    else:
        records = list(raw or [])
    result: list[SliverPivotInfo] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("pivot record must be an object")
        tunnel_id = _pick(record, "TunnelID", "tunnel_id", default=None)
        is_socks = tunnel_id is not None and (
            _pick(record, "SessionID", "session_id", default=None) is not None
            or _text(_pick(record, "kind", "Kind")).lower() == "socks5"
        )
        bind_address = _text(_pick(record, "BindAddress", "bind_address"))
        host_field = _text(_pick(record, "Host", "host", "remote_host"))
        remote_host, remote_port = _split_host_port(host_field)
        declared_kind = _text(_pick(record, "kind", "Kind")).lower()
        if declared_kind in {"portfwd", "socks5"}:
            kind = declared_kind
        elif is_socks:
            kind = "socks5"
        else:
            kind = "portfwd"
        bind_port = _int(_pick(record, "Port", "port", "bind_port"), 0)
        if not bind_port:
            bind_port = _split_host_port(bind_address)[1]
        result.append(
            SliverPivotInfo(
                forward_id=_int(
                    _pick(record, "ID", "Id", "id", default=tunnel_id or 0), 0
                )
                if not is_socks
                else _int(tunnel_id, 0),
                bind_port=bind_port,
                remote_host=remote_host,
                remote_port=remote_port,
                kind=kind,
            )
        )
    result.sort(key=lambda item: (item.kind, item.forward_id))
    return tuple(result)
