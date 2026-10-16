"""Deterministic parsers for normalized Metasploit RPC responses."""

from dataclasses import asdict, dataclass
import hashlib
import math
import json
from typing import Any


def _sha(raw: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            raw,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


@dataclass(frozen=True)
class MetasploitModule:
    fullname: str
    name: str = ""
    module_type: str = ""
    rank: str = ""
    disclosure_date: str = ""


@dataclass(frozen=True)
class MetasploitSearchResult:
    modules: tuple[MetasploitModule, ...]
    query: str
    raw_sha256: str

    def to_dict(self) -> dict:
        return {
            "modules": [asdict(x) for x in self.modules],
            "query": self.query,
            "count": len(self.modules),
            "raw_sha256": self.raw_sha256,
        }


def _pick(record: dict, *names: str, default: Any = "") -> Any:
    """Read the first present key, tolerating the daemon's casing."""
    for name in names:
        for candidate in (name, name.upper(), name.lower()):
            if candidate in record and record[candidate] is not None:
                return record[candidate]
    return default


def _port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return port if 0 <= port <= 65535 else 0


@dataclass(frozen=True)
class MetasploitSession:
    uuid: str
    type: str = ""
    tunnel_local: str = ""
    tunnel_peer: str = ""
    via_exploit: str = ""
    via_payload: str = ""
    session_host: str = ""
    session_port: int = 0
    target_host: str = ""
    username: str = ""
    info: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MetasploitSessionList:
    sessions: tuple[MetasploitSession, ...]
    count: int
    raw_sha256: str

    def to_dict(self) -> dict:
        return {
            "sessions": [asdict(x) for x in self.sessions],
            "count": self.count,
            "raw_sha256": self.raw_sha256,
        }


@dataclass(frozen=True)
class MetasploitExploitResult:
    module: str
    target: str
    status: str
    session: MetasploitSession | None
    job_uuid: str | None
    raw_sha256: str
    duration_seconds: float

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "session": self.session.to_dict() if self.session else None,
            "job_uuid": self.job_uuid,
            "raw_sha256": self.raw_sha256,
            "duration_seconds": self.duration_seconds,
        }


def parse_msf_session(record: dict, fallback_uuid: str = "") -> MetasploitSession:
    """Build one session record; every field is optional but the uuid."""
    if not isinstance(record, dict):
        raise ValueError("session record must be an object")
    uuid = str(_pick(record, "uuid", default=fallback_uuid) or fallback_uuid)
    if not uuid:
        raise ValueError("session record has no uuid")
    return MetasploitSession(
        uuid=uuid,
        type=str(_pick(record, "type")),
        tunnel_local=str(_pick(record, "tunnel_local")),
        tunnel_peer=str(_pick(record, "tunnel_peer")),
        via_exploit=str(_pick(record, "via_exploit")),
        via_payload=str(_pick(record, "via_payload")),
        session_host=str(_pick(record, "session_host")),
        session_port=_port(_pick(record, "session_port", default=0)),
        target_host=str(_pick(record, "target_host")),
        username=str(_pick(record, "username")),
        info=str(_pick(record, "info", "desc")),
    )


def parse_msf_sessions(raw_dict: dict) -> MetasploitSessionList:
    """Parse a ``session.list`` payload into an ordered, hash-stamped list."""
    if not isinstance(raw_dict, dict):
        raise ValueError("session.list must return an object")
    if any(not isinstance(value, dict) for value in raw_dict.values()):
        raise ValueError("session.list contains a malformed session")
    sessions = tuple(
        parse_msf_session(record, fallback_uuid=str(key))
        for key, record in sorted(raw_dict.items(), key=lambda item: str(item[0]))
    )
    return MetasploitSessionList(sessions, len(sessions), _sha(raw_dict))


def parse_msf_exploit(raw_dict: dict, module: str, target: str) -> MetasploitExploitResult:
    """Parse the outcome of one exploit run (session opened, timeout, failed)."""
    if not isinstance(raw_dict, dict):
        raise ValueError("exploit result must be an object")
    status = raw_dict.get("status")
    if not isinstance(status, str) or status not in {"session_opened", "timeout", "failed", "no_session"}:
        raise ValueError("unknown exploit status")
    record = raw_dict.get("session")
    session = None
    if isinstance(record, dict):
        session = parse_msf_session(record, fallback_uuid=str(raw_dict.get("session_uuid") or ""))
    elif status == "session_opened":
        raise ValueError("session_opened without a session record")
    try:
        duration = round(float(raw_dict.get("duration_seconds") or 0.0), 3)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("invalid duration_seconds") from None
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("invalid duration_seconds")
    return MetasploitExploitResult(
        module=str(module),
        target=str(target),
        status=str(status),
        session=session,
        job_uuid=str(raw_dict.get("job_uuid") or "") or None,
        raw_sha256=_sha(raw_dict),
        duration_seconds=duration,
    )


INTERACTION_STATUSES = ("ok", "timeout", "session_dead")


@dataclass(frozen=True)
class MetasploitSessionInteraction:
    session_uuid: str
    command: str
    status: str
    output: str
    output_bytes: int
    duration_seconds: float
    raw_sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_msf_interaction(
    raw_dict: dict, session_uuid: str, command: str
) -> MetasploitSessionInteraction:
    """Parse the outcome of one command sent to an open session."""
    if not isinstance(raw_dict, dict):
        raise ValueError("interaction result must be an object")
    status = raw_dict.get("status")
    if status not in INTERACTION_STATUSES:
        raise ValueError("unknown interaction status")
    output = raw_dict.get("output")
    if output is None:
        output = ""
    if not isinstance(output, str):
        raise ValueError("interaction output must be a string")
    try:
        duration = round(float(raw_dict.get("duration_seconds") or 0.0), 3)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("invalid duration_seconds") from None
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("invalid duration_seconds")
    return MetasploitSessionInteraction(
        session_uuid=str(session_uuid),
        command=str(command),
        status=str(status),
        output=output,
        output_bytes=len(output.encode("utf-8", errors="replace")),
        duration_seconds=duration,
        raw_sha256=_sha(raw_dict),
    )


@dataclass(frozen=True)
class MetasploitAuxiliaryResult:
    module: str
    target: str
    status: str
    uuid: str
    output: Any
    raw_sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_msf_search(raw_list: list, query: str) -> MetasploitSearchResult:
    if not isinstance(raw_list, list):
        raise ValueError("module.search must return a list")
    modules = []
    for record in raw_list:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("fullname"), str)
            or not record["fullname"]
        ):
            raise ValueError("module.search contains a malformed module")
        modules.append(
            MetasploitModule(
                fullname=record["fullname"],
                name=str(record.get("name") or ""),
                module_type=str(record.get("type") or record["fullname"].split("/")[0]),
                rank=str(record.get("rank") or ""),
                disclosure_date=str(record.get("disclosuredate") or ""),
            )
        )
    return MetasploitSearchResult(tuple(modules), query, _sha(raw_list))


def parse_msf_auxiliary(raw_dict: dict, module: str, target: str) -> MetasploitAuxiliaryResult:
    if not isinstance(raw_dict, dict):
        raise ValueError("module.results must return an object")
    status = raw_dict.get("status", "unknown")
    if not isinstance(status, str) or status not in {"ready", "running", "completed", "errored", "unknown", "timeout"}:
        raise ValueError("unknown module status")
    return MetasploitAuxiliaryResult(
        module,
        target,
        status,
        str(raw_dict.get("uuid") or ""),
        raw_dict.get("output", raw_dict.get("result", raw_dict.get("error", ""))),
        _sha(raw_dict),
    )
