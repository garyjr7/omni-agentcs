"""Deterministic parsers for normalized Metasploit RPC responses."""

from dataclasses import asdict, dataclass
import hashlib
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
    if status not in {"ready", "running", "completed", "errored", "unknown", "timeout"}:
        raise ValueError("unknown module status")
    return MetasploitAuxiliaryResult(
        module,
        target,
        status,
        str(raw_dict.get("uuid") or ""),
        raw_dict.get("output", raw_dict.get("result", raw_dict.get("error", ""))),
        _sha(raw_dict),
    )
