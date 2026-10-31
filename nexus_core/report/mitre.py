"""MITRE ATT&CK enrichment from a local, offline reference table.

The table lives in ``data/mitre_techniques.json`` (subset of ATT&CK enterprise
techniques relevant to an authorized engagement) and the tool/technique map in
``data/tool_ttp_map.json``. Nothing here calls the network: the report must be
reproducible and fail-safe.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).with_name("data")
TECHNIQUES_FILE = DATA_DIR / "mitre_techniques.json"
TOOL_MAP_FILE = DATA_DIR / "tool_ttp_map.json"

#: Command -> techniques. Keys are matched against the first token of the
#: command sent into a session, case-insensitively.
COMMAND_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "id": ("T1033",),
    "whoami": ("T1033",),
    "uname": ("T1082",),
    "hostname": ("T1082",),
    "sysinfo": ("T1082",),
    "systeminfo": ("T1082",),
    "ver": ("T1082",),
    "ipconfig": ("T1016",),
    "ifconfig": ("T1016",),
    "arp": ("T1016",),
    "route": ("T1016",),
    "netstat": ("T1046",),
    "ps": ("T1057",),
    "tasklist": ("T1057",),
    "ls": ("T1083",),
    "dir": ("T1083",),
    "pwd": ("T1083",),
    "cat": ("T1005",),
    "type": ("T1005",),
    "download": ("T1005",),
    "upload": ("T1105",),
    "getuid": ("T1033",),
    "getpid": ("T1057",),
    "getprivs": ("T1068",),
    "getsystem": ("T1068",),
    "hashdump": ("T1003",),
    "lsa_secrets": ("T1003",),
    "creds_all": ("T1003",),
    "kiwi": ("T1003",),
    "migrate": ("T1055",),
    "migrate_exec": ("T1055",),
    # ``steal_token``/``sh`` are recorded as separate first tokens, not aliases.
    "shell": ("T1059",),
    "execute": ("T1059",),
    "sessions": ("T1021",),
    "portfwd": ("T1021",),
    "run": ("T1059",),
    "clearev": ("T1070",),
    "timestomp": ("T1070",),
    "reg": ("T1112",),
    "netsh": ("T1562",),
    "sc": ("T1053",),
    "at": ("T1053",),
}

#: Everything in the map must exist in the technique table.
TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9_.-]")


def dataset_available() -> bool:
    """Whether both ATT&CK data files are installed.

    A wheel built without ``package-data`` for this package loses them (measured:
    ``nexus.report.generate`` died with ``FileNotFoundError`` on
    ``tool_ttp_map.json`` after a pipx install and the gateway reported the tool
    as ``unavailable``). The report can still be produced -ATT&CK enrichment is
    metadata- but it must say that it omitted it.
    """
    return TECHNIQUES_FILE.is_file() and TOOL_MAP_FILE.is_file()


def _read_dataset(path: Path, name: str) -> Any:
    """Read one dataset: missing file means "not installed", corrupt still fails.

    An absent optional dataset must not destroy a report that is otherwise
    complete (the durable record is the source of truth). A *malformed* file is a
    different thing -a broken install- and keeps raising.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    except ValueError as error:
        raise ValueError(f"{name} is not valid JSON: {error}") from error


@lru_cache(maxsize=1)
def techniques() -> dict[str, dict[str, str]]:
    """Return the parsed ``{technique_id: {name, tactic}}`` reference table."""
    data = _read_dataset(TECHNIQUES_FILE, "mitre_techniques.json")
    if data is None:
        return {}
    if not isinstance(data, dict) or not data:
        raise ValueError("mitre_techniques.json must be a non-empty object")
    for technique_id, value in data.items():
        if not isinstance(value, dict) or not value.get("name") or not value.get("tactic"):
            raise ValueError(f"mitre technique {technique_id} is malformed")
    return data


@lru_cache(maxsize=1)
def tool_map() -> dict[str, tuple[str, ...]]:
    """Return the parsed ``{tool_id: (technique_id, ...)}`` map."""
    data = _read_dataset(TOOL_MAP_FILE, "tool_ttp_map.json")
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("tool_ttp_map.json must be an object")
    return {
        str(tool_id): tuple(str(item) for item in (value or ()))
        for tool_id, value in data.items()
    }


def technique_name(technique_id: str) -> str:
    """Human-readable ATT&CK name (falls back to the bare id)."""
    entry = techniques().get(str(technique_id))
    return str(entry["name"]) if entry else str(technique_id)


def technique_tactic(technique_id: str) -> str:
    """ATT&CK tactic of a technique (empty when unknown)."""
    entry = techniques().get(str(technique_id))
    return str(entry["tactic"]) if entry else ""


def techniques_for_tool(tool_id: str) -> tuple[str, ...]:
    """Techniques statically mapped to a tool id (empty when unmapped)."""
    return tuple(tool_map().get(str(tool_id), ()))


def _first_token(command: str) -> str:
    head = str(command or "").strip().splitlines()[0] if str(command or "").strip() else ""
    return TOKEN_SPLIT.split(head.strip().lower(), maxsplit=1)[0] if head else ""


def techniques_for_command(command: str) -> tuple[str, ...]:
    """Techniques implied by one command sent into a session."""
    return tuple(COMMAND_TECHNIQUES.get(_first_token(command), ()))


def merge_techniques(*groups: Any) -> tuple[str, ...]:
    """Union of technique ids, preserving first-seen order."""
    merged: list[str] = []
    for group in groups:
        for item in group or ():
            value = str(item)
            if value and value not in merged:
                merged.append(value)
    return tuple(merged)


def enrich_finding_with_mitre(finding: Any) -> Any:
    """Return a copy of ``finding`` whose techniques are complete and ordered.

    The union combines what the finding already declared (for example from a
    session command) with the static map of the tool that discovered it. An
    empty result is legitimate: not every observation maps to a technique.
    """
    techniques_value = merge_techniques(
        finding.mitre_techniques, techniques_for_tool(finding.discovered_by_tool)
    )
    return replace(finding, mitre_techniques=techniques_value)


__all__ = [
    "COMMAND_TECHNIQUES",
    "dataset_available",
    "enrich_finding_with_mitre",
    "merge_techniques",
    "technique_name",
    "technique_tactic",
    "techniques",
    "techniques_for_command",
    "techniques_for_tool",
    "tool_map",
]
