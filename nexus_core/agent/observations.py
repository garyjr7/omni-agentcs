"""Compact tool observations before they enter the model context.

Every ReAct iteration re-sends the whole history, so a single 45 KB tool result
is paid for on *every* subsequent turn. ``nmap -p- -sV -sC`` can emit that much;
the fix (B4) is to keep the model on a bounded, structured summary and to store
the full payload as a content-addressed artifact that the report can cite.

Nothing here executes anything: it is pure reshaping plus one optional call to
the durable artifact store.
"""

from __future__ import annotations

import json
from typing import Any

from nexus_core.kernel.artifacts import ArtifactReference, ArtifactStore
from nexus_core.kernel.serialization import sanitized_object, encode_json, PayloadTooLarge

#: Observations longer than this are compacted (the durable message store is
#: text; full artifacts belong in the artifact store).
MAX_OBSERVATION_CHARS = 20_000

#: Character budget for the *raw* history handed to the model. A shared work
#: session accumulates every prior run's messages, and an unbounded prompt is
#: paid on every turn (and can exceed a provider's per-request token limit).
#: Older context still reaches the model through the summarised history block.
#: Measured on Simple CTF (2026-10-17): at 8 000 chars the raw history added
#: ~2 000 tokens to every turn on top of the (already compacted) system prompt
#: and pushed the run past 10 600 tokens/turn; 6 000 keeps the last few tool
#: results and lands the prompt under the 6 000-token target.
MAX_CONTEXT_CHARS = 6_000

#: Ports kept per host in an nmap summary. Real engagements rarely exceed this
#: and the model needs the services, not 65 535 closed ports.
NMAP_MAX_SUMMARY_PORTS = 80

#: Long free-text fields (product/version banners) are truncated per port.
MAX_SUMMARY_FIELD_CHARS = 60

#: Rows kept in a generic list summary.
GENERIC_MAX_ITEMS = 25


def encode_observation(value: Any) -> str:
    """JSON-encode an observation deterministically (never raises)."""
    return json.dumps(value, default=str, ensure_ascii=False)


def bounded_context(messages: list[Any], *, max_chars: int = MAX_CONTEXT_CHARS) -> list[Any]:
    """Keep the newest messages that fit a character budget (oldest dropped).

    The dropped tail is represented by the summarised history block already
    rendered into the system prompt, so the model keeps the gist without paying
    for every byte of the whole work session on each turn.
    """
    if max_chars <= 0:
        return list(messages)
    kept: list[Any] = []
    total = 0
    for message in reversed(messages):
        if isinstance(message, dict):
            size = len(str(message.get("content") or ""))
        else:
            size = len(str(getattr(message, "content", "") or ""))
        if kept and total + size > max_chars:
            break
        kept.append(message)
        total += size
        if total >= max_chars:
            break
    return list(reversed(kept))


def _short(value: Any, limit: int = MAX_SUMMARY_FIELD_CHARS) -> Any:
    """Truncate one free-text field so a single banner cannot blow the budget."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit]
    return value


def _compact_nmap(output: Any) -> dict[str, Any] | None:
    scan = output.get("scan") if isinstance(output, dict) else None
    if not isinstance(scan, dict):
        return None
    hosts: list[dict[str, Any]] = []
    ports_total = 0
    for host in scan.get("hosts") or []:
        if not isinstance(host, dict):
            continue
        ports: list[dict[str, Any]] = []
        for port in host.get("ports") or []:
            if not isinstance(port, dict):
                continue
            ports_total += 1
            if len(ports) >= NMAP_MAX_SUMMARY_PORTS:
                continue
            ports.append(
                {
                    key: _short(port.get(key))
                    for key in ("port", "protocol", "state", "service", "product", "version")
                    if port.get(key) not in (None, "")
                }
            )
        hosts.append(
            {
                "ip": _short(host.get("ip")),
                "hostname": _short(host.get("hostname")),
                "state": host.get("state"),
                "ports": ports,
            }
        )
    return {
        "hosts_up": scan.get("hosts_up"),
        "elapsed_seconds": scan.get("elapsed_seconds"),
        "ports_total": ports_total,
        "ports_truncated": ports_total > NMAP_MAX_SUMMARY_PORTS,
        "hosts": hosts,
    }


def _compact_httpx(output: Any) -> dict[str, Any] | None:
    probes = output.get("probes") if isinstance(output, dict) else None
    if not isinstance(probes, list):
        return None
    summarized = [
        {
            "url": _short(probe.get("url")),
            "status_code": probe.get("status_code"),
            "title": _short(probe.get("title")),
            "tech": [_short(item) for item in list(probe.get("tech") or [])[:20]],
        }
        for probe in probes[:GENERIC_MAX_ITEMS]
        if isinstance(probe, dict)
    ]
    return {"count": len(probes), "probes": summarized}


def _compact_whatweb(output: Any) -> dict[str, Any] | None:
    fingerprints = output.get("fingerprints") if isinstance(output, dict) else None
    if not isinstance(fingerprints, list):
        return None
    summarized = []
    for target in fingerprints[:GENERIC_MAX_ITEMS]:
        if not isinstance(target, dict):
            continue
        summarized.append(
            {
                "url": _short(target.get("url")),
                "http_status": target.get("http_status"),
                "fingerprints": [
                    {
                        "name": _short(item.get("name")),
                        "version": _short(item.get("version")),
                    }
                    for item in (target.get("fingerprints") or [])[:GENERIC_MAX_ITEMS]
                    if isinstance(item, dict)
                ],
            }
        )
    return {"count": len(fingerprints), "targets": summarized}


def _compact_generic(output: Any) -> Any:
    if isinstance(output, dict):
        return {
            key: (value[:GENERIC_MAX_ITEMS] if isinstance(value, list) else value)
            for key, value in output.items()
        }
    if isinstance(output, list):
        return output[:GENERIC_MAX_ITEMS]
    return output


_COMPACTERS = {
    "nexus.recon.nmap": _compact_nmap,
    "nexus.recon.httpx": _compact_httpx,
    "nexus.recon.whatweb": _compact_whatweb,
}


def compact_observation(tool_id: str, observation: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, structured version of one tool observation."""
    compact: dict[str, Any] = {
        key: value for key, value in observation.items() if key != "output"
    }
    compacter = _COMPACTERS.get(tool_id)
    summary = compacter(observation.get("output")) if compacter else None
    if summary is None:
        summary = _compact_generic(observation.get("output"))
    compact["output_summary"] = summary
    compact["compacted"] = True
    return compact


def default_artifact_store(store: Any) -> ArtifactStore:
    """Build the durable content-addressed store for compacted payloads.

    Imported lazily so importing this module never creates directories.
    """
    from nexus_core.config.xdg import resolve_xdg_paths
    from nexus_core.kernel.artifacts import configured_artifact_store

    return configured_artifact_store(store, resolve_xdg_paths().data_dir / "artifacts")


def prepare_observation(
    tool_id: str,
    observation: dict[str, Any],
    *,
    artifact_store: ArtifactStore | None = None,
    store: Any = None,
    tenant_id: str | None = None,
    run_id: str | None = None,
    limit_chars: int = MAX_OBSERVATION_CHARS,
) -> tuple[str, bool, dict[str, Any] | None]:
    """Encode an observation, compacting (and archiving) it when too large.

    Returns ``(content, compacted, artifact)`` where ``content`` is the JSON the
    model will read, ``compacted`` says whether reshaping happened, and
    ``artifact`` is the artifact-store record (or ``None``). ``store`` (a
    control store) is only used to *build* an artifact store when the payload is
    oversized, so no directory is created on the happy path.
    """
    if limit_chars < 512:
        raise ValueError("observation limit must be at least 512 characters")
    try:
        full = sanitized_object({**observation, "tool_id": tool_id})
    except PayloadTooLarge:
        return encode_observation({"error": "observation_too_large", "storage": {
            "status": "failed", "error_code": "PayloadTooLarge"}}), True, None
    except (ValueError, RecursionError):
        return encode_observation({"error": "invalid_observation", "storage": {
            "status": "failed", "error_code": "InvalidPayload"}}), True, None
    try:
        encoded = encode_json(full).decode()
    except PayloadTooLarge:
        return encode_observation({"error": "observation_too_large", "storage": {
            "status": "failed", "error_code": "PayloadTooLarge"}}), True, None
    if len(encoded) <= limit_chars:
        return encoded, False, None

    try:
        compact = compact_observation(tool_id, full)
    except (TypeError, ValueError, AttributeError):
        compact = {"tool_id": full["tool_id"], "compacted": True,
                   "output_summary": {"summary_error": "InvalidShape"}}
    artifact: dict[str, Any] | None = None
    storage: dict[str, str] = {"status": "unavailable", "error_code": "StoreNotConfigured"}
    try:
        if artifact_store is None and store is not None:
            artifact_store = default_artifact_store(store)
        if artifact_store is not None and tenant_id is not None:
            reference = ArtifactReference.parse(artifact_store.put(
                tenant_id, encoded.encode("utf-8"), "application/json", run_id=run_id,
                metadata={"tool_id": tool_id, "kind": "react-observation"},
            ))
            import hashlib
            if (reference.tenant_id != tenant_id or reference.size_bytes != len(encoded.encode())
                    or reference.sha256 != hashlib.sha256(encoded.encode()).hexdigest()
                    or reference.media_type != "application/json"):
                raise ValueError("observation artifact reference mismatch")
            artifact = reference.as_dict()
            compact["artifact"] = artifact
            storage = {"status": "stored"}
    except Exception as exc:  # Boundary: retain a safe summary and explicit failure.
        storage = {"status": "failed", "error_code": type(exc).__name__}
    compact["storage"] = storage
    compact_encoded = encode_observation(compact)
    if len(compact_encoded) > limit_chars:
        compact = {"tool_id": full["tool_id"][:100], "compacted": True,
                   "output_summary": {"summary_omitted": True}, "storage": storage}
        if artifact is not None:
            compact["artifact"] = artifact
        compact_encoded = encode_observation(compact)
        if len(compact_encoded) > limit_chars:
            compact.pop("artifact", None)
            compact["artifact_reference_omitted"] = artifact is not None
            compact_encoded = encode_observation(compact)
    return compact_encoded, True, artifact



__all__ = [
    "GENERIC_MAX_ITEMS",
    "MAX_CONTEXT_CHARS",
    "MAX_OBSERVATION_CHARS",
    "MAX_SUMMARY_FIELD_CHARS",
    "NMAP_MAX_SUMMARY_PORTS",
    "bounded_context",
    "compact_observation",
    "default_artifact_store",
    "encode_observation",
    "prepare_observation",
]
