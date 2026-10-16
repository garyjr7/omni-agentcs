"""Versioned journal references, with a verified reader for legacy records."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .artifacts import ArtifactReference, ArtifactStore, MAX_ARTIFACT_BYTES
from .serialization import decode_json, encode_json, result_payload


def encode_result(result: dict[str, Any], tenant_id: str,
                  artifacts: ArtifactStore | None) -> str:
    payload = result_payload(result)
    raw = encode_json(payload)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError("result exceeds persistence limit")
    digest = hashlib.sha256(raw).hexdigest()
    if artifacts is None:
        ref = {"version": 1, "kind": "inline", "payload": payload,
               "sha256": digest, "size_bytes": len(raw)}
    else:
        artifact = ArtifactReference.parse(artifacts.put(
            tenant_id, raw, "application/json", metadata={"source": "invocation_journal"}))
        if (artifact.tenant_id != tenant_id or artifact.sha256 != digest
                or artifact.size_bytes != len(raw) or artifact.media_type != "application/json"):
            raise ValueError("artifact result reference mismatch")
        ref = {"version": 1, "kind": "artifact", "artifact": artifact.as_dict()}
    return encode_json(ref).decode()


def decode_result(reference: str, tenant_id: str,
                  artifacts: ArtifactStore | None) -> dict[str, Any]:
    if len(reference) > MAX_ARTIFACT_BYTES * 2:
        raise ValueError("result reference exceeds limit")
    try:
        ref = decode_json(reference)
    except ValueError:
        # Only old records have a digest suffix. Split from the RIGHT so pipes
        # inside JSON string values retain their original meaning.
        value, separator, digest = reference.rpartition("|")
        if not separator or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("invalid legacy result reference") from None
        if value.lstrip().startswith("{"):
            raw = value.encode()
        else:
            if artifacts is None:
                raise RuntimeError("artifact store required")
            if not re.fullmatch(r"artifact_[a-f0-9]{32}", value):
                raise ValueError("invalid legacy artifact id")
            raw = artifacts.get(tenant_id, value)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError("invocation result integrity check failed")
        return result_payload(decode_json(raw))
    if not isinstance(ref, dict) or type(ref.get("version")) is not int or ref["version"] != 1:
        raise ValueError("unsupported result reference version")
    if ref.get("kind") == "inline":
        if set(ref) != {"version", "kind", "payload", "sha256", "size_bytes"}:
            raise ValueError("invalid inline reference fields")
        raw = encode_json(ref["payload"])
        digest, size = ref["sha256"], ref["size_bytes"]
    elif ref.get("kind") == "artifact":
        if set(ref) != {"version", "kind", "artifact"} or not isinstance(ref["artifact"], dict):
            raise ValueError("invalid artifact reference fields")
        artifact = ArtifactReference.parse(ref["artifact"])
        if artifact.tenant_id != tenant_id or artifact.media_type != "application/json":
            raise ValueError("artifact tenant or media type mismatch")
        if artifacts is None:
            raise RuntimeError("artifact store required")
        raw = artifacts.get(tenant_id, artifact.id)
        digest, size = artifact.sha256, artifact.size_bytes
    else:
        raise ValueError("invalid result reference kind")
    if type(size) is not int or size < 0 or len(raw) != size or size > MAX_ARTIFACT_BYTES:
        raise RuntimeError("invocation result size mismatch")
    if not isinstance(digest, str) or hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("invocation result integrity check failed")
    return result_payload(decode_json(raw))
