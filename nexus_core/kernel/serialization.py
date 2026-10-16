"""Strict JSON boundary: no object repr, non-finite numbers or excessive nesting."""
from __future__ import annotations

import json
import math
from typing import Any

from .redaction import sanitize


MAX_JSON_BYTES = 16 * 1024 * 1024


class PayloadTooLarge(ValueError):
    """The persistence boundary rejected an oversized payload."""


def validate_json(value: Any, depth: int = 0) -> None:
    # Preflight limits total string characters and nodes before redaction or
    # serialization makes copies. UTF-8 has at most four bytes per character.
    remaining = MAX_JSON_BYTES

    def visit(item: Any, level: int) -> None:
        nonlocal remaining
        if level > 64:
            raise ValueError("JSON nesting limit exceeded")
        remaining -= len(item) if isinstance(item, str) else 1
        if remaining < 0:
            raise PayloadTooLarge("JSON payload exceeds limit")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float) and math.isfinite(item):
            return
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            for key, child in item.items():
                visit(key, level + 1)
                visit(child, level + 1)
            return
        if isinstance(item, (list, tuple)):
            for child in item:
                visit(child, level + 1)
            return
        raise ValueError("unsupported JSON value")

    visit(value, depth)


def sanitized_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("payload must be an object")
    validate_json(value)
    result: dict[str, Any] = sanitize(value)
    return result


def encode_json(value: Any) -> bytes:
    validate_json(value)
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False)
    output = bytearray()
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        if len(output) + len(encoded) > MAX_JSON_BYTES:
            raise PayloadTooLarge("encoded JSON exceeds limit")
        output.extend(encoded)
    return bytes(output)


def decode_json(value: str | bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = item
        return result
    result = json.loads(value, object_pairs_hook=pairs)
    validate_json(result)
    return result


def result_payload(value: Any) -> dict[str, Any]:
    result = sanitized_object(value)
    if "evidence" in result and not isinstance(result["evidence"], dict):
        raise ValueError("evidence must be an object")
    for key in ("verified", "success"):
        if key in result and type(result[key]) is not bool:
            raise ValueError(f"{key} must be boolean")
    if "assertions" in result and (not isinstance(result["assertions"], list)
                                  or any(not isinstance(v, dict) for v in result["assertions"])):
        raise ValueError("assertions must be a list of objects")
    return result
