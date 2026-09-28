"""Small dependency-free validator for the JSON Schema subset used by tools."""

from __future__ import annotations

from typing import Any, Dict


class SchemaValidationError(ValueError):
    pass


TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "object": dict, "array": list, "string": str, "integer": int,
    "number": (int, float), "boolean": bool, "null": type(None),
}


def validate(instance: Any, schema: Dict[str, Any], path: str = "$") -> None:
    expected = schema.get("type")
    if expected:
        accepted = TYPE_MAP.get(expected)
        if not accepted:
            raise SchemaValidationError(f"{path}: unsupported schema type {expected}")
        if not isinstance(instance, accepted) or (expected in {"integer", "number"} and isinstance(instance, bool)):
            raise SchemaValidationError(f"{path}: expected {expected}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value is not in enum")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [name for name in required if name not in instance]
        if missing:
            raise SchemaValidationError(f"{path}: missing required fields {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = set(instance) - set(properties)
            if extras:
                raise SchemaValidationError(f"{path}: unexpected fields {sorted(extras)}")
        for name, value in instance.items():
            if name in properties:
                validate(value, properties[name], f"{path}.{name}")
    if isinstance(instance, list) and "items" in schema:
        for index, value in enumerate(instance):
            validate(value, schema["items"], f"{path}[{index}]")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise SchemaValidationError(f"{path}: string is too short")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise SchemaValidationError(f"{path}: string is too long")
