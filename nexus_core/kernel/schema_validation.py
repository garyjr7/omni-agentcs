"""Strict JSON Schema enforcement for tool inputs (V1-10).

The previous validator hand-implemented a subset of JSON Schema: ``type``,
``enum``, ``required``, ``properties``, ``additionalProperties``, ``items``,
``minLength`` and ``maxLength``. Every other keyword the catalog declares was
silently ignored —``minimum``/``maximum``, ``minItems``/``maxItems``,
``minProperties``/``maxProperties`` and ``pattern``— so a tool advertised limits
that no caller had to honour and each handler had to re-implement (or forget)
its own bounds. An out-of-range port, a 500-entry target list or a session id
with the wrong shape reached the handler as if the contract allowed it.

This module delegates to ``jsonschema`` with the Draft 2020-12 validator the
schemas are written against, so a declared keyword is an enforced keyword.
``check_schema`` fails closed when a definition carries a malformed schema,
which turns "discovered on the first invocation" into "rejected at
registration".
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Dict, Mapping

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError


class SchemaValidationError(ValueError):
    """Invalid arguments or an invalid schema, reported with a JSON path."""


def _cache_key(schema: Mapping[str, Any]) -> str:
    """Canonical form used to memoize compiled validators.

    Catalog schemas are built once per definition but validated on every
    invocation, and ``jsonschema`` compiles a validator per call. Keying on the
    serialized schema keeps the hot path cheap without holding references to
    mutable dicts.
    """
    return json.dumps(schema, sort_keys=True, default=str)


@lru_cache(maxsize=512)
def _compiled(key: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads(key))


def _validator(schema: Mapping[str, Any]) -> Draft202012Validator:
    try:
        return _compiled(_cache_key(schema))
    except TypeError:  # pragma: no cover - non JSON-serializable schema value
        return Draft202012Validator(dict(schema))


def check_schema(schema: Mapping[str, Any] | None) -> None:
    """Reject a definition whose schema is not valid Draft 2020-12.

    Raises ``SchemaValidationError`` (a ``ValueError``) so a malformed contract
    fails where the tool is registered, not where it is first invoked.
    """
    if not schema:
        return
    try:
        _checked(_cache_key(schema))
    except SchemaError as exc:
        location = "/".join(str(part) for part in exc.absolute_path) or "<root>"
        raise SchemaValidationError(
            f"invalid tool schema at {location}: {exc.message}"
        ) from None
    except TypeError:  # pragma: no cover - non JSON-serializable schema value
        try:
            Draft202012Validator.check_schema(dict(schema))
        except SchemaError as exc:
            raise SchemaValidationError(f"invalid tool schema: {exc.message}") from None


@lru_cache(maxsize=512)
def _checked(key: str) -> None:
    Draft202012Validator.check_schema(json.loads(key))


def _unknown_property_hint(error: ValidationError) -> str:
    """Name the allowed property an unknown one was reaching for.

    The allowed list alone is not enough: hijack_v5 (2026-10-29) sent
    ``credential_ref`` to ``nexus.web.request`` -the field is ``session_ref``- and
    the rejection listed sixteen names the model could not choose between, so the
    next turn guessed again (``rejected``, ``vault_handle``) and the credential the
    run had just proved went unused for 27 turns.

    A field is matched by its last ``_``-separated segment and only when exactly
    one allowed property shares it (``credential_ref``/``session_ref`` → ``ref``);
    with two candidates there is no hint, because a wrong suggestion is worse than
    none. The hint never restates the value: only whether it is a ``vault:`` handle,
    which tells the model that the field travels as-is.
    """
    schema = error.schema if isinstance(error.schema, dict) else {}
    properties = schema.get("properties")
    instance = error.instance if isinstance(error.instance, dict) else {}
    if not isinstance(properties, dict) or not instance:
        return ""
    for name in sorted(str(key) for key in instance):
        if name in properties or "_" not in name:
            continue
        tail = name.rsplit("_", 1)[-1]
        matches = [
            allowed
            for allowed in properties
            if "_" in str(allowed) and str(allowed).rsplit("_", 1)[-1] == tail
        ]
        if len(matches) != 1:
            continue
        hint = f"; '{name}' no existe: el campo que acepta ese valor aquí es '{matches[0]}'"
        if isinstance(instance.get(name), str) and str(instance[name]).startswith("vault:"):
            hint += " (un handle vault:... se pasa tal cual, el motor lo resuelve)"
        return hint
    return ""


def _location(path: str, error: ValidationError) -> str:
    """Join the caller's prefix with the failing JSON path.

    Keeps the previous ``$.field: message`` convention while reporting the
    nested location jsonschema resolved.
    """
    location = error.json_path or "$"
    if location in ("$", ""):
        return path
    if path in ("$", ""):
        return location
    return path + location[1:]


def validate(instance: Any, schema: Dict[str, Any], path: str = "$") -> None:
    """Validate ``instance`` against ``schema`` or raise ``SchemaValidationError``.

    Every keyword in the schema is enforced; the first failure (in document
    order) is reported so the operator sees the field the contract rejects
    instead of a generic "invalid arguments".
    """
    validator = _validator(schema)
    error = next(validator.iter_errors(instance), None)
    if error is None:
        return
    message = error.message
    if error.validator == "additionalProperties" and isinstance(error.schema, dict):
        # The raw message says what was rejected but not what the contract does
        # accept, so the model has to guess and burns a turn (run
        # 1052d63f9bba4838902b3aa21bd27d21: an ``options`` key met sqlmap's
        # schema, the rejection was opaque, and the next attempt spent 500 s).
        properties = error.schema.get("properties")
        allowed = sorted(str(key) for key in properties) if isinstance(properties, dict) else []
        if allowed:
            message += f" (allowed: {', '.join(allowed)})"
        message += _unknown_property_hint(error)
    raise SchemaValidationError(f"{_location(path, error)}: {message}") from None
