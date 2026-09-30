"""Credential redaction in :meth:`AuditWriter._sanitize`.

In AD/impacket contexts a ``hash`` is a full credential (NTLM relay), so the
sanitizer must redact it by field name. Integrity digests must survive.
"""

from __future__ import annotations

import pytest

from nexus_core.kernel.audit import AuditWriter

pytestmark = pytest.mark.unit


def test_sanitize_redacts_hash():
    sanitized = AuditWriter._sanitize({"hash": "a" * 32})
    assert sanitized["hash"] == "[REDACTED]"


def test_sanitize_redacts_hashes_lmnt():
    sanitized = AuditWriter._sanitize({"hashes": "a" * 32 + ":" + "b" * 32})
    assert sanitized["hashes"] == "[REDACTED]"


def test_sanitize_redacts_nested_hash():
    sanitized = AuditWriter._sanitize({"args": {"ntlm_hash": "abc"}})
    assert sanitized["args"]["ntlm_hash"] == "[REDACTED]"


def test_sanitize_redacts_nested_hashes_list():
    sanitized = AuditWriter._sanitize(
        {"args": [{"lm_hash": "x"}, {"nthash": "y"}]}
    )
    assert sanitized["args"][0]["lm_hash"] == "[REDACTED]"
    assert sanitized["args"][1]["nthash"] == "[REDACTED]"


def test_sanitize_redacts_whole_credentials_field():
    sanitized = AuditWriter._sanitize({"credentials": [{"lm_hash": "x"}]})
    assert sanitized["credentials"] == "[REDACTED]"


def test_sanitize_preserves_non_sensitive_keys():
    # Integrity digests are not credentials and must not be redacted.
    payload = {
        "content_sha256": "abc",
        "raw_sha256": "def",
        "event_hash": "ghi",
        "target": "10.0.0.5",
    }
    assert AuditWriter._sanitize(payload) == payload


@pytest.mark.parametrize(
    "key",
    ["password", "passwd", "pwd", "token", "api_key", "apikey", "authorization",
     "auth", "private_key", "ssh_key", "bearer", "cookie", "session_id",
     "password_hash", "credential"],
)
def test_sanitize_redacts_all_known_secret_terms(key):
    assert AuditWriter._sanitize({key: "value"})[key] == "[REDACTED]"
