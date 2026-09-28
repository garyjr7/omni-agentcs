from pathlib import Path
from unittest.mock import patch

import pytest

from nexus_core.utils.security import (
    InputValidator,
    SecurityLevel,
    SecurityMiddleware,
    SecurityPolicy,
    SecurityViolationError,
)


@pytest.mark.unit
def test_path_containment_blocks_prefix_and_traversal(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = SecurityPolicy(allowed_paths=[str(allowed)], blocked_paths=[])
    assert InputValidator.validate_file_path(str(allowed / "ok.txt"), policy).endswith("ok.txt")
    with pytest.raises(SecurityViolationError):
        InputValidator.validate_file_path(str(tmp_path / "allowed-evil" / "secret"), policy)
    with pytest.raises(SecurityViolationError):
        InputValidator.validate_file_path(str(allowed / ".." / "secret"), policy)


@pytest.mark.unit
def test_high_policy_blocks_dynamic_execution():
    policy = SecurityPolicy(level=SecurityLevel.HIGH)
    with pytest.raises(SecurityViolationError):
        InputValidator.validate_content("eval('unsafe')", policy)


@pytest.mark.unit
def test_url_validation_blocks_ssrf():
    policy = SecurityPolicy(allow_network=True)
    with patch("nexus_core.utils.security.socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]):
        with pytest.raises(SecurityViolationError, match="Private or reserved"):
            InputValidator.validate_url("http://example.test/path", policy)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rate_limit_and_blocked_attempt_are_audited(tmp_path: Path):
    policy = SecurityPolicy(
        allowed_paths=[str(tmp_path)], blocked_paths=[], rate_limit_per_minute=1
    )
    middleware = SecurityMiddleware(policy)
    await middleware.intercept("agent", "read_file", {"file_path": str(tmp_path / "ok")})
    with pytest.raises(SecurityViolationError, match="Rate Limit"):
        await middleware.intercept("agent", "read_file", {"file_path": str(tmp_path / "ok")})

    blocked = SecurityMiddleware(SecurityPolicy(allowed_paths=[str(tmp_path)], blocked_paths=[]))
    with pytest.raises(SecurityViolationError):
        await blocked.intercept("agent", "unknown", {})
    assert blocked.get_stats()["blocked"] == 1
    assert blocked.get_audit_trail()[0]["blocked"] is True
