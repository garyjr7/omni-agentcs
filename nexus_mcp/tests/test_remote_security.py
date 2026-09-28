"""Remote MCP must fail closed unless its public identity is complete."""

import os
from unittest.mock import patch

import pytest

from nexus_mcp.server import validate_remote_configuration


def test_loopback_needs_no_remote_identity() -> None:
    validate_remote_configuration("127.0.0.1")


def test_remote_rejects_local_trust_in_production() -> None:
    with patch.dict(os.environ, {
        "NEXUS_ENV": "production",
        "NEXUS_MCP_TRUST_LOCAL_CONTAINER": "true",
    }, clear=True):
        with pytest.raises(SystemExit, match="forbidden"):
            validate_remote_configuration("0.0.0.0")


def test_remote_requires_https_and_audience() -> None:
    with patch.dict(os.environ, {
        "NEXUS_ENV": "production",
        "OIDC_ISSUER": "http://identity.example.test",
        "NEXUS_MCP_PUBLIC_URL": "https://mcp.example.test/mcp",
        "OIDC_AUDIENCE": "https://mcp.example.test/mcp",
    }, clear=True):
        with pytest.raises(SystemExit, match="OIDC_ISSUER must be an HTTPS URL"):
            validate_remote_configuration("0.0.0.0")


def test_remote_accepts_complete_public_identity() -> None:
    with patch.dict(os.environ, {
        "NEXUS_ENV": "production",
        "OIDC_ISSUER": "https://identity.example.test",
        "NEXUS_MCP_PUBLIC_URL": "https://mcp.example.test/mcp",
        "OIDC_AUDIENCE": "https://mcp.example.test/mcp",
    }, clear=True):
        validate_remote_configuration("0.0.0.0")
