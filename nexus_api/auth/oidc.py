"""Optional OIDC bearer verification with discovery/JWKS caching."""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx
import jwt
from jwt import InvalidTokenError as JWTError


class OIDCVerifier:
    def __init__(self):
        self.issuer = os.getenv("OIDC_ISSUER", "").rstrip("/")
        self.audience = os.getenv("OIDC_AUDIENCE", "nexus-api")
        self.tenant_claim = os.getenv("OIDC_TENANT_CLAIM", "tenant_id")
        self.role_claim = os.getenv("OIDC_ROLE_CLAIM", "nexus_role")
        self._keys: dict[str, Any] = {}
        self._expires = 0.0
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.issuer)

    async def _refresh(self) -> None:
        if os.getenv("NEXUS_ENV", "development") == "production" and not self.issuer.startswith("https://"):
            raise JWTError("production OIDC issuer must use HTTPS")
        async with self._lock:
            if self._keys and time.monotonic() < self._expires:
                return
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                discovery = (await client.get(
                    f"{self.issuer}/.well-known/openid-configuration"
                )).raise_for_status().json()
                if discovery.get("issuer", "").rstrip("/") != self.issuer:
                    raise JWTError("OIDC discovery issuer mismatch")
                jwks_uri = discovery.get("jwks_uri", "")
                if not jwks_uri.startswith(self.issuer + "/"):
                    raise JWTError("OIDC JWKS endpoint must belong to the configured issuer")
                keys = (await client.get(jwks_uri)).raise_for_status().json().get("keys", [])
            self._keys = {item["kid"]: item for item in keys if item.get("kid")}
            self._expires = time.monotonic() + 300

    async def verify(self, token: str) -> dict:
        if not self.enabled:
            raise JWTError("OIDC is not configured")
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in {"RS256", "ES256"} or not header.get("kid"):
            raise JWTError("unsupported OIDC token algorithm")
        await self._refresh()
        key = self._keys.get(header["kid"])
        if not key:
            self._expires = 0
            await self._refresh()
            key = self._keys.get(header["kid"])
        if not key:
            raise JWTError("OIDC signing key not found")
        claims = jwt.decode(
            token, jwt.PyJWK.from_dict(key).key, algorithms=[header["alg"]],
            audience=self.audience, issuer=self.issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
        role = claims.get(self.role_claim, "viewer")
        if role not in {"admin", "operator", "viewer"}:
            role = "viewer"
        tenant_id = claims.get(self.tenant_claim)
        if not tenant_id:
            raise JWTError("OIDC token has no tenant claim")
        return {
            "id": f"oidc:{claims['sub']}", "tenant_id": str(tenant_id),
            "email": claims.get("email", ""), "name": claims.get("name", claims["sub"]),
            "role": role, "active": True, "identity_provider": self.issuer,
        }


oidc_verifier = OIDCVerifier()
