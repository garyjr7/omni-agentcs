"""End-to-end API smoke with ephemeral SQLite and Fake LLM."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path


async def smoke() -> None:
    with tempfile.TemporaryDirectory() as directory:
        os.environ.update({
            "NEXUS_ENV": "development",
            "NEXUS_DB_PATH": str(Path(directory) / "api.db"),
            "NEXUS_DATA_PATH": directory,
            "JWT_SECRET_KEY": "api-smoke-secret-key-with-more-than-thirty-two-bytes",
            "NEXUS_ADMIN_EMAIL": "admin@example.com",
            "NEXUS_ADMIN_PASSWORD": "correct-horse-battery-staple",
            "LLM_PROVIDER": "fake",
            "CORS_ORIGINS": "https://console.example.test",
        })
        import httpx

        from nexus_api.main import app, lifespan

        unprotected = [route.path for route in app.routes
                       if hasattr(route, "path") and route.path.startswith("/api/v1")
                       and hasattr(route, "dependant") and not route.dependant.dependencies]
        assert unprotected == [], f"unprotected v1 routes: {unprotected}"

        async with lifespan(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                health = await client.get("/health")
                assert health.status_code == 200
                assert health.json()["durable_control_plane"] == "ok"
                unauthenticated = await client.get(
                    "/api/v1/directory/agents", params={"tenant_id": "system"}
                )
                assert unauthenticated.status_code == 401
                login = await client.post("/api/v1/auth/login", json={
                    "email": "admin@example.com", "password": "correct-horse-battery-staple",
                    "tenant_id": "system",
                })
                assert login.status_code == 200, login.text
                tokens = login.json()
                headers = {"Authorization": f"Bearer {tokens['access_token']}"}
                tenant = await client.post(
                    "/api/v1/directory/tenants", headers=headers,
                    json={"name": "BAJIOWARE Demo", "tenant_id": "bajioware-demo"},
                )
                assert tenant.status_code == 201, tenant.text
                agent = await client.post(
                    "/api/v1/directory/agents", headers=headers,
                    json={
                        "tenant_id": "bajioware-demo",
                        "name": "bajioware-marketing-agent",
                        "description": "Marketing lead",
                        "capabilities": ["campaign_dispatch", "lead_scoring"],
                    },
                )
                assert agent.status_code == 201, agent.text
                conversation = await client.post(
                    "/api/v1/sovereign/conversations", headers=headers,
                    json={"tenant_id": "system", "title": "Sovereign smoke"},
                )
                assert conversation.status_code == 201, conversation.text
                queued_message = await client.post(
                    f"/api/v1/sovereign/conversations/{conversation.json()['id']}/messages",
                    headers=headers, json={"content": "hola", "model_route": "fake"},
                )
                assert queued_message.status_code == 202, queued_message.text
                sovereign_run = await client.get(
                    f"/api/v1/sovereign/runs/{queued_message.json()['run']['id']}",
                    headers=headers, params={"tenant_id": "system"},
                )
                assert sovereign_run.status_code == 200, sovereign_run.text
                workflow = await client.post(
                    "/api/v1/workflows", headers=headers,
                    json={
                        "tenant_id": "bajioware-demo",
                        "name": "marketing_campaign_simulation",
                        "definition": {"steps": [{
                            "key": "draft", "task_type": "debug.fake_llm",
                            "payload": {"message": "Create campaign", "scenario": "echo"},
                        }]},
                    },
                )
                assert workflow.status_code == 201, workflow.text
                dispatched = await client.post(
                    "/api/v1/workflows/dispatch", headers=headers,
                    json={
                        "tenant_id": "bajioware-demo",
                        "workflow_name": "marketing_campaign_simulation",
                        "input_data": {"target_audience": "SMBs"},
                    },
                )
                assert dispatched.status_code == 202, dispatched.text
                audit = await client.get(
                    "/api/v1/audit/logs", headers=headers,
                    params={"tenant_id": "bajioware-demo"},
                )
                assert audit.status_code == 200, audit.text
                assert audit.json()["total"] >= 2
                import jwt

                from nexus_api.auth.service import (
                    ALGORITHM,
                    JWT_AUDIENCE,
                    JWT_ISSUER,
                    SECRET_KEY,
                )
                expired = jwt.encode({
                    "sub": tokens["user"]["id"], "exp": int(time.time()) - 1,
                    "iat": int(time.time()) - 60, "jti": "expired-smoke-token",
                    "iss": JWT_ISSUER, "aud": JWT_AUDIENCE,
                }, SECRET_KEY, algorithm=ALGORITHM)
                assert (await client.get("/api/v1/auth/me", headers={
                    "Authorization": f"Bearer {expired}"
                })).status_code == 401
                agents = await client.get(
                    "/api/v1/directory/agents",
                    params={"tenant_id": "system"}, headers=headers,
                )
                assert agents.status_code == 200
                refresh_as_access = await client.get(
                    "/api/v1/directory/agents", params={"tenant_id": "system"},
                    headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
                )
                assert refresh_as_access.status_code == 401
                refreshed = await client.post(
                    "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
                )
                assert refreshed.status_code == 200
                assert (await client.post(
                    "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
                )).status_code == 401
                for role in ("operator", "viewer"):
                    created = await client.post("/api/v1/auth/users", headers=headers, json={
                        "email": f"{role}@example.com", "name": role,
                        "password": "role-password-is-long", "role": role,
                        "tenant_id": "system",
                    })
                    assert created.status_code == 201, created.text
                    role_login = await client.post("/api/v1/auth/login", json={
                        "email": f"{role}@example.com",
                        "password": "role-password-is-long", "tenant_id": "system",
                    })
                    role_headers = {
                        "Authorization": f"Bearer {role_login.json()['access_token']}"
                    }
                    assert (await client.get(
                        "/api/v1/directory/agents", params={"tenant_id": "system"},
                        headers=role_headers,
                    )).status_code == 403
                    memory_status = await client.get("/api/v1/memory/agents", headers=role_headers)
                    assert memory_status.status_code == 200
                assert (await client.get(
                    "/system/metrics", headers=headers
                )).status_code == 200
                preflight = await client.options(
                    "/health", headers={"Origin": "https://evil.example",
                                         "Access-Control-Request-Method": "GET"},
                )
                assert preflight.status_code == 400
                logout = await client.post("/api/v1/auth/logout", headers=headers)
                assert logout.status_code == 200
                assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401


def main() -> None:
    asyncio.run(smoke())


if __name__ == "__main__":
    main()
