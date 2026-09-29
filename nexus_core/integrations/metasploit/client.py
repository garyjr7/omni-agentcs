"""Async Metasploit RPC client: MessagePack v10 and bearer-authenticated JSON.

The installed msfrpcd exposes MessagePack at /api/. Its JSON service is a
different server: MSF_RPC_PASSWORD must contain its API bearer token there.
Neither transport retries a failed call or starts external processes.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
import msgpack


class MetasploitError(Exception):
    """RPC failed; messages deliberately exclude remote bodies and secrets."""


class MetasploitUnavailable(MetasploitError):
    """Transport unavailable or request timed out."""


class MetasploitAuthError(MetasploitError):
    """Credentials were missing or rejected."""


def normalize(value: Any) -> Any:
    """Ruby's binary strings remain bytes even with unpackb(raw=False)."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {normalize(key): normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


@dataclass(frozen=True)
class MetasploitConfig:
    url: str
    user: str
    password: str = field(repr=False)
    timeout_seconds: float = 30.0
    transport: Literal["json", "msgpack"] = "msgpack"

    def __post_init__(self):
        if self.transport not in {"json", "msgpack"}:
            raise MetasploitError("unsupported MSF_RPC_TRANSPORT")
        try:
            url = httpx.URL(self.url)
        except (httpx.InvalidURL, ValueError):
            raise MetasploitError("invalid MSF_RPC_URL") from None
        if (
            url.scheme not in {"http", "https"}
            or not url.host
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
        ):
            raise MetasploitError("MSF_RPC_URL must be an HTTP origin without credentials")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise MetasploitError("invalid RPC timeout")

    @classmethod
    def from_env(cls) -> MetasploitConfig:
        return cls(
            url=os.getenv("MSF_RPC_URL", "http://127.0.0.1:55552"),
            user=os.getenv("MSF_RPC_USER", "msf"),
            password=os.getenv("MSF_RPC_PASSWORD", ""),
            transport=os.getenv("MSF_RPC_TRANSPORT", "msgpack").lower(),
        )


class MetasploitClient:
    def __init__(self, config: MetasploitConfig, *, transport=None):
        self._config = config
        self._token: str | None = None
        self._request_id = 0
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )

    async def __aenter__(self):
        try:
            await self.authenticate()
        except BaseException:
            await self._client.aclose()
            raise
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    async def aclose(self):
        await self._client.aclose()

    async def authenticate(self) -> None:
        if not self._config.password:
            raise MetasploitAuthError("RPC credentials missing")
        if self._config.transport == "json":
            # JSON-RPC uses HTTP bearer authentication, not v10 auth.login.
            self._token = self._config.password
            await self._rpc("core.version", [])
            return
        response = await self._rpc(
            "auth.login",
            [self._config.user, self._config.password],
            auth=False,
        )
        if (
            not isinstance(response, dict)
            or response.get("result") != "success"
            or not isinstance(response.get("token"), str)
            or not response["token"]
        ):
            raise MetasploitAuthError("auth.login did not return success and token")
        self._token = response["token"]

    async def _rpc(self, method: str, params: list, *, auth: bool = True) -> Any:
        if auth and not self._token:
            raise MetasploitAuthError("not authenticated")
        self._request_id += 1
        try:
            if self._config.transport == "msgpack":
                arguments = [method] + ([self._token] if auth else []) + params
                response = await self._client.post(
                    self._config.url.rstrip("/") + "/api/",
                    content=msgpack.packb(arguments, use_bin_type=True),
                    headers={"Content-Type": "binary/message-pack"},
                )
            else:
                response = await self._client.post(
                    self._config.url.rstrip("/") + "/api/v1/json-rpc",
                    json={
                        "jsonrpc": "2.0",
                        "id": self._request_id,
                        "method": method,
                        "params": params,
                    },
                    headers={"Authorization": f"Bearer {self._token}"},
                )
            if response.status_code in {401, 403}:
                raise MetasploitAuthError("RPC authentication rejected")
            response.raise_for_status()
            data = (
                normalize(msgpack.unpackb(response.content, raw=False))
                if self._config.transport == "msgpack"
                else response.json()
            )
        except httpx.RequestError:
            raise MetasploitUnavailable("msfrpcd unavailable or request timed out") from None
        except httpx.HTTPStatusError:
            raise MetasploitError("RPC HTTP error") from None
        except (ValueError, TypeError, msgpack.UnpackException):
            raise MetasploitError("invalid RPC response") from None
        if self._config.transport == "json":
            if (
                not isinstance(data, dict)
                or data.get("jsonrpc") != "2.0"
                or data.get("id") != self._request_id
                or "result" not in data
                or data.get("error")
            ):
                raise MetasploitError("invalid JSON-RPC result or RPC error")
            data = data["result"]
        if isinstance(data, dict) and data.get("error") and data.get("status") != "errored":
            raise MetasploitError("RPC error")
        return data

    async def is_available(self) -> bool:
        try:
            if not self._token:
                await self.authenticate()
            data = await self._rpc("core.version", [])
            return isinstance(data, dict) and bool(data.get("version"))
        except MetasploitError:
            return False

    async def search_modules(
        self,
        query: str = "",
        *,
        module_type: str | None = None,
        platform: str | None = None,
        cve: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if module_type and module_type not in {
            "exploit",
            "auxiliary",
            "post",
            "payload",
            "encoder",
            "nop",
            "evasion",
        }:
            raise ValueError("invalid module_type")
        if platform and not re.fullmatch(r"[A-Za-z0-9_.-]+", platform):
            raise ValueError("invalid platform")
        if cve and not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("invalid CVE")
        terms = [query]
        terms.extend(
            f"{key}:{value}"
            for key, value in (
                ("type", module_type),
                ("platform", platform),
                ("cve", cve),
            )
            if value
        )
        result = await self._rpc("module.search", [" ".join(terms).strip()])
        if not isinstance(result, list) or not all(isinstance(x, dict) for x in result):
            raise MetasploitError("invalid module.search result")
        return result[:limit]

    async def execute_module(self, fullname: str, options: dict) -> dict:
        result = await self._rpc(
            "module.execute",
            [
                self._module_type(fullname),
                fullname.split("/", 1)[1],
                options,
            ],
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("uuid"), str)
            or not result["uuid"]
        ):
            raise MetasploitError("module.execute did not return a UUID")
        return result

    async def get_module_results(self, uuid: str) -> dict:
        result = await self._rpc("module.results", [uuid])
        if not isinstance(result, dict) or "status" not in result:
            raise MetasploitError("invalid module.results response")
        return result

    async def stop_job(self, job_id: int) -> None:
        await self._rpc("job.stop", [str(job_id)])

    async def get_module_options(self, fullname: str) -> dict:
        """Declared datastore options of a module (``module.options``).

        Used to honour a module's *own* defaults (for example ``RPORT``) instead
        of inventing values in a handler. An unavailable/odd response degrades to
        an empty dict: the caller keeps its explicit options and lets msfrpcd
        apply the module default.
        """
        self._module_type(fullname)
        module_type, module_name = fullname.split("/", 1)
        result = await self._rpc("module.options", [module_type, module_name])
        return result if isinstance(result, dict) else {}

    async def list_sessions(self) -> dict[str, dict]:
        """Active sessions keyed by session UUID (``session.list``).

        ``session.list`` takes no parameters, so the RPC argument list is empty;
        passing a dict there would raise before reaching the daemon.
        """
        result = await self._rpc("session.list", [])
        if result is None:
            return {}
        if not isinstance(result, dict):
            raise MetasploitError("invalid session.list response")
        if not all(isinstance(value, dict) for value in result.values()):
            raise MetasploitError("session.list contains a malformed session")
        return result

    async def stop_session(self, session_uuid: str) -> dict:
        """Terminate one session (``session.stop``); ``{"result": "success"}``."""
        if not isinstance(session_uuid, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}", session_uuid
        ):
            raise ValueError("invalid session uuid")
        result = await self._rpc("session.stop", [session_uuid])
        return result if isinstance(result, dict) else {"result": result}

    async def execute_exploit(
        self,
        module_fullname: str,
        options: dict,
        *,
        wait_for_session_seconds: int = 120,
        poll_interval_seconds: float = 2.0,
    ) -> dict:
        """Run an exploit and wait for a *new* session to appear.

        Returns one of ``status in {"session_opened", "timeout", "failed"}``
        together with ``job_id``/``job_uuid``/``duration_seconds``. The loop is
        bounded by both a monotonic deadline and an attempt budget, so it always
        terminates and stays cancellable through ``asyncio`` timeouts.
        """
        if type(wait_for_session_seconds) is not int or not 1 <= wait_for_session_seconds <= 3600:
            raise ValueError("wait_for_session_seconds must be between 1 and 3600")
        if (
            not isinstance(poll_interval_seconds, (int, float))
            or isinstance(poll_interval_seconds, bool)
            or not math.isfinite(poll_interval_seconds)
            or not 0.1 <= poll_interval_seconds <= 60
        ):
            raise ValueError("poll_interval_seconds must be between 0.1 and 60")
        started = time.monotonic()
        before = set(await self.list_sessions())
        execution = await self.execute_module(module_fullname, options)
        job_id = execution.get("job_id") if type(execution.get("job_id")) is int else None
        job_uuid = str(execution["uuid"])
        attempts = max(1, math.ceil(wait_for_session_seconds / poll_interval_seconds))
        deadline = started + wait_for_session_seconds

        def outcome(status: str, **extra: Any) -> dict:
            return {
                "status": status,
                "module": module_fullname,
                "job_id": job_id,
                "job_uuid": job_uuid,
                "duration_seconds": round(time.monotonic() - started, 3),
                **extra,
            }

        for _ in range(attempts):
            sessions = await self.list_sessions()
            opened = sorted(set(sessions) - before)
            if opened:
                return outcome("session_opened", session_uuid=opened[0], session=sessions[opened[0]])
            results = await self.get_module_results(job_uuid)
            status = results.get("status")
            if status in {"errored", "failed"}:
                return outcome("failed", error=str(results.get("error") or status)[:500])
            if status == "completed" or time.monotonic() >= deadline:
                return outcome("timeout")
            await asyncio.sleep(poll_interval_seconds)
        return outcome("timeout")

    def redact(self, value: Any, extra_secrets: tuple[str, ...] = ()) -> Any:
        if isinstance(value, str):
            for secret in (self._config.password, self._token, *extra_secrets):
                if secret:
                    value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {
                self.redact(k, extra_secrets): self.redact(v, extra_secrets)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact(v, extra_secrets) for v in value]
        return value

    @staticmethod
    def _module_type(fullname: str) -> str:
        if not re.fullmatch(
            r"(?:exploit|auxiliary|post|payload|encoder|nop|evasion)/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*",
            fullname,
        ):
            raise MetasploitError("invalid module fullname")
        return fullname.split("/", 1)[0]
