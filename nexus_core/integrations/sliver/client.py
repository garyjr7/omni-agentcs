"""Async gRPC client for Sliver C2.

A thin, fail-closed wrapper over ``sliver-py``. It connects to the team
server's *multiplayer* service over mTLS using the operator config file
(``.cfg``), talks asyncio gRPC end to end and never runs a local process.

Design rules (mirroring the Metasploit client):

- ``connect()`` is idempotent.
- A missing/empty ``SLIVER_OPERATOR_CONFIG`` raises :class:`SliverAuthError`
  with a clear remediation message; an unreachable server raises
  :class:`SliverUnavailable`.
- No infinite retries: every RPC is bounded by ``asyncio.timeout``.
- ``is_available()`` never raises.
- The provider config file (which embeds the mTLS private key and the auth
  token) is never logged and its path is redacted from tool output.
"""

from __future__ import annotations

import asyncio
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Extra seconds the outer asyncio timeout waits on top of the gRPC deadline,
#: so a slow-but-alive server produces a clean SliverUnavailable instead of a
#: raw grpc error.
RPC_SLACK_SECONDS = 5.0

#: Interactive kinds Sliver exposes.
SESSION_KINDS = ("session", "beacon")

GENERATE_HINT = (
    "genera un operator config con `sliver-server operator --name <op> "
    "--lhost <host> --save <ruta>.cfg` y define SLIVER_OPERATOR_CONFIG"
)


class SliverError(Exception):
    """A Sliver operation failed; messages never contain secrets."""


class SliverUnavailable(SliverError):
    """The team server could not be reached, timed out or answered badly."""


class SliverAuthError(SliverError):
    """The operator config is missing, unreadable or invalid."""


@dataclass(frozen=True)
class SliverConfig:
    """Connection parameters of the bridge (never reprs the config path)."""

    operator_config: str = field(repr=False)
    timeout_seconds: float = 30.0
    lhost: str = "127.0.0.1"
    lport: int = 31337

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("SLIVER_TIMEOUT must be a positive number")
        if type(self.lport) is not int or not 0 < self.lport < 65535:
            raise ValueError("SLIVER_LPORT must be between 1 and 65534")
        if not str(self.lhost).strip():
            raise ValueError("SLIVER_LHOST must not be empty")

    @classmethod
    def from_env(cls) -> "SliverConfig":
        return cls(
            operator_config=str(os.getenv("SLIVER_OPERATOR_CONFIG", "") or ""),
            timeout_seconds=float(os.getenv("SLIVER_TIMEOUT", "30")),
            lhost=str(os.getenv("SLIVER_LHOST", "127.0.0.1") or "127.0.0.1"),
            lport=int(os.getenv("SLIVER_LPORT", "31337")),
        )


def _decode(value: Any) -> str:
    """Sliver returns bytes for command output; be tolerant of str/None."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class SliverClient:
    """Async wrapper around :class:`sliver.SliverClient`."""

    def __init__(self, config: SliverConfig):
        self._config = config
        self._client: Any = None
        self._connected = False

    # ------------------------------------------------------------- lifecycle
    def _build_client(self) -> Any:
        """Instantiate the underlying sliver-py client (no connection yet)."""
        path_text = str(self._config.operator_config or "").strip()
        if not path_text:
            raise SliverAuthError(
                f"SLIVER_OPERATOR_CONFIG is not set; {GENERATE_HINT}"
            )
        config_path = Path(path_text)
        if not config_path.is_file():
            raise SliverAuthError(
                f"operator config not found: {config_path}; {GENERATE_HINT}"
            )
        try:
            from sliver import SliverClient as SliverPyClient
            from sliver import SliverClientConfig
        except ImportError as exc:  # pragma: no cover - sliver-py is a dependency
            raise SliverUnavailable("sliver-py is not installed") from exc
        try:
            parsed = SliverClientConfig.parse_config_file(str(config_path))
        except Exception as exc:  # noqa: BLE001 - a bad file must fail closed
            raise SliverAuthError(
                f"invalid operator config: {type(exc).__name__}"
            ) from exc
        return SliverPyClient(parsed)

    async def connect(self) -> None:
        """Connect to the team server. Idempotent."""
        if self._connected and self._client is not None:
            return
        if self._client is None:
            # Raises SliverAuthError before touching the network.
            self._client = self._build_client()
        try:
            async with asyncio.timeout(self._config.timeout_seconds + RPC_SLACK_SECONDS):
                await self._client.connect()
        except (asyncio.TimeoutError, TimeoutError) as exc:
            await self.disconnect()
            raise SliverUnavailable("sliver connect timed out") from exc
        except SliverError:
            await self.disconnect()
            raise
        except Exception as exc:  # noqa: BLE001 - never leak the raw traceback
            await self.disconnect()
            raise SliverUnavailable(
                f"sliver connect failed: {type(exc).__name__}"
            ) from exc
        self._connected = True

    async def disconnect(self) -> None:
        """Close the gRPC channel. Safe to call when not connected."""
        client, self._client = self._client, None
        self._connected = False
        if client is None:
            return
        # sliver-py 0.0.19 has no public disconnect: the channel is the real
        # resource, so it is always closed (a future ``disconnect`` is honoured
        # first when present).
        try:
            closer = getattr(client, "disconnect", None)
            if callable(closer):
                await closer()
        except Exception:  # noqa: BLE001 - closing is best-effort
            pass
        try:
            channel = getattr(client, "_channel", None)
            if channel is not None:
                await channel.close()
        except Exception:  # noqa: BLE001 - closing is best-effort
            pass

    async def __aenter__(self) -> "SliverClient":
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.disconnect()

    def is_connected(self) -> bool:
        return self._connected

    # -------------------------------------------------------------- helpers
    def _require_client(self) -> Any:
        if self._client is None:
            raise SliverUnavailable("not connected")
        return self._client

    async def _call(
        self, method: str, *args: Any, timeout: float | None = None, **kwargs: Any
    ) -> Any:
        """Invoke one sliver-py RPC, bounded by timeouts and fail-closed."""
        client = self._require_client()
        wait = self._config.timeout_seconds if timeout is None else float(timeout)
        call = getattr(client, method)
        try:
            async with asyncio.timeout(wait + RPC_SLACK_SECONDS):
                return await call(*args, timeout=wait, **kwargs)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise SliverUnavailable("sliver rpc timed out") from exc
        except SliverError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SliverUnavailable(
                f"sliver rpc failed: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def _to_dict(message: Any) -> dict:
        """Convert a protobuf message (or a plain dict) to a plain dict."""
        if message is None:
            return {}
        if isinstance(message, dict):
            return message
        from google.protobuf.json_format import MessageToDict

        return MessageToDict(
            message,
            preserving_proto_field_name=True,
            always_print_fields_with_no_presence=True,
        )

    # --------------------------------------------------------------- server
    async def version(self) -> dict:
        return self._to_dict(await self._call("version"))

    async def operators(self) -> list[dict]:
        return [self._to_dict(item) for item in await self._call("operators")]

    async def list_jobs(self) -> list[dict]:
        return [self._to_dict(item) for item in await self._call("jobs")]

    # ----------------------------------------------------- sessions/beacons
    async def list_sessions(self) -> list[dict]:
        return [self._to_dict(item) for item in await self._call("sessions")]

    async def list_beacons(self) -> list[dict]:
        return [self._to_dict(item) for item in await self._call("beacons")]

    async def session_info(self, session_id: str) -> dict | None:
        raw = await self._call("session_by_id", session_id)
        return None if raw is None else self._to_dict(raw)

    async def beacon_info(self, beacon_id: str) -> dict | None:
        raw = await self._call("beacon_by_id", beacon_id)
        return None if raw is None else self._to_dict(raw)

    async def kill_session(self, session_id: str, *, force: bool = False) -> dict:
        await self._call("kill_session", session_id, force=force)
        return {"session_id": session_id, "killed": True}

    async def kill_beacon(self, beacon_id: str) -> dict:
        await self._call("kill_beacon", beacon_id)
        return {"beacon_id": beacon_id, "killed": True}

    # ------------------------------------------------------------ interactive
    async def interact_session(self, session_id: str, *, timeout: float | None = None) -> Any:
        return await self._call("interact_session", session_id, timeout=timeout)

    async def interact_beacon(self, beacon_id: str, *, timeout: float | None = None) -> Any:
        return await self._call("interact_beacon", beacon_id, timeout=timeout)

    # -------------------------------------------------------------- implants
    async def list_implant_builds(self) -> dict[str, dict]:
        raw = await self._call("implant_builds")
        return {str(key): self._to_dict(value) for key, value in (raw or {}).items()}

    async def list_implant_profiles(self) -> list[dict]:
        return [self._to_dict(item) for item in await self._call("implant_profiles")]

    # --------------------------------------------------------- command exec
    async def execute_command(
        self,
        session_id: str,
        command: str,
        *,
        kind: str = "session",
        timeout_seconds: float | None = None,
    ) -> dict:
        """Run one shell command inside an interactive session or beacon.

        Sliver's ``execute`` takes an executable plus an argument list, so the
        interpreter is chosen by target OS (``cmd.exe /c`` on Windows,
        ``/bin/sh -c`` elsewhere). Returns a plain, hashable-friendly dict.
        """
        if kind not in SESSION_KINDS:
            raise ValueError("kind must be 'session' or 'beacon'")
        if not isinstance(command, str) or not command:
            raise ValueError("command must be a non-empty string")
        interactive = (
            await self.interact_session(session_id, timeout=timeout_seconds)
            if kind == "session"
            else await self.interact_beacon(session_id, timeout=timeout_seconds)
        )
        if interactive is None:
            raise SliverError("session does not exist")
        os_name = str(getattr(interactive, "os", "") or "").lower()
        if os_name.startswith("win"):
            exe, args = "cmd.exe", ["/c", command]
        else:
            exe, args = "/bin/sh", ["-c", command]
        wait = self._config.timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        started = time.monotonic()
        try:
            async with asyncio.timeout(wait + RPC_SLACK_SECONDS):
                result = await interactive.execute(exe, args)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise SliverUnavailable("sliver execute timed out") from exc
        except SliverError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SliverUnavailable(
                f"sliver execute failed: {type(exc).__name__}"
            ) from exc
        duration = round(time.monotonic() - started, 3)
        return {
            "session_id": str(session_id),
            "kind": kind,
            "command": command,
            "status_code": int(getattr(result, "Status", 0) or 0),
            "stdout": _decode(getattr(result, "Stdout", b"")),
            "stderr": _decode(getattr(result, "Stderr", b"")),
            "pid": int(getattr(result, "Pid", 0) or 0),
            "duration_seconds": duration,
        }

    # ---------------------------------------------------------------- pivot
    # sliver-py 0.0.19 exposes no high-level portfwd/SOCKS API, so these go
    # through the generated gRPC stub. The request still carries the owning
    # session, so it is as scoped as the high-level calls.
    async def _stub_call(
        self, method: str, request: Any, *, timeout: float | None = None
    ) -> Any:
        stub = getattr(self._require_client(), "_stub", None)
        if stub is None:  # pragma: no cover - a connected client always has one
            raise SliverUnavailable("sliver stub unavailable")
        wait = self._config.timeout_seconds if timeout is None else float(timeout)
        try:
            async with asyncio.timeout(wait + RPC_SLACK_SECONDS):
                return await getattr(stub, method)(request, timeout=wait)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise SliverUnavailable("sliver rpc timed out") from exc
        except SliverError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SliverUnavailable(f"sliver rpc failed: {type(exc).__name__}") from exc

    @staticmethod
    def _bind_request(request: Any, session_id: str, kind: str) -> Any:
        if kind == "beacon":
            request.Request.BeaconID = session_id
        else:
            request.Request.SessionID = session_id
        return request

    async def list_pivots(
        self, session_id: str, *, kind: str = "session", timeout_seconds: float | None = None
    ) -> list[dict]:
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(
            sliver_pb2.PivotListenersReq(), session_id, kind
        )
        result = await self._stub_call(
            "PivotSessionListeners", request, timeout=timeout_seconds
        )
        listeners = list(getattr(result, "Listeners", []) or [])
        return [self._to_dict(item) for item in listeners]

    async def start_portfwd(
        self,
        session_id: str,
        *,
        bind_port: int,
        remote_host: str,
        remote_port: int,
        kind: str = "session",
        timeout_seconds: float | None = None,
    ) -> dict:
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(
            sliver_pb2.PortfwdReq(
                Port=int(bind_port),
                Protocol=6,  # TCP
                Host=f"{remote_host}:{int(remote_port)}",
            ),
            session_id,
            kind,
        )
        result = await self._stub_call("Portfwd", request, timeout=timeout_seconds)
        return self._to_dict(result)

    async def start_socks5(
        self, session_id: str, *, kind: str = "session", timeout_seconds: float | None = None
    ) -> dict:
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(sliver_pb2.Socks(), session_id, kind)
        result = await self._stub_call("CreateSocks", request, timeout=timeout_seconds)
        return self._to_dict(result)

    async def stop_pivot(
        self,
        session_id: str,
        *,
        forward_id: int,
        kind: str = "session",
        timeout_seconds: float | None = None,
    ) -> dict:
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(
            sliver_pb2.PivotStopListenerReq(ID=int(forward_id)), session_id, kind
        )
        await self._stub_call("PivotStopListener", request, timeout=timeout_seconds)
        return {"forward_id": int(forward_id), "stopped": True}

    async def close_socks5(
        self,
        session_id: str,
        *,
        tunnel_id: int,
        kind: str = "session",
        timeout_seconds: float | None = None,
    ) -> dict:
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(
            sliver_pb2.Socks(TunnelID=int(tunnel_id)), session_id, kind
        )
        await self._stub_call("CloseSocks", request, timeout=timeout_seconds)
        return {"tunnel_id": int(tunnel_id), "closed": True}

    # ------------------------------------------------------------ implants
    # sliver-py exposes no high-level Generate/Upload/Execute/Loot helpers, so
    # these go through the generated gRPC stub. Nothing here runs locally.
    OUTPUT_FORMATS = {
        "shared": "SHARED_LIB",
        "shellcode": "SHELLCODE",
        "executable": "EXECUTABLE",
        "service": "SERVICE",
    }

    @staticmethod
    def _output_format(value: str) -> int:
        from sliver.protobuf import client_pb2

        name = SliverClient.OUTPUT_FORMATS.get(str(value or "executable").lower())
        if name is None:
            raise ValueError("unsupported implant format")
        return int(getattr(client_pb2, name))

    async def generate_implant(
        self,
        *,
        os_name: str,
        arch: str,
        format: str = "executable",
        beacon: bool = False,
        interval: int = 60,
        jitter: int = 30,
        name: str = "",
        persistent: bool = False,
        timeout_seconds: float | None = None,
    ) -> tuple[dict, bytes]:
        """Build one implant; returns (redacted info, implant bytes).

        ``persistent`` maps to a service implant that starts at load
        (``IsService`` + ``RunAtLoad``); the implant bytes are returned so the
        caller can deploy them without a second round-trip, and are never put
        in a tool result.
        """
        import hashlib

        from sliver.protobuf import client_pb2 as clientpb
        from sliver.protobuf import common_pb2

        config = clientpb.ImplantConfig(
            GOOS=str(os_name),
            GOARCH=str(arch),
            Format=self._output_format(format),
            IsBeacon=bool(beacon),
            BeaconInterval=int(interval),
            BeaconJitter=int(jitter),
            Name=str(name or ""),
            IsService=bool(persistent),
            RunAtLoad=bool(persistent),
        )
        result = await self._stub_call(
            "Generate", clientpb.GenerateReq(Config=config), timeout=timeout_seconds
        )
        file = getattr(result, "File", None) or common_pb2.File()
        data = bytes(getattr(file, "Data", b"") or b"")
        filename = _decode(getattr(file, "Name", "")) or str(name or os_name)
        return (
            {
                "name": str(name or os_name),
                "filename": filename,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "format": str(format),
                "os": str(os_name),
                "arch": str(arch),
                "beacon": bool(beacon),
                "persistent": bool(persistent),
            },
            data,
        )

    async def upload_file(
        self,
        session_id: str,
        remote_path: str,
        data: bytes,
        *,
        kind: str = "session",
        is_ioc: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict:
        """Upload ``data`` to ``remote_path`` on an owned session's host."""
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(
            sliver_pb2.UploadReq(
                Path=str(remote_path), Data=bytes(data), IsIOC=bool(is_ioc)
            ),
            session_id,
            kind,
        )
        result = await self._stub_call("Upload", request, timeout=timeout_seconds)
        return {"path": _decode(getattr(result, "Path", remote_path))}

    async def execute_path(
        self,
        session_id: str,
        path: str,
        args: tuple[str, ...] | list[str] = (),
        *,
        kind: str = "session",
        output: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict:
        """Execute an uploaded binary on the session's host (no shell)."""
        from sliver.protobuf import sliver_pb2

        request = self._bind_request(
            sliver_pb2.ExecuteReq(
                Path=str(path), Args=[str(arg) for arg in args], Output=bool(output)
            ),
            session_id,
            kind,
        )
        result = await self._stub_call("Execute", request, timeout=timeout_seconds)
        return {
            "path": str(path),
            "status_code": int(getattr(result, "Status", 0) or 0),
            "stdout": _decode(getattr(result, "Stdout", b"")),
            "stderr": _decode(getattr(result, "Stderr", b"")),
            "pid": int(getattr(result, "Pid", 0) or 0),
        }

    # ----------------------------------------------------------------- loot
    async def loot_list(self, *, timeout_seconds: float | None = None) -> list[dict]:
        from sliver.protobuf import common_pb2

        result = await self._stub_call(
            "LootAll", common_pb2.Empty(), timeout=timeout_seconds
        )
        return [self._to_dict(item) for item in (getattr(result, "Loot", []) or [])]

    async def loot_get(
        self, loot_id: str = "", *, name: str = "", timeout_seconds: float | None = None
    ) -> dict:
        from sliver.protobuf import client_pb2 as clientpb

        result = await self._stub_call(
            "LootContent",
            clientpb.Loot(LootID=str(loot_id), Name=str(name)),
            timeout=timeout_seconds,
        )
        return self._to_dict(result)

    async def loot_add_file(
        self, name: str, data: bytes, *, timeout_seconds: float | None = None
    ) -> dict:
        from sliver.protobuf import client_pb2 as clientpb
        from sliver.protobuf import common_pb2

        result = await self._stub_call(
            "LootAdd",
            clientpb.Loot(
                Type=clientpb.LOOT_FILE,
                Name=str(name),
                FileType=clientpb.BINARY,
                File=common_pb2.File(Name=str(name), Data=bytes(data)),
            ),
            timeout=timeout_seconds,
        )
        return self._to_dict(result)

    async def loot_add_credential(
        self,
        name: str,
        *,
        user: str = "",
        password: str = "",
        api_key: str = "",
        timeout_seconds: float | None = None,
    ) -> dict:
        from sliver.protobuf import client_pb2 as clientpb

        credential_type = clientpb.API_KEY if api_key else clientpb.USER_PASSWORD
        result = await self._stub_call(
            "LootAdd",
            clientpb.Loot(
                Type=clientpb.LOOT_CREDENTIAL,
                Name=str(name),
                CredentialType=credential_type,
                Credential=clientpb.Credential(
                    User=str(user), Password=str(password), APIKey=str(api_key)
                ),
            ),
            timeout=timeout_seconds,
        )
        return self._to_dict(result)

    # ------------------------------------------------------------- health
    async def is_available(self) -> bool:
        """Best-effort ping. Never raises."""
        try:
            await self.connect()
            await self._call("version")
            return True
        except SliverError:
            return False
        except Exception:  # noqa: BLE001 - a health probe must never raise
            return False

    # ----------------------------------------------------------- redaction
    def redact(self, value: Any, extra_secrets: tuple[str, ...] = ()) -> Any:
        """Recursively replace secrets (and the config path) with [REDACTED]."""
        secrets = tuple(
            secret
            for secret in (*extra_secrets, self._config.operator_config)
            if secret
        )
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {
                self.redact(key, extra_secrets): self.redact(item, extra_secrets)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact(item, extra_secrets) for item in value]
        return value
