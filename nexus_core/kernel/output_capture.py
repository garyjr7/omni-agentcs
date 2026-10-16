"""Bounded binary capture: hashes describe observed bytes, never decoded text."""
from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class StreamManifest:
    total_bytes: int
    retained_bytes: int
    discarded_bytes: int
    sha256: str
    retained_sha256: str
    truncated: bool
    complete: bool
    error: str | None


class BoundedCapture:
    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("capture limit must be nonnegative")
        self.limit = limit
        self.buffer = bytearray()
        self.total = 0
        self.digest = hashlib.sha256()
        self.complete = False
        self.error: str | None = None

    async def drain(self, reader: asyncio.StreamReader) -> None:
        try:
            while chunk := await reader.read(65536):
                self.total += len(chunk)
                self.digest.update(chunk)
                self.buffer.extend(chunk[:max(0, self.limit - len(self.buffer))])
            self.complete = True
        except OSError as exc:
            self.error = type(exc).__name__
        except asyncio.CancelledError:
            self.error = "DrainInterrupted"
            raise

    def manifest(self) -> StreamManifest:
        retained = len(self.buffer)
        return StreamManifest(self.total, retained, self.total - retained,
                              self.digest.hexdigest(), hashlib.sha256(self.buffer).hexdigest(),
                              self.total > retained, self.complete, self.error)

    def text(self) -> str:
        return self.buffer.decode("utf-8", errors="replace")
