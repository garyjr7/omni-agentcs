"""Minimal BAJIOWARE Desktop Connector client with filesystem allowlists."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import ssl
import urllib.request
from pathlib import Path


class ConnectorFilesystem:
    def __init__(self, allowed_roots: list[str]):
        self.roots = [Path(root).expanduser().resolve() for root in allowed_roots]

    def resolve(self, path: str) -> Path:
        candidate = Path(path).expanduser().resolve()
        if not any(candidate == root or root in candidate.parents for root in self.roots):
            raise PermissionError("path is outside connector allowlist")
        return candidate

    def list(self, path: str) -> list[dict]:
        resolved = self.resolve(path)
        return [{"name": item.name, "type": "dir" if item.is_dir() else "file"}
                for item in sorted(resolved.iterdir())]

    def read_text(self, path: str, max_bytes: int = 1_000_000) -> str:
        resolved = self.resolve(path)
        if resolved.stat().st_size > max_bytes:
            raise ValueError("file exceeds connector read limit")
        return resolved.read_text(encoding="utf-8")


def heartbeat(server: str, connector_id: str, credential: str,
              cert_file: str | None = None, key_file: str | None = None) -> dict:
    request = urllib.request.Request(
        f"{server.rstrip('/')}/connectors/{connector_id}/heartbeat",
        method="POST",
        headers={"X-NEXUS-Connector-Token": credential},
    )
    context = ssl.create_default_context()
    if cert_file:
        context.load_cert_chain(cert_file, key_file)
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        return json.loads(response.read())


class SignedUpdate:
    """Verify Ed25519 update metadata and install atomically with one-step rollback."""

    @staticmethod
    def verify(payload: bytes, expected_sha256: str, signature_b64: str,
               public_key_pem: bytes) -> None:
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ValueError("update checksum mismatch")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("connector update key must be Ed25519")
        key.verify(base64.b64decode(signature_b64, validate=True), payload)

    @classmethod
    def install(cls, target: Path, payload: bytes, expected_sha256: str,
                signature_b64: str, public_key_pem: bytes) -> Path:
        cls.verify(payload, expected_sha256, signature_b64, public_key_pem)
        target = target.resolve()
        backup = target.with_suffix(target.suffix + ".previous")
        staging = target.with_suffix(target.suffix + ".staging")
        staging.write_bytes(payload)
        if target.exists():
            shutil.copy2(target, backup)
        os.replace(staging, target)
        return backup

    @staticmethod
    def rollback(target: Path) -> None:
        target = target.resolve()
        backup = target.with_suffix(target.suffix + ".previous")
        if not backup.exists():
            raise FileNotFoundError("connector update backup not found")
        os.replace(backup, target)


def main() -> None:
    parser = argparse.ArgumentParser(description="BAJIOWARE Desktop Connector")
    parser.add_argument("--heartbeat", action="store_true")
    args = parser.parse_args()
    if args.heartbeat:
        print(json.dumps(heartbeat(
            os.environ["NEXUS_SERVER_URL"], os.environ["NEXUS_CONNECTOR_ID"],
            os.environ["NEXUS_CONNECTOR_TOKEN"],
            os.getenv("NEXUS_CONNECTOR_CERT"), os.getenv("NEXUS_CONNECTOR_KEY"),
        ), indent=2))


if __name__ == "__main__":
    main()
