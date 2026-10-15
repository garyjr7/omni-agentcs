"""Tenant-scoped content-addressed repository with pluggable blob storage."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


def validate_address(tenant_id: str, digest: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", tenant_id):
        raise ValueError("invalid artifact tenant")
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("invalid artifact digest")


@dataclass(frozen=True)
class ArtifactReference:
    id: str
    tenant_id: str
    sha256: str
    size_bytes: int
    media_type: str

    def __post_init__(self) -> None:
        validate_address(self.tenant_id, self.sha256)
        if not re.fullmatch(r"artifact_[a-f0-9]{32}", self.id):
            raise ValueError("invalid artifact id")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("invalid artifact size")
        if not re.fullmatch(r"[\w.+-]+/[\w.+-]+(?:;[^\r\n]+)?", self.media_type):
            raise ValueError("invalid artifact media type")

    @classmethod
    def parse(cls, value: dict[str, Any]) -> ArtifactReference:
        if set(value) != {"id", "tenant_id", "sha256", "size_bytes", "media_type"}:
            raise ValueError("invalid artifact reference fields")
        if any(not isinstance(value[k], str) for k in ("id", "tenant_id", "sha256", "media_type")):
            raise ValueError("invalid artifact reference types")
        return cls(**value)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ArtifactStore(Protocol):
    def put(self, tenant_id: str, content: bytes, media_type: str,
            run_id: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def get(self, tenant_id: str, artifact_id: str) -> bytes: ...


class BlobBackend(Protocol):
    """Implementations must provide immutable, tenant-scoped atomic publication."""
    def put(self, tenant_id: str, digest: str, content: bytes) -> None: ...
    def get(self, tenant_id: str, digest: str, max_bytes: int) -> bytes: ...


class FilesystemBlobBackend:
    """Local or shared POSIX volume; all workers must mount the same contents.

    Directory descriptors and O_NOFOLLOW prevent symlink traversal. Publication
    uses an atomic hard link, so racing writers never replace an existing blob.
    The configured root and its ancestors must be managed by the operator.
    """
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _directory(self, tenant_id: str, digest: str, *, create: bool) -> Iterator[int]:
        validate_address(tenant_id, digest)
        descriptors = [os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
        try:
            for part in (tenant_id, digest[:2]):
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptors[-1])
                        os.fsync(descriptors[-1])
                    except FileExistsError:
                        pass
                descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                           dir_fd=descriptors[-1]))
            yield descriptors[-1]
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def put(self, tenant_id: str, digest: str, content: bytes) -> None:
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("blob digest mismatch")
        with self._directory(tenant_id, digest, create=True) as directory:
            name = f".{uuid4().hex}.tmp"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(name, digest, src_dir_fd=directory, dst_dir_fd=directory,
                            follow_symlinks=False)
                    os.fsync(directory)
                except FileExistsError:
                    if self.get(tenant_id, digest, len(content)) != content:
                        raise RuntimeError("existing artifact integrity check failed")
            finally:
                os.unlink(name, dir_fd=directory)

    def get(self, tenant_id: str, digest: str, max_bytes: int) -> bytes:
        with self._directory(tenant_id, digest, create=False) as directory:
            fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                    raise RuntimeError("artifact size or file type rejected")
                content = stream.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise RuntimeError("artifact exceeds read limit")
                return content


class ArtifactRepository:
    def __init__(self, store: ControlStore, backend: BlobBackend,
                 max_bytes: int = MAX_ARTIFACT_BYTES) -> None:
        if max_bytes < 0:
            raise ValueError("artifact limit must be nonnegative")
        self.store, self.backend, self.max_bytes = store, backend, max_bytes

    def put(self, tenant_id: str, content: bytes, media_type: str,
            run_id: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        from .serialization import sanitized_object, encode_json
        if not isinstance(content, bytes) or len(content) > self.max_bytes:
            raise ValueError("artifact payload exceeds limit or is not bytes")
        digest = hashlib.sha256(content).hexdigest()
        ref = ArtifactReference(f"artifact_{uuid4().hex}", tenant_id, digest, len(content), media_type)
        encoded_metadata = encode_json(sanitized_object(metadata or {})).decode()
        self.backend.put(tenant_id, digest, content)
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_artifacts
                (id,tenant_id,run_id,media_type,storage_uri,sha256,size_bytes,metadata,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (ref.id, tenant_id, run_id, media_type, f"cas:v1/{tenant_id}/{digest}", digest,
                 len(content), encoded_metadata, utc_now()),
            )
        return ref.as_dict()

    def get(self, tenant_id: str, artifact_id: str) -> bytes:
        if not isinstance(artifact_id, str) or not re.fullmatch(r"artifact_[a-f0-9]{32}", artifact_id):
            raise ValueError("invalid artifact id")
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_artifacts WHERE id=? AND tenant_id=?",
                (artifact_id, tenant_id),
            ).fetchone()
        if not row:
            raise KeyError("artifact not found")
        ref = ArtifactReference(artifact_id, tenant_id, row["sha256"], row["size_bytes"], row["media_type"])
        if ref.size_bytes > self.max_bytes:
            raise RuntimeError("artifact exceeds read limit")
        uri = row["storage_uri"]
        expected = f"cas:v1/{tenant_id}/{ref.sha256}"
        if uri != expected:
            # Legacy absolute paths are translated by content address, never opened.
            path = Path(uri)
            if not path.is_absolute() or path.parts[-3:] != (tenant_id, ref.sha256[:2], ref.sha256):
                raise RuntimeError("artifact storage address rejected")
        content = self.backend.get(tenant_id, ref.sha256, ref.size_bytes)
        if len(content) != ref.size_bytes or hashlib.sha256(content).hexdigest() != ref.sha256:
            raise RuntimeError("artifact integrity check failed")
        return content


class LocalArtifactStore(ArtifactRepository):
    """Compatibility facade; a shared mount can be supplied as root."""
    def __init__(self, store: ControlStore, root: str | Path,
                 max_bytes: int = MAX_ARTIFACT_BYTES) -> None:
        backend = FilesystemBlobBackend(root)
        self.root = backend.root
        super().__init__(store, backend, max_bytes)


def configured_artifact_store(store: ControlStore, default_root: str | Path) -> LocalArtifactStore:
    mode = os.environ.get("NEXUS_ARTIFACT_MODE", "local")
    root = os.environ.get("NEXUS_ARTIFACT_ROOT")
    if mode not in {"local", "shared"}:
        raise ValueError("invalid artifact storage mode")
    if mode == "shared" and (not root or not Path(root).is_absolute()):
        raise ValueError("shared artifact storage requires an absolute NEXUS_ARTIFACT_ROOT")
    if mode == "shared" and root is not None and not Path(root).is_dir():
        raise FileNotFoundError("shared artifact root must already exist")
    return LocalArtifactStore(store, root or default_root)
