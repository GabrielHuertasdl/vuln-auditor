"""Storage backend abstraction for scan artifacts.

Supports:
  - LocalStorageBackend: filesystem (default, dev + single-node prod)
  - S3StorageBackend: AWS S3 or S3-compatible (MinIO, Cloudflare R2, etc.)

Usage:
    from core.storage_backend import get_storage_backend

    backend = get_storage_backend()
    await backend.write(key="scans/abc123/scan.json", data=content.encode())
    data = await backend.read(key="scans/abc123/scan.json")

Keys use forward slashes and follow the pattern:
  scans/{scan_id}/{filename}
  reports/{scan_id}/{filename}
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator

log = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract interface for scan artifact storage."""

    @abstractmethod
    async def write(self, key: str, data: bytes) -> None:
        """Write bytes to the given key (creates/overwrites)."""

    @abstractmethod
    async def read(self, key: str) -> bytes:
        """Read bytes from the given key. Raises FileNotFoundError if missing."""

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Return True if the key exists in storage."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete the given key. No-op if it doesn't exist."""

    @abstractmethod
    async def list_prefix(self, prefix: str) -> list[str]:
        """Return all keys under the given prefix."""

    async def write_text(self, key: str, text: str, encoding: str = "utf-8") -> None:
        await self.write(key, text.encode(encoding))

    async def read_text(self, key: str, encoding: str = "utf-8") -> str:
        return (await self.read(key)).decode(encoding)


# ── Local filesystem backend ──────────────────────────────────────────────────

class LocalStorageBackend(StorageBackend):
    """Stores files on the local filesystem under a configurable root directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # Prevent path traversal
        resolved = (self.root / key).resolve()
        if not str(resolved).startswith(str(self.root.resolve())):
            raise ValueError(f"Path traversal detected: {key!r}")
        return resolved

    async def write(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        await asyncio.to_thread(tmp.write_bytes, data)
        await asyncio.to_thread(tmp.replace, path)

    async def read(self, key: str) -> bytes:
        path = self._path(key)
        if not path.exists():
            raise FileNotFoundError(f"Storage key not found: {key}")
        return await asyncio.to_thread(path.read_bytes)

    async def exists(self, key: str) -> bool:
        return self._path(key).exists()

    async def delete(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            await asyncio.to_thread(path.unlink)

    async def list_prefix(self, prefix: str) -> list[str]:
        base = self._path(prefix) if prefix else self.root
        if not base.exists():
            return []
        keys = []
        for p in base.rglob("*"):
            if p.is_file():
                keys.append(str(p.relative_to(self.root)))
        return keys

    def get_raw_path(self, key: str) -> Path:
        """Return the absolute filesystem path for a key (useful for legacy tool integrations)."""
        return self._path(key)


# ── S3 backend ────────────────────────────────────────────────────────────────

class S3StorageBackend(StorageBackend):
    """
    Stores files in AWS S3 or any S3-compatible service (MinIO, Cloudflare R2, etc.).

    Requires: pip install aioboto3 (or boto3 via asyncio.to_thread)

    Configure via environment:
      S3_BUCKET, S3_REGION, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY
      S3_ENDPOINT_URL (optional, for MinIO/custom endpoint)
    """

    def __init__(
        self,
        bucket: str,
        region: str = "us-east-1",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        endpoint_url: str | None = None,
        prefix: str = "",
    ) -> None:
        self.bucket = bucket
        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.endpoint_url = endpoint_url
        self.prefix = prefix.rstrip("/")

    def _s3_key(self, key: str) -> str:
        return f"{self.prefix}/{key}".lstrip("/") if self.prefix else key

    def _get_client(self):
        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "S3 storage backend requires boto3. Install with: pip install boto3"
            )
        kwargs: dict = {"region_name": self.region}
        if self.access_key_id:
            kwargs["aws_access_key_id"] = self.access_key_id
            kwargs["aws_secret_access_key"] = self.secret_access_key
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return boto3.client("s3", **kwargs)

    async def write(self, key: str, data: bytes) -> None:
        s3_key = self._s3_key(key)
        client = self._get_client()
        await asyncio.to_thread(
            client.put_object,
            Bucket=self.bucket,
            Key=s3_key,
            Body=data,
        )

    async def read(self, key: str) -> bytes:
        s3_key = self._s3_key(key)
        client = self._get_client()
        try:
            response = await asyncio.to_thread(
                client.get_object,
                Bucket=self.bucket,
                Key=s3_key,
            )
            return await asyncio.to_thread(response["Body"].read)
        except Exception as e:
            if "NoSuchKey" in str(type(e).__name__):
                raise FileNotFoundError(f"S3 key not found: {s3_key}")
            raise

    async def exists(self, key: str) -> bool:
        s3_key = self._s3_key(key)
        client = self._get_client()
        try:
            await asyncio.to_thread(
                client.head_object,
                Bucket=self.bucket,
                Key=s3_key,
            )
            return True
        except Exception:
            return False

    async def delete(self, key: str) -> None:
        s3_key = self._s3_key(key)
        client = self._get_client()
        await asyncio.to_thread(
            client.delete_object,
            Bucket=self.bucket,
            Key=s3_key,
        )

    async def list_prefix(self, prefix: str) -> list[str]:
        s3_prefix = self._s3_key(prefix)
        client = self._get_client()
        paginator = client.get_paginator("list_objects_v2")
        keys = []
        async for page in asyncio.to_thread(paginator.paginate, Bucket=self.bucket, Prefix=s3_prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"].removeprefix(self.prefix + "/"))
        return keys


# ── Factory ───────────────────────────────────────────────────────────────────

_backend_instance: StorageBackend | None = None


def get_storage_backend() -> StorageBackend:
    """Return the configured storage backend singleton."""
    global _backend_instance
    if _backend_instance is not None:
        return _backend_instance

    from core.config import settings

    if settings.storage_backend == "s3":
        if not settings.s3_bucket:
            raise RuntimeError(
                "S3_BUCKET is required when STORAGE_BACKEND=s3. "
                "Set S3_BUCKET in your environment."
            )
        _backend_instance = S3StorageBackend(
            bucket=settings.s3_bucket,
            region=settings.s3_region,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
            endpoint_url=settings.s3_endpoint_url,
            prefix="vulnaudit",
        )
        log.info("Using S3 storage backend: bucket=%s endpoint=%s", settings.s3_bucket, settings.s3_endpoint_url)
    else:
        _backend_instance = LocalStorageBackend(root=settings.data_dir)
        log.info("Using local storage backend: root=%s", settings.data_dir)

    return _backend_instance
