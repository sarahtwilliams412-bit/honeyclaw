#!/usr/bin/env python3
"""
Honeyclaw Immutable Log Storage

Configures and manages S3 buckets with Object Lock for tamper-proof log
retention. Provides write-once-read-many (WORM) guarantees for forensic
log integrity.

Environment variables:
    IMMUTABLE_S3_BUCKET          - S3 bucket name for immutable logs
    IMMUTABLE_S3_REGION          - AWS region (default: us-east-1)
    IMMUTABLE_S3_PREFIX          - Key prefix (default: immutable-logs/)
    IMMUTABLE_S3_ENDPOINT        - Custom S3 endpoint (for MinIO, etc.)
    IMMUTABLE_RETENTION_DAYS     - Object Lock retention in days (default: 90)
    IMMUTABLE_RETENTION_MODE     - COMPLIANCE or GOVERNANCE (default: COMPLIANCE)
    IMMUTABLE_VERSIONING         - Enable versioning (default: true)
    IMMUTABLE_REPLICATION_BUCKET - Cross-region replication bucket (optional)
    IMMUTABLE_REPLICATION_REGION - Replication region (optional)
    AWS_ACCESS_KEY_ID            - AWS credentials
    AWS_SECRET_ACCESS_KEY        - AWS credentials

Requires: boto3 (pip install boto3)
"""

import os
import json
import gzip
import hashlib
import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict

logger = logging.getLogger("honeyclaw.immutable_storage")

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logger.info("boto3 not installed — immutable storage disabled (pip install boto3)")


DEFAULT_RETENTION_DAYS = 90
DEFAULT_PREFIX = "immutable-logs/"
DEFAULT_REGION = "us-east-1"
FLUSH_INTERVAL_SECONDS = 30
MAX_BUFFER_SIZE = 500


@dataclass
class ImmutableStorageConfig:
    """Configuration for immutable S3 log storage."""

    bucket: str = ""
    region: str = DEFAULT_REGION
    prefix: str = DEFAULT_PREFIX
    endpoint_url: Optional[str] = None
    retention_days: int = DEFAULT_RETENTION_DAYS
    retention_mode: str = "COMPLIANCE"  # COMPLIANCE or GOVERNANCE
    versioning_enabled: bool = True
    replication_bucket: Optional[str] = None
    replication_region: Optional[str] = None
    compress: bool = True  # gzip compress before upload

    @classmethod
    def from_env(cls) -> "ImmutableStorageConfig":
        """Load configuration from environment variables."""
        return cls(
            bucket=os.environ.get("IMMUTABLE_S3_BUCKET", ""),
            region=os.environ.get("IMMUTABLE_S3_REGION", DEFAULT_REGION),
            prefix=os.environ.get("IMMUTABLE_S3_PREFIX", DEFAULT_PREFIX),
            endpoint_url=os.environ.get("IMMUTABLE_S3_ENDPOINT"),
            retention_days=int(
                os.environ.get("IMMUTABLE_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)
            ),
            retention_mode=os.environ.get(
                "IMMUTABLE_RETENTION_MODE", "COMPLIANCE"
            ).upper(),
            versioning_enabled=os.environ.get(
                "IMMUTABLE_VERSIONING", "true"
            ).lower()
            == "true",
            replication_bucket=os.environ.get("IMMUTABLE_REPLICATION_BUCKET"),
            replication_region=os.environ.get("IMMUTABLE_REPLICATION_REGION"),
        )


class ImmutableLogStore:
    """
    Writes log events to S3 with Object Lock for tamper-proof retention.

    Events are buffered, compressed, and uploaded in batches. Each uploaded
    object receives an Object Lock retention period in COMPLIANCE mode,
    preventing deletion or modification for the configured retention period.

    Thread-safe.
    """

    def __init__(self, config: Optional[ImmutableStorageConfig] = None):
        self.config = config or ImmutableStorageConfig.from_env()
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._client = None
        self._replication_client = None
        self._enabled = False

        # Statistics
        self._stats = {
            "events_buffered": 0,
            "events_shipped": 0,
            "objects_uploaded": 0,
            "upload_errors": 0,
            "bytes_uploaded": 0,
        }

        if not self.config.bucket:
            logger.info("Immutable storage not configured (no bucket specified)")
            return

        if not BOTO3_AVAILABLE:
            logger.warning(
                "boto3 not available — immutable storage disabled"
            )
            return

        try:
            kwargs = {"region_name": self.config.region}
            if self.config.endpoint_url:
                kwargs["endpoint_url"] = self.config.endpoint_url
            self._client = boto3.client("s3", **kwargs)
            self._enabled = True
            logger.info(
                f"Immutable log storage enabled: "
                f"s3://{self.config.bucket}/{self.config.prefix}"
            )

            # Set up replication client if configured
            if self.config.replication_bucket and self.config.replication_region:
                rep_kwargs = {"region_name": self.config.replication_region}
                self._replication_client = boto3.client("s3", **rep_kwargs)
                logger.info(
                    f"Replication target: "
                    f"s3://{self.config.replication_bucket}/ "
                    f"({self.config.replication_region})"
                )
        except NoCredentialsError:
            logger.warning("AWS credentials not configured — immutable storage disabled")
        except Exception as e:
            logger.warning(f"Failed to initialize S3 client: {e}")

        # Background flush thread
        self._stop_event = threading.Event()
        if self._enabled:
            self._flush_thread = threading.Thread(
                target=self._flush_loop, daemon=True
            )
            self._flush_thread.start()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def store_event(self, event: Dict[str, Any]) -> None:
        """
        Buffer an event for immutable storage.

        Events are batched and uploaded periodically or when the buffer
        reaches MAX_BUFFER_SIZE.
        """
        if not self._enabled:
            return

        with self._lock:
            self._buffer.append(event)
            self._stats["events_buffered"] += 1

            if len(self._buffer) >= MAX_BUFFER_SIZE:
                self._flush_locked()

    def flush(self) -> int:
        """Force flush buffered events to S3. Returns count of events shipped."""
        if not self._enabled:
            return 0
        with self._lock:
            return self._flush_locked()

    def setup_bucket(self) -> Dict[str, Any]:
        """
        Configure the S3 bucket for immutable storage.

        Enables:
        - Versioning
        - Object Lock (default retention)
        - Lifecycle rules for storage class transitions

        Returns dict with setup results. Call this once during initial setup.
        """
        if not self._enabled:
            return {"error": "Immutable storage not enabled"}

        results = {}

        # Enable versioning
        if self.config.versioning_enabled:
            try:
                self._client.put_bucket_versioning(
                    Bucket=self.config.bucket,
                    VersioningConfiguration={"Status": "Enabled"},
                )
                results["versioning"] = "enabled"
                logger.info(f"Versioning enabled on {self.config.bucket}")
            except ClientError as e:
                results["versioning_error"] = str(e)
                logger.error(f"Failed to enable versioning: {e}")

        # Set default Object Lock retention
        try:
            self._client.put_object_lock_configuration(
                Bucket=self.config.bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {
                        "DefaultRetention": {
                            "Mode": self.config.retention_mode,
                            "Days": self.config.retention_days,
                        }
                    },
                },
            )
            results["object_lock"] = {
                "mode": self.config.retention_mode,
                "days": self.config.retention_days,
            }
            logger.info(
                f"Object Lock configured: {self.config.retention_mode} "
                f"for {self.config.retention_days} days"
            )
        except ClientError as e:
            results["object_lock_error"] = str(e)
            logger.error(f"Failed to configure Object Lock: {e}")

        # Set lifecycle rules
        try:
            self._client.put_bucket_lifecycle_configuration(
                Bucket=self.config.bucket,
                LifecycleConfiguration={
                    "Rules": [
                        {
                            "ID": "honeyclaw-ia-transition",
                            "Status": "Enabled",
                            "Filter": {"Prefix": self.config.prefix},
                            "Transitions": [
                                {
                                    "Days": 30,
                                    "StorageClass": "STANDARD_IA",
                                },
                                {
                                    "Days": 90,
                                    "StorageClass": "GLACIER",
                                },
                            ],
                        }
                    ]
                },
            )
            results["lifecycle"] = "configured"
            logger.info("Lifecycle rules configured (IA at 30d, Glacier at 90d)")
        except ClientError as e:
            results["lifecycle_error"] = str(e)
            logger.error(f"Failed to configure lifecycle: {e}")

        return results

    def verify_integrity(self, key: str) -> Dict[str, Any]:
        """
        Verify the integrity and lock status of a stored log object.

        Returns dict with version_id, lock_mode, lock_retain_until, and
        content_hash for independent verification.
        """
        if not self._enabled:
            return {"error": "Immutable storage not enabled"}

        try:
            resp = self._client.head_object(
                Bucket=self.config.bucket, Key=key
            )

            result = {
                "key": key,
                "version_id": resp.get("VersionId"),
                "content_length": resp.get("ContentLength"),
                "etag": resp.get("ETag"),
                "last_modified": resp.get("LastModified", "").isoformat()
                if hasattr(resp.get("LastModified", ""), "isoformat")
                else str(resp.get("LastModified", "")),
            }

            # Check Object Lock status
            try:
                lock_resp = self._client.get_object_retention(
                    Bucket=self.config.bucket, Key=key
                )
                retention = lock_resp.get("Retention", {})
                result["lock_mode"] = retention.get("Mode")
                retain_date = retention.get("RetainUntilDate")
                result["lock_retain_until"] = (
                    retain_date.isoformat()
                    if hasattr(retain_date, "isoformat")
                    else str(retain_date)
                )
                result["immutable"] = True
            except ClientError:
                result["immutable"] = False

            return result

        except ClientError as e:
            return {"error": str(e), "key": key}

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        with self._lock:
            return {
                **self._stats,
                "buffer_size": len(self._buffer),
                "enabled": self._enabled,
                "bucket": self.config.bucket,
                "retention_days": self.config.retention_days,
                "retention_mode": self.config.retention_mode,
                "replication": bool(self.config.replication_bucket),
            }

    def shutdown(self):
        """Flush remaining events and stop background thread."""
        self._stop_event.set()
        if self._enabled:
            self.flush()

    def _flush_locked(self) -> int:
        """Flush buffer — must be called with self._lock held."""
        if not self._buffer:
            return 0

        events = self._buffer
        self._buffer = []

        # Release lock during upload
        count = len(events)

        # Build NDJSON content
        lines = [json.dumps(e, default=str) for e in events]
        content = "\n".join(lines) + "\n"
        content_bytes = content.encode("utf-8")

        # Generate key with timestamp-based path
        now = datetime.now(timezone.utc)
        date_prefix = now.strftime("%Y/%m/%d")
        time_part = now.strftime("%H%M%S")
        content_hash = hashlib.sha256(content_bytes).hexdigest()[:12]
        key = (
            f"{self.config.prefix}{date_prefix}/"
            f"events_{time_part}_{content_hash}.jsonl"
        )

        # Compress if enabled
        if self.config.compress:
            content_bytes = gzip.compress(content_bytes)
            key += ".gz"

        # Upload to primary bucket
        success = self._upload_object(
            self._client, self.config.bucket, key, content_bytes
        )

        if success:
            self._stats["events_shipped"] += count
            self._stats["objects_uploaded"] += 1
            self._stats["bytes_uploaded"] += len(content_bytes)

            # Replicate to secondary bucket
            if self._replication_client and self.config.replication_bucket:
                self._upload_object(
                    self._replication_client,
                    self.config.replication_bucket,
                    key,
                    content_bytes,
                )
        else:
            self._stats["upload_errors"] += 1

        return count if success else 0

    def _upload_object(
        self, client, bucket: str, key: str, content: bytes
    ) -> bool:
        """Upload bytes to S3 with Object Lock retention."""
        try:
            put_kwargs: Dict[str, Any] = {
                "Bucket": bucket,
                "Key": key,
                "Body": content,
                "ContentType": "application/x-ndjson",
            }

            if self.config.compress:
                put_kwargs["ContentEncoding"] = "gzip"

            # Add content hash for integrity verification
            content_md5 = hashlib.md5(content).digest()
            import base64

            put_kwargs["ContentMD5"] = base64.b64encode(content_md5).decode()

            # Set per-object retention (supplements bucket default)
            retain_until = datetime.now(timezone.utc) + timedelta(
                days=self.config.retention_days
            )
            put_kwargs["ObjectLockMode"] = self.config.retention_mode
            put_kwargs["ObjectLockRetainUntilDate"] = retain_until

            client.put_object(**put_kwargs)
            logger.debug(f"Uploaded immutable log: s3://{bucket}/{key}")
            return True

        except ClientError as e:
            # Object Lock may not be enabled on bucket — fall back to plain upload
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in (
                "InvalidRequest",
                "ObjectLockConfigurationNotFoundError",
            ):
                try:
                    simple_kwargs = {
                        "Bucket": bucket,
                        "Key": key,
                        "Body": content,
                        "ContentType": "application/x-ndjson",
                    }
                    if self.config.compress:
                        simple_kwargs["ContentEncoding"] = "gzip"
                    client.put_object(**simple_kwargs)
                    logger.warning(
                        f"Object Lock not available on {bucket} — "
                        f"uploaded without lock"
                    )
                    return True
                except Exception as e2:
                    logger.error(f"Failed to upload to s3://{bucket}/{key}: {e2}")
                    return False
            else:
                logger.error(f"Failed to upload to s3://{bucket}/{key}: {e}")
                return False
        except Exception as e:
            logger.error(f"Failed to upload to s3://{bucket}/{key}: {e}")
            return False

    def _flush_loop(self):
        """Periodically flush buffered events."""
        while not self._stop_event.wait(FLUSH_INTERVAL_SECONDS):
            with self._lock:
                if self._buffer:
                    self._flush_locked()
