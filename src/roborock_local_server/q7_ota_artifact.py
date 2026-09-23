"""Short-lived, private delivery of an owner-prepared Q7 OTA candidate.

The server never builds an OTA or sends an upgrade command. An admin uploads
encrypted bytes and receives an opaque download path for a controlled trial.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time


TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MD5_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
MAX_PACKAGE_BYTES = 4 * 1024 * 1024
MAX_ACTIVE_PACKAGES = 2
TTL_SECONDS = 15 * 60


class Q7OtaArtifactStore:
    def __init__(self, *, clock=time.monotonic) -> None:
        self.clock = clock
        self._entries: dict[str, tuple[float, bytes, str]] = {}

    def _prune(self) -> None:
        now = self.clock()
        for token, (expires, _payload, _digest) in list(self._entries.items()):
            if now >= expires:
                del self._entries[token]

    def register(self, payload: bytes, *, sha256: str, md5: str) -> dict[str, object]:
        self._prune()
        if len(self._entries) >= MAX_ACTIVE_PACKAGES:
            raise ValueError("Too many active Q7 packages")
        if not payload or len(payload) > MAX_PACKAGE_BYTES or len(payload) % 16:
            raise ValueError("Q7 package must be nonempty AES-block-aligned bytes within the size limit")
        if not SHA256_PATTERN.fullmatch(sha256) or not MD5_PATTERN.fullmatch(md5):
            raise ValueError("Expected lowercase SHA-256 and MD5 digests")
        actual_sha = hashlib.sha256(payload).hexdigest()
        actual_md5 = hashlib.md5(payload).hexdigest()
        if actual_sha != sha256 or actual_md5 != md5:
            raise ValueError("Q7 package digest mismatch")
        token = secrets.token_hex(32)
        expires = self.clock() + TTL_SECONDS
        self._entries[token] = (expires, payload, sha256)
        return {
            "download_path": f"/q7/ota-package/{token}",
            "expires_in_seconds": TTL_SECONDS,
            "encrypted_size_bytes": len(payload),
            "encrypted_md5": md5,
            "encrypted_sha256": sha256,
        }

    def fetch(self, token: str) -> bytes | None:
        self._prune()
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        entry = self._entries.get(token)
        if entry is None:
            return None
        _expires, payload, digest = entry
        if hashlib.sha256(payload).hexdigest() != digest:
            return None
        return payload
