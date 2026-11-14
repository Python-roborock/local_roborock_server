"""Voice packs for robots that cannot reach Roborock's servers.

The official app reads a list of voice packs from Roborock's resource host and then tells the robot,
with ``dnld_install_sound``, to download one from a URL in that list. A robot whose internet access is
blocked (as a local setup usually is) cannot fetch it. This module mirrors the list and the files on
this server: the list is served with every URL pointing here, and each file is fetched from Roborock
once, checked, and kept under ``<data_dir>/voice_packs`` from then on.

Layout upstream (from the official app's device plugin): ``https://<region>-app.roborock.com/app/
<bucket>/voice-pkg/info`` for the list, and ``.../voice-pkg/{package,pic,wav}/<file>`` for the files.
The bucket is per product (for example ``vida`` for the Saros 20 Neo, a295/a296).
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import aiohttp

UPSTREAM_HOSTS = {"eu": "eu-app.roborock.com", "us": "us-app.roborock.com", "cn": "cn-app.roborock.com"}
KINDS = {"package": ".pkg", "pic": ".png", "wav": ".wav"}
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
LIST_MAX_AGE_SECONDS = 24 * 3600
LIST_TIMEOUT_SECONDS = 15.0
# A refused file, or a list whose refresh failed, is not asked for again for this long.
RETRY_AFTER_SECONDS = 600.0
MAX_RETRY_ENTRIES = 1024
# Voice packs are a few MB; anything far larger is not one.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LIST_BYTES = 2 * 1024 * 1024
# A home has a handful of products; this keeps public requests from mirroring every bucket Roborock has.
MAX_BUCKETS = 8
_LOGGER = logging.getLogger(__name__)
_URL_KEYS = {"voice_pkg_url": "package", "bg_pic": "pic", "voice_pre_listen": "wav"}


class VoicePackError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def valid_bucket(bucket: str) -> bool:
    return bool(_BUCKET_RE.match(bucket or ""))


def valid_file(kind: str, name: str) -> bool:
    ext = KINDS.get(kind)
    return bool(ext and _FILE_RE.match(name or "") and name.endswith(ext) and ".." not in name)


def rewrite_list(info: dict[str, Any], base_url: str, bucket: str) -> dict[str, Any]:
    """The list with every pack, picture and preview URL pointing at this server."""
    out = copy.deepcopy(info)
    for voice in out.get("voice_list") or []:
        if not isinstance(voice, dict):
            continue
        for key, kind in _URL_KEYS.items():
            url = voice.get(key)
            if isinstance(url, str) and url:
                name = url.rsplit("/", 1)[-1].split("?", 1)[0]
                if valid_file(kind, name):
                    voice[key] = f"{base_url.rstrip('/')}/voice-pkg/{bucket}/{kind}/{name}"
    return out


def listed_entry(info: dict[str, Any] | None, kind: str, name: str) -> dict[str, Any] | None:
    """The list entry whose package, picture or preview ([kind]) is the file [name], if any."""
    keys = [key for key, k in _URL_KEYS.items() if k == kind]
    for voice in (info or {}).get("voice_list") or []:
        if not isinstance(voice, dict):
            continue
        for key in keys:
            if str(voice.get(key) or "").rsplit("/", 1)[-1].split("?", 1)[0] == name:
                return voice
    return None


def _source_tag(entry: dict[str, Any]) -> str:
    """What identifies a package's content in the list; a change means Roborock published a new file."""
    return f"{entry.get('voice_pkg_md5', '')}:{entry.get('version', '')}"


class VoicePackMirror:
    """With ``offline`` set, only copies already under ``<data_dir>/voice_packs`` are served and Roborock is never contacted."""

    def __init__(self, data_dir: Path, region: str, timeout_seconds: float = 120.0, offline: bool = False) -> None:
        self.root = Path(data_dir) / "voice_packs"
        self.offline = offline
        region = (region or "").lower()
        if region not in UPSTREAM_HOSTS:
            _LOGGER.warning("Voice packs: no Roborock host known for region %r, using eu", region)
        self.upstream_host = UPSTREAM_HOSTS.get(region, UPSTREAM_HOSTS["eu"])
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.list_timeout = aiohttp.ClientTimeout(total=min(timeout_seconds, LIST_TIMEOUT_SECONDS))
        # Lists are small and rare: one lock for all of them. File locks are only made for files in a
        # stored list, so their number stays bounded.
        self._list_lock = asyncio.Lock()
        self._file_locks: dict[str, asyncio.Lock] = {}
        # Keys Roborock refused, and lists whose refresh failed, with when to ask again.
        self._retry_after: dict[str, float] = {}

    def _upstream(self, bucket: str, tail: str) -> str:
        return f"https://{self.upstream_host}/app/{bucket}/voice-pkg/{tail}"

    def _list_path(self, bucket: str) -> Path:
        return self.root / bucket / "info.json"

    def _stored_buckets(self) -> set[str]:
        try:
            return {p.parent.name for p in self.root.glob("*/info.json")}
        except OSError:
            return set()

    def _backing_off(self, key: str) -> bool:
        until = self._retry_after.get(key)
        if until is None:
            return False
        if until > time.monotonic():
            return True
        del self._retry_after[key]
        return False

    def _back_off(self, key: str) -> None:
        if len(self._retry_after) >= MAX_RETRY_ENTRIES:
            now = time.monotonic()
            self._retry_after = {k: v for k, v in self._retry_after.items() if v > now}
            if len(self._retry_after) >= MAX_RETRY_ENTRIES:
                self._retry_after.clear()
        self._retry_after[key] = time.monotonic() + RETRY_AFTER_SECONDS

    async def _download(self, url: str, max_bytes: int = MAX_FILE_BYTES, list_request: bool = False) -> bytes:
        """
        The body at [url], read in chunks and refused past [max_bytes], and checked against Roborock's
        ETag when that is an MD5 (their storage sets it to the file's MD5).
        """
        timeout = self.list_timeout if list_request else self.timeout
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise VoicePackError(502 if response.status != 404 else 404, f"Roborock answered {response.status} for {url}")
                if (response.content_length or 0) > max_bytes:
                    raise VoicePackError(502, f"{url} is larger than {max_bytes} bytes")
                digest = hashlib.md5()
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.content.iter_chunked(64 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise VoicePackError(502, f"{url} is larger than {max_bytes} bytes")
                    digest.update(chunk)
                    chunks.append(chunk)
                etag = (response.headers.get("ETag") or "").strip('"').lower()
                if re.fullmatch(r"[0-9a-f]{32}", etag) and digest.hexdigest() != etag:
                    raise VoicePackError(502, f"The download of {url} was incomplete")
                return b"".join(chunks)

    def _read_stored_list(self, path: Path) -> dict[str, Any] | None:
        """The stored list, or None when there is none or it no longer parses (it is then removed)."""
        try:
            info = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            _LOGGER.warning("Voice packs: removing unreadable list %s", path)
            path.unlink(missing_ok=True)
            return None
        return info if isinstance(info, dict) and isinstance(info.get("voice_list"), list) else None

    @staticmethod
    def _write_atomic(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_bytes(data)
            tmp.replace(path)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise VoicePackError(507, f"Could not store {path.name}: {exc}") from exc

    async def get_list(self, bucket: str) -> dict[str, Any]:
        """
        Roborock's list for [bucket], fetched at most once a day; the last copy is used when Roborock
        can't be reached, and a failed refresh is not retried for a while. At most [MAX_BUCKETS]
        buckets are mirrored.
        """
        if not valid_bucket(bucket):
            raise VoicePackError(400, "Unknown voice pack bucket")
        path = self._list_path(bucket)
        if self.offline:
            info = self._read_stored_list(path)
            if info is None:
                raise VoicePackError(404, "No stored voice pack list for this bucket")
            return info
        async with self._list_lock:
            stored = self._read_stored_list(path)
            try:
                fresh = stored is not None and time.time() - path.stat().st_mtime < LIST_MAX_AGE_SECONDS
            except OSError:
                fresh = False
            key = f"list:{bucket}"
            if fresh or self._backing_off(key):
                if stored is None:
                    raise VoicePackError(404, "No voice pack list for this bucket")
                return stored
            if stored is None and len(self._stored_buckets()) >= MAX_BUCKETS:
                raise VoicePackError(404, "This server already mirrors the most voice pack buckets it keeps")
            try:
                raw = await self._download(self._upstream(bucket, "info"), max_bytes=MAX_LIST_BYTES, list_request=True)
                info = json.loads(raw)
                if not isinstance(info, dict) or not isinstance(info.get("voice_list"), list):
                    raise VoicePackError(502, "Roborock's voice pack list has an unexpected shape")
                self._write_atomic(path, json.dumps(info, ensure_ascii=False).encode("utf-8"))
                return info
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, VoicePackError) as exc:
                self._back_off(key)
                if stored is not None:
                    return stored
                if isinstance(exc, VoicePackError):
                    raise
                raise VoicePackError(502, f"Could not fetch the voice pack list: {exc}") from exc

    async def get_file(self, bucket: str, kind: str, name: str) -> Path:
        """
        The local copy of a file in the list, fetched from Roborock the first time, and again when the
        list shows a new version of a package. The list's `voice_pkg_md5` is not the MD5 of the file (an
        a296 `nl.pkg` hashes to its ETag instead), so it is passed on to the robot untouched and the
        download is checked against the ETag.
        """
        if not valid_bucket(bucket) or not valid_file(kind, name):
            raise VoicePackError(404, "Not Found")
        path = self.root / bucket / kind / name
        if self.offline:
            if path.exists():
                return path
            raise VoicePackError(404, "Not Found")
        entry = listed_entry(await self.get_list(bucket), kind, name)
        if entry is None:
            raise VoicePackError(404, "This file is not in the voice pack list")
        tag_path = path.with_name(path.name + ".src")
        tag = _source_tag(entry) if kind == "package" else ""

        def current() -> bool:
            if not path.exists():
                return False
            if kind != "package":
                return True
            try:
                return tag_path.read_text(encoding="utf-8") == tag
            except OSError:
                # Copies stored before the tag existed are kept.
                return not tag_path.exists()

        if current():
            return path
        key = f"{bucket}/{kind}/{name}"
        async with self._file_locks.setdefault(key, asyncio.Lock()):
            if current():
                return path
            if self._backing_off(f"file:{key}"):
                if path.exists():
                    return path
                raise VoicePackError(404, f"Roborock did not have {name}")
            try:
                data = await self._download(self._upstream(bucket, f"{kind}/{name}"))
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if path.exists():
                    return path
                raise VoicePackError(502, f"Could not fetch {name}: {exc}") from exc
            except VoicePackError:
                self._back_off(f"file:{key}")
                if path.exists():
                    return path
                raise
            self._write_atomic(path, data)
            if kind == "package":
                self._write_atomic(tag_path, tag.encode("utf-8"))
            return path

    async def prefetch(self, bucket: str) -> dict[str, Any]:
        """Downloads every package, picture and preview in the list, so later installs need no internet."""
        if self.offline:
            return {"bucket": bucket, "stored": 0, "failed": {}}
        info = await self.get_list(bucket)
        done: list[str] = []
        failed: dict[str, str] = {}
        for voice in info.get("voice_list") or []:
            if not isinstance(voice, dict):
                continue
            for key, kind in _URL_KEYS.items():
                name = str(voice.get(key) or "").rsplit("/", 1)[-1].split("?", 1)[0]
                if not valid_file(kind, name):
                    continue
                try:
                    await self.get_file(bucket, kind, name)
                    done.append(f"{kind}/{name}")
                except VoicePackError as exc:
                    failed[f"{kind}/{name}"] = str(exc)
        return {"bucket": bucket, "stored": len(done), "failed": failed}
