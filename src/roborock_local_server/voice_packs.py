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
import hashlib
import json
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
    out = json.loads(json.dumps(info))
    for voice in out.get("voice_list") or []:
        for key, kind in _URL_KEYS.items():
            url = voice.get(key)
            if isinstance(url, str) and url:
                name = url.rsplit("/", 1)[-1].split("?", 1)[0]
                if valid_file(kind, name):
                    voice[key] = f"{base_url.rstrip('/')}/voice-pkg/{bucket}/{kind}/{name}"
    return out


def expected_md5(info: dict[str, Any] | None, name: str) -> str | None:
    for voice in (info or {}).get("voice_list") or []:
        url = str(voice.get("voice_pkg_url") or "")
        if url.rsplit("/", 1)[-1].split("?", 1)[0] == name:
            md5 = str(voice.get("voice_pkg_md5") or "").lower()
            return md5 if re.fullmatch(r"[0-9a-f]{32}", md5) else None
    return None


class VoicePackMirror:
    """With ``offline`` set, only copies already under ``<data_dir>/voice_packs`` are served and Roborock is never contacted."""

    def __init__(self, data_dir: Path, region: str, timeout_seconds: float = 120.0, offline: bool = False) -> None:
        self.root = Path(data_dir) / "voice_packs"
        self.offline = offline
        self.upstream_host = UPSTREAM_HOSTS.get((region or "").lower(), UPSTREAM_HOSTS["eu"])
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock(self, key: str) -> asyncio.Lock:
        return self._locks.setdefault(key, asyncio.Lock())

    def _upstream(self, bucket: str, tail: str) -> str:
        return f"https://{self.upstream_host}/app/{bucket}/voice-pkg/{tail}"

    def _list_path(self, bucket: str) -> Path:
        return self.root / bucket / "info.json"

    async def _download(self, url: str) -> bytes:
        """The body at [url], checked against Roborock's ETag when that is an MD5 (their storage sets it to the file's MD5)."""
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise VoicePackError(502 if response.status != 404 else 404, f"Roborock answered {response.status} for {url}")
                data = await response.read()
                etag = (response.headers.get("ETag") or "").strip('"').lower()
                if re.fullmatch(r"[0-9a-f]{32}", etag) and hashlib.md5(data).hexdigest() != etag:
                    raise VoicePackError(502, f"The download of {url} was incomplete")
                return data

    async def get_list(self, bucket: str) -> dict[str, Any]:
        """Roborock's list for [bucket], fetched at most once a day; the last copy is used when Roborock can't be reached."""
        if not valid_bucket(bucket):
            raise VoicePackError(400, "Unknown voice pack bucket")
        path = self._list_path(bucket)
        if self.offline:
            if not path.exists():
                raise VoicePackError(404, "No stored voice pack list for this bucket")
            return json.loads(path.read_text(encoding="utf-8"))
        async with self._lock(f"list:{bucket}"):
            fresh = path.exists() and time.time() - path.stat().st_mtime < LIST_MAX_AGE_SECONDS
            if not fresh:
                try:
                    raw = await self._download(self._upstream(bucket, "info"))
                    info = json.loads(raw)
                    if not isinstance(info, dict) or not isinstance(info.get("voice_list"), list):
                        raise VoicePackError(502, "Roborock's voice pack list has an unexpected shape")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    tmp = path.with_suffix(".tmp")
                    tmp.write_text(json.dumps(info, ensure_ascii=False), encoding="utf-8")
                    tmp.replace(path)
                    return info
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, VoicePackError) as exc:
                    if not path.exists():
                        if isinstance(exc, VoicePackError):
                            raise
                        raise VoicePackError(502, f"Could not fetch the voice pack list: {exc}") from exc
            return json.loads(path.read_text(encoding="utf-8"))

    async def get_file(self, bucket: str, kind: str, name: str) -> Path:
        """
        The local copy of a file, fetched from Roborock the first time. A package must be in the list. The
        list's `voice_pkg_md5` is not the MD5 of the file (an a296 `nl.pkg` hashes to its ETag instead), so
        it is passed on to the robot untouched and the download is checked against the ETag.
        """
        if not valid_bucket(bucket) or not valid_file(kind, name):
            raise VoicePackError(404, "Not Found")
        path = self.root / bucket / kind / name
        if path.exists():
            return path
        if self.offline:
            raise VoicePackError(404, "Not Found")
        async with self._lock(f"file:{bucket}/{kind}/{name}"):
            if path.exists():
                return path
            if kind == "package" and expected_md5(await self.get_list(bucket), name) is None:
                raise VoicePackError(404, "This package is not in the voice pack list")
            try:
                data = await self._download(self._upstream(bucket, f"{kind}/{name}"))
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                raise VoicePackError(502, f"Could not fetch {name}: {exc}") from exc
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(path)
            return path

    async def prefetch(self, bucket: str) -> dict[str, Any]:
        """Downloads every package, picture and preview in the list, so later installs need no internet."""
        if self.offline:
            return {"bucket": bucket, "stored": 0, "failed": {}}
        info = await self.get_list(bucket)
        done: list[str] = []
        failed: dict[str, str] = {}
        for voice in info.get("voice_list") or []:
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
