"""A bounded dry run of a robot's local OTA command: it is asked to download, never to install.

Random mode serves a throwaway file that is not a firmware, so nothing could be flashed even if
install were on. Package mode uses the robot's own CURRENT firmware package, resolved from the
cloud and checked against its checksum, with install off. Either way the file is served from a
token URL on this server (reusable until it expires), or the CDN address is given directly when asked.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import time
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi.responses import Response, StreamingResponse

from . import firmware_versions

FILE_BYTES = 64 * 1024
TOKEN_TTL_SECONDS = 600
WATCH_SECONDS = 60
PACKAGE_WATCH_SECONDS = 240
# An install: the robot reboots and is briefly unreachable, so the watch is long and tolerates silence.
INSTALL_WATCH_SECONDS = 900
INSTALL_TOKEN_TTL_SECONDS = 1800
INSTALL_MIN_BATTERY = 80
WAIT_INSTALL_STUCK_SECONDS = 60
MAX_PACKAGE_BYTES = 400 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
# CDN response headers that are not replayed: this server sets its own length, ranges and connection handling.
_NOT_MIRRORED = {"content-length", "transfer-encoding", "connection", "keep-alive", "date", "content-encoding", "accept-ranges"}
POLL_SECONDS = 2
# Charging states of the robot: 8 charging, 100 fully charged.
DOCKED_STATES = {8, 100}
# A robot asleep on its dock reports state 2 (charger disconnected) while charge_status says it is on the charger.
SLEEPING_ON_DOCK_STATE = 2
# States a new attempt may start from: wait_install is a package a dry run staged earlier, replaced by the new one.
STARTABLE_STATES = ("idle", "failed", "wait_install")
# Hosts the cloud has handed out firmware and plugin packages from (the app's regional CDN and file hosts).
PACKAGE_HOSTS = frozenset({
    "rrpkg-us.roborock.com", "files.roborock.com", "app-files.roborock.com", "cn-app.roborock.com", "us-app.roborock.com",
    "cdn.awsusor0.fds.api.mi-img.com", "cdn.awssgp0.fds.api.mi-img.com", "cdn.cnbj2.fds.api.mi-img.com",
    "cdn.ksyru0-eco.fds.api.mi-img.com",
})
_PACKAGE_FAMILY = re.compile(r"/rriotpkg/([^/]+)/")
_PACKAGE_MD5 = re.compile(r"\.([0-9a-f]{32})\.signed\.pkg$")
_PATH = re.compile(r"^/ota_test/([A-Za-z0-9_-]{16,})(?:/([A-Za-z0-9._-]{1,200})|\.bin)$")
_RANGE = re.compile(r"^bytes=(\d*)-(\d*)$")
_HEADERS_KEPT = ("user-agent", "range", "accept", "host", "connection", "if-none-match", "if-range")


class _CasedResponse(StreamingResponse):
    """A streamed response that sends header names exactly as given.

    Starlette lowercases header names, which a minimal embedded HTTP client may not accept; uvicorn's h11
    keeps the case it is handed, so names like Content-Length reach the wire as written.
    """

    def init_headers(self, headers: Any = None) -> None:
        self.raw_headers = [(name.encode("latin-1"), value.encode("latin-1")) for name, value in (headers or {}).items()]


def _size(data: bytes | Path) -> int:
    return data.stat().st_size if isinstance(data, Path) else len(data)


def _chunks(data: bytes | Path, start: int, end: int):
    """The bytes from start to end (inclusive) in chunks, read from memory or from the cached file."""
    if isinstance(data, Path):
        with data.open("rb") as handle:
            handle.seek(start)
            left = end - start + 1
            while left > 0:
                chunk = handle.read(min(CHUNK_BYTES, left))
                if not chunk:
                    break
                left -= len(chunk)
                yield chunk
        return
    for offset in range(start, end + 1, CHUNK_BYTES):
        yield data[offset:min(offset + CHUNK_BYTES, end + 1)]


def _fully_fetched(hits: list[dict[str, Any]], total: int) -> bool:
    """True when the requests the robot made together delivered every byte of the file."""
    reached = 0
    for hit in sorted(hits, key=lambda item: item.get("start", 0)):
        start, sent = int(hit.get("start", 0)), int(hit.get("bytes_sent", 0))
        if start > reached:
            return False
        reached = max(reached, start + sent)
    return total > 0 and reached >= total


@dataclass
class _Active:
    token: str
    data: bytes | Path
    md5: str
    expires_at: float
    filename: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    variant: dict[str, bool] = field(default_factory=dict)
    hits: list[dict[str, Any]] = field(default_factory=list)


class OtaDryRun:
    def __init__(self) -> None:
        # One slot per robot, so a second robot's run does not take the first one's file away.
        self._slots: dict[str, _Active] = {}

    def _find(self, token: str) -> _Active | None:
        return next((active for active in list(self._slots.values()) if secrets.compare_digest(active.token, token)), None)

    def file_response(self, clean_path: str, method: str, headers: Any, remote: str) -> Response | None:
        """The test file for its token URL (reusable until it expires), or None when the path is not a dry-run path."""
        match = _PATH.match(clean_path)
        if match is None:
            return None
        active = self._find(match.group(1))
        asked_name = match.group(2)
        if active is None or time.time() > active.expires_at or (asked_name is not None and asked_name != active.filename):
            return Response(status_code=404)
        hit: dict[str, Any] = {
            "time": time.time(), "method": method, "remote": remote,
            "headers": {key: headers.get(key) for key in _HEADERS_KEPT if headers.get(key) is not None},
        }
        active.hits.append(hit)
        total = _size(active.data)
        status, start, end, extra = 200, 0, total - 1, {"Accept-Ranges": "bytes", **active.headers}
        requested = _RANGE.match(str(headers.get("range") or ""))
        if requested:
            start_text, end_text = requested.groups()
            first = int(start_text) if start_text else max(0, total - int(end_text or 0))
            last = min(int(end_text), total - 1) if end_text and start_text else total - 1
            if 0 <= first <= last < total:
                status, start, end = 206, first, last
                extra["Content-Range"] = f"bytes {start}-{end}/{total}"
        length = max(0, end - start + 1)
        if method == "HEAD":
            return Response(content=b"", status_code=status, media_type="application/octet-stream",
                            headers={**extra, "Content-Length": str(length)})
        variant = active.variant
        body = self._counted(active.data, start, end, total, hit)
        # Robots only accept the file when header names are capitalised (Content-Length), as the CDN sends them.
        if variant.get("title_case", True):
            headers_out = {"Content-Type": "application/octet-stream", "Content-Length": str(length), **extra}
            if variant.get("connection_close"):
                headers_out["Connection"] = "close"
            return _CasedResponse(body, status_code=status, headers=headers_out)
        return StreamingResponse(
            body, status_code=status, media_type="application/octet-stream",
            headers={**extra, "Content-Length": str(length), **({"Connection": "close"} if variant.get("connection_close") else {})},
        )

    @staticmethod
    async def _counted(data: bytes | Path, start: int, end: int, total: int, hit: dict[str, Any]):
        """Sends the file in chunks and records how much the robot took and whether it took all of it."""
        sent, started = 0, time.monotonic()
        hit["start"] = start
        try:
            for chunk in _chunks(data, start, end):
                yield chunk
                sent += len(chunk)
            hit["completed"] = True
        finally:
            hit.setdefault("completed", False)
            hit["bytes_sent"], hit["of_bytes"], hit["seconds"] = sent, total, round(time.monotonic() - started, 2)

    async def run(
        self, client: Any, api_url: str, package: dict[str, Any] | None = None, variant: dict[str, bool] | None = None,
        install: bool = False, on_state: Any = None, duid: str = "",
    ) -> dict[str, Any]:
        """Checks the robot is docked and idle, asks it to download the file, and watches its OTA state.

        [package] is {"url", "md5", "data"}: the robot's current firmware, with its bytes when this server
        should serve it, or None for data when the robot should fetch the url directly. Without a package
        a random file is used. With [install] the robot is asked to download AND install the package.
        """
        refusal = await self._refusal(client, INSTALL_MIN_BATTERY if install else 30)
        if refusal:
            return {"ran": False, "reason": refusal}

        direct_url, filename, headers = None, "", {}
        if package is None:
            data = os.urandom(FILE_BYTES)
            md5 = hashlib.md5(data).hexdigest()  # noqa: S324
        else:
            data, md5 = package.get("data") or b"", package["md5"]
            if package.get("data") is None:
                direct_url = package["url"]
            else:
                filename, headers = package.get("filename", ""), package.get("headers", {})
        ttl = INSTALL_TOKEN_TTL_SECONDS if install else TOKEN_TTL_SECONDS
        active = _Active(secrets.token_urlsafe(18), data, md5, time.time() + ttl, filename, headers, dict(variant or {}))
        self._slots[duid] = active
        served = f"{api_url}/ota_test/{active.token}/{filename}" if filename else f"{api_url}/ota_test/{active.token}.bin"
        params = {
            "mode": "normal", "install": "1" if install else "0", "app_url": direct_url or served,
            "file_md5": md5, "proc": "dnld install" if install else "dnld",
        }
        seconds = INSTALL_WATCH_SECONDS if install else (PACKAGE_WATCH_SECONDS if package else WATCH_SECONDS)
        try:
            reply = await self._ask(client, "miIO.ota", params)
            trace = await self._watch(client, seconds, install=install, on_state=on_state)
        finally:
            if self._slots.get(duid) is active:
                del self._slots[duid]
        states = [step["state"] for step in trace]
        return {
            "ran": True, "package": package is not None, "variant": active.variant, "install": install,
            "saw_offline": None in states,
            "stuck_in_wait_install": install and bool(trace) and trace[-1]["state"] == "wait_install",
            "params": {**params, "app_url": params["app_url"].replace(active.token, "<token>")},
            "ota_reply": reply, "file_fetched": bool(active.hits), "package_fully_fetched": _fully_fetched(active.hits, _size(data)),
            "hits": active.hits, "trace": trace,
            "final_state": trace[-1]["state"] if trace else None,
        }

    @staticmethod
    async def _ask(client: Any, method: str, params: Any) -> Any:
        try:
            return await client.send_command(method, params)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}

    async def _refusal(self, client: Any, min_battery: int = 30) -> str:
        status = await self._ask(client, "get_status", [])
        first = status[0] if isinstance(status, list) and status and isinstance(status[0], dict) else None
        if first is None:
            return f"Could not read the robot's status: {status}"
        state = first.get("state")
        docked = state in DOCKED_STATES or (state == SLEEPING_ON_DOCK_STATE and first.get("charge_status") == 1)
        if not docked or first.get("in_cleaning") or first.get("error_code"):
            return f"The robot must be docked, idle and error-free (state={first.get('state')}, error={first.get('error_code')})"
        if int(first.get("battery") or 0) < min_battery:
            return f"The battery is too low ({first.get('battery')}%)"
        ota = await self._ask(client, "get_ota_state", [])
        state = ota.get("ota_state") if isinstance(ota, dict) else None
        if state not in STARTABLE_STATES:
            # failed only records that the last attempt ended, and wait_install is a package an earlier dry run
            # staged; a new attempt replaces either.
            return f"The robot's OTA state is {state!r}, so an update may be in progress"
        return ""

    async def _watch(
        self, client: Any, seconds: float = WATCH_SECONDS, install: bool = False, on_state: Any = None,
    ) -> list[dict[str, Any]]:
        """Polls the robot's OTA state. In install mode wait_install is not a resting place, so the watch goes on
        through it (the robot may pass through it on the way to installing) unless it sits there too long."""
        resting = ("idle", "failed") if install else ("idle", "failed", "wait_install")
        trace: list[dict[str, Any]] = []
        started = time.monotonic()
        left_idle = False
        settled_at: float | None = None
        waiting_since: float | None = None
        while time.monotonic() - started < seconds:
            ota = await self._ask(client, "get_ota_state", [])
            progress = await self._ask(client, "get_ota_progress", [])
            state = ota.get("ota_state") if isinstance(ota, dict) else ota
            trace.append({
                "t": round(time.monotonic() - started, 1), "state": state,
                "progress": progress.get("ota_progress") if isinstance(progress, dict) else progress,
                "raw": ota,
            })
            if on_state is not None:
                on_state(state, trace[-1]["progress"])
            if state not in (None,) + resting:
                left_idle, settled_at = True, None
            if install and state == "wait_install":
                waiting_since = waiting_since or time.monotonic()
                if time.monotonic() - waiting_since > WAIT_INSTALL_STUCK_SECONDS:
                    break
            elif state is not None:
                waiting_since = None
            if left_idle and state in resting:
                settled_at = settled_at or time.monotonic()
                if time.monotonic() - settled_at > 4:
                    break
            await asyncio.sleep(POLL_SECONDS)
        return trace


class PackageRefused(Exception):
    """The firmware package could not be used safely; the message says why."""


class PackageUnavailable(PackageRefused):
    """The package server would not hand out the file, so its address may have gone stale."""


async def _download_to_file(url: str, target: Path) -> tuple[str, dict[str, str]]:
    """Streams the package to [target] and returns its md5 and the CDN's response headers."""
    import aiohttp

    digest, size = hashlib.md5(), 0  # noqa: S324
    timeout = aiohttp.ClientTimeout(total=1800)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise PackageUnavailable(f"The package server answered HTTP {response.status}")
                headers = dict(response.headers)
                with partial.open("wb") as handle:
                    async for chunk in response.content.iter_chunked(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_PACKAGE_BYTES:
                            raise PackageRefused("The package is larger than the limit")
                        digest.update(chunk)
                        handle.write(chunk)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)
    return digest.hexdigest(), headers


def _file_md5(path: Path) -> str:
    digest = hashlib.md5()  # noqa: S324
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Cached package names a robot is downloading or installing right now; a clean-up for another robot leaves them.
_PINNED: dict[str, int] = {}


def pin_package(name: str) -> None:
    _PINNED[name] = _PINNED.get(name, 0) + 1


def release_package(name: str) -> None:
    left = _PINNED.get(name, 0) - 1
    if left > 0:
        _PINNED[name] = left
    else:
        _PINNED.pop(name, None)


def clean_package_cache(cache_dir: Path, keep: str | Collection[str] = ()) -> None:
    """Removes cached packages (and half-downloaded ones) other than [keep] and the ones in use."""
    kept = ({keep} if isinstance(keep, str) else set(keep)) | set(_PINNED)
    for path in cache_dir.glob("*.pkg*") if cache_dir.is_dir() else ():
        if path.name not in kept:
            path.unlink(missing_ok=True)


async def _download(url: str) -> tuple[bytes, dict[str, str]]:
    """The package bytes and the CDN's response headers."""
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=600)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as response:
            if response.status != 200:
                raise PackageUnavailable(f"The package server answered HTTP {response.status}")
            if int(response.headers.get("Content-Length") or 0) > MAX_PACKAGE_BYTES:
                raise PackageRefused("The package is larger than the limit")
            return await response.read(), dict(response.headers)


def package_md5(url: Any) -> str:
    """The checksum in a package address, or an empty string when the address is not https on a Roborock package host."""
    match = _PACKAGE_MD5.search(str(url or ""))
    if match is None or urlparse(str(url)).scheme != "https" or (urlparse(str(url)).hostname or "") not in PACKAGE_HOSTS:
        return ""
    return match.group(1)


def package_family(url: Any) -> str:
    """The hardware folder of a package address (the a245 of .../rriotpkg/a245/...), or an empty string when it has none."""
    match = _PACKAGE_FAMILY.search(str(url or ""))
    return match.group(1) if match else ""


async def package_address(cloud: Any, duid: str, version: str) -> str:
    """The package address the cloud gives for [version]: an https URL with its checksum, or an empty string
    for a version that was never released."""
    reply = await cloud.iot_get(f"/user/devices/{duid}/fw", {"version": version})
    url = reply.get("url") if isinstance(reply, dict) else None
    return str(url) if package_md5(url) else ""


async def package_headers(url: str) -> tuple[str, int | None]:
    """The CDN's upload time as ISO UTC and the package size from a headers-only request; ("", None) on any failure."""
    import aiohttp

    try:
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session,
            session.head(url, allow_redirects=True) as response,
        ):
            if response.status != 200:
                return "", None
            modified, length = response.headers.get("Last-Modified", ""), response.headers.get("Content-Length", "")
    except Exception:  # noqa: BLE001
        return "", None
    try:
        released = parsedate_to_datetime(modified).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        released = ""
    return released, int(length) if length.isdigit() and int(length) > 0 else None


async def resolve_package(
    cloud: Any, duid: str, version: str, *, serve: bool, allow_update: bool = False, cache_dir: Path | None = None,
    reported: str = "", known_url: str = "", keep: Collection[str] = (),
) -> dict[str, Any]:
    """The robot's current firmware package: its address from the cloud, and its checksum verified.

    Only the version the robot runs is accepted (as it reports it, else as the cloud says), so a dry
    run can never change the firmware. With [known_url] the caller vouches for the version and the
    gate is skipped. With [serve] the bytes are fetched here and checked against the checksum in the
    file name; the robot then downloads them from this server instead of the CDN.
    """
    if known_url:
        url = known_url
    else:
        info = firmware_versions.apply_reported(await cloud.firmware_update_info(duid), reported)
        current = info.get("currentVersion") if isinstance(info, dict) else None
        offered = info.get("version") if isinstance(info, dict) and info.get("updatable") is True else None
        if not version or (current != version and not (allow_update and offered == version)):
            source = "the robot reports" if reported else "the cloud says"
            raise PackageRefused(f"Only the robot's current version can be used ({source} {current!r}, asked for {version!r})")
        reply = await cloud.iot_get(f"/user/devices/{duid}/fw", {"version": version})
        url = reply.get("url") if isinstance(reply, dict) else None
    md5 = package_md5(url)
    if not md5:
        raise PackageRefused(f"The cloud's package address is not in the expected form: {url!r}")
    if not serve:
        return {"url": url, "md5": md5, "data": None}
    if cache_dir is not None:
        name = f"{md5}.pkg"
        path = cache_dir / name
        # Pinned until the caller releases it, so another robot's clean-up cannot delete it mid-download.
        pin_package(name)
        try:
            clean_package_cache(cache_dir, keep={name, *keep})
            loop = asyncio.get_running_loop()
            if path.is_file() and await loop.run_in_executor(None, _file_md5, path) == md5:
                cdn_headers: dict[str, str] = {}
            else:
                path.unlink(missing_ok=True)
                got, cdn_headers = await _download_to_file(str(url), path)
                if got != md5:
                    path.unlink(missing_ok=True)
                    raise PackageRefused("The downloaded package does not match the checksum in its address")
        except BaseException:
            release_package(name)
            raise
        return {
            "url": url, "md5": md5, "data": path, "filename": str(url).rsplit("/", 1)[-1],
            "headers": {key: value for key, value in cdn_headers.items() if key.lower() not in _NOT_MIRRORED},
        }
    data, cdn_headers = await _download(url)
    if hashlib.md5(data).hexdigest() != md5:  # noqa: S324
        raise PackageRefused("The downloaded package does not match the checksum in its address")
    # Served under its real file name and with the CDN's own response headers, as the robot may rely on either.
    return {
        "url": url, "md5": md5, "data": data, "filename": str(url).rsplit("/", 1)[-1],
        "headers": {key: value for key, value in cdn_headers.items() if key.lower() not in _NOT_MIRRORED},
    }
