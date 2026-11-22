"""Voice pack list and package passthrough for clients that give our URL to the robot unchanged.
The official app rebuilds the robot URL on its own res host and discards ours (see tests)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse

import aiohttp
from fastapi.responses import FileResponse, JSONResponse, Response
from shared.context import ServerContext

VOICE_INFO_ROUTE_NAME = "voice_pkg_info"
VOICE_FILE_ROUTE_NAME = "voice_pkg_file"
VOICE_PROXY_HEADER = "x-rr-voice-proxy"
VOICE_PKG_MAX_BYTES = 64 * 1024 * 1024
VOICE_INFO_MAX_BYTES = 2 * 1024 * 1024
VOICE_PKG_CACHE_MAX_FILES = 64
VOICE_PKG_CACHE_MAX_BYTES = 512 * 1024 * 1024
_STALE_TMP_SECONDS = 3600

# The official plugin's areaServerMap: cosHost first (NewEndpoint robots), then the FDS host.
_REGION_HOSTS: dict[str, tuple[str, ...]] = {
    "cn": ("cn-app.roborock.com", "cnbj2.fds.api.xiaomi.com"),
    "us": ("us-app.roborock.com", "awsusor0.fds.api.xiaomi.com"),
    "eu": ("eu-app.roborock.com", "awsde0.fds.api.xiaomi.com"),
    "de": ("eu-app.roborock.com", "awsde0.fds.api.xiaomi.com"),
    "ru": ("ksyru0-eco.fds.api.xiaomi.com",),
}
_DEFAULT_HOSTS = ("us-app.roborock.com", "awssgp0.fds.api.xiaomi.com")
_ALLOWED_HOSTS = {"us-app.roborock.com", "eu-app.roborock.com", "cn-app.roborock.com"}

# Voice-pkg bucket to short model ids; a config that inherits without forceRealResource uses its parent's bucket.
_BUCKET_MODELS: dict[str, tuple[str, ...]] = {
    "pearl": ("a74", "a75"),
    "pearls": ("a100", "a101"),
    "pearlc": ("a103", "a104"),
    "pearlclite": ("a198", "a199", "a205"),
    "pearlplus": ("a86", "a87"),
    "pearlpluss": ("a116", "a117", "a136"),
    "pearlslite": ("a122", "a123"),
    "pearle": ("a167", "a168", "a325", "a326"),
    "pearlepro": ("a169", "a170"),
    "quinn": ("a293", "a294"),
    "quinne": ("a358", "a359"),
    "vivian": ("a134", "a135", "a155", "a156", "a182", "a243", "a250"),
    "vivianc": ("a158", "a159", "a186", "a187", "a209", "a210", "a246"),
    "vivians": ("a184", "a185"),
    "vivianspro": ("a225", "a226"),
    "viviansproc": ("a297", "a298"),
    "vida": ("a295", "a296"),
    "viviansc": ("a196", "a197", "a216", "a217"),
    "hera": ("a224", "a249"),
    "beryllite": ("a244", "a245"),
    "beryl": ("a120", "a121"),
    "beryls": ("a306", "a307"),
    "beryle": ("a311", "a312"),
    "berylc": ("a327", "a328"),
    "coral": ("a20", "a21"),
    "coralpro": ("a143", "a144", "a231", "a236", "a232", "a308"),
    "coralpros": ("a219", "a220"),
    "coralprosaw": ("a287", "a288"),
    "r50": ("a157", "a179"),
    "ultron": ("a50", "a51"),
    "ultrone": ("a72", "a84"),
    "ultronlite": ("a73", "a85"),
    "ultronsc": ("a94", "a95"),
    "ultronse": ("a124", "a125", "a139", "a140"),
    "ultronsplus": ("a68", "a69", "a70"),
    "ultronsv": ("a96", "a97"),
    "verdelite": ("a146", "a147"),
    "verdelites": ("a279", "a278"),
    "topazs": ("a29", "a30", "a76"),
    "topazsplus": ("a46", "a47", "a66"),
    "topazspower": ("a62",),
    "topazsc": ("a64", "a65"),
    "topazsv": ("a26", "a27"),
    "tanoss": ("a14", "a15"),
    "tanossplus": ("a23", "a24"),
    "tanosslite": ("a37", "a38", "a360", "a361"),
    "tanossc": ("a39", "a40"),
    "tanosse": ("a33", "a34"),
    "tanossmax": ("a52",),
    "tanos": ("t6", "s6"),
    "tanose": ("t7", "a11"),
    "tanosv": ("t7p", "a09", "a10"),
    "rubyplus": ("t4", "s4"),
    "rubysc": ("p5", "a08"),
    "rubyse": ("a19",),
    "rubyslite": ("p6", "s5e", "a05"),
}
_MODEL_BUCKETS = {
    model: bucket for bucket, models in _BUCKET_MODELS.items() for model in models
}
# These keep the old "/<bucket>/app/voice-pkg/" layout.
_LEGACY_LAYOUT_BUCKETS = {"tanos", "tanose", "tanosv", "rubyplus", "rubyse", "rubysc"}

_INFO_PATH = re.compile(
    r"^(?:/app/[a-z0-9_]{1,40}/voice-pkg/|/[a-z0-9_]{1,40}/app/voice-pkg/)(?:debug/)?info$"
)
_FILE_PATH = re.compile(
    r"^/voice-pkg/files/([a-z0-9.-]{1,80})(/[A-Za-z0-9_./-]{1,200}\.pkg)$"
)


class VoicePkgError(RuntimeError):
    def __init__(self, message: str, *, source_url: str = "") -> None:
        super().__init__(message)
        self.source_url = source_url


def is_allowed_voice_host(host: str) -> bool:
    host = host.strip().lower()
    return host in _ALLOWED_HOSTS or host.endswith(
        (".fds.api.xiaomi.com", ".fds.api.mi-img.com")
    )


def voice_info_path_for_model(model: str) -> str:
    """The plugin's soundPackageFilePath plus "info" for a model id like roborock.vacuum.a245."""
    full = model.strip().lower()
    short = full.rsplit(".", 1)[-1]
    debug = full.endswith(("v2", "v3", "v4", "v5"))
    # The plugin's model list also holds "<short>v2" to "<short>v5" (p223 L280750-280830).
    bucket = _MODEL_BUCKETS.get(
        short[:-2] if debug else short, ""
    ) or _MODEL_BUCKETS.get(short, "")
    if not bucket:
        return ""
    if "a136" in full:
        bucket = "ppscouple"
    if bucket in _LEGACY_LAYOUT_BUCKETS:
        prefix = f"/{'rubysc1' if bucket == 'rubysc' else bucket}/app/voice-pkg/"
    else:
        prefix = f"/app/{bucket}/voice-pkg/"
    return f"{prefix}{'debug/' if debug else ''}info"


def upstream_hosts(region: str) -> tuple[str, ...]:
    return _REGION_HOSTS.get(region.strip().lower(), _DEFAULT_HOSTS)


async def fetch_voice_bytes(url: str, *, max_bytes: int, timeout_s: float) -> bytes:
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    headers = {"User-Agent": "roborock-local-server/0.1", VOICE_PROXY_HEADER: "1"}
    # No redirects, so the allowed-host check holds; the size cap is enforced while reading.
    async with (
        aiohttp.ClientSession(timeout=timeout, headers=headers) as session,
        session.get(url, allow_redirects=False) as response,
    ):
        if int(response.status) != 200:
            raise RuntimeError(f"upstream returned HTTP {response.status}")
        if response.content_length is not None and response.content_length > max_bytes:
            raise RuntimeError(f"voice file too large: {response.content_length} bytes")
        data = bytearray()
        async for chunk in response.content.iter_chunked(64 * 1024):
            data.extend(chunk)
            if len(data) > max_bytes:
                raise RuntimeError(f"voice file too large: over {max_bytes} bytes")
    if not data:
        raise RuntimeError("upstream returned empty content")
    return bytes(data)


def _cache_dir(runtime_dir: Path) -> Path:
    path = runtime_dir / "voice_pkg_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


_T = TypeVar("_T")
_inflight: dict[str, asyncio.Task[Any]] = {}


def _consume_exception(task: asyncio.Task[Any]) -> None:
    if not task.cancelled():
        task.exception()


async def _single_flight(key: str, factory: Callable[[], Awaitable[_T]]) -> _T:
    """Concurrent callers with the same key share one run of factory."""
    task = _inflight.get(key)
    if task is None:
        task = asyncio.ensure_future(factory())
        _inflight[key] = task
        task.add_done_callback(lambda _t: _inflight.pop(key, None))
        task.add_done_callback(_consume_exception)
    return await asyncio.shield(task)


def _write_atomic(path: Path, data: bytes) -> None:
    temp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    temp.write_bytes(data)
    temp.replace(path)


def _touch(path: Path) -> bool:
    """Marks a cached file as just used; False when it is missing or was evicted."""
    try:
        os.utime(path)
    except OSError:
        return False
    return True


def _write_and_evict(path: Path, data: bytes) -> None:
    _write_atomic(path, data)
    _evict_old_packages(path.parent)


def _evict_old_packages(cache_dir: Path) -> None:
    """Keeps the newest packages within the file and byte caps and drops stale temp files."""
    now = time.time()
    packages: list[tuple[float, int, Path]] = []
    for entry in cache_dir.iterdir():
        try:
            mtime = entry.stat().st_mtime
            if entry.suffix == ".tmp" and now - mtime > _STALE_TMP_SECONDS:
                entry.unlink()
            elif entry.suffix == ".pkg":
                packages.append((mtime, entry.stat().st_size, entry))
        except OSError:
            continue
    packages.sort(key=lambda item: item[0], reverse=True)
    kept_bytes = 0
    for index, (_, size, entry) in enumerate(packages):
        kept_bytes += size
        if index >= VOICE_PKG_CACHE_MAX_FILES or kept_bytes > VOICE_PKG_CACHE_MAX_BYTES:
            kept_bytes -= size
            with contextlib.suppress(OSError):
                entry.unlink(missing_ok=True)


def _rewrite_info(
    info: dict[str, Any], *, info_host: str, api_url: str
) -> dict[str, Any]:
    """Points every voice_pkg_url at this server and records the upstream URL as voice_pkg_source_url."""
    out = dict(info)
    for key in ("voice_list", "special_voice_list", "factory_test_list"):
        items = info.get(key)
        if not isinstance(items, list):
            continue
        rewritten: list[Any] = []
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("voice_pkg_url"), str):
                item = dict(item)
                path = urlparse(item["voice_pkg_url"]).path
                if path.endswith(".pkg"):
                    item["voice_pkg_source_url"] = f"https://{info_host}{path}"
                    item["voice_pkg_url"] = (
                        f"{api_url}/voice-pkg/files/{info_host}{path}"
                    )
            rewritten.append(item)
        out[key] = rewritten
    out["voice_pkg_host"] = info_host
    return out


async def _fetch_info(
    ctx: ServerContext, cache_file: Path, upstream_path: str
) -> tuple[str, dict[str, Any]]:
    errors: list[str] = []
    for host in upstream_hosts(ctx.region):
        url = f"https://{host}{upstream_path}"
        try:
            raw = await fetch_voice_bytes(
                url, max_bytes=VOICE_INFO_MAX_BYTES, timeout_s=20
            )
            info = json.loads(raw)
            if not isinstance(info, dict) or not isinstance(
                info.get("voice_list"), list
            ):
                raise TypeError("upstream answer has no voice_list")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{host}: {exc}")
            continue
        await asyncio.to_thread(
            _write_atomic,
            cache_file,
            json.dumps({"host": host, "info": info}).encode("utf-8"),
        )
        return host, info
    raise VoicePkgError(
        "; ".join(errors) or "no upstream host", source_url=upstream_path
    )


def _read_cached_info(cache_file: Path) -> tuple[str, dict[str, Any]] | None:
    """The cached info as (host, info), or None when it is missing or unreadable."""
    try:
        cached = json.loads(cache_file.read_text(encoding="utf-8"))
        host, info = cached["host"], cached["info"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(host, str) or not isinstance(info, dict):
        return None
    return host, info


async def _voice_info_response(
    ctx: ServerContext, runtime_dir: Path, upstream_path: str
) -> tuple[str, Response]:
    region = ctx.region.strip().lower()
    cache_file = (
        _cache_dir(runtime_dir)
        / f"info-{_digest(f'{region}:{upstream_path}')[:24]}.json"
    )
    try:
        host, info = await _single_flight(
            f"info:{region}:{cache_file}",
            lambda: _fetch_info(ctx, cache_file, upstream_path),
        )
    except VoicePkgError:
        cached = await asyncio.to_thread(_read_cached_info, cache_file)
        if cached is None:
            raise
        host, info = cached
        return f"https://{host}{upstream_path}", JSONResponse(
            _rewrite_info(info, info_host=host, api_url=ctx.api_url()),
            headers={"X-RR-Voice-Cache": "stale"},
        )
    body = _rewrite_info(info, info_host=host, api_url=ctx.api_url())
    return f"https://{host}{upstream_path}", JSONResponse(
        body, headers={"X-RR-Voice-Cache": "miss"}
    )


async def _voice_file_response(
    runtime_dir: Path, host: str, path: str
) -> tuple[str, Response]:
    source_url = f"https://{host}{path}"
    cache_file = _cache_dir(runtime_dir) / f"{_digest(source_url)}.pkg"
    headers = {"Cache-Control": "public, max-age=86400"}
    if await asyncio.to_thread(_touch, cache_file):
        return source_url, FileResponse(
            cache_file,
            media_type="application/octet-stream",
            headers={**headers, "X-RR-Voice-Cache": "hit"},
        )

    async def download() -> bytes:
        data = await fetch_voice_bytes(
            source_url, max_bytes=VOICE_PKG_MAX_BYTES, timeout_s=120
        )
        await asyncio.to_thread(_write_and_evict, cache_file, data)
        return data

    try:
        payload = await _single_flight(f"pkg:{cache_file}", download)
    except Exception as exc:
        raise VoicePkgError(str(exc), source_url=source_url) from exc
    return source_url, Response(
        payload,
        media_type="application/octet-stream",
        headers={**headers, "X-RR-Voice-Cache": "miss"},
    )


async def dispatch_voice_pkg_request(
    *,
    clean_path: str,
    query_params: dict[str, list[str]],
    headers: Mapping[str, str],
    context: ServerContext,
    runtime_dir: Path,
) -> tuple[str, str, Response] | None:
    """Answers the voice pack list and package paths, or None for any other path."""
    path = clean_path.rstrip("/")
    upstream_path = ""
    if path == "/voice-pkg/info":
        model = next((v for v in query_params.get("model") or [] if v.strip()), "")
        upstream_path = voice_info_path_for_model(model)
        if not upstream_path:
            return (
                VOICE_INFO_ROUTE_NAME,
                "",
                JSONResponse(
                    {
                        "success": False,
                        "code": 404,
                        "msg": "voice_pkg_unknown_model",
                        "data": {"model": model},
                    },
                    status_code=404,
                ),
            )
    elif _INFO_PATH.match(path):
        upstream_path = path
    file_match = _FILE_PATH.match(path)
    if not upstream_path and not file_match:
        return None
    route = VOICE_INFO_ROUTE_NAME if upstream_path else VOICE_FILE_ROUTE_NAME
    if any(k.lower() == VOICE_PROXY_HEADER for k in headers):
        # Our own upstream request came back here (DNS points the cloud host at this server).
        return (
            route,
            "",
            JSONResponse(
                {"success": False, "code": 508, "msg": "voice_pkg_loop"},
                status_code=508,
            ),
        )
    if upstream_path:
        source, response = await _voice_info_response(
            context, runtime_dir, upstream_path
        )
        return route, source, response
    host, file_path = file_match.group(1), file_match.group(2)
    if (
        not is_allowed_voice_host(host)
        or "/voice-pkg/" not in file_path
        or ".." in file_path
    ):
        return (
            route,
            "",
            JSONResponse(
                {"success": False, "code": 403, "msg": "voice_pkg_host_not_allowed"},
                status_code=403,
            ),
        )
    source, response = await _voice_file_response(runtime_dir, host, file_path)
    return route, source, response
