"""Shared plugin constants and services used by plugin routes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import quote, urlparse

import aiohttp
from fastapi.responses import Response

from shared.context import ServerContext

PLUGIN_PROXY_ALLOWED_HOSTS = {
    "files.roborock.com",
    "app-files.roborock.com",
    "rrpkg-us.roborock.com",
    "cdn.awsusor0.fds.api.mi-img.com",
}

PLUGIN_PROXY_MAX_BYTES = 32 * 1024 * 1024

LEGACY_CATEGORY_PLUGIN_SOURCES = {
    "robot_vacuum_cleaner": "https://files.roborock.com/iot/plugin/979bb22f91a24f10a8bafe232b4fb5ee.zip",
    "roborock_wetdryvac": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/10320c51139848e9ade1e6bd231e15c8.zip",
    "roborock_wm": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/7f2a3e398aa54427afb48461f69a1a8c.zip",
}

APP_FEATURE_PLUGIN_LIST = [
    {
        "moduleType": "DEVICE_PAIRING",
        "version": 120,
        "apiLevel": 10028,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/0e2aad7a7c0b4721ac06c415b48bd0a8.zip",
        "pluginLevel": 3001,
        "scope": None,
    },
    {
        "moduleType": "PERSONAL_CENTER",
        "version": 292,
        "apiLevel": 10044,
        "url": "https://app-files.roborock.com/iot/plugin/ddb433cf4f2b43c9b553aea3ace73f4e.zip",
        "pluginLevel": 3002,
        "scope": None,
    },
]

CATEGORY_PLUGIN_LIST = [
    {
        "categoryId": 1,
        "category": "robot.vacuum.cleaner",
        "md5": None,
        "version": 2050,
        "apiLevel": 10028,
        "url": "https://files.roborock.com/iot/plugin/979bb22f91a24f10a8bafe232b4fb5ee.zip",
        "pluginLevel": 1,
        "scope": None,
    },
    {
        "categoryId": 2,
        "category": "roborock.wetdryvac",
        "md5": None,
        "version": 1024,
        "apiLevel": 10028,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/10320c51139848e9ade1e6bd231e15c8.zip",
        "pluginLevel": 1,
        "scope": None,
    },
    {
        "categoryId": 3,
        "category": "roborock.wm",
        "md5": None,
        "version": 1014,
        "apiLevel": 10028,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/7f2a3e398aa54427afb48461f69a1a8c.zip",
        "pluginLevel": 1,
        "scope": None,
    },
]

APPPLUGIN_LIST = [
    {
        "version": 6058,
        "url": "https://files.roborock.com/iot/plugin/ea53983b82e948638904d9154bb7f474.zip",
        "pluginLevel": 3001,
        "productid": 110,
        "apilevel": 10028,
    },
    {
        "version": 5208,
        "url": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/7cf4eb4c705c420483741189be389927.zip",
        "pluginLevel": 3001,
        "productid": 23,
        "apilevel": 10028,
    },
    {
        "version": 90,
        "url": "https://rrpkg-us.roborock.com/iot/plugin/019b4e083fbe7f81a28d79756be6f0ed.zip",
        "pluginLevel": 3001,
        "productid": 10001,
        "apilevel": 10028,
    },
]


def plugin_proxy_url(ctx: ServerContext, source_url: str) -> str:
    source = str(source_url or "").strip()
    if not source:
        return source
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
    encoded_source = quote(source, safe="")
    return f"{ctx.api_url()}/plugin/proxy/{digest}.zip?src={encoded_source}"


def proxied_plugin_records(
    ctx: ServerContext,
    records: Sequence[dict[str, Any]],
    *,
    url_key: str = "url",
) -> list[dict[str, Any]]:
    proxied: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        item = dict(record)
        source_url = str(item.get(url_key) or "").strip()
        if source_url:
            item[url_key] = plugin_proxy_url(ctx, source_url)
        proxied.append(item)
    return proxied


def first_query_value(query_params: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        values = query_params.get(key) or []
        for value in values:
            candidate = str(value or "").strip()
            if candidate:
                return candidate
    return ""


def is_allowed_plugin_source(source_url: str) -> bool:
    parsed = urlparse(source_url)
    if parsed.scheme.lower() != "https":
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    if host in PLUGIN_PROXY_ALLOWED_HOSTS:
        return True
    return host.endswith(".fds.api.mi-img.com")


def plugin_cache_path(runtime_dir: Path, source_url: str) -> Path:
    digest = hashlib.sha256(source_url.encode("utf-8")).hexdigest()
    return runtime_dir / "plugin_proxy_cache" / f"{digest}.zip"


async def download_plugin_zip(source_url: str) -> tuple[bytes, str]:
    timeout = aiohttp.ClientTimeout(total=45)
    headers = {"User-Agent": "roborock-local-server/0.1"}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(source_url, allow_redirects=True) as response:
            status = int(response.status)
            if status != 200:
                raise RuntimeError(f"upstream returned HTTP {status}")
            data = await response.read()
            if not data:
                raise RuntimeError("upstream returned empty content")
            if len(data) > PLUGIN_PROXY_MAX_BYTES:
                raise RuntimeError(
                    f"plugin too large: {len(data)} bytes exceeds {PLUGIN_PROXY_MAX_BYTES} byte limit"
                )
            content_type = str(response.headers.get("Content-Type") or "application/zip").strip()
            return data, content_type


async def plugin_proxy_response(*, runtime_dir: Path, source_url: str) -> Response:
    cache_path = plugin_cache_path(runtime_dir, source_url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists():
        payload = cache_path.read_bytes()
        return Response(
            content=payload,
            media_type="application/zip",
            headers={"Cache-Control": "public, max-age=86400", "X-RR-Plugin-Cache": "hit"},
        )

    payload, upstream_content_type = await download_plugin_zip(source_url)
    temp_path = cache_path.with_suffix(".tmp")
    temp_path.write_bytes(payload)
    temp_path.replace(cache_path)
    media_type = upstream_content_type if "zip" in upstream_content_type.lower() else "application/zip"
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Cache-Control": "public, max-age=86400", "X-RR-Plugin-Cache": "miss"},
    )
