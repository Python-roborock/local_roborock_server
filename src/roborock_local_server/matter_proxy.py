"""Forwards a robot's Matter key request to Roborock's cloud.

A robot asked to download its Matter key (``matter.dnld_key``) calls ``GET /iot.roborock.com/fwapi/matter/key``
on the server it was paired to. The key is issued by Roborock's cloud, so with this switched on the request is
passed on to the regional cloud host and the answer handed back unchanged. Off by default: it sends the robot's
own request, with its own headers, to Roborock.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs

import aiohttp
from fastapi import Request
from fastapi.responses import Response
from yarl import URL

logger = logging.getLogger("real_stack.api")

_PATH = re.compile(r"^/(?:[A-Za-z0-9.-]+/)?fwapi/matter/key/?$")
REGIONS = frozenset({"us", "eu", "cn", "ru"})
UPSTREAM_BASE = "https://{region}iot.roborock.com"
# Hop headers, proxy-added headers and browser state: none of these belong to the robot's own request.
_DROPPED = {
    "host", "connection", "content-length", "accept-encoding", "transfer-encoding", "keep-alive", "upgrade",
    "te", "trailer", "proxy-authorization", "proxy-connection", "cookie", "forwarded", "via", "origin", "referer",
    "x-real-ip", "true-client-ip", "cf-connecting-ip", "x-local-sync-secret",
}
_DROPPED_PREFIXES = ("x-forwarded-", "cf-", "x-envoy-", "x-amzn-", "sec-")
TIMEOUT_SECONDS = 20
MAX_QUERY_LENGTH = 1024
MAX_QUERY_PARAMS = 16
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_HEADER_VALUE = 2048
_QUERY_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_DID_KEYS = ("did", "duid", "d", "device_id", "deviceId", "device_did", "deviceDid")


def matches(clean_path: str, method: str) -> bool:
    return method.upper() == "GET" and _PATH.match(clean_path) is not None


def upstream_url(region: str, query: str) -> str:
    code = region.strip().lower()
    if code not in REGIONS:
        raise ValueError(f"unsupported region {region!r}")
    return UPSTREAM_BASE.format(region=code) + "/fwapi/matter/key" + (f"?{query}" if query else "")


def forwardable_headers(headers: Any) -> dict[str, str]:
    kept: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _DROPPED or lowered.startswith(_DROPPED_PREFIXES) or len(value) > MAX_HEADER_VALUE:
            logger.debug("Matter key request: header %r not forwarded", name)
            continue
        kept[name] = value
    return kept


def parse_query(query: str) -> dict[str, list[str]]:
    return parse_qs(query, keep_blank_values=True)


def query_is_acceptable(query: str) -> bool:
    """Plain key=value pairs of bounded size; the raw query is signed, so it is passed on unchanged."""
    if len(query) > MAX_QUERY_LENGTH:
        return False
    keys = [part.split("=", 1)[0] for part in query.split("&") if part]
    return len(keys) <= MAX_QUERY_PARAMS and all(_QUERY_KEY.match(key) for key in keys)


class RateLimiter:
    def __init__(self, limit: int = RATE_LIMIT_REQUESTS, window: float = RATE_LIMIT_WINDOW_SECONDS) -> None:
        self._limit, self._window = limit, window
        self._hits: dict[str, list[float]] = {}

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self._hits.get(client, []) if now - t < self._window]
        allowed = len(recent) < self._limit
        if allowed:
            recent.append(now)
        self._hits[client] = recent
        if len(self._hits) > 1024:
            self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self._window}
        return allowed


def known_device(vacuums: list[dict[str, Any]], query_params: dict[str, list[str]], client_ip: str) -> bool:
    """A request names a paired robot (did/duid in the query), or comes from the address of one that is connected."""
    named = {value for key in _DID_KEYS for value in query_params.get(key, []) if value}
    for vac in vacuums:
        if named & {str(vac.get("duid") or ""), str(vac.get("did") or "")}:
            return True
    if named:
        return False
    ips = {ip for vac in vacuums for ip in [*(vac.get("ips") or []), vac.get("last_ip")] if ip}
    return client_ip in ips


def redact_log_entry(entry: dict[str, object]) -> None:
    """The robot's header and query values are its cloud credentials: keep names only, drop the query from the path."""
    headers = entry.get("headers")
    if isinstance(headers, dict):
        entry["headers"] = {key: "<redacted>" for key in headers}
    query = entry.get("query")
    if isinstance(query, dict):
        entry["query"] = {key: "<redacted>" for key in query}
    entry["raw_path"] = str(entry.get("clean_path") or "")


async def forward(request: Request, region: str) -> Response:
    try:
        url = upstream_url(region, request.url.query)
    except ValueError as exc:
        logger.warning("Matter key request not forwarded: %s (expected one of %s)", exc, sorted(REGIONS))
        return Response(content=b"", status_code=502)
    headers = forwardable_headers(request.headers)
    # Names only: the values are the robot's credentials for the cloud.
    logger.info(
        "Matter key request from %s: forwarding to %s (header names: %s; query names: %s)",
        request.client.host if request.client else "-", url.split("?")[0], sorted(headers), sorted(request.query_params),
    )
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
            async with session.get(URL(url, encoded=True), headers=headers) as upstream:
                body = await upstream.read()
                content_type = upstream.headers.get("Content-Type", "application/octet-stream")
                status = upstream.status
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        logger.warning("Matter key request could not reach Roborock: %s", exc)
        return Response(content=b"", status_code=502)
    logger.info("Matter key answer from Roborock: HTTP %d, %d bytes, %s", status, len(body), content_type)
    return Response(content=body, status_code=status, media_type=content_type)
