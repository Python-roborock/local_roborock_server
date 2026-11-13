"""Forwards a robot's Matter key request to Roborock's cloud.

A robot asked to download its Matter key (``matter.dnld_key``) calls ``GET /iot.roborock.com/fwapi/matter/key``
on the server it was paired to. The key is issued by Roborock's cloud, so with this switched on the request is
passed on to the regional cloud host and the answer handed back unchanged. Off by default: it sends the robot's
own request, with its own headers, to Roborock.
"""

from __future__ import annotations

import logging
import re

from fastapi import Request
from fastapi.responses import Response

logger = logging.getLogger("real_stack.api")

_PATH = re.compile(r"^/(?:[A-Za-z0-9.-]+/)?fwapi/matter/key/?$")
# Headers that describe this hop, not the robot's request.
_DROPPED = {"host", "connection", "content-length", "accept-encoding", "transfer-encoding", "keep-alive", "upgrade"}
TIMEOUT_SECONDS = 20


def matches(clean_path: str, method: str) -> bool:
    return method.upper() == "GET" and _PATH.match(clean_path) is not None


def upstream_url(region: str, query: str) -> str:
    code = region.strip().lower()
    host = f"{code if re.fullmatch(r'[a-z]{2,3}', code) else 'us'}iot.roborock.com"
    return f"https://{host}/fwapi/matter/key" + (f"?{query}" if query else "")


async def forward(request: Request, region: str) -> Response:
    import aiohttp

    url = upstream_url(region, request.url.query)
    headers = {name: value for name, value in request.headers.items() if name.lower() not in _DROPPED}
    # Names only: the values are the robot's credentials for the cloud.
    logger.info(
        "Matter key request from %s: forwarding to %s (header names: %s; query names: %s)",
        request.client.host if request.client else "-", url.split("?")[0], sorted(headers), sorted(request.query_params),
    )
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
            async with session.get(url, headers=headers) as upstream:
                body = await upstream.read()
                content_type = upstream.headers.get("Content-Type", "application/octet-stream")
                status = upstream.status
    except Exception as exc:  # noqa: BLE001
        logger.warning("Matter key request could not reach Roborock: %s", exc)
        return Response(content=b"", status_code=502)
    logger.info("Matter key answer from Roborock: HTTP %d, %d bytes, %s", status, len(body), content_type)
    return Response(content=body, status_code=status, media_type=content_type)

