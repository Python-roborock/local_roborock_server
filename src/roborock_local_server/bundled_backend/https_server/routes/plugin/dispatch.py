"""Dispatcher for plugin ZIP routes."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi.responses import Response

from .category import source_from_category_path
from .common import plugin_proxy_response
from .proxy import source_from_proxy_request
from .voice_pkg import VoicePkgError, dispatch_voice_pkg_request

PLUGIN_PROXY_ROUTE_NAME = "plugin_proxy"

PluginZipDispatchResult = tuple[str, str, Response]


class PluginZipDispatchError(RuntimeError):
    """Raised when plugin ZIP routing matched but proxying failed."""

    def __init__(self, *, route_name: str, source_url: str, cause: Exception) -> None:
        super().__init__(str(cause))
        self.route_name = route_name
        self.source_url = source_url
        self.cause = cause


def resolve_plugin_zip_source(clean_path: str, query_params: dict[str, list[str]]) -> str:
    source = source_from_proxy_request(clean_path, query_params)
    if source:
        return source
    return source_from_category_path(clean_path)


async def dispatch_plugin_zip_request(
    *,
    clean_path: str,
    query_params: dict[str, list[str]],
    runtime_dir: Path,
    context: Any = None,
    headers: Mapping[str, str] | None = None,
) -> PluginZipDispatchResult | None:
    source_url = resolve_plugin_zip_source(clean_path, query_params)
    if not source_url:
        if context is None:
            return None
        try:
            return await dispatch_voice_pkg_request(
                clean_path=clean_path,
                query_params=query_params,
                headers=headers or {},
                context=context,
                runtime_dir=runtime_dir,
            )
        except VoicePkgError as exc:
            raise PluginZipDispatchError(route_name="voice_pkg_proxy", source_url=exc.source_url, cause=exc) from exc

    try:
        response = await plugin_proxy_response(runtime_dir=runtime_dir, source_url=source_url)
    except Exception as exc:  # noqa: BLE001
        raise PluginZipDispatchError(
            route_name=PLUGIN_PROXY_ROUTE_NAME,
            source_url=source_url,
            cause=exc,
        ) from exc

    return PLUGIN_PROXY_ROUTE_NAME, source_url, response
