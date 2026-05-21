"""Bridge to the vendored backend modules shipped with the release package."""

from __future__ import annotations

from pathlib import Path
import sys


def _resolve_backend_path() -> Path:
    candidate = Path(__file__).resolve().parent / "bundled_backend"
    if candidate.exists():
        return candidate.resolve()
    raise RuntimeError("Unable to locate the bundled backend modules.")


BACKEND_PATH = _resolve_backend_path()
backend_str = str(BACKEND_PATH)
if backend_str not in sys.path:
    sys.path.insert(0, backend_str)

from https_server.endpoint_rules import default_endpoint_rules, resolve_route  # type: ignore  # noqa: E402
from https_server.routes.plugin.dispatch import PluginZipDispatchError, dispatch_plugin_zip_request  # type: ignore  # noqa: E402
from import_web_inventory_from_cloud import (  # type: ignore  # noqa: E402
    _build_inventory,
    _fetch_additional_web_cache,
    _fetch_cloud_home_data_with_api,
    _flatten_device_scenes,
    _load_existing_inventory_for_merge,
    _merge_existing_inventory_mutations,
    _normalize_dict_list,
    _normalize_dict_map,
    _normalize_room_list,
    _normalize_schedule_map,
    _normalize_value_map,
)
from mqtt_broker_server import MqttTopicBridge, start_broker  # type: ignore  # noqa: E402
from mqtt_tls_proxy_server import MqttTlsProxy  # type: ignore  # noqa: E402
from shared import RuntimeCredentialsStore, RuntimeState, setup_file_logger  # type: ignore  # noqa: E402
from shared.context import ServerContext  # type: ignore  # noqa: E402
from shared.http_helpers import classify_host, strip_roborock_prefix  # type: ignore  # noqa: E402
from shared.io_utils import append_jsonl  # type: ignore  # noqa: E402

from .inventory import _extract_inventory_vacuums, _load_inventory, _merge_vacuum_state

__all__ = [
    "MqttTlsProxy",
    "MqttTopicBridge",
    "RuntimeCredentialsStore",
    "RuntimeState",
    "ServerContext",
    "_build_inventory",
    "_extract_inventory_vacuums",
    "_fetch_additional_web_cache",
    "_fetch_cloud_home_data_with_api",
    "_flatten_device_scenes",
    "_load_existing_inventory_for_merge",
    "_load_inventory",
    "_merge_existing_inventory_mutations",
    "_merge_vacuum_state",
    "_normalize_dict_list",
    "_normalize_dict_map",
    "_normalize_room_list",
    "_normalize_schedule_map",
    "_normalize_value_map",
    "append_jsonl",
    "classify_host",
    "dispatch_plugin_zip_request",
    "default_endpoint_rules",
    "PluginZipDispatchError",
    "resolve_route",
    "setup_file_logger",
    "start_broker",
    "strip_roborock_prefix",
]
