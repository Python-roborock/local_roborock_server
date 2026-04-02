from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import time
from typing import Any, Callable, Sequence

from shared.constants import DEFAULT_HOME_NAME, DEFAULT_TIMEZONE, MODEL_PRODUCT_ID_OVERRIDES
from shared.context import ServerContext
from shared.data_helpers import as_bool, as_int, default_home_id, default_product_name, get_value, stable_int
from shared.http_helpers import wrap_response
from shared.inventory_io import WEB_API_INVENTORY_FILE, load_inventory, write_inventory

from .routes.api.v1.appfeatureplugin import build as _build_app_feature_plugin
from .routes.api.v1.appfeatureplugin import match as _match_app_feature_plugin
from .routes.api.v1.appconfig import build as _build_app_config_v1
from .routes.api.v1.appconfig import match as _match_app_config_v1
from .routes.api.v1.country import build_country_list as _build_country_list_v1
from .routes.api.v1.country import build_country_version as _build_country_version_v1
from .routes.api.v1.country import match_country_list as _match_country_list_v1
from .routes.api.v1.country import match_country_version as _match_country_version_v1
from .routes.api.v1.home import build_get_home_detail as _build_get_home_detail_v1
from .routes.api.v1.home import build_home_devices_order as _build_home_devices_order_v1
from .routes.api.v1.home import match_get_home_detail as _match_get_home_detail_v1
from .routes.api.v1.home import match_home_devices_order as _match_home_devices_order_v1
from .routes.api.v1.appplugin import build as _build_download_code
from .routes.api.v1.appplugin import match as _match_download_code
from .routes.api.v1.plugins import build as _build_download_category_code
from .routes.api.v1.plugins import match as _match_download_category_code
from .routes.api.v2.appconfig import build as _build_app_config_v2
from .routes.api.v2.appconfig import match as _match_app_config_v2
from .routes.api.v3.login import build_login_key_sign as _build_login_key_sign_v3
from .routes.api.v3.login import build_login_password_submit as _build_login_password_submit_v3
from .routes.api.v3.login import build_login_sms_code_send as _build_login_sms_code_send_v3
from .routes.api.v3.login import match_login_key_sign as _match_login_key_sign_v3
from .routes.api.v3.login import match_login_password_submit as _match_login_password_submit_v3
from .routes.api.v3.login import match_login_sms_code_send as _match_login_sms_code_send_v3
from .routes.api.v4.agreement import build as _build_agreement_latest_v4
from .routes.api.v4.agreement import match as _match_agreement_latest_v4
from .routes.api.v4.login import build_login_code_submit as _build_login_code_submit_v4
from .routes.api.v4.login import build_login_code_validate as _build_login_code_validate_v4
from .routes.api.v4.login import build_login_email_code_send as _build_login_email_code_send_v4
from .routes.api.v4.login import build_login_key_captcha as _build_login_key_captcha_v4
from .routes.api.v4.login import build_login_sms_code_send as _build_login_sms_code_send_v4
from .routes.api.v4.login import match_login_code_submit as _match_login_code_submit_v4
from .routes.api.v4.login import match_login_code_validate as _match_login_code_validate_v4
from .routes.api.v4.login import match_login_email_code_send as _match_login_email_code_send_v4
from .routes.api.v4.login import match_login_key_captcha as _match_login_key_captcha_v4
from .routes.api.v4.login import match_login_sms_code_send as _match_login_sms_code_send_v4
from .routes.api.v4.product import build as _build_get_products_v4
from .routes.api.v4.product import match as _match_get_products_v4
from .routes.api.v5.login import build_login_code_submit as _build_login_code_submit_v5
from .routes.api.v5.login import build_login_code_validate as _build_login_code_validate_v5
from .routes.api.v5.login import build_login_email_code_send as _build_login_email_code_send_v5
from .routes.api.v5.login import build_login_password_reset as _build_login_password_reset_v5
from .routes.api.v5.login import build_login_password_submit as _build_login_password_submit_v5
from .routes.api.v5.login import build_login_sms_code_send as _build_login_sms_code_send_v5
from .routes.api.v5.login import match_login_code_submit as _match_login_code_submit_v5
from .routes.api.v5.login import match_login_code_validate as _match_login_code_validate_v5
from .routes.api.v5.login import match_login_email_code_send as _match_login_email_code_send_v5
from .routes.api.v5.login import match_login_password_reset as _match_login_password_reset_v5
from .routes.api.v5.login import match_login_password_submit as _match_login_password_submit_v5
from .routes.api.v5.login import match_login_sms_code_send as _match_login_sms_code_send_v5
from .routes.api.v5.product import build as _build_get_products_v5
from .routes.api.v5.product import match as _match_get_products_v5
from .routes.bootstrap.catchall import build as _build_catchall
from .routes.bootstrap.catchall import match as _match_catchall
from .routes.bootstrap.location import build as _build_location
from .routes.bootstrap.location import match as _match_location
from .routes.bootstrap.nc_prepare import build as _build_nc_prepare
from .routes.bootstrap.nc_prepare import match as _match_nc_prepare
from .routes.bootstrap.region import build as _build_region
from .routes.bootstrap.region import match as _match_region
from .routes.bootstrap.time import build as _build_time
from .routes.bootstrap.time import match as _match_time
from .routes.api.v1.user import build_get_url_by_email as _build_get_url_by_email_v1
from .routes.api.v1.user import build_logout as _build_logout_v1
from .routes.api.v1.user import build_user_info as _build_user_info_v1
from .routes.api.v1.user import build_user_roles as _build_user_roles_v1
from .routes.api.v1.user import match_get_url_by_email as _match_get_url_by_email_v1
from .routes.api.v1.user import match_logout as _match_logout_v1
from .routes.api.v1.user import match_user_info as _match_user_info_v1
from .routes.api.v1.user import match_user_roles as _match_user_roles_v1
from .routes.user.app.info import build as _build_post_app_info
from .routes.user.app.info import match as _match_post_app_info
from .routes.user.inbox.latest import build as _build_get_inbox_latest
from .routes.user.inbox.latest import match as _match_get_inbox_latest
from .routes.auth.login import build_login_code_submit as _build_login_code_submit_v1
from .routes.auth.login import build_login_code_validate as _build_login_code_validate_v1
from .routes.auth.login import build_login_email_code_send as _build_login_email_code_send_v1
from .routes.auth.login import build_login_ml_c as _build_login_ml_c_v1
from .routes.auth.login import build_login_password_submit as _build_login_password_submit_v1
from .routes.auth.login import build_login_sms_code_send as _build_login_sms_code_send_v1
from .routes.auth.login import match_login_code_submit as _match_login_code_submit_v1
from .routes.auth.login import match_login_code_validate as _match_login_code_validate_v1
from .routes.auth.login import match_login_email_code_send as _match_login_email_code_send_v1
from .routes.auth.login import match_login_ml_c as _match_login_ml_c_v1
from .routes.auth.login import match_login_password_submit as _match_login_password_submit_v1
from .routes.auth.login import match_login_sms_code_send as _match_login_sms_code_send_v1
from .routes.user.devices.detail import build as _build_get_device
from .routes.user.devices.detail import build_extra as _build_get_device_extra
from .routes.user.devices.detail import match as _match_get_device
from .routes.user.devices.detail import match_extra as _match_get_device_extra
from .routes.user.devices.jobs import build as _build_get_schedules
from .routes.user.devices.jobs import match as _match_get_schedules
from .routes.user.devices.newadd import build as _build_add_device
from .routes.user.devices.newadd import match as _match_add_device
from .routes.user.homes.item import build as _build_get_home_data
from .routes.user.homes.item import match as _match_get_home_data
from .routes.user.homes.rooms import build as _build_get_home_rooms
from .routes.user.homes.rooms import build_post as _build_post_home_rooms
from .routes.user.homes.rooms import match as _match_get_home_rooms
from .routes.user.homes.rooms import match_post as _match_post_home_rooms
from .routes.user.homes.service import normalize_rooms as _normalize_rooms
from .routes.user.scene.device import build as _build_get_scenes
from .routes.user.scene.device import match as _match_get_scenes
from .routes.user.scene.home import build as _build_get_home_scenes
from .routes.user.scene.home import match as _match_get_home_scenes
from .routes.user.scene.item import build_execute as _build_execute_scene
from .routes.user.scene.item import build_put_name as _build_put_scene_name
from .routes.user.scene.item import build_put_param as _build_put_scene_param
from .routes.user.scene.item import match_execute as _match_execute_scene
from .routes.user.scene.item import match_put_name as _match_put_scene_name
from .routes.user.scene.item import match_put_param as _match_put_scene_param
from .routes.user.scene.order import build as _build_get_scene_order
from .routes.user.scene.order import match as _match_get_scene_order
from .routes.v2.user.scene import build as _build_post_scene_create
from .routes.v2.user.scene import match as _match_post_scene_create

RouteMatcher = Callable[..., bool]
RouteResponseFactory = Callable[[ServerContext, dict[str, list[str]], dict[str, list[str]], str], dict[str, Any]]

_RSA_OAEP_SHA1_MAX_PLAINTEXT = 214
_AGREEMENT_LATEST_DATA = {
    "userAgreement": {
        "version": "16.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/7f65ba7da3ab4e0db1177c366a03d06e.html",
            "en": "https://files.roborock.com/iot/doc/8765be2db5dd4b87bac8ba82ba1b6878.html",
        },
        "popupText": None,
    },
    "privacyProtocol": {
        "version": "17.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/e8143aeb64544008b864e1b06cde4543.html",
            "en": "https://files.roborock.com/iot/doc/d1945f29e9794bdba80496a998298751.html",
        },
        "popupText": None,
    },
    "personalInfoCol": {
        "version": "2.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/1df929732c104dcc9f0f489d5b368cc9.html",
            "en": "https://files.roborock.com/iot/doc/d24f84ac2f3d4b50a9897d64b4faacbd.html",
        },
        "popupText": None,
    },
    "thirdPartyInfoShare": {
        "version": "3.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/23f480bb58e14db593639878095249a6.html",
            "en": "https://files.roborock.com/iot/doc/dd725a4e900a47b382897a59da09aed5.html",
        },
        "popupText": None,
    },
    "improvementPlan": {
        "version": "1.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/1184a5a566c24bd1b520e4063cae1a14.html",
            "en": "https://files.roborock.com/iot/doc/3e754f53d8934487ad448a5defec6caa.html",
        },
        "popupText": None,
    },
}


def _ok(data: Any) -> dict[str, Any]:
    # Match upstream auth/iot envelope exactly for app login flow.
    return {"code": 200, "msg": "success", "data": data}


def _runtime_connected_identity_set(ctx: ServerContext) -> tuple[set[str], bool]:
    """Return runtime-connected device identities keyed by DUID/DID."""
    runtime_state = getattr(ctx, "runtime_state", None)
    if runtime_state is None:
        return set(), False
    runtime_credentials = getattr(ctx, "runtime_credentials", None)

    try:
        snapshot = runtime_state.vacuum_snapshot()
        key_models_by_did = runtime_state.key_models_by_did()
    except Exception:
        return set(), False

    connected_ids: set[str] = set()
    connected_models: set[str] = set()
    for vac in snapshot:
        if not isinstance(vac, dict):
            continue
        if not as_bool(vac.get("connected"), False):
            continue
        for key in ("duid", "did"):
            value = vac.get(key)
            if value is None:
                continue
            normalized = str(value).strip()
            if normalized:
                connected_ids.add(normalized)
        did = str(vac.get("did") or "").strip()
        if did:
            if runtime_credentials is not None:
                credential_device = runtime_credentials.resolve_device(did=did)
                if credential_device is not None:
                    credential_duid = str(credential_device.get("duid") or "").strip()
                    if credential_duid:
                        connected_ids.add(credential_duid)
            model_hint = str(vac.get("key_model") or key_models_by_did.get(did) or "").strip().lower()
            if model_hint:
                connected_models.add(model_hint)

    # Runtime MQTT topics often identify devices by numeric DID while cloud
    # inventory uses DUID. Link connected runtime devices back to inventory
    # entries via unique model when possible.
    inventory = load_inventory(ctx)
    inventory_sources: list[dict[str, Any]] = []
    for source_key in ("devices", "received_devices", "receivedDevices"):
        source_list = inventory.get(source_key)
        if not isinstance(source_list, list):
            continue
        for raw in source_list:
            if isinstance(raw, dict):
                inventory_sources.append(raw)

    model_counts: dict[str, int] = {}
    for raw in inventory_sources:
        model = str(get_value(raw, "model", default="")).strip().lower()
        if not model:
            continue
        model_counts[model] = model_counts.get(model, 0) + 1

    for raw in inventory_sources:
        model = str(get_value(raw, "model", default="")).strip().lower()
        if not model or model_counts.get(model, 0) != 1 or model not in connected_models:
            continue
        inventory_duid = str(get_value(raw, "duid", "did", "device_id", default="")).strip()
        if inventory_duid:
            connected_ids.add(inventory_duid)
    return connected_ids, bool(connected_ids)


def _runtime_online_for_device(
    raw_item: dict[str, Any],
    *,
    runtime_connected_ids: set[str],
) -> bool:
    """Decide if a device should be marked online from runtime connectivity."""
    for key in ("duid", "did", "device_did", "deviceDid", "device_id", "deviceId"):
        value = raw_item.get(key)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized and normalized in runtime_connected_ids:
            return True

    return False


def _normalize_devices(
    ctx: ServerContext,
    devices_raw: list[dict[str, Any]],
    *,
    now_ts: int,
    default_name_prefix: str = "Vacuum",
    runtime_connected_ids: set[str] | None = None,
    runtime_online_authoritative: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    connected_ids = runtime_connected_ids or set()
    products_by_id: dict[str, dict[str, Any]] = {}
    devices: list[dict[str, Any]] = []
    for index, raw in enumerate(devices_raw):
        raw_item = raw if isinstance(raw, dict) else {}
        fallback_duid = ctx.duid if index == 0 else f"{ctx.duid}_{index + 1}"
        duid = str(get_value(raw_item, "duid", "did", "device_id", default=fallback_duid))
        local_key = ctx.resolve_device_localkey(
            did=str(get_value(raw_item, "did", "device_did", default="")),
            duid=duid,
            model=str(get_value(raw_item, "model", default="")),
            name=str(get_value(raw_item, "name", "device_name", default="")),
            product_id=str(get_value(raw_item, "product_id", "productId", default="")),
            source="web_home_data",
            assign_if_missing=True,
        )
        product_id = str(get_value(raw_item, "product_id", "productId", default=f"product_{index + 1}"))
        model = str(get_value(raw_item, "model", default="roborock.vacuum.a117"))
        category = str(get_value(raw_item, "category", default="robot.vacuum.cleaner"))
        product_name = str(get_value(raw_item, "product_name", "productName", default=default_product_name(model)))
        timezone = str(get_value(raw_item, "timezone", "timeZoneId", "time_zone_id", default=DEFAULT_TIMEZONE))
        room_id_value = get_value(raw_item, "room_id", "roomId")
        room_id = as_int(room_id_value, 0) if room_id_value is not None else None
        runtime_online = _runtime_online_for_device(
            raw_item,
            runtime_connected_ids=connected_ids,
        )
        inventory_online = as_bool(get_value(raw_item, "online", default=True), True)
        resolved_online = runtime_online if runtime_online_authoritative else (inventory_online or runtime_online)
        device = {
            "duid": duid,
            "name": str(get_value(raw_item, "name", "device_name", default=f"{default_name_prefix} {index + 1}")),
            "localKey": local_key,
            "productId": product_id,
            "fv": str(get_value(raw_item, "fv", "firmware", "firmware_version", default="02.33.88")),
            "pv": str(get_value(raw_item, "pv", "protocol_version", default="1.0")),
            "activeTime": as_int(get_value(raw_item, "active_time", "activeTime", default=now_ts), now_ts),
            "timeZoneId": timezone,
            "online": resolved_online,
            "sn": str(
                get_value(
                    raw_item,
                    "sn",
                    "serial_number",
                    default=f"RR{hashlib.sha256(duid.encode()).hexdigest()[:12].upper()}",
                )
            ),
        }
        if room_id is not None and room_id > 0:
            device["roomId"] = room_id
        feature_set = get_value(raw_item, "feature_set", "featureSet")
        if feature_set is not None:
            device["featureSet"] = str(feature_set)
        new_feature_set = get_value(raw_item, "new_feature_set", "newFeatureSet")
        if new_feature_set is not None:
            device["newFeatureSet"] = str(new_feature_set)
        devices.append(device)
        if product_id not in products_by_id:
            product = {
                "id": product_id,
                "name": product_name,
                "model": model,
                "category": category,
                "code": str(get_value(raw_item, "code", default=model.split(".")[-1] if model else "a117")),
                "iconUrl": str(get_value(raw_item, "icon_url", "iconUrl", default="")),
            }
            capability = get_value(raw_item, "capability")
            if capability is not None:
                product["capability"] = capability
            schema = get_value(raw_item, "schema")
            if isinstance(schema, list):
                product["schema"] = schema
            products_by_id[product_id] = product
    return devices, list(products_by_id.values())


def _build_web_state(ctx: ServerContext) -> dict[str, Any]:
    inventory = load_inventory(ctx)
    home_value = inventory.get("home")
    home_data = home_value if isinstance(home_value, dict) else {}
    now_ts = int(time.time())
    runtime_connected_ids, any_runtime_connected = _runtime_connected_identity_set(ctx)
    raw_devices = inventory.get("devices")
    devices_source = raw_devices if isinstance(raw_devices, list) and raw_devices else [{}]
    devices, products = _normalize_devices(
        ctx,
        devices_source,
        now_ts=now_ts,
        runtime_connected_ids=runtime_connected_ids,
        runtime_online_authoritative=any_runtime_connected,
    )
    raw_received = get_value(inventory, "received_devices", "receivedDevices", default=[])
    received_source = raw_received if isinstance(raw_received, list) else []
    received_devices, received_products = _normalize_devices(
        ctx,
        received_source,
        now_ts=now_ts,
        default_name_prefix="Shared Vacuum",
        runtime_connected_ids=runtime_connected_ids,
        runtime_online_authoritative=any_runtime_connected,
    )
    for product in received_products:
        product_id = str(product["id"])
        if all(existing["id"] != product_id for existing in products):
            products.append(product)

    home_id = as_int(
        get_value(home_data, "rr_home_id", "rrHomeId", "home_id", "id", default=default_home_id(ctx)),
        default_home_id(ctx),
    )
    home_name = str(get_value(home_data, "name", "home_name", default=DEFAULT_HOME_NAME))
    rooms = _normalize_rooms(inventory)
    home_payload = {
        "id": home_id,
        "name": home_name,
        "products": products,
        "devices": devices,
        "receivedDevices": received_devices,
        "rooms": rooms,
    }
    lon = get_value(home_data, "lon")
    if lon is not None:
        home_payload["lon"] = lon
    lat = get_value(home_data, "lat")
    if lat is not None:
        home_payload["lat"] = lat
    geo_name = get_value(home_data, "geo_name", "geoName")
    if geo_name is not None:
        home_payload["geoName"] = geo_name

    scenes_value = inventory.get("scenes")
    scenes = scenes_value if isinstance(scenes_value, list) else []
    scene_order_value = inventory.get("scene_order")
    scene_order = scene_order_value if isinstance(scene_order_value, list) else []
    schedules_value = inventory.get("schedules")
    schedules = schedules_value if isinstance(schedules_value, dict) else {}
    return {
        "home_id": home_id,
        "home_name": home_name,
        "home_data": home_payload,
        "scenes": scenes,
        "scene_order": scene_order,
        "schedules": schedules,
    }


def _device_has_runtime_did(ctx: ServerContext, duid: str) -> bool:
    runtime_credentials = getattr(ctx, "runtime_credentials", None)
    if runtime_credentials is None:
        return False
    try:
        credential_device = runtime_credentials.resolve_device(duid=duid)
    except Exception:
        return False
    if credential_device is None:
        return False
    did = str(credential_device.get("did") or "").strip()
    mqtt_user = str(credential_device.get("device_mqtt_usr") or "").strip()
    return bool(did or mqtt_user)


def _filter_home_data_to_runtime_devices(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    filtered_home = dict(home_data)
    allowed_product_ids: set[str] = set()

    for collection_key in ("devices", "receivedDevices", "received_devices"):
        devices_value = home_data.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        filtered_devices: list[dict[str, Any]] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            duid = str(get_value(device, "duid", "did", default="")).strip()
            if not duid or not _device_has_runtime_did(ctx, duid):
                continue
            filtered_devices.append(dict(device))
            product_id = str(get_value(device, "productId", "product_id", default="")).strip()
            if product_id:
                allowed_product_ids.add(product_id)
        filtered_home[collection_key] = filtered_devices

    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    filtered_products: list[dict[str, Any]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        product_id = str(get_value(product, "id", "productId", "product_id", default="")).strip()
        if not product_id or product_id not in allowed_product_ids:
            continue
        filtered_products.append(dict(product))
    filtered_home["products"] = filtered_products
    return filtered_home


def _build_product_response(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    filtered_home_data = _filter_home_data_to_runtime_devices(ctx, home_data)
    products_value = filtered_home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    categories: dict[str, dict[str, Any]] = {}
    for product in products:
        if not isinstance(product, dict):
            continue
        raw_product_id = str(product.get("id") or "")
        category_name = str(product.get("category") or "robot.vacuum.cleaner")
        if category_name not in categories:
            category_id = len(categories) + 1
            categories[category_name] = {
                "category": {
                    "id": category_id,
                    "displayName": category_name,
                    "iconUrl": "",
                },
                "productList": [],
            }
        model = str(product.get("model") or "roborock.vacuum.a117")
        model_key = model.strip().lower()
        product_id = MODEL_PRODUCT_ID_OVERRIDES.get(
            model_key,
            as_int(raw_product_id, stable_int(raw_product_id or category_name) % 1_000_000),
        )
        product_entry = {
            "id": product_id,
            "name": str(product.get("name") or default_product_name(model)),
            "model": model,
            "packagename": f"com.roborock.{model.split('.')[-1]}",
            "ncMode": "global",
            "status": 10,
        }
        icon_url = product.get("iconUrl")
        if isinstance(icon_url, str) and icon_url:
            product_entry["picurl"] = icon_url
            product_entry["cardPicUrl"] = icon_url
            product_entry["pluginPicUrl"] = icon_url
        categories[category_name]["productList"].append(product_entry)
    return {"categoryDetailList": list(categories.values())}


@dataclass(frozen=True)
class EndpointRule:
    """Describes when a path matches and how to build its response."""

    name: str
    matcher: RouteMatcher
    build_response: RouteResponseFactory


def default_endpoint_rules() -> Sequence[EndpointRule]:
    """Returns endpoint rules in match priority order."""

    return (
        EndpointRule("get_url_by_email", _match_get_url_by_email_v1, _build_get_url_by_email_v1),
        EndpointRule("login_ml_c_v1", _match_login_ml_c_v1, _build_login_ml_c_v1),
        EndpointRule("login_key_sign_v3", _match_login_key_sign_v3, _build_login_key_sign_v3),
        EndpointRule("login_key_captcha_v4", _match_login_key_captcha_v4, _build_login_key_captcha_v4),
        EndpointRule("login_email_code_send_v1", _match_login_email_code_send_v1, _build_login_email_code_send_v1),
        EndpointRule("login_email_code_send_v4", _match_login_email_code_send_v4, _build_login_email_code_send_v4),
        EndpointRule("login_email_code_send_v5", _match_login_email_code_send_v5, _build_login_email_code_send_v5),
        EndpointRule("login_sms_code_send_v1", _match_login_sms_code_send_v1, _build_login_sms_code_send_v1),
        EndpointRule("login_sms_code_send_v3", _match_login_sms_code_send_v3, _build_login_sms_code_send_v3),
        EndpointRule("login_sms_code_send_v4", _match_login_sms_code_send_v4, _build_login_sms_code_send_v4),
        EndpointRule("login_sms_code_send_v5", _match_login_sms_code_send_v5, _build_login_sms_code_send_v5),
        EndpointRule("login_code_validate_v1", _match_login_code_validate_v1, _build_login_code_validate_v1),
        EndpointRule("login_code_validate_v4", _match_login_code_validate_v4, _build_login_code_validate_v4),
        EndpointRule("login_code_validate_v5", _match_login_code_validate_v5, _build_login_code_validate_v5),
        EndpointRule("login_code_submit_v1", _match_login_code_submit_v1, _build_login_code_submit_v1),
        EndpointRule("login_code_submit_v4", _match_login_code_submit_v4, _build_login_code_submit_v4),
        EndpointRule("login_code_submit_v5", _match_login_code_submit_v5, _build_login_code_submit_v5),
        EndpointRule("login_password_submit_v1", _match_login_password_submit_v1, _build_login_password_submit_v1),
        EndpointRule("login_password_submit_v3", _match_login_password_submit_v3, _build_login_password_submit_v3),
        EndpointRule("login_password_submit_v5", _match_login_password_submit_v5, _build_login_password_submit_v5),
        EndpointRule("login_password_reset_v5", _match_login_password_reset_v5, _build_login_password_reset_v5),
        EndpointRule("country_version", _match_country_version_v1, _build_country_version_v1),
        EndpointRule("country_list", _match_country_list_v1, _build_country_list_v1),
        EndpointRule("agreement_latest_v4", _match_agreement_latest_v4, _build_agreement_latest_v4),
        EndpointRule("get_home_detail", _match_get_home_detail_v1, _build_get_home_detail_v1),
        EndpointRule("user_info", _match_user_info_v1, _build_user_info_v1),
        EndpointRule("app_config", _match_app_config_v1, _build_app_config_v1),
        EndpointRule("app_config_v2", _match_app_config_v2, _build_app_config_v2),
        EndpointRule("app_feature_plugin", _match_app_feature_plugin, _build_app_feature_plugin),
        EndpointRule("home_devices_order", _match_home_devices_order_v1, _build_home_devices_order_v1),
        EndpointRule("user_roles", _match_user_roles_v1, _build_user_roles_v1),
        EndpointRule("logout", _match_logout_v1, _build_logout_v1),
        EndpointRule("get_home_data", _match_get_home_data, _build_get_home_data),
        EndpointRule("post_home_rooms", _match_post_home_rooms, _build_post_home_rooms),
        EndpointRule("post_scene_create", _match_post_scene_create, _build_post_scene_create),
        EndpointRule("get_home_rooms", _match_get_home_rooms, _build_get_home_rooms),
        EndpointRule("get_scenes", _match_get_scenes, _build_get_scenes),
        EndpointRule("get_home_scenes", _match_get_home_scenes, _build_get_home_scenes),
        EndpointRule("get_scene_order", _match_get_scene_order, _build_get_scene_order),
        EndpointRule("put_scene_name", _match_put_scene_name, _build_put_scene_name),
        EndpointRule("put_scene_param", _match_put_scene_param, _build_put_scene_param),
        EndpointRule("execute_scene", _match_execute_scene, _build_execute_scene),
        EndpointRule("get_device", _match_get_device, _build_get_device),
        EndpointRule("get_device_extra", _match_get_device_extra, _build_get_device_extra),
        EndpointRule("get_schedules", _match_get_schedules, _build_get_schedules),
        EndpointRule("post_app_info", _match_post_app_info, _build_post_app_info),
        EndpointRule("get_inbox_latest", _match_get_inbox_latest, _build_get_inbox_latest),
        EndpointRule("get_products_v4", _match_get_products_v4, _build_get_products_v4),
        EndpointRule("get_products_v5", _match_get_products_v5, _build_get_products_v5),
        EndpointRule("download_code", _match_download_code, _build_download_code),
        EndpointRule("download_category_code", _match_download_category_code, _build_download_category_code),
        EndpointRule("add_device", _match_add_device, _build_add_device),
        EndpointRule("region", _match_region, _build_region),
        EndpointRule("nc_prepare", _match_nc_prepare, _build_nc_prepare),
        EndpointRule("time", _match_time, _build_time),
        EndpointRule("location", _match_location, _build_location),
        EndpointRule("catchall", _match_catchall, _build_catchall),
    )


def resolve_route(
    *,
    rules: Sequence[EndpointRule],
    context: ServerContext,
    clean_path: str,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    method: str = "GET",
) -> tuple[str, dict[str, Any]]:
    """Resolves the first matching rule and returns (rule_name, response_payload)."""

    for rule in rules:
        try:
            matched = rule.matcher(clean_path, method)
        except TypeError:
            matched = rule.matcher(clean_path)
        if matched:
            return rule.name, rule.build_response(context, query_params, body_params, clean_path)
    return "catchall", _build_catchall(context, query_params, body_params, clean_path)
