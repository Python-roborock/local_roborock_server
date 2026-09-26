from __future__ import annotations

from typing import Any

DEFAULT_HOME_NAME = "Local Home"
DEFAULT_TIMEZONE = "America/New_York"

DEFAULT_PRODUCT_SCHEMA: list[dict[str, Any]] = [
    {
        "id": 101,
        "name": "rpc_request",
        "code": "rpc_request",
        "mode": "rw",
        "type": "RAW",
    },
    {
        "id": 102,
        "name": "rpc_response",
        "code": "rpc_response",
        "mode": "rw",
        "type": "RAW",
    },
    {
        "id": 120,
        "name": "error_code",
        "code": "error_code",
        "mode": "ro",
        "type": "ENUM",
    },
    {
        "id": 121,
        "name": "state",
        "code": "state",
        "mode": "ro",
        "type": "ENUM",
    },
    {
        "id": 122,
        "name": "battery",
        "code": "battery",
        "mode": "ro",
        "type": "VALUE",
    },
    {
        "id": 123,
        "name": "fan_power",
        "code": "fan_power",
        "mode": "rw",
        "type": "ENUM",
    },
    {
        "id": 124,
        "name": "water_box_mode",
        "code": "water_box_mode",
        "mode": "rw",
        "type": "ENUM",
    },
    {
        "id": 125,
        "name": "main_brush_life",
        "code": "main_brush_life",
        "mode": "rw",
        "type": "VALUE",
    },
    {
        "id": 126,
        "name": "side_brush_life",
        "code": "side_brush_life",
        "mode": "rw",
        "type": "VALUE",
    },
    {
        "id": 127,
        "name": "filter_life",
        "code": "filter_life",
        "mode": "rw",
        "type": "VALUE",
    },
    {
        "id": 128,
        "name": "additional_props",
        "code": "additional_props",
        "mode": "ro",
        "type": "RAW",
    },
    {
        "id": 130,
        "name": "task_complete",
        "code": "task_complete",
        "mode": "ro",
        "type": "RAW",
    },
    {
        "id": 131,
        "name": "task_cancel_low_power",
        "code": "task_cancel_low_power",
        "mode": "ro",
        "type": "RAW",
    },
    {
        "id": 132,
        "name": "task_cancel_in_motion",
        "code": "task_cancel_in_motion",
        "mode": "ro",
        "type": "RAW",
    },
    {
        "id": 133,
        "name": "charge_status",
        "code": "charge_status",
        "mode": "ro",
        "type": "RAW",
    },
    {
        "id": 134,
        "name": "drying_status",
        "code": "drying_status",
        "mode": "ro",
        "type": "RAW",
    },
    {
        "id": 135,
        "name": "offline_status",
        "code": "offline_status",
        "mode": "ro",
        "type": "RAW",
    },
]

MODEL_PRODUCT_ID_OVERRIDES = {
    "roborock.vacuum.a87": 110,
    "roborock.vacuum.a15": 23,
    "roborock.vacuum.sc05": 10001,
}

MQTT_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}

DNS_OVERRIDES = [
    # App Login / Identity
    "api.roborock.com",
    "oauth2.roborock.com",
    "us.roborock.com",
    "cn.roborock.com",
    # MQTT
    "mqtt-us.roborock.com",
    "mqtt-us-2.roborock.com",
    "mqtt-us-3.roborock.com",
    "mqtt-eu.roborock.com",
    "mqtt-cn.roborock.com",
    "mqtt-ap.roborock.com",
    "mqtt-ru.roborock.com",
    # API
    "api-us.roborock.com",
    "api-eu.roborock.com",
    "api-cn.roborock.com",
    "api-ru.roborock.com",
    # IOT
    "usiot.roborock.com",
    "euiot.roborock.com",
    "cniot.roborock.com",
    "ruiot.roborock.com",
    # WOODS
    "wood-us.roborock.com",
    "wood-eu.roborock.com",
    "wood-cn.roborock.com",
    "wood-ru.roborock.com",
]
