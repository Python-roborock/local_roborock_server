DEFAULT_HOME_NAME = "Local Home"
DEFAULT_TIMEZONE = "America/New_York"

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
