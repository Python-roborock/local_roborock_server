import asyncio
import json
import logging
from types import SimpleNamespace

from roborock_local_server.bundled_backend.mqtt_broker_server.topic_bridge import (
    CloudTopicKey,
    DeviceTopicKey,
    MqttTopicBridge,
)


class DummyClient:
    def __init__(self) -> None:
        self.published: list[dict[str, object]] = []

    async def publish(self, topic: str, payload: bytes, *, qos: int = 0, retain: bool = False) -> None:
        self.published.append(
            {
                "topic": topic,
                "payload": payload,
                "qos": qos,
                "retain": retain,
            }
        )


class DummyMessage:
    def __init__(self, payload: bytes = b"{}", *, qos: int = 0, retain: bool = False) -> None:
        self.payload = payload
        self.qos = qos
        self.retain = retain


def test_topic_bridge_does_not_reuse_single_cloud_route_across_multiple_device_dids() -> None:
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.multi_device"),
    )
    s7_cloud = CloudTopicKey(
        rriot_u="cloud-user",
        mqtt_username="cloud-mqtt-user",
        duid="1OVJHS7cL6XxkYkoOGr2Hw",
    )
    s7_device = DeviceTopicKey(did="1103811971559", mqtt_usr="s7-mqtt-user")
    qrevo_device = DeviceTopicKey(did="1103821560705", mqtt_usr="qrevo-mqtt-user")

    bridge._m_to_d[s7_cloud] = s7_device
    bridge._d_to_m[s7_device] = s7_cloud
    bridge._remember_device_seen(s7_device)
    bridge._remember_device_seen(qrevo_device)

    assert bridge._resolve_cloud_for_device(qrevo_device) is None


def test_topic_bridge_cloud_fallback_uses_latest_topic_when_only_one_did_was_seen() -> None:
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.single_device"),
    )
    older_topic = DeviceTopicKey(did="1103821560705", mqtt_usr="mqtt-user-old")
    newer_topic = DeviceTopicKey(did="1103821560705", mqtt_usr="mqtt-user-new")
    cloud_topic = CloudTopicKey(
        rriot_u="cloud-user",
        mqtt_username="cloud-mqtt-user",
        duid="6HL2zfniaoYYV01CkVuhkO",
    )

    bridge._seen_device_topics[older_topic] = 1.0
    bridge._seen_device_topics[newer_topic] = 2.0

    assert bridge._resolve_device_for_cloud(cloud_topic) == newer_topic


def test_topic_bridge_fans_device_messages_out_to_all_cloud_routes_for_same_device() -> None:
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.multi_session"),
    )
    device_topic = DeviceTopicKey(did="1103821560705", mqtt_usr="c25b14ceac358d2a")
    app_cloud = CloudTopicKey(
        rriot_u="5qsJ4238qnGM42lyZefPlx",
        mqtt_username="fe25c7dd",
        duid="6HL2zfniaoYYV01CkVuhkO",
    )
    routine_cloud = CloudTopicKey(
        rriot_u="c72569aa0bb81cb8",
        mqtt_username="9ec62f99",
        duid="6HL2zfniaoYYV01CkVuhkO",
    )
    client = DummyClient()
    bridge._remember_device_seen(device_topic)

    async def exercise() -> None:
        await bridge._handle_cloud_message(client, DummyMessage(b"app"), app_cloud, app_cloud.topic_in)
        await bridge._handle_cloud_message(client, DummyMessage(b"routine"), routine_cloud, routine_cloud.topic_in)
        client.published.clear()
        await bridge._handle_device_message(client, DummyMessage(b"reply"), device_topic, device_topic.topic_in)

    asyncio.run(exercise())

    published_topics = [str(entry["topic"]) for entry in client.published]
    assert sorted(published_topics) == sorted([app_cloud.topic_out, routine_cloud.topic_out])
    assert bridge._m_to_d.get(app_cloud) == device_topic
    assert bridge._m_to_d.get(routine_cloud) == device_topic


def test_topic_bridge_fans_out_to_all_cloud_routes_even_with_mixed_device_topic_keys() -> None:
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.mixed_device_topics"),
    )
    old_device_topic = DeviceTopicKey(did="1103821560705", mqtt_usr="mqtt-user-old")
    new_device_topic = DeviceTopicKey(did="1103821560705", mqtt_usr="mqtt-user-new")
    app_cloud = CloudTopicKey(
        rriot_u="app-user",
        mqtt_username="app-mqtt-user",
        duid="6HL2zfniaoYYV01CkVuhkO",
    )
    ha_cloud = CloudTopicKey(
        rriot_u="ha-user",
        mqtt_username="ha-mqtt-user",
        duid="6HL2zfniaoYYV01CkVuhkO",
    )
    client = DummyClient()

    # Simulate one caller already remapped to the new mqtt_usr while another
    # caller still points at the older mqtt_usr for the same DID.
    bridge._m_to_d[app_cloud] = new_device_topic
    bridge._m_to_d[ha_cloud] = old_device_topic

    async def exercise() -> None:
        await bridge._handle_device_message(client, DummyMessage(b"reply"), new_device_topic, new_device_topic.topic_in)

    asyncio.run(exercise())

    published_topics = [str(entry["topic"]) for entry in client.published]
    assert sorted(published_topics) == sorted([app_cloud.topic_out, ha_cloud.topic_out])
    assert bridge._m_to_d.get(app_cloud) == new_device_topic
    assert bridge._m_to_d.get(ha_cloud) == new_device_topic


def test_topic_bridge_maps_same_model_devices_from_learned_runtime_credentials(tmp_path) -> None:
    pairs = {
        "7RMLFxGvQx7HNHyrkf4uxN": "1103812576952",
        "4Nzba8pCrwFHCc53nLc5aB": "1103812576978",
        "ej7PNYHNhbpcFJZd8HMoZ": "1103812579307",
    }
    inventory_path = tmp_path / "web_api_inventory.json"
    inventory_path.write_text(
        json.dumps({"devices": [{"duid": duid, "model": "roborock.vacuum.a10"} for duid in pairs]}),
        encoding="utf-8",
    )
    runtime_state = SimpleNamespace(
        key_models_by_did=lambda: {did: "roborock.vacuum.a10" for did in pairs.values()},
        runtime_credentials=SimpleNamespace(
            devices=lambda: [{"did": did, "duid": duid} for duid, did in pairs.items()],
        ),
    )
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.same_model"),
        runtime_state=runtime_state,
        inventory_path=inventory_path,
    )
    device_topics = {did: DeviceTopicKey(did=did, mqtt_usr=f"usr-{did}") for did in pairs.values()}
    for device_topic in device_topics.values():
        bridge._remember_device_seen(device_topic)

    for duid, did in pairs.items():
        cloud_topic = CloudTopicKey(rriot_u="ha-user", mqtt_username="ha-mqtt", duid=duid)
        assert bridge._resolve_device_for_cloud(cloud_topic) == device_topics[did]


def test_topic_bridge_model_fallback_does_not_reuse_did_learned_for_another_duid(tmp_path) -> None:
    # The only a168 with a known model is already paired with another DUID, for
    # example a replaced vacuum. The inventory's lone a168 must stay unmapped
    # rather than be routed to that vacuum.
    inventory_path = tmp_path / "web_api_inventory.json"
    inventory_path.write_text(
        json.dumps({"devices": [{"duid": "1mRc3mFQhMWxkAQIAGI46w", "model": "roborock.vacuum.a168"}]}),
        encoding="utf-8",
    )
    runtime_state = SimpleNamespace(
        key_models_by_did=lambda: {"1103841353419": "roborock.vacuum.a168"},
        runtime_credentials=SimpleNamespace(
            devices=lambda: [{"did": "1103841353419", "duid": "6aEI34L0ZtsALO8XtccuPw"}],
        ),
    )
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.learned_did_guard"),
        runtime_state=runtime_state,
        inventory_path=inventory_path,
    )

    bridge._refresh_duid_to_did_map()

    assert bridge._duid_to_did == {"6aEI34L0ZtsALO8XtccuPw": "1103841353419"}


def test_topic_bridge_handles_runtime_credentials_exception(tmp_path) -> None:
    def broken_devices():
        raise RuntimeError("Store locked")

    runtime_state = SimpleNamespace(
        key_models_by_did=lambda: {},
        runtime_credentials=SimpleNamespace(devices=broken_devices),
    )
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.exception"),
        runtime_state=runtime_state,
        inventory_path=tmp_path / "web_api_inventory.json",
    )

    bridge._refresh_duid_to_did_map()

    assert bridge._duid_to_did == {}


def test_topic_bridge_handles_runtime_credentials_malformed_devices(tmp_path) -> None:
    runtime_state = SimpleNamespace(
        key_models_by_did=lambda: {},
        runtime_credentials=SimpleNamespace(
            devices=lambda: [None, "invalid", {"duid": "", "did": "123"}, {"duid": "d1", "did": "123"}],
        ),
    )
    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.topic_bridge.malformed"),
        runtime_state=runtime_state,
        inventory_path=tmp_path / "web_api_inventory.json",
    )

    bridge._refresh_duid_to_did_map()

    assert bridge._duid_to_did == {"d1": "123"}

