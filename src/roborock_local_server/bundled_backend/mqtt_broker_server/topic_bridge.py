"""Bridge between python-roborock MQTT topics and device-native MQTT topics."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import re
import time
from typing import Any

import aiomqtt

M_TOPIC_IN_RE = re.compile(r"^rr/m/i/([^/]+)/([^/]+)/([^/]+)$")
D_TOPIC_IN_RE = re.compile(r"^rr/d/i/([^/]+)/([^/]+)$")


@dataclass(frozen=True)
class CloudTopicKey:
    """python-roborock topic key parts."""

    rriot_u: str
    mqtt_username: str
    duid: str

    @property
    def topic_in(self) -> str:
        return f"rr/m/i/{self.rriot_u}/{self.mqtt_username}/{self.duid}"

    @property
    def topic_out(self) -> str:
        return f"rr/m/o/{self.rriot_u}/{self.mqtt_username}/{self.duid}"


@dataclass(frozen=True)
class DeviceTopicKey:
    """Firmware-native topic key parts."""

    did: str
    mqtt_usr: str

    @property
    def topic_in(self) -> str:
        return f"rr/d/i/{self.did}/{self.mqtt_usr}"

    @property
    def topic_out(self) -> str:
        return f"rr/d/o/{self.did}/{self.mqtt_usr}"


def _extract_qos(message: aiomqtt.Message) -> int:
    qos_obj = getattr(message, "qos", 0)
    qos_value = getattr(qos_obj, "value", qos_obj)
    try:
        return int(qos_value)
    except (TypeError, ValueError):
        return 0


class MqttTopicBridge:
    """Republish MQTT payloads between rr/m/* and rr/d/* topics."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str = "",
        password: str = "",
        logger: logging.Logger,
        fixed_device_did: str = "",
        fixed_device_duid: str = "",
        fixed_device_mqtt_usr: str = "",
        runtime_state: Any | None = None,
        inventory_path: Path | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._logger = logger
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

        self._m_to_d: dict[CloudTopicKey, DeviceTopicKey] = {}
        # Tracks the most recently observed cloud-side route for a device topic.
        # Fan-out for active multi-session routing is derived from _m_to_d.
        self._d_to_m: dict[DeviceTopicKey, CloudTopicKey] = {}
        self._seen_device_topics: dict[DeviceTopicKey, float] = {}
        self._duid_to_did: dict[str, str] = {}
        self._last_duid_map_refresh_monotonic = 0.0
        self._warned_unmapped_duids: set[str] = set()
        self._warned_unmapped_device_topics: set[DeviceTopicKey] = set()
        self._warned_multi_device = False
        self._runtime_state = runtime_state
        self._inventory_path = Path(inventory_path) if inventory_path is not None else None

        fixed_did = fixed_device_did.strip() or fixed_device_duid.strip()
        fixed_usr = fixed_device_mqtt_usr.strip()
        self._fixed_device = DeviceTopicKey(fixed_did, fixed_usr) if fixed_did and fixed_usr else None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run(), name="mqtt-topic-bridge")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None

    def _remember_device_seen(self, device_topic: DeviceTopicKey) -> None:
        self._seen_device_topics[device_topic] = time.monotonic()
        seen_device_count = self._seen_device_did_count()
        if seen_device_count <= 1:
            return
        if self._warned_multi_device:
            return
        self._warned_multi_device = True
        self._logger.warning(
            "MQTT topic bridge detected multiple rr/d devices (%d). "
            "Bridge routing now prefers deterministic DUID->DID mapping; "
            "single-device latest-seen fallback is only used when one rr/d device is present.",
            seen_device_count,
        )

    def _seen_device_did_count(self) -> int:
        return len({device_topic.did for device_topic in self._seen_device_topics})

    def _latest_seen_device(self) -> DeviceTopicKey | None:
        if not self._seen_device_topics:
            return None
        return max(self._seen_device_topics.items(), key=lambda item: item[1])[0]

    def _latest_seen_device_for_did(self, did: str) -> DeviceTopicKey | None:
        normalized_did = did.strip()
        if not normalized_did:
            return None
        latest_topic: DeviceTopicKey | None = None
        latest_seen = 0.0
        for device_topic, seen_at in self._seen_device_topics.items():
            if device_topic.did != normalized_did:
                continue
            if latest_topic is None or seen_at > latest_seen:
                latest_topic = device_topic
                latest_seen = seen_at
        return latest_topic

    def _load_inventory_devices(self) -> list[dict[str, Any]]:
        if self._inventory_path is None or not self._inventory_path.exists():
            return []
        try:
            parsed = json.loads(self._inventory_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(parsed, dict):
            return []

        devices: list[dict[str, Any]] = []
        for source_key in ("devices", "received_devices", "receivedDevices"):
            source = parsed.get(source_key)
            if not isinstance(source, list):
                continue
            for item in source:
                if isinstance(item, dict):
                    devices.append(item)
        return devices

    def _refresh_duid_to_did_map(self) -> None:
        if self._runtime_state is None or self._inventory_path is None:
            return

        now = time.monotonic()
        if now - self._last_duid_map_refresh_monotonic < 2.0:
            return
        self._last_duid_map_refresh_monotonic = now

        try:
            key_models_by_did = self._runtime_state.key_models_by_did()
        except Exception:
            key_models_by_did = {}
        if not isinstance(key_models_by_did, dict):
            key_models_by_did = {}

        inventory_devices = self._load_inventory_devices()
        if not inventory_devices:
            self._duid_to_did = {}
            return

        did_counts_by_model: dict[str, int] = {}
        unique_did_by_model: dict[str, str] = {}
        for did, model_value in key_models_by_did.items():
            normalized_did = str(did or "").strip()
            normalized_model = str(model_value or "").strip().lower()
            if not normalized_did or not normalized_model:
                continue
            did_counts_by_model[normalized_model] = did_counts_by_model.get(normalized_model, 0) + 1
            if normalized_model not in unique_did_by_model:
                unique_did_by_model[normalized_model] = normalized_did

        inv_counts_by_model: dict[str, int] = {}
        for raw in inventory_devices:
            model = str(raw.get("model") or "").strip().lower()
            if model:
                inv_counts_by_model[model] = inv_counts_by_model.get(model, 0) + 1

        fresh_map: dict[str, str] = {}
        for raw in inventory_devices:
            duid = str(raw.get("duid") or raw.get("did") or raw.get("device_id") or "").strip()
            if not duid:
                continue
            explicit_did = str(raw.get("did") or raw.get("device_did") or "").strip()
            if explicit_did:
                fresh_map[duid] = explicit_did
                continue
            model = str(raw.get("model") or "").strip().lower()
            if not model:
                continue
            if inv_counts_by_model.get(model, 0) != 1:
                continue
            if did_counts_by_model.get(model, 0) != 1:
                continue
            mapped_did = unique_did_by_model.get(model)
            if mapped_did:
                fresh_map[duid] = mapped_did

        map_changed = fresh_map != self._duid_to_did
        if map_changed:
            self._duid_to_did = fresh_map
            if fresh_map:
                details = ", ".join(f"{duid}->{did}" for duid, did in sorted(fresh_map.items()))
                self._logger.info("MQTT topic bridge DUID->DID map refreshed: %s", details)
        if not self._duid_to_did:
            return

        # Drop stale cloud->device bindings when deterministic DUID->DID says
        # the route should target a different DID.
        stale_cloud_routes: list[tuple[CloudTopicKey, DeviceTopicKey, str]] = []
        for cloud_topic, mapped_device in self._m_to_d.items():
            expected_did = self._duid_to_did.get(cloud_topic.duid, "")
            if expected_did and mapped_device.did != expected_did:
                stale_cloud_routes.append((cloud_topic, mapped_device, expected_did))
        for cloud_topic, mapped_device, expected_did in stale_cloud_routes:
            self._m_to_d.pop(cloud_topic, None)
            if self._d_to_m.get(mapped_device) == cloud_topic:
                self._d_to_m.pop(mapped_device, None)
            self._logger.warning(
                "MQTT topic bridge cleared stale route for duid=%s: had did=%s now expect did=%s",
                cloud_topic.duid,
                mapped_device.did,
                expected_did,
            )

    def _resolve_device_for_cloud(self, cloud_topic: CloudTopicKey) -> DeviceTopicKey | None:
        if self._fixed_device is not None:
            return self._fixed_device

        self._refresh_duid_to_did_map()
        mapped_did = self._duid_to_did.get(cloud_topic.duid, "")
        if mapped_did:
            preferred = self._latest_seen_device_for_did(mapped_did)
            if preferred is not None:
                return preferred
            # If we know the DID but have not seen a fresh topic key yet, keep
            # an existing mapping when it still targets the expected DID.
            mapped = self._m_to_d.get(cloud_topic)
            if mapped is not None and mapped.did == mapped_did:
                return mapped
        if mapped := self._m_to_d.get(cloud_topic):
            return mapped
        if mapped_did:
            return self._latest_seen_device_for_did(mapped_did)
        if self._seen_device_did_count() == 1:
            return self._latest_seen_device()
        return None

    def _resolve_cloud_for_device(self, device_topic: DeviceTopicKey) -> CloudTopicKey | None:
        exact_matches = [
            cloud_topic
            for cloud_topic, mapped_device in self._m_to_d.items()
            if mapped_device == device_topic
        ]
        if len(exact_matches) == 1:
            return exact_matches[0]
        if len(exact_matches) > 1:
            return None
        did_matches = [
            cloud_topic
            for cloud_topic, mapped_device in self._m_to_d.items()
            if mapped_device.did == device_topic.did
        ]
        if len(did_matches) == 1:
            return did_matches[0]
        self._refresh_duid_to_did_map()
        mapped_duids = [duid for duid, did in self._duid_to_did.items() if did == device_topic.did]
        if len(mapped_duids) == 1:
            mapped_duid = mapped_duids[0]
            duid_matches = [
                cloud_topic
                for cloud_topic, mapped_device in self._m_to_d.items()
                if cloud_topic.duid == mapped_duid
            ]
            if len(duid_matches) == 1:
                return duid_matches[0]
        if len(self._m_to_d) == 1 and self._seen_device_did_count() == 1:
            # With one cloud-side session, mirror everything from the single vac.
            return next(iter(self._m_to_d))
        return None

    def _resolve_cloud_targets_for_device(self, device_topic: DeviceTopicKey) -> list[CloudTopicKey]:
        targets: list[CloudTopicKey] = []
        seen: set[CloudTopicKey] = set()

        def add_matches(matches: list[CloudTopicKey]) -> None:
            for cloud_topic in matches:
                if cloud_topic in seen:
                    continue
                seen.add(cloud_topic)
                targets.append(cloud_topic)

        exact_matches = [
            cloud_topic
            for cloud_topic, mapped_device in self._m_to_d.items()
            if mapped_device == device_topic
        ]
        add_matches(exact_matches)

        did_matches = [
            cloud_topic
            for cloud_topic, mapped_device in self._m_to_d.items()
            if mapped_device.did == device_topic.did
        ]
        add_matches(did_matches)
        if targets:
            return targets

        self._refresh_duid_to_did_map()
        mapped_duids = [duid for duid, did in self._duid_to_did.items() if did == device_topic.did]
        if len(mapped_duids) == 1:
            mapped_duid = mapped_duids[0]
            duid_matches = [
                cloud_topic
                for cloud_topic, mapped_device in self._m_to_d.items()
                if cloud_topic.duid == mapped_duid
            ]
            add_matches(duid_matches)
            if targets:
                return targets

        if len(self._m_to_d) == 1 and self._seen_device_did_count() == 1:
            add_matches([next(iter(self._m_to_d))])
        return targets

    async def _publish_mirror(self, client: aiomqtt.Client, message: aiomqtt.Message, target_topic: str) -> None:
        qos = _extract_qos(message)
        retain = bool(getattr(message, "retain", False))
        await client.publish(target_topic, message.payload, qos=qos, retain=retain)

    async def _handle_cloud_message(
        self,
        client: aiomqtt.Client,
        message: aiomqtt.Message,
        cloud_topic: CloudTopicKey,
        src_topic: str,
    ) -> None:
        device_topic = self._resolve_device_for_cloud(cloud_topic)
        if device_topic is None:
            if cloud_topic.duid not in self._warned_unmapped_duids:
                self._warned_unmapped_duids.add(cloud_topic.duid)
                if self._seen_device_topics:
                    self._logger.warning(
                        "MQTT topic bridge dropped %s: no deterministic rr/d mapping for duid=%s "
                        "(seen rr/d devices=%d). Set --bridge-device-* or ensure unique model mapping.",
                        src_topic,
                        cloud_topic.duid,
                        len(self._seen_device_topics),
                    )
                else:
                    self._logger.warning(
                        "MQTT topic bridge dropped %s: no rr/d device topic discovered yet. "
                        "Wait for a vacuum rr/d/i publish or set --bridge-device-*.",
                        src_topic,
                    )
            return

        previous_device = self._m_to_d.get(cloud_topic)
        if previous_device is not None and previous_device != device_topic:
            self._d_to_m.pop(previous_device, None)
        self._m_to_d[cloud_topic] = device_topic
        self._d_to_m[device_topic] = cloud_topic

        target_topic = device_topic.topic_out
        await self._publish_mirror(client, message, target_topic)
        self._logger.info(
            "MQTT bridge m->d %s -> %s bytes=%d",
            src_topic,
            target_topic,
            len(message.payload),
        )

    async def _handle_device_message(
        self,
        client: aiomqtt.Client,
        message: aiomqtt.Message,
        device_topic: DeviceTopicKey,
        src_topic: str,
    ) -> None:
        self._remember_device_seen(device_topic)
        cloud_targets = self._resolve_cloud_targets_for_device(device_topic)
        if not cloud_targets:
            if device_topic not in self._warned_unmapped_device_topics:
                self._warned_unmapped_device_topics.add(device_topic)
                self._logger.warning(
                    "MQTT topic bridge dropped %s: no rr/m mapping for rr/d topic %s "
                    "(active cloud routes=%d).",
                    src_topic,
                    device_topic.topic_in,
                    len(self._m_to_d),
                )
            # Device uplink messages still flow to normal rr/d/i consumers.
            return
        for cloud_topic in cloud_targets:
            # If mqtt_usr changed for an already-known DID, bind the latest topic key.
            self._d_to_m[device_topic] = cloud_topic
            self._m_to_d[cloud_topic] = device_topic

            target_topic = cloud_topic.topic_out
            await self._publish_mirror(client, message, target_topic)
            self._logger.info(
                "MQTT bridge d->m %s -> %s bytes=%d",
                src_topic,
                target_topic,
                len(message.payload),
            )

    async def _run(self) -> None:
        auth: dict[str, str] = {}
        if self._username:
            auth["username"] = self._username
            auth["password"] = self._password
            self._logger.info(
                "MQTT topic bridge auth attempt with username:password (%s:REDACTED)",
                self._username
            )
        retry_delay_seconds = 2.0
        while not self._stop_event.is_set():
            try:
                async with aiomqtt.Client(hostname=self._host, port=self._port, **auth) as client:
                    await client.subscribe("rr/m/i/#")
                    await client.subscribe("rr/d/i/#")
                    self._logger.info(
                        "MQTT topic bridge connected (%s:%d), subscribed to rr/m/i/# and rr/d/i/#",
                        self._host,
                        self._port,
                    )
                    if self._fixed_device is not None:
                        self._logger.info(
                            "MQTT topic bridge using fixed rr/d target: %s",
                            self._fixed_device.topic_out,
                        )
                    async for message in client.messages:
                        if self._stop_event.is_set():
                            break
                        topic = message.topic.value if hasattr(message.topic, "value") else str(message.topic)
                        m_match = M_TOPIC_IN_RE.match(topic)
                        if m_match:
                            cloud_topic = CloudTopicKey(
                                rriot_u=m_match.group(1),
                                mqtt_username=m_match.group(2),
                                duid=m_match.group(3),
                            )
                            await self._handle_cloud_message(client, message, cloud_topic, topic)
                            continue
                        d_match = D_TOPIC_IN_RE.match(topic)
                        if d_match:
                            device_topic = DeviceTopicKey(did=d_match.group(1), mqtt_usr=d_match.group(2))
                            await self._handle_device_message(client, message, device_topic, topic)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                self._logger.warning(
                    "MQTT topic bridge error: %s (retrying in %.1fs)",
                    exc,
                    retry_delay_seconds,
                )
                await asyncio.sleep(retry_delay_seconds)
