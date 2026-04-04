"""Shared runtime context for server packages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from pathlib import Path
import secrets
from typing import Any

from .bootstrap_crypto import BootstrapEncryptor
from .device_key_recovery import DeviceKeyCache
from .http_helpers import pick_first
from .runtime_credentials import RuntimeCredentialsStore
from .runtime_state import RuntimeState
from .zone_ranges_store import ZoneRangesStore


@dataclass
class ServerContext:
    api_host: str
    mqtt_host: str
    wood_host: str
    region: str
    localkey: str
    duid: str
    mqtt_usr: str
    mqtt_passwd: str
    mqtt_clientid: str
    mqtt_tls_port: int
    http_jsonl: Path
    mqtt_jsonl: Path
    loggers: dict[str, logging.Logger]
    key_state_file: Path | None = None
    bootstrap_encryption_enabled: bool = True
    runtime_state: RuntimeState | None = None
    runtime_credentials: RuntimeCredentialsStore | None = None
    zone_ranges_store: ZoneRangesStore | None = None
    _bootstrap_encryptor: BootstrapEncryptor | None = field(init=False, default=None, repr=False)
    _device_key_cache: DeviceKeyCache | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if self.key_state_file is not None:
            self._device_key_cache = DeviceKeyCache(self.key_state_file)
        if self.bootstrap_encryption_enabled:
            self._bootstrap_encryptor = BootstrapEncryptor(self.key_state_file)
        if self.runtime_credentials is not None:
            self.runtime_credentials.sync_inventory()

    def region_payload(self) -> dict[str, Any]:
        api_url = f"https://{self.api_host}"
        mqtt_url = f"ssl://{self.mqtt_host}:{self.mqtt_tls_port}"
        wood_url = f"https://{self.wood_host}"
        return {
            "apiUrl": api_url,
            "mqttUrl": mqtt_url,
            "api_url": api_url,
            "mqtt_url": mqtt_url,
            "woodUrl": wood_url,
            "regionCode": self.region.upper(),
            "region": self.region,
            "a": api_url,
            "m": mqtt_url,
            "l": wood_url,
            "r": self.region.upper(),
        }

    def extract_did(self, query_params: dict[str, list[str]], body_params: dict[str, list[str]]) -> str:
        return pick_first(
            (query_params.get("did") or [])
            + (query_params.get("d") or [])
            + (query_params.get("duid") or [])
            + (body_params.get("did") or [])
            + (body_params.get("d") or [])
            + (body_params.get("duid") or [])
            + [self.duid]
        )

    def extract_explicit_did(self, query_params: dict[str, list[str]], body_params: dict[str, list[str]]) -> str:
        return pick_first(
            (query_params.get("did") or [])
            + (query_params.get("d") or [])
            + (query_params.get("duid") or [])
            + (body_params.get("did") or [])
            + (body_params.get("d") or [])
            + (body_params.get("duid") or [])
        )

    def extract_pid(self, query_params: dict[str, list[str]], body_params: dict[str, list[str]]) -> str:
        return pick_first(
            (query_params.get("pid") or [])
            + (query_params.get("m") or [])
            + (query_params.get("model") or [])
            + (body_params.get("pid") or [])
            + (body_params.get("m") or [])
            + (body_params.get("model") or [])
        )

    def encrypt_bootstrap_result(self, did: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        if not self.bootstrap_encryption_enabled:
            return None
        if not did:
            return None
        if self._device_key_cache is not None:
            encrypted = self._device_key_cache.encrypt_for_did(did, payload)
            if encrypted:
                return {"code": 200, "result": encrypted}
        if self._bootstrap_encryptor is None:
            return None
        encrypted = self._bootstrap_encryptor.encrypt_for_did(did, payload)
        if not encrypted:
            return None
        return {"code": 200, "result": encrypted}

    def known_bootstrap_dids(self) -> list[str]:
        if self._device_key_cache is not None:
            return self._device_key_cache.get_known_dids()
        if self._bootstrap_encryptor is None:
            return []
        return self._bootstrap_encryptor.known_dids()

    def device_key_cache(self) -> DeviceKeyCache | None:
        return self._device_key_cache

    def resolve_device_localkey(
        self,
        *,
        did: str = "",
        duid: str = "",
        model: str = "",
        name: str = "",
        product_id: str = "",
        source: str = "",
        assign_if_missing: bool = True,
    ) -> str:
        if self.runtime_credentials is None:
            return self.localkey
        return self.runtime_credentials.resolve_device_localkey(
            did=did,
            duid=duid,
            model=model,
            name=name,
            product_id=product_id,
            source=source,
            assign_if_missing=assign_if_missing,
        )

    def nc_payload(
        self,
        query_params: dict[str, list[str]],
        body_params: dict[str, list[str]],
    ) -> dict[str, Any]:
        did = self.extract_did(query_params, body_params)
        session = pick_first(
            (query_params.get("session") or [])
            + (query_params.get("s") or [])
            + (body_params.get("session") or [])
            + (body_params.get("s") or [])
        ) or f"s_{secrets.token_hex(8)}"
        token = pick_first(
            (query_params.get("token") or [])
            + (query_params.get("t") or [])
            + (body_params.get("token") or [])
            + (body_params.get("t") or [])
        ) or f"t_{secrets.token_hex(8)}"
        model = self.extract_pid(query_params, body_params)
        device_localkey = self.resolve_device_localkey(
            did=did,
            model=model,
            source="onboarding_nc",
            assign_if_missing=True,
        )
        api_url = f"https://{self.api_host}"
        mqtt_url = f"ssl://{self.mqtt_host}:{self.mqtt_tls_port}"
        if self.runtime_credentials is not None:
            self.runtime_credentials.ensure_device(
                did=did,
                model=model,
                localkey=device_localkey,
                local_key_source="onboarding_nc",
                last_nc_at=datetime.now(timezone.utc).isoformat(),
            )
        return {
            "k": device_localkey,
            "d": did,
            "localkey": device_localkey,
            "mqtt_usr": self.mqtt_usr,
            "mqtt_passwd": self.mqtt_passwd,
            "mqtt_clientid": self.mqtt_clientid,
            "apiUrl": api_url,
            "mqttUrl": mqtt_url,
            "s": session,
            "t": token,
            "rriot": {
                "u": self.mqtt_usr,
                "s": self.mqtt_passwd,
                "h": secrets.token_hex(5),
                "k": device_localkey,
                "r": {
                    "r": self.region.upper(),
                    "a": api_url,
                    "m": mqtt_url,
                    "l": f"https://{self.wood_host}",
                },
            },
        }
