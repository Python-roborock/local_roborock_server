"""A restore must use the manifest that built its companion package."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from scripts import q7_local_restore


FIELDS = {
    "api_url": "https://local.test:555",
    "mqtt_url": "ssl://local.test:8881",
    "mqtt_clientid": "0123456789abcdef",
    "mqtt_usr": "0123456789abcdef",
    "mqtt_passwd": "0123456789abcdef0123456789abcdef",
}


def test_restore_refuses_changed_manifest_before_broker_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "metadata.json").write_text(json.dumps({"config_sha256": "0" * 64}))
    config = tmp_path / "fields.json"
    config.write_text(json.dumps(FIELDS))
    monkeypatch.setattr(q7_local_restore, "package_request", lambda *_args, **_kwargs: {})
    args = argparse.Namespace(artifact_dir=artifact, config=config, url="http://192.0.2.1/restore")
    with pytest.raises(ValueError, match="manifest differs"):
        asyncio.run(q7_local_restore.run(args))


def test_restore_accepts_pinned_manifest_and_rejects_changed_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = {"duid_sha256": "1" * 64, "local_key_sha256": "2" * 64}
    source = {**FIELDS, "_preflight": preflight}
    config = tmp_path / "fields.json"
    config.write_text(json.dumps(source))
    assert q7_local_restore._broker(config) == (
        "local.test", 8881, FIELDS["mqtt_usr"], FIELDS["mqtt_passwd"], FIELDS["mqtt_url"]
    )
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    config_sha256 = hashlib.sha256(
        json.dumps(FIELDS, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    metadata = {"config_sha256": config_sha256, "preflight": preflight, "target_firmware": "03.01.80"}
    (artifact / "metadata.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(q7_local_restore, "package_request", lambda *_args, **_kwargs: {})

    async def reached_account(*_args: object) -> None:
        raise RuntimeError("manifest checks passed")

    monkeypatch.setattr(q7_local_restore, "_account", reached_account)
    args = argparse.Namespace(artifact_dir=artifact, config=config, url="http://192.0.2.1/restore")
    with pytest.raises(RuntimeError, match="manifest checks passed"):
        asyncio.run(q7_local_restore.run(args))

    metadata["preflight"] = {**preflight, "local_key_sha256": "3" * 64}
    (artifact / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="preflight differs"):
        asyncio.run(q7_local_restore.run(args))
