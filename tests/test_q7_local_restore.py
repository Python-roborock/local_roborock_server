"""A restore must use the manifest that built its companion package."""

import argparse
import asyncio
import json
from pathlib import Path

import pytest

from scripts import q7_local_restore


def test_restore_refuses_changed_manifest_before_broker_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "metadata.json").write_text(json.dumps({"config_sha256": "0" * 64}))
    config = tmp_path / "fields.json"
    config.write_text(json.dumps({
        "api_url": "https://local.test:555",
        "mqtt_url": "ssl://local.test:8881",
        "mqtt_clientid": "0123456789abcdef",
        "mqtt_usr": "0123456789abcdef",
        "mqtt_passwd": "0123456789abcdef0123456789abcdef",
    }))
    monkeypatch.setattr(q7_local_restore, "package_request", lambda *_args, **_kwargs: {})
    args = argparse.Namespace(artifact_dir=artifact, config=config, url="http://192.0.2.1/restore")
    with pytest.raises(ValueError, match="manifest differs"):
        asyncio.run(q7_local_restore.run(args))
