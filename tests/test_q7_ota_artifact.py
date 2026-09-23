"""Bounded staging and delivery of an encrypted Q7 OTA research package."""

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.q7_ota_artifact import Q7OtaArtifactStore, TTL_SECONDS
from roborock_local_server.server import ReleaseSupervisor


PAYLOAD = b"synthetic-block!"  # Exactly one AES block, no credentials.


def _digests(payload: bytes) -> dict[str, str]:
    return {
        "x-q7-sha256": hashlib.sha256(payload).hexdigest(),
        "x-q7-md5": hashlib.md5(payload).hexdigest(),
        "content-type": "application/octet-stream",
    }


def test_q7_ota_package_staging_requires_admin_and_expires(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    now = [100.0]
    supervisor.q7_ota_artifacts.clock = lambda: now[0]
    client = TestClient(supervisor.app)

    assert client.post("/admin/api/q7/ota-package", content=PAYLOAD, headers=_digests(PAYLOAD)).status_code == 401
    assert client.post("/admin/api/login", json={"password": "correct horse battery staple"}).status_code == 200
    wrong = dict(_digests(PAYLOAD), **{"x-q7-sha256": "0" * 64})
    assert client.post("/admin/api/q7/ota-package", content=PAYLOAD, headers=wrong).status_code == 400
    assert not supervisor.q7_ota_artifacts._entries

    staged = client.post("/admin/api/q7/ota-package", content=PAYLOAD, headers=_digests(PAYLOAD))
    assert staged.status_code == 200
    details = staged.json()
    assert details["encrypted_size_bytes"] == len(PAYLOAD)
    assert details["encrypted_md5"] == _digests(PAYLOAD)["x-q7-md5"]
    assert details["hardware_tested"] is False
    path = details["download_path"]
    assert path.startswith("/q7/ota-package/")
    downloaded = client.get(path)
    assert downloaded.status_code == 200
    assert downloaded.content == PAYLOAD
    assert downloaded.headers["cache-control"] == "no-store"
    assert client.get("/q7/ota-package/not-a-token").status_code == 404

    now[0] += TTL_SECONDS
    assert client.get(path).status_code == 404
    assert not supervisor.q7_ota_artifacts._entries


def test_q7_ota_package_store_rejects_tampered_bytes() -> None:
    store = Q7OtaArtifactStore()
    details = store.register(PAYLOAD, sha256=_digests(PAYLOAD)["x-q7-sha256"], md5=_digests(PAYLOAD)["x-q7-md5"])
    token = str(details["download_path"]).rsplit("/", 1)[-1]
    expires, _payload, digest = store._entries[token]
    store._entries[token] = (expires, b"modified payload", digest)
    assert store.fetch(token) is None
