"""The first-stage Q7 package must preserve MQTT and carry a rollback."""

import gzip
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from scripts import q7_api_only_ota_builder as builder


def _unpack(blob: bytes, key: bytes) -> tuple[bytes, bytes]:
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(blob) + decryptor.finalize()
    pad = padded[-1]
    assert 1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad
    container = gzip.decompress(padded[:-pad])
    checksum, major, minor, blocks, payload, begin_size, end_size = struct.unpack_from("<7I", container)
    assert checksum == sum(container[4:])
    assert (major, minor, blocks, payload) == (0, 3, 0, 0)
    assert len(container) == 28 + begin_size + end_size
    return container[28 : 28 + begin_size], container[28 + begin_size :]


@pytest.mark.parametrize("url", [
    "http://local.test", "https://local.test/path", "https://local.test/?token=1",
    "https://user:pass@local.test", "https://local.test:bad",
])
def test_rejects_bad_api_origin_before_reading_private_material(tmp_path: Path, url: str) -> None:
    out = tmp_path / "output"
    with pytest.raises(ValueError):
        builder.build(tmp_path / "missing-reference", tmp_path / "missing-key", url, out)
    assert not out.exists()


def test_builds_distinct_set_and_restore_packages_without_mqtt_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = b"synthetic-key-12"
    assert len(key) == 16
    key_file = tmp_path / "key"
    key_file.write_bytes(key)
    monkeypatch.setattr(builder, "_scripts", lambda _path: (b"#!/bin/sh\necho vendor-begin\n", b"#!/bin/sh\necho vendor-end\n"))
    monkeypatch.setattr(builder.reference_builder, "KEY_SHA256", builder.reference_builder.digest(key))
    out = tmp_path / "output"
    result = builder.build(tmp_path / "unused-reference", key_file, "https://local.test:555", out)
    assert result["signed"] is False
    assert result["hardware_tested"] is False
    assert set(result["packages"]) == {"set-api", "restore-api"}
    assert json.loads((out / "metadata.json").read_text()) == result

    begins = {}
    for mode, item in result["packages"].items():
        begin, end = _unpack((out / item["file"]).read_bytes(), key)
        begins[mode] = begin
        assert end == b"#!/bin/sh\necho vendor-end\n"
        assert b"mqtt_url" not in begin and b"mqtt_usr" not in begin
        assert b"mqtt_passwd" not in begin and b"mqtt_clientid" not in begin
    assert b"set -- set " in begins["set-api"]
    assert b"https://local.test:555" in begins["set-api"]
    assert b"set -- restore " in begins["restore-api"]
    assert b"https://local.test:555" not in begins["restore-api"]
