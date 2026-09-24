"""Portable Q7 profile builds a staged, script-only five-field package."""

import gzip
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from scripts import q7_migration_ota_builder as builder
from scripts.q7_stage_ota import inspect


FIELDS = {
    "api_url": "https://local.test:555",
    "mqtt_url": "ssl://local.test:8881",
    "mqtt_clientid": "0123456789abcdef",
    "mqtt_usr": "abcdef0123456789",
    "mqtt_passwd": "0123456789abcdef0123456789abcdef",
}


def _fixture_profile(path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    key = b"synthetic-key-12"
    files = {
        "ota-key.bin": key,
        "return.sh": b"#!/bin/sh\necho normal-boot\n",
        "editor.sh": b"#!/bin/sh\necho edit-existing-iot\n",
    }
    path.mkdir()
    hashes = {name: builder._sha256(blob) for name, blob in files.items()}
    monkeypatch.setattr(builder, "PROFILE_HASHES", hashes)
    for name, blob in files.items():
        (path / name).write_bytes(blob)
    (path / "manifest.json").write_text(json.dumps({
        "schema": builder.SCHEMA,
        "model": builder.MODEL,
        "firmware_version": builder.VERSION,
        "file_sha256": hashes,
    }))
    return key


def test_portable_package_is_stagable_and_contains_only_scripts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile"
    key = _fixture_profile(profile, monkeypatch)
    out = tmp_path / "candidate"
    metadata = builder.build(FIELDS, profile, out)
    payload, details = inspect(out)
    assert details["encrypted_sha256"] == metadata["encrypted_sha256"]
    assert metadata["build_mode"] == "portable_profile"
    assert metadata["signed"] is False

    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(payload) + decryptor.finalize()
    pad = padded[-1]
    assert padded[-pad:] == bytes([pad]) * pad
    container = gzip.decompress(padded[:-pad])
    checksum, major, minor, blocks, payload_size, begin_size, end_size = struct.unpack_from(
        "<7I", container
    )
    assert checksum == sum(container[4:])
    assert (major, minor, blocks, payload_size) == (0, 3, 0, 0)
    assert len(container) == 28 + begin_size + end_size
    begin = container[28 : 28 + begin_size]
    end = container[28 + begin_size :]
    assert begin.startswith(b"#!/bin/sh\nset -- ")
    assert b"/userdata/rriot/data_dir/iot.json" in begin
    assert all(value.encode("ascii") in begin for value in FIELDS.values())
    assert begin.endswith(b"echo edit-existing-iot\n")
    assert end == b"#!/bin/sh\necho normal-boot\n"


def test_refuses_unsafe_values_and_tampered_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile"
    _fixture_profile(profile, monkeypatch)
    out = tmp_path / "candidate"
    with pytest.raises(ValueError, match="api_url"):
        builder.build({**FIELDS, "api_url": "https://local.test';touch /tmp/pwn"}, profile, out)
    assert not out.exists()
    (profile / "return.sh").write_bytes(b"#!/bin/sh\necho changed\n")
    with pytest.raises(ValueError, match="pinned hash"):
        builder.build(FIELDS, profile, out)
    assert not out.exists()
