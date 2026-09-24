"""Portable Q7 profile builds a staged, script-only five-field package."""

import gzip
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

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


def test_accepts_pinned_reentry_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = tmp_path / "profile"
    _fixture_profile(profile, monkeypatch)
    manifest_path = profile / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["schema"] = builder.REENTRY_SCHEMA
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(builder, "REENTRY_PROFILE_HASHES", manifest["file_sha256"])
    metadata = builder.build(FIELDS, profile, tmp_path / "candidate")
    assert metadata["profile_schema"] == builder.REENTRY_SCHEMA
    assert builder._sha256(Path(builder.__file__).with_name("q7_iot_local_fields_reentry.sh").read_bytes()) == (
        "2fce38f7ba828b361fa644c5e8fea8c5858f9bc0eeaeab931610e18e6da3fb04"
    )


@pytest.mark.skipif(sys.platform == "win32" or not shutil.which("sh"), reason="requires POSIX shell")
def test_reentry_editor_preserves_matching_backup_and_refuses_mismatch(tmp_path: Path) -> None:
    script = Path(builder.__file__).with_name("q7_iot_local_fields_reentry.sh")
    wrapper = tmp_path / "busybox"
    wrapper.write_text('#!/bin/sh\nexec "$@"\n')
    wrapper.chmod(0o755)
    source = {
        "api_url": "https://vendor.test",
        "mqtt_url": "ssl://vendor.test:8883",
        "mqtt_clientid": "fedcba9876543210",
        "mqtt_usr": "1234567890abcdef",
        "mqtt_passwd": "fedcba9876543210fedcba9876543210",
        "duid": "leave-this-alone",
    }
    original = (json.dumps(source, indent=2) + "\n").encode()
    iot = tmp_path / "iot.json"
    backup = tmp_path / "iot.json.before-q7-local-edit"
    env = {**os.environ, "Q7_BUSYBOX": str(wrapper)}
    command = ["sh", str(script), str(iot), *FIELDS.values()]

    iot.write_bytes(original)
    assert subprocess.run(command, env=env, capture_output=True).returncode == 0
    assert backup.read_bytes() == original
    assert json.loads(iot.read_bytes())["duid"] == source["duid"]

    iot.write_bytes(original)
    assert subprocess.run(command, env=env, capture_output=True).returncode == 0
    assert backup.read_bytes() == original
    assert all(json.loads(iot.read_bytes())[name] == value for name, value in FIELDS.items())

    iot.write_bytes(original)
    backup.write_bytes(b"mismatch")
    assert subprocess.run(command, env=env, capture_output=True).returncode != 0
    assert iot.read_bytes() == original
    assert backup.read_bytes() == b"mismatch"
