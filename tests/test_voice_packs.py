import asyncio
import hashlib
import json

import pytest

from roborock_local_server import voice_packs as vp

INFO = {
    "voice_pkg_version": 1,
    "voice_list": [
        {
            "voice_id": 129, "lang": "nl", "version": 4,
            "voice_pkg_url": "https://eu-app.roborock.com/app/vida/voice-pkg/package/nl.pkg",
            "bg_pic": "https://eu-app.roborock.com/app/vida/voice-pkg/pic/nl.png",
            "voice_pre_listen": "https://eu-app.roborock.com/app/vida/voice-pkg/wav/nl.wav",
            "voice_pkg_md5": hashlib.md5(b"dutch").hexdigest(),
        }
    ],
}


def test_list_urls_point_at_this_server():
    out = vp.rewrite_list(INFO, "https://api-roborock.example.com", "vida")
    voice = out["voice_list"][0]
    assert voice["voice_pkg_url"] == "https://api-roborock.example.com/voice-pkg/vida/package/nl.pkg"
    assert voice["bg_pic"] == "https://api-roborock.example.com/voice-pkg/vida/pic/nl.png"
    assert voice["voice_pre_listen"] == "https://api-roborock.example.com/voice-pkg/vida/wav/nl.wav"
    assert voice["voice_pkg_md5"] == INFO["voice_list"][0]["voice_pkg_md5"]
    # The original is left alone.
    assert INFO["voice_list"][0]["voice_pkg_url"].startswith("https://eu-app.roborock.com/")


@pytest.mark.parametrize("kind,name,ok", [
    ("package", "nl.pkg", True), ("pic", "nl.png", True), ("wav", "es-la.wav", True),
    ("package", "../x.pkg", False), ("package", "nl.png", False), ("other", "nl.pkg", False),
    ("package", ".pkg", False), ("package", "a/b.pkg", False),
])
def test_only_plain_file_names_are_served(kind, name, ok):
    assert vp.valid_file(kind, name) is ok


@pytest.mark.parametrize("bucket,ok", [("vida", True), ("a-b_1", True), ("", False), ("../etc", False), ("Vida", False)])
def test_bucket_names(bucket, ok):
    assert vp.valid_bucket(bucket) is ok


def test_files_are_fetched_once_and_checked(tmp_path, monkeypatch):
    asyncio.run(_fetched_once(tmp_path, monkeypatch))


async def _fetched_once(tmp_path, monkeypatch):
    mirror = vp.VoicePackMirror(tmp_path, "eu")
    calls = []

    async def fake_download(url):
        calls.append(url)
        if url.endswith("/info"):
            return json.dumps(INFO).encode()
        return b"dutch"

    monkeypatch.setattr(mirror, "_download", fake_download)
    path = await mirror.get_file("vida", "package", "nl.pkg")
    assert path.read_bytes() == b"dutch"
    assert calls == [
        "https://eu-app.roborock.com/app/vida/voice-pkg/info",
        "https://eu-app.roborock.com/app/vida/voice-pkg/package/nl.pkg",
    ]
    await mirror.get_file("vida", "package", "nl.pkg")
    assert len(calls) == 2


def test_a_package_not_in_the_list_is_not_fetched(tmp_path, monkeypatch):
    asyncio.run(_not_listed(tmp_path, monkeypatch))


async def _not_listed(tmp_path, monkeypatch):
    mirror = vp.VoicePackMirror(tmp_path, "eu")
    calls = []

    async def fake_download(url):
        calls.append(url)
        return json.dumps(INFO).encode()

    monkeypatch.setattr(mirror, "_download", fake_download)
    with pytest.raises(vp.VoicePackError):
        await mirror.get_file("vida", "package", "xx.pkg")
    assert calls == ["https://eu-app.roborock.com/app/vida/voice-pkg/info"]


def test_the_last_list_is_used_when_roborock_is_unreachable(tmp_path, monkeypatch):
    asyncio.run(_last_list(tmp_path, monkeypatch))


async def _last_list(tmp_path, monkeypatch):
    mirror = vp.VoicePackMirror(tmp_path, "eu")

    async def ok(url):
        return json.dumps(INFO).encode()

    monkeypatch.setattr(mirror, "_download", ok)
    await mirror.get_list("vida")
    monkeypatch.setattr(vp, "LIST_MAX_AGE_SECONDS", -1)

    async def down(url):
        raise vp.aiohttp.ClientError("offline")

    monkeypatch.setattr(mirror, "_download", down)
    assert (await mirror.get_list("vida"))["voice_list"][0]["voice_id"] == 129


def test_offline_serves_stored_copies_and_never_downloads(tmp_path, monkeypatch):
    asyncio.run(_offline(tmp_path, monkeypatch))


async def _offline(tmp_path, monkeypatch):
    online = vp.VoicePackMirror(tmp_path, "eu")

    async def fake_download(url):
        return json.dumps(INFO).encode() if url.endswith("/info") else b"dutch"

    monkeypatch.setattr(online, "_download", fake_download)
    await online.get_file("vida", "package", "nl.pkg")

    offline = vp.VoicePackMirror(tmp_path, "eu", offline=True)

    async def no_download(url):
        raise AssertionError(f"offline mode fetched {url}")

    monkeypatch.setattr(offline, "_download", no_download)
    assert (await offline.get_list("vida"))["voice_list"][0]["voice_id"] == 129
    assert (await offline.get_file("vida", "package", "nl.pkg")).read_bytes() == b"dutch"
    with pytest.raises(vp.VoicePackError) as missing:
        await offline.get_file("vida", "wav", "nl.wav")
    assert missing.value.status == 404
    with pytest.raises(vp.VoicePackError) as no_list:
        await offline.get_list("other")
    assert no_list.value.status == 404
    assert (await offline.prefetch("vida"))["stored"] == 0


def _client(tmp_path, monkeypatch, extra: str = "", https_port: int = 443):
    from fastapi.testclient import TestClient
    from conftest import write_release_config
    from roborock_local_server.config import load_config, resolve_paths
    from roborock_local_server.server import ReleaseSupervisor

    config_file = write_release_config(tmp_path, https_port=https_port)
    if extra:
        config_file.write_text(config_file.read_text() + extra)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))

    async def fake_download(url):
        return json.dumps(INFO).encode() if url.endswith("/info") else b"dutch"

    monkeypatch.setattr(supervisor.voice_packs, "_download", fake_download)
    monkeypatch.setattr(supervisor.voice_packs, "prefetch", lambda bucket: asyncio.sleep(0))
    return TestClient(supervisor.app)


def test_the_list_route_points_at_the_advertised_https_port(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    voice = client.get("/voice-pkg/vida/info").json()["voice_list"][0]
    assert voice["voice_pkg_url"] == "https://api-roborock.example.com/voice-pkg/vida/package/nl.pkg"
    assert client.get("/voice-pkg/vida/package/nl.pkg").content == b"dutch"

    other = _client(tmp_path / "p555", monkeypatch, https_port=555)
    voice = other.get("/voice-pkg/vida/info").json()["voice_list"][0]
    assert voice["voice_pkg_url"] == "https://api-roborock.example.com:555/voice-pkg/vida/package/nl.pkg"


def test_disabled_mode_turns_the_routes_off(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, extra='\n[voice_packs]\nmode="disabled"\n')
    assert client.get("/voice-pkg/vida/info").status_code == 404
    assert client.get("/voice-pkg/vida/package/nl.pkg").status_code == 404
