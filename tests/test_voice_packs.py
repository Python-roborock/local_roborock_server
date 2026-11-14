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
