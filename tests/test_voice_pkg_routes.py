import json
from pathlib import Path

from conftest import write_release_config
from fastapi.testclient import TestClient

from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor

INFO = {
    "voice_pkg_version": 1,
    "voice_list": [
        {
            "voice_id": 3,
            "version": 7,
            "applicable": ["us"],
            "lang": "en",
            "voice_pri": 3,
            "voice_title": "English",
            "voice_pkg_url": "https://cnbj2.fds.api.xiaomi.com/app/beryllite/voice-pkg/package/en.pkg",
            "voice_pkg_md5": "e4681aee0381290597475a598fdfdda6",
        }
    ],
}


def _client(tmp_path: Path) -> TestClient:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    return TestClient(
        ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config)).app
    )


def _fake_fetch(monkeypatch, answers: dict[str, bytes]) -> list[str]:
    from https_server.routes.plugin import voice_pkg

    calls: list[str] = []

    async def fake(url: str, *, max_bytes: int, timeout_s: float) -> bytes:
        calls.append(url)
        if url not in answers:
            raise RuntimeError("upstream returned HTTP 404")
        return answers[url]

    monkeypatch.setattr(voice_pkg, "fetch_voice_bytes", fake)
    return calls


def test_model_maps_to_the_plugin_sound_package_path() -> None:
    from https_server.routes.plugin.voice_pkg import voice_info_path_for_model

    assert (
        voice_info_path_for_model("roborock.vacuum.a245")
        == "/app/beryllite/voice-pkg/info"
    )
    assert (
        voice_info_path_for_model("roborock.vacuum.a136")
        == "/app/ppscouple/voice-pkg/info"
    )
    assert (
        voice_info_path_for_model("roborock.vacuum.a08")
        == "/rubysc1/app/voice-pkg/info"
    )
    assert (
        voice_info_path_for_model("roborock.vacuum.a19") == "/rubyse/app/voice-pkg/info"
    )
    assert voice_info_path_for_model("roborock.vacuum.zzz") == ""


def test_tanos_and_tanose_use_the_legacy_layout() -> None:
    from https_server.routes.plugin.voice_pkg import voice_info_path_for_model

    cases = (("t6", "tanos"), ("s6", "tanos"), ("t7", "tanose"), ("a11", "tanose"))
    for short, bucket in cases:
        assert (
            voice_info_path_for_model(f"roborock.vacuum.{short}")
            == f"/{bucket}/app/voice-pkg/info"
        )


def test_inherited_configs_use_their_parents_bucket() -> None:
    from https_server.routes.plugin.voice_pkg import voice_info_path_for_model

    expected = {
        "a325": "pearle",
        "a182": "vivian",
        "a243": "vivian",
        "a250": "vivian",
        "a216": "viviansc",
        "a360": "tanosslite",
    }
    for short, bucket in expected.items():
        assert (
            voice_info_path_for_model(f"roborock.vacuum.{short}")
            == f"/app/{bucket}/voice-pkg/info"
        )


def _plugin_robot_url(res_host: str, voice_pkg_url: str) -> str:
    """What the official plugin sends the robot: 'https://' + resHost + url.split('.com')[1]."""
    return "https://" + res_host + voice_pkg_url.split(".com")[1]


def test_official_plugin_discards_the_rewritten_host() -> None:
    from https_server.routes.plugin.voice_pkg import _rewrite_info

    def rewritten(api_url: str) -> str:
        info = _rewrite_info(INFO, info_host="us-app.roborock.com", api_url=api_url)
        return info["voice_list"][0]["voice_pkg_url"]

    # No ".com" in our URL: the plugin falls back to the original path on Roborock's host.
    plain = rewritten("https://home.lan")
    assert _plugin_robot_url("us-app.roborock.com", plain) == (
        "https://us-app.roborock.com/app/beryllite/voice-pkg/package/en.pkg"
    )
    # ".com" in our URL: the plugin cuts at the first one and the URL is garbled.
    dotcom = rewritten("https://api-roborock.example.com")
    assert _plugin_robot_url("us-app.roborock.com", dotcom) == (
        "https://us-app.roborock.com/voice-pkg/files/us-app.roborock"
    )
    # Either way the robot never receives our host, so only clients that pass the URL
    # through unchanged (LocalRock) install from this server.
    assert "home.lan" not in _plugin_robot_url("us-app.roborock.com", plain)


def test_info_is_fetched_from_the_region_host_and_urls_point_at_this_server(
    tmp_path: Path, monkeypatch
) -> None:
    upstream = "https://us-app.roborock.com/app/beryllite/voice-pkg/info"
    calls = _fake_fetch(monkeypatch, {upstream: json.dumps(INFO).encode()})
    client = _client(tmp_path)

    response = client.get("/voice-pkg/info", params={"model": "roborock.vacuum.a245"})

    assert response.status_code == 200
    assert calls == [upstream]
    item = response.json()["voice_list"][0]
    assert item["voice_pkg_url"] == (
        "https://api-roborock.example.com/voice-pkg/files/us-app.roborock.com/app/beryllite/voice-pkg/package/en.pkg"
    )
    assert (
        item["voice_pkg_source_url"]
        == "https://us-app.roborock.com/app/beryllite/voice-pkg/package/en.pkg"
    )
    assert item["voice_pkg_md5"] == INFO["voice_list"][0]["voice_pkg_md5"]
    assert response.json()["voice_pkg_host"] == "us-app.roborock.com"


def test_info_falls_back_to_the_fds_host_then_to_the_cached_copy(
    tmp_path: Path, monkeypatch
) -> None:
    fds = "https://awsusor0.fds.api.xiaomi.com/app/beryllite/voice-pkg/info"
    calls = _fake_fetch(monkeypatch, {fds: json.dumps(INFO).encode()})
    client = _client(tmp_path)

    first = client.get("/app/beryllite/voice-pkg/info?time=1")
    assert first.status_code == 200
    assert first.headers["X-RR-Voice-Cache"] == "miss"
    assert calls[-1] == fds

    _fake_fetch(monkeypatch, {})
    stale = client.get("/app/beryllite/voice-pkg/info")
    assert stale.status_code == 200
    assert stale.headers["X-RR-Voice-Cache"] == "stale"
    assert stale.json()["voice_list"][0]["voice_id"] == 3


def test_info_without_any_upstream_is_a_502(tmp_path: Path, monkeypatch) -> None:
    _fake_fetch(monkeypatch, {})
    response = _client(tmp_path).get("/voice-pkg/info?model=roborock.vacuum.a245")
    assert response.status_code == 502


def test_unknown_model_is_a_404(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_fetch(monkeypatch, {})
    response = _client(tmp_path).get("/voice-pkg/info?model=roborock.vacuum.zzz")
    assert response.status_code == 404
    assert calls == []


def test_package_is_proxied_once_then_served_from_cache(
    tmp_path: Path, monkeypatch
) -> None:
    source = "https://us-app.roborock.com/app/beryllite/voice-pkg/package/en.pkg"
    calls = _fake_fetch(monkeypatch, {source: b"pkg-bytes"})
    client = _client(tmp_path)
    path = "/voice-pkg/files/us-app.roborock.com/app/beryllite/voice-pkg/package/en.pkg"

    first = client.get(path)
    second = client.get(path)

    assert first.content == second.content == b"pkg-bytes"
    assert first.headers["X-RR-Voice-Cache"] == "miss"
    assert second.headers["X-RR-Voice-Cache"] == "hit"
    assert calls == [source]


def test_package_from_an_unknown_host_is_refused(tmp_path: Path, monkeypatch) -> None:
    calls = _fake_fetch(monkeypatch, {})
    response = _client(tmp_path).get(
        "/voice-pkg/files/example.com/app/x/voice-pkg/package/en.pkg"
    )
    assert response.status_code == 403
    assert calls == []


def test_a_request_from_our_own_proxy_is_not_proxied_again(
    tmp_path: Path, monkeypatch
) -> None:
    calls = _fake_fetch(monkeypatch, {})
    response = _client(tmp_path).get(
        "/app/beryllite/voice-pkg/info", headers={"X-RR-Voice-Proxy": "1"}
    )
    assert response.status_code == 508
    assert calls == []


def _serve_and_fetch(app, path: str, max_bytes: int) -> Exception | None:
    import asyncio

    from aiohttp import web

    from roborock_local_server.bundled_backend.https_server.routes.plugin import (
        voice_pkg,
    )

    async def run() -> Exception | None:
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        try:
            await voice_pkg.fetch_voice_bytes(
                f"http://127.0.0.1:{port}{path}", max_bytes=max_bytes, timeout_s=5
            )
        except Exception as exc:  # noqa: BLE001
            return exc
        finally:
            await runner.cleanup()
        return None

    return asyncio.run(run())


def test_fetch_does_not_follow_redirects_off_the_allowed_host() -> None:
    from aiohttp import web

    async def redirect(_request):
        raise web.HTTPFound("http://example.invalid/evil.pkg")

    app = web.Application()
    app.router.add_get("/a.pkg", redirect)
    error = _serve_and_fetch(app, "/a.pkg", max_bytes=1024)
    assert error is not None and "HTTP 302" in str(error)


def test_fetch_stops_reading_past_the_size_cap() -> None:
    from aiohttp import web

    async def big(_request):
        response = web.StreamResponse()
        await response.prepare(_request)
        for _ in range(64):
            await response.write(b"x" * 1024)
        return response

    async def declared(_request):
        return web.Response(body=b"x" * 4096)

    def app():
        application = web.Application()
        application.router.add_get("/big.pkg", big)
        application.router.add_get("/declared.pkg", declared)
        return application

    streamed = _serve_and_fetch(app(), "/big.pkg", max_bytes=8 * 1024)
    assert streamed is not None and "too large" in str(streamed)
    by_length = _serve_and_fetch(app(), "/declared.pkg", max_bytes=1024)
    assert by_length is not None and "too large: 4096" in str(by_length)


def test_concurrent_requests_for_one_package_download_it_once(
    tmp_path: Path, monkeypatch
) -> None:
    import asyncio

    from https_server.routes.plugin import voice_pkg

    calls: list[str] = []

    async def slow(url: str, *, max_bytes: int, timeout_s: float) -> bytes:
        calls.append(url)
        await asyncio.sleep(0.05)
        return b"pkg-bytes"

    monkeypatch.setattr(voice_pkg, "fetch_voice_bytes", slow)

    async def run() -> list[bytes]:
        results = await asyncio.gather(
            *(
                voice_pkg._voice_file_response(
                    tmp_path, "us-app.roborock.com", "/a/voice-pkg/package/en.pkg"
                )
                for _ in range(4)
            )
        )
        return [response.body for _, response in results]

    bodies = asyncio.run(run())

    assert bodies == [b"pkg-bytes"] * 4
    assert len(calls) == 1
    cache_dir = tmp_path / "voice_pkg_cache"
    assert [p.suffix for p in cache_dir.iterdir()] == [".pkg"]


def test_concurrent_info_requests_share_one_upstream_fetch(
    tmp_path: Path, monkeypatch
) -> None:
    import asyncio
    from types import SimpleNamespace

    from https_server.routes.plugin import voice_pkg

    calls: list[str] = []

    async def slow(url: str, *, max_bytes: int, timeout_s: float) -> bytes:
        calls.append(url)
        await asyncio.sleep(0.05)
        return json.dumps(INFO).encode()

    monkeypatch.setattr(voice_pkg, "fetch_voice_bytes", slow)
    ctx = SimpleNamespace(region="us", api_url=lambda: "https://api.example")

    async def run() -> list[int]:
        results = await asyncio.gather(
            *(
                voice_pkg._voice_info_response(
                    ctx, tmp_path, "/app/beryllite/voice-pkg/info"
                )
                for _ in range(4)
            )
        )
        return [response.status_code for _, response in results]

    assert asyncio.run(run()) == [200] * 4
    assert len(calls) == 1


def test_package_cache_keeps_only_the_newest_files(tmp_path: Path, monkeypatch) -> None:
    import os

    from https_server.routes.plugin import voice_pkg

    monkeypatch.setattr(voice_pkg, "VOICE_PKG_CACHE_MAX_FILES", 3)
    for index in range(5):
        path = tmp_path / f"{index}.pkg"
        path.write_bytes(b"x")
        os.utime(path, (1000 + index, 1000 + index))
    stale_tmp = tmp_path / "old.pkg.abc.tmp"
    stale_tmp.write_bytes(b"x")
    os.utime(stale_tmp, (1, 1))
    info = tmp_path / "info-x.json"
    info.write_bytes(b"{}")

    voice_pkg._evict_old_packages(tmp_path)

    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "2.pkg",
        "3.pkg",
        "4.pkg",
        "info-x.json",
    ]


def test_v2_to_v5_model_strings_use_the_debug_path() -> None:
    from https_server.routes.plugin.voice_pkg import voice_info_path_for_model

    assert (
        voice_info_path_for_model("roborock.vacuum.a245v4")
        == "/app/beryllite/voice-pkg/debug/info"
    )
    assert (
        voice_info_path_for_model("roborock.vacuum.t6v2")
        == "/tanos/app/voice-pkg/debug/info"
    )
    assert voice_info_path_for_model("roborock.vacuum.zzzv2") == ""


def test_cache_hit_that_vanishes_before_it_is_served_is_a_miss(
    tmp_path: Path, monkeypatch
) -> None:
    import asyncio
    import os

    from https_server.routes.plugin import voice_pkg

    source = "https://us-app.roborock.com/a/voice-pkg/package/en.pkg"
    _fake_fetch(monkeypatch, {source: b"fresh"})
    cache_dir = tmp_path / "voice_pkg_cache"
    cache_dir.mkdir()
    path = cache_dir / (
        voice_pkg._digest("https://us-app.roborock.com/a/voice-pkg/package/en.pkg")
        + ".pkg"
    )
    path.write_bytes(b"old")
    real = os.utime

    def vanishing(target, *args, **kwargs):
        if str(target).endswith(".pkg"):
            raise FileNotFoundError(str(target))
        return real(target, *args, **kwargs)

    monkeypatch.setattr(voice_pkg.os, "utime", vanishing)
    _, response = asyncio.run(
        voice_pkg._voice_file_response(
            tmp_path, "us-app.roborock.com", "/a/voice-pkg/package/en.pkg"
        )
    )
    assert response.body == b"fresh"
    assert response.headers["X-RR-Voice-Cache"] == "miss"


def test_cache_hit_removed_after_the_touch_still_answers(
    tmp_path: Path, monkeypatch
) -> None:
    import asyncio
    import os

    from https_server.routes.plugin import voice_pkg

    source = "https://us-app.roborock.com/a/voice-pkg/package/en.pkg"
    _fake_fetch(monkeypatch, {source: b"fresh"})
    cache_dir = tmp_path / "voice_pkg_cache"
    cache_dir.mkdir()
    path = cache_dir / (voice_pkg._digest(source) + ".pkg")
    path.write_bytes(b"old")
    real = os.utime

    def touch_then_evict(target, *args, **kwargs):
        real(target, *args, **kwargs)
        if str(target).endswith(".pkg"):
            os.remove(target)

    monkeypatch.setattr(voice_pkg.os, "utime", touch_then_evict)
    _, response = asyncio.run(
        voice_pkg._voice_file_response(
            tmp_path, "us-app.roborock.com", "/a/voice-pkg/package/en.pkg"
        )
    )
    assert response.body == b"fresh"
    assert response.headers["X-RR-Voice-Cache"] == "miss"


def test_package_cache_is_bounded_by_total_bytes(tmp_path: Path, monkeypatch) -> None:
    import os

    from https_server.routes.plugin import voice_pkg

    monkeypatch.setattr(voice_pkg, "VOICE_PKG_CACHE_MAX_BYTES", 25)
    for index in range(4):
        path = tmp_path / f"{index}.pkg"
        path.write_bytes(b"x" * 10)
        os.utime(path, (1000 + index, 1000 + index))

    voice_pkg._evict_old_packages(tmp_path)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["2.pkg", "3.pkg"]


def test_info_cache_is_kept_per_region(tmp_path: Path, monkeypatch) -> None:
    from https_server.routes.plugin import voice_pkg

    class Ctx:
        def __init__(self, region: str) -> None:
            self.region = region

        def api_url(self) -> str:
            return "https://api-roborock.example.com"

    import asyncio

    path = "/app/beryllite/voice-pkg/info"
    _fake_fetch(
        monkeypatch, {"https://us-app.roborock.com" + path: json.dumps(INFO).encode()}
    )
    asyncio.run(voice_pkg._voice_info_response(Ctx("us"), tmp_path, path))
    _fake_fetch(monkeypatch, {})
    try:
        asyncio.run(voice_pkg._voice_info_response(Ctx("eu"), tmp_path, path))
    except voice_pkg.VoicePkgError:
        pass
    else:
        raise AssertionError("an eu request must not be answered from the us cache")


def test_a_corrupt_cached_info_is_a_502_not_an_error(
    tmp_path: Path, monkeypatch
) -> None:
    fds = "https://awsusor0.fds.api.xiaomi.com/app/beryllite/voice-pkg/info"
    _fake_fetch(monkeypatch, {fds: json.dumps(INFO).encode()})
    client = _client(tmp_path)
    assert client.get("/app/beryllite/voice-pkg/info").status_code == 200
    _fake_fetch(monkeypatch, {})
    cache_files = list(tmp_path.rglob("info-*.json"))
    assert len(cache_files) == 1
    for content in (b"{not json", b"[]", b'{"host": "x"}', b'{"host": 1, "info": {}}'):
        cache_files[0].write_bytes(content)
        assert client.get("/app/beryllite/voice-pkg/info").status_code == 502
