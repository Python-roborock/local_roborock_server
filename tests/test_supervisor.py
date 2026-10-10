import asyncio
from dataclasses import replace
import pytest
from pathlib import Path

from conftest import write_release_config
from roborock_local_server import server as server_module
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from roborock_local_server.config import TurnConfig


@pytest.mark.parametrize("endpoint", ["status", "health"])
def test_status_reports_provided_relay_process_death(tmp_path: Path, endpoint: str) -> None:
    config_file = write_release_config(tmp_path)
    config = replace(load_config(config_file), turn=TurnConfig(mode="provided", host="api-vac.cc"))
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    class Process:
        code = None
        def poll(self):
            return self.code
    process = Process()
    supervisor._turn_relay.process = process
    def health():
        if endpoint == "health":
            return supervisor._ui_health_payload()
        status = supervisor._status_payload()
        assert status["turn"] == {"mode": "provided", "host": "api-vac.cc", "port": 3478}
        return status["health"]
    before = health()
    assert next(s for s in before["services"] if s["name"] == "turn_relay")["running"]
    process.code = 1
    after = health()
    assert not next(s for s in after["services"] if s["name"] == "turn_relay")["running"]


class _DummyProxy:
    def __init__(self) -> None:
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


class _DummyHttpServer:
    def __init__(self) -> None:
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


def test_release_supervisor_start_stop_external_mode(tmp_path: Path, monkeypatch) -> None:
    config_file = write_release_config(tmp_path, broker_mode="external", enable_topic_bridge=False)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    monkeypatch.setattr(server_module, "_connectivity_check", lambda host, port: None)

    async def fake_start_http_server(self: ReleaseSupervisor) -> None:
        self._http_server = _DummyHttpServer()  # type: ignore[assignment]
        self.runtime_state.set_service("https_server", running=True, required=True, enabled=True)

    def fake_start_mqtt_proxy(self: ReleaseSupervisor) -> None:
        self._mqtt_proxy = _DummyProxy()  # type: ignore[assignment]
        self.runtime_state.set_service("mqtt_tls_proxy", running=True, required=True, enabled=True)

    monkeypatch.setattr(ReleaseSupervisor, "_start_http_server", fake_start_http_server)
    monkeypatch.setattr(ReleaseSupervisor, "_start_mqtt_proxy", fake_start_mqtt_proxy)

    asyncio.run(supervisor.start())
    health = supervisor.runtime_state.health_snapshot()
    service_map = {service["name"]: service for service in health["services"]}
    assert service_map["https_server"]["running"] is True
    assert service_map["mqtt_tls_proxy"]["running"] is True
    assert service_map["mqtt_backend_broker"]["running"] is True

    asyncio.run(supervisor.stop())
    health = supervisor.runtime_state.health_snapshot()
    service_map = {service["name"]: service for service in health["services"]}
    assert service_map["https_server"]["running"] is False
    assert service_map["mqtt_tls_proxy"]["running"] is False
    assert service_map["mqtt_backend_broker"]["running"] is False


def test_relay_dns_failure_keeps_core_services_running(tmp_path, monkeypatch):
    import socket
    from roborock_local_server import turn_relay
    config_file = write_release_config(tmp_path)
    config = replace(load_config(config_file), turn=TurnConfig(mode="provided", host="missing.example", username="u", password="p", realm="r"))
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    monkeypatch.setattr(server_module, "_connectivity_check", lambda *a: None)
    def dns_failure(*a):
        raise socket.gaierror("DNS unavailable")
    monkeypatch.setattr(turn_relay.socket, "getaddrinfo", dns_failure)
    async def http(self):
        self._http_server = _DummyHttpServer()
        self.runtime_state.set_service("https_server", running=True)
    def mqtt(self):
        self._mqtt_proxy = _DummyProxy()
        self.runtime_state.set_service("mqtt_tls_proxy", running=True)
    monkeypatch.setattr(ReleaseSupervisor, "_start_http_server", http)
    monkeypatch.setattr(ReleaseSupervisor, "_start_mqtt_proxy", mqtt)
    asyncio.run(supervisor.start())
    health = supervisor._status_payload()["health"]
    services = {service["name"]: service for service in health["services"]}
    assert not services["turn_relay"]["running"]
    assert not health["overall_ok"]
    assert services["https_server"]["running"] and services["mqtt_tls_proxy"]["running"]
    asyncio.run(supervisor.stop())


def test_partial_startup_always_runs_cleanup(tmp_path, monkeypatch):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    stopped = []
    async def start():
        raise RuntimeError("HTTP bind failed")
    async def stop():
        stopped.append(True)
    monkeypatch.setattr(supervisor, "start", start)
    monkeypatch.setattr(supervisor, "stop", stop)
    with pytest.raises(RuntimeError, match="HTTP bind failed"):
        asyncio.run(supervisor.serve_forever())
    assert stopped == [True]


def test_disabled_turn_does_not_publish_empty_health_entry(tmp_path):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    assert not any(s["name"] == "turn_relay" for s in supervisor._status_payload()["health"]["services"])
