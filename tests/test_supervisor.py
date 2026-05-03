import asyncio
from pathlib import Path

from conftest import write_release_config
from roborock_local_server import server as server_module
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


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
