import subprocess

import pytest

from roborock_local_server.config import TurnConfig
from roborock_local_server.turn_relay import EmbeddedTurnRelay
from roborock_local_server import turn_relay


@pytest.mark.parametrize("mode", ["disabled", "external"])
def test_other_modes_do_not_start_coturn(tmp_path, monkeypatch, mode):
    def unexpected(*args, **kwargs):
        pytest.fail("coturn should not start")
    monkeypatch.setattr(turn_relay.subprocess, "Popen", unexpected)
    relay = EmbeddedTurnRelay(TurnConfig(mode=mode), tmp_path)
    relay.start()
    assert not relay.running


def test_failed_coturn_launch_does_not_leave_process(tmp_path, monkeypatch):
    monkeypatch.setattr(turn_relay.socket, "getaddrinfo", lambda *args: [(None, None, None, None, ("192.0.2.1", 3478))])
    def missing(*args, **kwargs):
        raise FileNotFoundError("coturn unavailable")
    monkeypatch.setattr(turn_relay.subprocess, "Popen", missing)
    relay = EmbeddedTurnRelay(TurnConfig(mode="provided", host="turn.example.com", username="user", password="secret", realm="example.com"), tmp_path)
    with pytest.raises(FileNotFoundError):
        relay.start()
    assert not relay.running


def test_stop_kills_relay_that_ignores_termination(tmp_path):
    class Process:
        terminated = False
        killed = False
        def terminate(self):
            self.terminated = True
        def wait(self, timeout):
            if not self.killed:
                raise subprocess.TimeoutExpired("turnserver", timeout)
        def kill(self):
            self.killed = True
    relay = EmbeddedTurnRelay(TurnConfig(), tmp_path)
    process = Process()
    relay.process = process
    relay.stop()
    assert process.terminated and process.killed
    assert relay.process is None
