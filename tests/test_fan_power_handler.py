import roborock_local_server.server  # noqa: F401  (puts the bundled backend on sys.path)
from mqtt_tls_proxy_server.command_handlers import FanPowerHandler


def _handled(method: str, params: object) -> dict | None:
    result = FanPowerHandler().handle_request({"method": method, "params": params})
    return None if result is None else result.state_updates


def test_set_custom_mode_still_reads_a_plain_list() -> None:
    assert _handled("set_custom_mode", [103]) == {"fan_power": 103}


def test_set_clean_motor_mode_reads_the_dict_the_app_sends() -> None:
    params = [{"fan_power": 102, "water_box_mode": 202, "mop_mode": 300}]
    assert _handled("set_clean_motor_mode", params) == {"fan_power": 102}


def test_a_bare_dict_is_read_too() -> None:
    assert _handled("set_clean_motor_mode", {"fan_power": 104}) == {"fan_power": 104}


def test_a_dict_without_fan_power_records_nothing() -> None:
    assert _handled("set_clean_motor_mode", [{"water_box_mode": 202}]) is None
    assert _handled("set_clean_motor_mode", [{"fan_power": True}]) is None
