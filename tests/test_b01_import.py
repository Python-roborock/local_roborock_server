"""Device imports preserve unrelated entries and reject accidental replacement."""

import json

import pytest

from roborock_local_server.b01_import import import_device


@pytest.fixture
def files(tmp_path):
    device = tmp_path / "device.json"
    iot = tmp_path / "iot.json"
    output = tmp_path / "state" / "b01_devices.json"
    device.write_text(
        json.dumps(
            {
                "did": 123456789,
                "model": "roborock.vacuum.sc05",
                "secret": "0123456789abcdef" * 2,
            }
        )
    )
    iot.write_text(json.dumps({"duid": "synthetic-cloud-duid"}))
    return device, iot, output


def test_import_is_repeatable_and_preserves_other_devices(files):
    device, iot, output = files
    output.parent.mkdir()
    other = {"model": "roborock.vacuum.sc05", "duid": "other", "secret": "a" * 32}
    output.write_text(json.dumps({"devices": {"987654321": other}}))
    import_device(*files)
    first = output.read_bytes()
    import_device(*files)
    assert output.read_bytes() == first
    entries = json.loads(first)["devices"]
    assert entries["987654321"] == other
    assert entries["123456789"]["duid"] == "synthetic-cloud-duid"
    assert not list(output.parent.glob(".b01-*"))


def test_import_refuses_to_replace_existing_credentials(files):
    device, iot, output = files
    import_device(*files)
    original = output.read_bytes()
    iot.write_text(json.dumps({"duid": "different-cloud-duid"}))
    with pytest.raises(ValueError, match="different entry"):
        import_device(*files)
    assert output.read_bytes() == original


@pytest.mark.parametrize(
    "update",
    [{"model": "roborock.vacuum.a15"}, {"did": "invalid"}, {"secret": "short"}],
)
def test_invalid_device_does_not_create_state(files, update):
    device, _, output = files
    value = json.loads(device.read_text())
    value.update(update)
    device.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        import_device(*files)
    assert not output.exists()
