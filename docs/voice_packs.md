# Voice Packs (Robot Language)

The language a robot speaks is the installed voice pack. There is no separate language setting. The Roborock app's "Voice pack" screen needs a cloud endpoint this server does not implement, so switch packs by sending three RPC commands to the robot yourself. No server changes are needed.

| Command | Params | What it does |
|---|---|---|
| `get_current_sound` | none | Returns `sid_in_use` (pack id) and `sid_version` |
| `dnld_install_sound` | `{"url", "md5", "sid", "sver"}` or `{"sid": 3, "default": "en"}` | Downloads and installs a pack, or switches to a built-in one (`prc`=1, `tw`=2, `en`=3) |
| `get_sound_progress` | none | `state` 1 downloading, 3 installed, 4 error. `error` is an errno: 2 no such pack, 13 cannot write pack storage |

Verified on a Roborock S6 MaxV (`roborock.vacuum.a10`, firmware `02.62.46`): a 1.9 MB German pack installs in about 10 seconds. Other models and firmware are untested. Send the commands while the robot is docked and idle; you can always go back to the built-in English pack (see Troubleshooting).

## Find The Pack For Your Model

Xiaomi still hosts the original packs for the Mi Home generation of Roborock robots, and the Roborock firmware accepts them. Look up your model on [robotinfo.dev](https://robotinfo.dev/) and open the link in the "Soundfiles" column. That is the manifest, for example for the S6 MaxV (`tanosv`):

```bash
curl -s https://awsde0.fds.api.xiaomi.com/tanosv/app/voice-pkg/info \
  | python3 -c 'import json,sys; [print(v["voice_id"], v["version"], v.get("lang"), v["voice_pkg_url"]) for v in json.load(sys.stdin)["voice_list"]]'
```

`voice_id` is the `sid`, `version` is the `sver`. Ignore the manifest's `voice_pkg_md5` field (it repeats the same value across packs). Compute the real checksum from the file:

```bash
curl -sL https://cnbj2.fds.api.xiaomi.com/tanosv/app/voice-pkg/package/tanosv_de_v6.pkg | md5sum   # macOS: md5 -r
```

S6 MaxV values used below. `sid`, `sver`, URL and md5 are model-specific: take them from your own model's manifest, do not reuse these for another robot.

| Language | `sid` | `sver` | URL | md5 |
|---|---|---|---|---|
| English | 3 | 3 | `https://cnbj2.fds.api.xiaomi.com/tanosv/app/voice-pkg/package/tanosv_en_v6.pkg` | `04b50630731a1a05c05bd5a65604b3b2` |
| German | 103 | 5 | `https://cnbj2.fds.api.xiaomi.com/tanosv/app/voice-pkg/package/tanosv_de_v6.pkg` | `f04545d288df99a4f8b0ed8a6ee345e6` |

## Let The Robot Fetch The File

The robot downloads the URL itself. Two options:

- **Direct:** allow the robot DNS plus TCP 443 to `cnbj2.fds.api.xiaomi.com` for the duration of the install.
- **LAN host (for robots without internet):** download the `.pkg` to any machine the robot's network can reach over plain HTTP and serve it from there, then use that URL (for example `http://<lan-host-ip>:8000/tanosv_de_v6.pkg`). Stop the server after the install:

    ```bash
    mkdir -p /tmp/voicepkg && cd /tmp/voicepkg
    curl -sLO https://cnbj2.fds.api.xiaomi.com/tanosv/app/voice-pkg/package/tanosv_de_v6.pkg
    python3 -m http.server 8000 --bind 0.0.0.0
    ```

Both paths were verified.

## Send The Commands

### From Home Assistant

`vacuum.send_command` forwards command and params unchanged (Developer Tools → Actions):

```yaml
action: vacuum.send_command
target:
  entity_id: vacuum.robi_one
data:
  command: dnld_install_sound
  params:
    url: https://cnbj2.fds.api.xiaomi.com/tanosv/app/voice-pkg/package/tanosv_de_v6.pkg
    md5: f04545d288df99a4f8b0ed8a6ee345e6
    sid: 103
    sver: 5
```

Then send `get_sound_progress` (no params) until `state` is 3, and `get_current_sound` to confirm. Home Assistant does not show RPC replies; read them from the decoded MQTT trace in the data directory, `runtime/decompiled_mqtt.jsonl` (see [Log Retention](logging.md)). The first command prints the last `get_sound_progress` replies, the second the last `get_current_sound` replies:

```bash
grep -o '\\"102\\":\\"{[^}]*}' runtime/decompiled_mqtt.jsonl | grep sid_in_progress | tail -3
grep -o '\\"102\\":\\"{[^}]*}' runtime/decompiled_mqtt.jsonl | grep sid_in_use | tail -3
```

### From Python

[python-roborock](https://github.com/Python-roborock/python-roborock) logs in to the local stack the same way Home Assistant does and prints the replies. Set `EMAIL` and `PIN` to `protocol_login_email` and `protocol_login_pin` from `config.toml`, `BASE` to your API URL, and `country`/`country_code` to your own country:

```python
import asyncio
from roborock.devices.device_manager import UserParams, create_device_manager
from roborock.web_api import RoborockApiClient

EMAIL, PIN, BASE = "you@example.com", "123456", "https://api-roborock.example.com:555"
DUID = "<robot duid>"

async def main():
    client = RoborockApiClient(EMAIL, base_url=BASE)
    await client.request_code_v4()
    user_data = await client.code_login_v4(PIN, country="DE", country_code=49)
    manager = await create_device_manager(UserParams(EMAIL, user_data, BASE))
    try:
        device = await manager.get_device(DUID)
        assert device is not None and device.v1_properties is not None, "unknown duid or not a V1 robot"
        cmd = device.v1_properties.command
        print(await cmd.send("get_current_sound"))
        print(await cmd.send("dnld_install_sound", {"url": "...", "md5": "...", "sid": 103, "sver": 5}))
        for _ in range(12):
            await asyncio.sleep(5)
            print(await cmd.send("get_sound_progress"))
    finally:
        await manager.close()

asyncio.run(main())
```

Use the v4 login methods. The v1 `loginWithCode` path only works on server versions that include [#145](https://github.com/Python-roborock/local_roborock_server/pull/145).

## Troubleshooting

- `state 4, error 2` after a `default` install: that built-in pack does not exist on the robot (verified). After a URL install it most likely means the download failed; check DNS and egress, or use the LAN host.
- `state 4, error 13` immediately, no network traffic, while built-in packs (`{"sid": 3, "default": "en"}`) still switch fine: the robot cannot write its downloadable-pack storage. Seen on one S6 MaxV (cause unknown, reboot did not help) while two others of the same model and firmware installed fine.
- `dnld_install_sound` answers `["ok"]` or `{"progress": 0, "state": 0, "error": 0}` either way; only `get_sound_progress` tells you whether it worked.
- To go back to the built-in English pack: `dnld_install_sound` with `{"sid": 3, "default": "en"}`.

## Related Docs

- [Home Assistant](home_assistant.md)
- [Log Retention](logging.md)
- [Known Limitations](known_limitations.md)
