# Log retention

The server automatically rotates the six service logs (`api_server.log`,
`iot_server.log`, `wood_server.log`, `https_server.log`, `mqtt_server.log`, and
`unknown_server.log`) and both protocol traces (`decompiled_http.jsonl` and
`decompiled_mqtt.jsonl`) in the data directory's `runtime/` folder.

The defaults are **10 MiB per file and three backups per file**. The active file
keeps its usual name; `.1` is the newest backup and `.3` is the oldest. Older
backups expire automatically. At these defaults, the eight log families normally
use no more than about **320 MiB combined**. The threshold is per file, not a
quota for the entire data directory. A single larger record is kept intact and
can exceed the threshold; the next record causes rotation.

Console output remains available through Home Assistant's Logs tab or
`docker logs`. Container console-log retention is managed separately by the
container host. Changing console verbosity does not disable the JSONL files.

## Home Assistant

Set these options in the add-on configuration, then restart it:

```yaml
log_max_size_mb: 10
log_backup_count: 3
```

`log_max_size_mb` accepts an integer from 1 to 1024, measured in MiB
(1,048,576 bytes). `log_backup_count` accepts an integer from 0 to 20.
Setting the backup count to `0` keeps only the active file; it still rolls over
when full. There is no unlimited-size setting.

## Docker and standalone installs

Add this optional section to `config.toml`, then restart:

```toml
[logging]
max_size_mb = 10
backup_count = 3
```

The same ranges apply. Existing configurations that omit this section receive
the defaults automatically.

## Existing large logs and changes to retention

At startup, the server first recovers missing MQTT credentials and seeds missing
zone-range state from the existing logs, including numbered backups. It then
trims oversized logs to their most recent complete lines and removes backups
beyond the configured count. This also applies when reducing either limit and
to logs that are no longer receiving traffic. The trimming operation reads only
a tail window and replaces each file atomically; it does not load a multi-GB
log into memory or retain it as a multi-GB backup.

Older diagnostic history is discarded. Copy any logs you need for an ongoing
investigation before upgrading or lowering retention. Persistent credentials,
inventory, zone ranges, device keys, and other state files are not subject to
log rotation. Do not delete the entire `runtime/` directory to clear logs: it
also contains persistent state.

Rotation coordinates writers within one server process. Run only one server
against a given data directory, and let the server manage these files rather
than running a second external rotation job on them.
