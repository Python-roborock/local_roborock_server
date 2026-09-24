# Q7 sc05 03.01.74 no-dump owner trial

This procedure was completed on one physical Q7. It uses the owner's current
Roborock account and a firmware-wide profile; it does **not** need that Q7's
flash dump, factory HMAC secret, numeric DID, SSH, or UART. A second owner's
device has not yet been tested. The longer evidence record is in
[`q7_no_dump_migration.md`](q7_no_dump_migration.md).
The public restore and owner sender scripts completed a physical
round trip on that unit using a private owner-account export. The fresh
email-code login in the commands below still needs an independent trial.

Use a charging, cloud-online `roborock.vacuum.sc05` running exactly
`03.01.74`. The **server and owner scripts must both use the
`research/q7-no-dump-on-latest` branch**; a stable release may lack the Q7
migration-credentials endpoint and MQTT route fix. For a fresh source checkout:

```text
git clone --branch research/q7-no-dump-on-latest --single-branch https://github.com/Python-roborock/local_roborock_server.git
cd local_roborock_server
uv sync --extra dev --locked
```

Set up the server from that checkout using the Docker Compose method in
[`installation.md`](installation.md), including `docker compose up -d --build`.
If updating an existing server, retain its configuration and data while
rebuilding from this branch. The stable Home Assistant add-on is not a
substitute for deploying this branch's source. The server needs an HTTPS
origin and MQTT TLS origin that the vacuum can reach and trust. Import the
**same current Roborock account** in its admin dashboard using **Send code**
and **Fetch data**. Keep the vacuum on vendor cloud until the migration
command below.

The four-file `03.01.74` v2 re-entry profile is distributed privately because
it contains the firmware-wide OTA key. Its archive is 3,593 bytes, SHA-256
`f2d07bec35888b771afb3ebd671efa64946df1127272599e20319112f6f033b1`.
Verify that hash before extracting `manifest.json`, `ota-key.bin`, `editor.sh`,
and `return.sh` to a private directory. Do not substitute the `03.01.80`
profile. The builder checks the individual file hashes again.

From a checkout of this repository, run these steps. Replace the example
email, DUID, server origin, profile path, and LAN IP with the tester's values.
The first command requests one Roborock login code and exclusively creates
`../private/q7-owner-account.json`. That file contains account tokens: keep it
private, do not share it with the server or another tester, and delete it after
the trial. The command refuses to overwrite an existing export. Later commands
reuse it without requesting more login codes.

1. List the account's Q7 devices. Identify the intended Q7 and confirm
   firmware `03.01.74`, cloud online, and `local_key_length` 16:

   ```text
   uv run --no-sync python scripts/q7_owner_ota.py --email OWNER_EMAIL --save-account ../private/q7-owner-account.json --list
   ```

2. Reserve this Q7's local MQTT credentials and build both packages. This
   stage contacts only the local server and writes private files. The
   preparer records hashes of the imported cloud DUID and local key;
   the builder keeps those hashes in package metadata, outside the OTA bytes:

   ```text
   uv run --no-sync python scripts/q7_prepare_migration.py --server https://api-your-domain.example:555 --duid CURRENT_CLOUD_DUID --api-url https://api-your-domain.example:555 --mqtt-url ssl://api-your-domain.example:8881 --out ../private/q7-five-fields.json
   uv run --no-sync python scripts/q7_migration_ota_builder.py --config ../private/q7-five-fields.json --profile ../private/q7_ota_profile_sc05_030174_reentry --out ../private/q7-candidate
   uv run --no-sync python scripts/q7_stage_ota.py --artifact-dir ../private/q7-candidate
   uv run --no-sync python scripts/q7_stage_ota.py --artifact-dir ../private/q7-candidate --package restore
   ```

3. From the candidate directory, serve **both** encrypted files at a LAN IP
   reachable by the Q7. Keep this server running until the restore is
   finished. For example, in another terminal:

   ```text
   cd ../private/q7-candidate
   python -m http.server 8765 --bind LAN_IP
   ```

4. While the Q7 is charging and still cloud-online, run the owner sender
   without `--live` first. It checks the current account identity, firmware,
   charging state, idle OTA state, exact hosted bytes, and that the current
   cloud local key matches the server import used to build the package. If those pass,
   repeat with `--live` to send one migration OTA:

   ```text
   uv run --no-sync python scripts/q7_owner_ota.py --account ../private/q7-owner-account.json --duid CURRENT_CLOUD_DUID --artifact-dir ../private/q7-candidate --url http://LAN_IP:8765/q7-migration-v03.bin.gz.aes
   uv run --no-sync python scripts/q7_owner_ota.py --account ../private/q7-owner-account.json --duid CURRENT_CLOUD_DUID --artifact-dir ../private/q7-candidate --url http://LAN_IP:8765/q7-migration-v03.bin.gz.aes --live
   ```

5. Wait for the Q7 to reboot. Verify the local server shows its MQTT
   connection, then run the companion restore sender **without** `--live`.
   A successful dry run means an authenticated local owner command reached
   the Q7 and it reports charging status 4 and OTA `idle`:

   ```text
   uv run --no-sync python scripts/q7_local_restore.py --account ../private/q7-owner-account.json --duid CURRENT_CLOUD_DUID --config ../private/q7-five-fields.json --artifact-dir ../private/q7-candidate --url http://LAN_IP:8765/q7-restore-local-v03.bin.gz.aes
   ```

6. To return to Roborock cloud, repeat that exact restore command with
   `--live`. It restores the saved vendor IoT profile and reboots the Q7.
   Confirm the device appears online in the same Roborock account. Remove
   the temporary hosted copies after the trial; retain the private manifest
   and profile for review.

An OTA response of `result: 0` or `installed` alone does not establish a
successful migration. Verify the post-reboot MQTT connection and owner RPC.
The rollback copy is created from the Q7's current IoT profile, so old
identity values from the original research dump are not used. A failed
first migration should be investigated before sending another package.
If the Q7 was re-paired after the server imported it, refresh the same account
in the server, prepare a new manifest, and rebuild both packages. Older
artifacts lacking the key fingerprint now fail the owner preflight.
