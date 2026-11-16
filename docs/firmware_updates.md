# Firmware updates

A robot that is paired to this server never talks to Roborock's cloud, so it never learns about a new firmware
and the official app cannot install one on its own. The server closes that gap in two steps. It reads the update
information from Roborock with the login stored at sign-in, and, when you opt in, it installs the update itself
through the app's own Update button.

!!! note
    Everything here needs the cloud login the server stored when you signed in (one email-code sign-in). Without it
    the update check is unavailable and the Update button is refused.

## Checking for an update

The official app asks the server `GET /ota/firmware/<duid>/updatev2` (or `/ota/firmware/updatev2?duids=...`). The
server asks Roborock's cloud and returns its answer, so the app shows the real version and release notes. Both calls
need the app's signature, like the rest of the protocol, and are never refused as replayed.

`GET /admin/api/cloud/firmware` lists the update status of every robot on the account in one call, for scripts.

### The version a robot reports

Roborock's cloud learns a robot's version from the robot's own connection to it. A robot paired here never makes
one, so after a local update the cloud would keep saying the old version and offering the same update. The robot
reports its firmware version itself (protocol 203) each time it connects. The server keeps that version and uses it
in place of the cloud's:

- `currentVersion` in the update check is the version the robot reports.
- `updatable` is `false` when that version is the offered one or newer. Versions are compared as numbers.
- The `fv` field the apps read from the device list and device detail is the reported version.
- The install checks compare against the reported version too, so a package is only accepted for the version the
  robot really runs or the version on offer.

A robot that has not reported yet is left as the cloud describes it.

## Installing an update

Installing is off by default. Switch it on with either:

```toml
[ota]
enable_install = true
```

or the environment variable `ROBOROCK_SERVER_OTA_ENABLE_INSTALL=true`. The variable wins when it is set, so it also
works for a `config.toml` that already exists.

With it on, pressing Update in the official app (`POST /ota/device/<duid>/upgrade`) does the following:

1. The server asks the cloud for the offered version and refuses if there is none. The request then answers at once
   (`started`) and steps 2 to 5 run in the background, so a slow package download cannot time the request out. The
   status poll shows `START` until the robot takes over, and a failure in the steps below shows as `FAILED` with the reason.
2. It asks the cloud for the package address (`/user/devices/<duid>/fw?version=<version>`). The file name carries the
   package's MD5. The server downloads the package to `runtime/ota_packages/` and checks it against that MD5.
3. It checks the robot: docked (charging, fully charged, or asleep on the charger), idle, not cleaning, no error, at
   least 80% battery, and no other install running. Otherwise it answers with the reason and changes nothing.
4. It serves the package to the robot from a one-time URL on this server and sends the robot's own OTA command
   (`miIO.ota`, `proc: "dnld install"`).
5. It follows the robot through download, install and reboot, and returns once the robot is idle again.

The `latest-stable` upgrade call is still refused, and the Update button only installs the version the cloud offers.
The package cache is cleared after a successful install and holds a single file otherwise, unless
`keep_previous_package` is on (see below).

## The firmware catalog

Roborock's cloud has no route that lists firmware versions. It only gives a package address for a version asked for
by name (`/user/devices/<duid>/fw?version=<version>`), and answers `{"url": null}` for versions that were never
released. The server therefore keeps its own catalog in `runtime/firmware_catalog.json`, keyed by robot model, and
never removes an entry. A version is added when the server learns of a real package:

- the version a robot reports just before an install (`robot_reported`),
- the package being installed (`install`),
- a version the cloud offers in an update check the server answers or the admin listing (`cloud_offer`).

Each entry has the model, version, package URL, MD5, size when known, the time it was first seen and the sources it
was learned from. An entry is never given a different MD5. The catalog also keeps, per robot, the version it ran
before its last install. `GET /admin/api/firmware/catalog` lists it, `?model=roborock.vacuum.a245` for one model.

## Installing another version

!!! warning
    Installing an older version was proven on one robot only, a Qrevo Curv 2 Flow (a245), going from 02.35.52 back
    to 02.33.48. It is untested on every other model.

This is off unless both are set:

```toml
[ota]
enable_install = true
allow_downgrade = true
```

With both on, any catalog version of the robot's model other than the one it reports can be installed, older ones
included. Without a version the one the robot ran before its last install is used. The install goes the same way as
an update: the same docked, idle, error-free and 80% battery checks, the same one-time URL and the same live status
for the app. The package is fetched from the address in the catalog and checked against its MD5; if that address no
longer works, a new one is asked for and accepted only with the same MD5.

- LocalRock: `POST /ota/device/<duid>/upgrade/version?version=<version>`. The path-style update check
  (`GET /ota/firmware/<duid>/updatev2`) adds `downgradeAllowed`, `availableVersions` (each with `version`,
  `current`, `installable`, `firstSeen`, `size`) and `previousVersion` when the robot ran another version before its
  last install.
- Admin: `GET /admin/api/firmware/<duid>/versions` and `POST /admin/api/firmware/<duid>/install-version` with
  `{"version": "02.33.48"}` (or no body for the previous version).

`keep_previous_package = true` keeps the package files from before and after each install in `runtime/ota_packages/`
(two files of about 300 MB), so going back needs no download. The catalog is kept either way.

The downgrade was done with a development debug endpoint that sends the same OTA command; the catalog route above
has not run against a robot yet. On the Curv 2 Flow the older package downloaded through the server in 36 seconds, the robot installed it, was offline
for about 30 seconds while it restarted and was idle again about 4 minutes after the start. Maps, rooms and settings
were unchanged, and the official app then showed 02.33.48 with the update to 02.35.52 on offer.

### What the robot needs

The robot's downloader only accepts HTTP responses whose header names are capitalised (`Content-Length`), as its
CDN sends them. The server serves packages that way, with range requests and from disk. Anything else a robot
downloads from this server has to be served the same way.

### What the app sees

The cloud knows nothing about an install that runs here, and it answers the app's status poll
(`GET /ota/firmware/<duid>/upgrade/status`, or `/ota/firmware/upgrade/status?duids=...`) with an error. The official
app treats an error from that poll as a failed update, and polls it whenever the robot's own status messages go
quiet for 90 seconds, which the reboot does. While an install runs, the server therefore answers that poll itself
with the robot's real state: `DOWNLOADING`, `INSTALLING` or `WAIT_INSTALL` with the progress, `IDLE` only once the
robot has rebooted and is idle again (the app reads `IDLE` as success), and `FAILED` with the reason when the install
did not finish. The answer is kept for 30 minutes.

During the install the robot's own status messages reach the app as usual: `P201` carries the status
(`DOWNLOADING`, `INSTALLING`, `IDLE`), `P200` the download progress from 0 to 100, and `P203` the new version when
the robot reconnects.

### The install record

Each install writes `runtime/ota_results/<time>_<duid>.json` with the parameters sent to the robot (the one-time token
is hidden), the robot's state timeline, whether it went offline and came back, and the version it reports afterwards.
It is the place to look when an install did not behave.

### An example

A Qrevo Curv 2 Flow (a245) went from 02.33.48 to 02.35.52 this way. Download of the 283 MB package took 1 minute 24
seconds, the install 2 minutes 15 seconds, the robot was offline for 52 seconds while it restarted, and it reported
02.35.52 on reconnecting. The official app showed the update as successful about 4 minutes 36 seconds after the
button was pressed.

## How this was investigated

The behaviour above was found by asking a robot, step by step, what its OTA command accepts. Two tools were used and are
not part of the server:

- A dry run of the robot's local OTA command: an admin call that asks a docked, idle robot to download a file from
  this server without installing it, first a random file and then a real package, and reports how the robot reacts.
  It showed the header capitalisation requirement and the robot's state names.
- An explorer for candidate cloud OTA paths, read with the stored login, which located the package address route.

Both were admin-only debug endpoints on a development branch (`feat/ota-install-test` in the author's fork). They are
left out of the server because they let an admin drive a robot's firmware by hand. The robot's OTA commands are
`get_ota_state` (`idle`, `downloading`, `installing`, `wait_install`, `failed`), `get_ota_progress` (0 to 100, and 0
while installing) and `miIO.ota` with `{"mode": "normal", "install": "0" or "1", "app_url": ..., "file_md5": ...,
"proc": "dnld" or "dnld install"}`.

## Limits

- The cloud login stored at sign-in is required.
- The server does not update robots by itself. Nothing installs unless someone presses Update or asks for another version.
- Only robots paired to this server can be installed to; the robot has to be online and reachable over MQTT.
- Voice packages are downloaded by the robot the same way and need the same header handling. They are not covered here.
