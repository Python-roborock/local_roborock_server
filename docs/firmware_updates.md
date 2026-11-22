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
need the app's signature, like the rest of the protocol. The app sends the check and the progress read within milliseconds
of each other with the same signature, so these read-only GETs (the four check and status paths, nothing else) are not
refused for repeating a signature; the signature and its age are still verified, and every other route, the upgrade
POSTs included, refuses a repeated one.

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

1. The server checks the robot is in its inventory (404 otherwise), asks the cloud for the offered version and refuses
   if there is none. Only one install runs at a time for the whole server: a second press while one is starting or
   running answers `started: false` with the reason and leaves the running install and its status alone. The request
   then answers at once (`started`) and steps 2 to 5 run in the background, so a slow package download cannot time the request out. The
   status poll shows `START` until the robot takes over, and a failure in the steps below shows as `FAILED` with the reason.
2. It asks the cloud for the package address (`/user/devices/<duid>/fw?version=<version>`). The file name carries the
   package's MD5. The server downloads the package to `runtime/ota_packages/` and checks it against that MD5.
3. It checks the robot: docked (charging, fully charged, or asleep on the charger), idle, not cleaning, no error, at
   least 80% battery, and no other install running. Otherwise it answers with the reason and changes nothing.
4. It serves the package to the robot from a URL with a random token on this server and sends the robot's own OTA
   command (`miIO.ota`, `proc: "dnld install"`). The URL is not single use: it answers every request until it expires
   (30 minutes) or the install ends.
5. It follows the robot through download, install and reboot. The install counts as done (`IDLE` for the app) only when
   the robot fetched the whole package from this server, went offline and came back idle, and reports the target
   version afterwards (the server waits up to 3 minutes for that report). Otherwise the status is `FAILED` with the
   reason, so a brief disconnect is never reported as a success.

Package addresses are only accepted on Roborock's package hosts (`rrpkg-us.roborock.com`, `files.roborock.com`,
`app-files.roborock.com`, `cn-app.roborock.com`, `us-app.roborock.com` and the `cdn.*.fds.api.mi-img.com` hosts of
the app's regions) over https; any other address is refused. The package cache is shared by all robots, and a package
a robot is downloading or installing is never removed by another robot's clean-up.

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
an update: the same docked, idle, error-free and 80% battery checks, the same token URL and the same live status
for the app. The catalog is keyed by model, so what it remembers may have been learned from another robot. The
cloud is therefore asked for THIS robot's package of the version every time, and the install is refused when:

- the cloud gives this robot no package of that version,
- the checksum differs from the catalog's (another variant or region), or
- the package's hardware folder (the `a245` of `.../rriotpkg/a245/...`) differs from the one of the package the robot
  runs now, when both addresses have one.

Going to an older version also needs a confirmation in the request, so a stray call cannot downgrade a robot.

- LocalRock: `POST /ota/device/<duid>/upgrade/version` with a JSON body
  `{"version": "02.33.48", "confirm_downgrade": true}`. For a version older than the one the robot reports,
  `confirm_downgrade` must be `true` and `version` must be in the body and name the same version as the one
  installed; otherwise the answer is 409 with `needs_confirmation: true`. A newer catalog version needs no
  confirmation. A `?version=` in the query is still read, but is not a confirmation. The path-style update check
  (`GET /ota/firmware/<duid>/updatev2`) adds `downgradeAllowed`, `availableVersions` (each with `version`,
  `current`, `installable`, `firstSeen`, `size`, `released`) and `previousVersion` when the robot ran another version before its
  last install.
- Admin: `GET /admin/api/firmware/<duid>/versions` and `POST /admin/api/firmware/<duid>/install-version` with
  `{"version": "02.33.48", "confirm_downgrade": true}` (the previous version when `version` is empty, which is also
  a downgrade and also needs `confirm_downgrade`).

Both routes work for robots in this server's inventory only (404 otherwise). The server holds a single account, so a
signed-in app session may install on any robot of that account, and the cloud checks the stored login too.

`keep_previous_package = true` keeps the package files from before and after each install in `runtime/ota_packages/`
(two files of about 300 MB), so going back needs no download. The catalog is kept either way.

The downgrade was done with a development debug endpoint that sends the same OTA command; the catalog route above
has not run against a robot yet. On the Curv 2 Flow the older package downloaded through the server in 36 seconds, the robot installed it, was offline
for about 30 seconds while it restarted and was idle again about 4 minutes after the start. Maps, rooms and settings
were unchanged, and the official app then showed 02.33.48 with the update to 02.35.52 on offer.

### Adding versions the server has not seen

`POST /admin/api/firmware/<duid>/learn-versions` with `{"versions": ["02.15.20", ...]}` (at most 100) asks the cloud
for a package address for each version and adds the ones it confirms to the catalog. Nothing is installed. The release
date (`released`) is the package's `Last-Modified` header on the CDN, read with a headers-only request, and the size
comes from the same reply. Running it again for versions already in the catalog fills in a missing release date or
size. Candidate version numbers can be found by asking the cloud for them, which is a read-only call.

#### Scanning for versions

`POST /admin/api/firmware/<duid>/scan-versions` with an optional `{"max_empty_minors": 8}` (1 to 30) does the asking
for you in the background and returns the initial state at once. It starts from the version the robot reported (else
the version the cloud believes is current, else the newest catalog version of the model) and walks down, one minor
line (`major.minor`) at a time, asking the cloud for builds 99 down to 0 of each. The builds of the starting line at or
above the current one are skipped. Every version the cloud confirms is added to the catalog exactly as
`learn-versions` does it, with its release date and size. Versions already in the catalog with a checksum are not
asked for again and count as found.

The scan stops after `max_empty_minors` minor lines in a row with nothing found. A line with at least one version
(new or already known) resets the count. The walk continues across the major boundary (after minor 0 comes minor 99
of the previous major) and ends at 00.00.00. On the Qrevo Pro and the Curv 2 Flow the longest empty stretch inside
the real version history was 4 minor lines, so the default of 8 is a safe margin. A scan stops early with an error on
the first cloud failure and records the version it was on.

Requests are paced 0.2 seconds apart, so a full minor line takes about 20 seconds. The scan only reads from the cloud
(the same package-address question the app asks) and installs nothing. One scan runs at a time per server.

- `POST /admin/api/firmware/<duid>/scan-versions` starts a scan: 409 when one is running, 404 for an unknown device,
  400 for a bad parameter or when no current version is known.
- `GET /admin/api/firmware/scan` returns the state: `running`, `model`, `startedAt`, `finishedAt`, `checking` (the
  version being asked for), `minorsDone`, `emptyMinors`, `found`, `error`, `stoppedAt` and `stoppedReason`
  (`empty_minors`, `floor`, `error` or `cancelled`).
- `POST /admin/api/firmware/scan/cancel` stops the running scan after its current request.

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
did not finish. The answer is kept for 30 minutes and saved to `runtime/ota_live.json`, so it survives a restart of
the server. An install that was still running at the restart is then answered as `FAILED` ("The server restarted
during the install"), because the server no longer watches the robot and the app would read a missing status as
success. The robot may still finish the update on its own; check the version it reports. The path-form poll
(`/ota/firmware/<duid>/upgrade/status`) is forwarded to the cloud like the query form when no local install is shown.

During the install the robot's own status messages reach the app as usual: `P201` carries the status
(`DOWNLOADING`, `INSTALLING`, `IDLE`), `P200` the download progress from 0 to 100, and `P203` the new version when
the robot reconnects.

### The install record

Each install writes `runtime/ota_results/<time>_<duid>.json` with the parameters sent to the robot (the URL token
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

Both were admin-only debug endpoints on a development branch (`feat/ota-install-test` in the author's fork). The
admin endpoints are left out of the server because they let an admin drive a robot's firmware by hand; the download
and watch code they used ships as `ota_dry_run.py`, which the installer runs. The robot's OTA commands are
`get_ota_state` (`idle`, `downloading`, `installing`, `wait_install`, `failed`), `get_ota_progress` (0 to 100, and 0
while installing) and `miIO.ota` with `{"mode": "normal", "install": "0" or "1", "app_url": ..., "file_md5": ...,
"proc": "dnld" or "dnld install"}`.

## Limits

- The cloud login stored at sign-in is required.
- The server does not update robots by itself. Nothing installs unless someone presses Update or asks for another version.
- Only robots paired to this server can be installed to; the robot has to be online and reachable over MQTT.
- Voice packages are downloaded by the robot the same way and need the same header handling. They are not covered here.
