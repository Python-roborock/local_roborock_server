# Dashboard schedule editor

Open the standalone `/admin` dashboard, choose a vacuum at the top, and use its
**Schedules** section. MQTT recovery and activity remain scoped to that same vacuum.
The **Server** tab contains cloud import and connection settings.
The list includes imported native jobs, including jobs that a client's legacy
`get_timer` screen does not show. No cloud re-import or new pairing is needed.

The compact list sorts schedules by start time, earliest first, whether enabled
or disabled. Equal start times keep their existing order. Advanced expressions
with multiple daily times sort by their earliest clock time; unreadable times
appear last. Sorting uses each schedule's own timezone and clock time, rather
than the next occurrence's date.

Each row shows the start time, repeat pattern, map, selected room names (or
**Full**) and cleaning mode. Long room lists wrap onto additional lines. Names
are kept separately for each vacuum and map during the page session; a room
whose name has not been loaded appears as **Room 16**, for example. Opening the
list never loads another map on the robot. Select a row to open its editor. More settings
contains the timezone, next calculated run and native timer information.
Next-run times are displayed in the job's timezone. A next-run time describes
when the server will evaluate a job; it is not confirmation that the robot can
or will clean.

## Using the editor

- **Enable schedule** is the switch at the right of each row. It saves
  immediately, including when the editor is closed. It does not save
  an unfinished time or cleaning draft.
- Choose **Start time** and **Repeat**: Once, Every day, Weekdays, Weekends or
  Custom days. Once targets the next selected start time; the existing scheduler
  consumes it atomically and turns it off at its first trigger, even if the robot
  cannot start. Advanced expressions can be retained or edited as five-field cron.
- For native jobs, choose a map and **Full** or **Rooms** with named checkboxes.
  Cleaning mode offers **Vacuum**, **Vac & mop**, **Mop** and **Custom**. Custom
  uses the per-room cleaning preferences already stored on the vacuum (V1 codes
  106/204/302); this editor does not rewrite those per-room preferences. Other
  modes expose appropriate suction, water, route and pass controls. Use **Save schedule**
  to apply these changes together. The initial room read is automatic for the
  selected locally connected vacuum; **Refresh rooms** retries it explicitly.
- Room names join the vacuum's live segment-to-cloud-room mapping with imported
  home room names. Unknown names appear as **Room 16**, for example. Map names
  come from the vacuum. Full can target any reported saved map. To select rooms
  on another floor, choose it and click **Load map and rooms**. This explicitly
  loads that saved floor on the robot, then reads its rooms. The server refuses
  the load while the robot is busy or has an unfinished clean. Opening the
  editor and refreshing room metadata never switch maps.
- Save rechecks the loaded map and room catalog. Changes to the map, room IDs
  or names require refreshing and reviewing the selection. Other drafts remain.
- **More settings** shows cleaning order, mop preparation and mop
  template with readable labels. These model-specific values remain read-only;
  the editor does not guess their meaning. Existing custom cleaning values are
  retained and displayed, even when outside the common dropdown choices.
- Preserve the job ID, native timer link, unedited cleaning settings, unknown
  model fields, recurrence flag and occurrence claims.
- Keep unsaved edits when the dashboard refreshes. Reject stale updates after
  another client changes or deletes a job; the user can discard and reload.
- One-time and repeating jobs can both be edited. Cleaning edits are limited to native jobs
  whose complete payload reaches the vacuum; legacy/unknown formats display
  saved settings read-only. Creating/deleting jobs or robot-native timer entries
  is outside this editor.

**Enable schedule** updates both parts of a native schedule. It reads the
vacuum's `get_server_timer` list, matches the job's existing `param.params[0].name`,
and sends `upd_server_timer` with `[[timerName, "on" or "off"]]` when needed.
A fresh timer read must confirm the requested state before the job's `enabled`
flag is saved. Reapplying the same server flag also repairs an opposite native
state; an already matching timer needs no additional write. A lost write
acknowledgement can be confirmed by read-back without resending the write.

Missing, duplicate or invalid timer references and unconfirmed writes produce
an error without saving the job. The editor never guesses a timer ID or creates
a replacement timer. Dashboard edits, direct job API edits and background reconciliation for one
vacuum share a lock, and changes
from another client are checked again after the initial read and during the
inventory save. If the timer changes but the job save fails or conflicts, the
error reports that incomplete operation; it does not claim success or blindly
roll back a timer another client may have changed. Refresh and retry after
reviewing the current values.

Timer verification is shown under **More settings** after a successful toggle.
The server also reconciles Homebridge, LocalRock and OEM native toggles after
a fresh robot read, with periodic recovery for missed or direct LAN changes.
The normal dashboard polling shows those saved changes while preserving unsaved
editor drafts. Listing schedules itself stays read-only and reports
**Not checked in this view** rather than presenting an earlier check as current.
Jobs without a native `name` retain their server-only enablement, including new
jobs created by LocalRock with `method: server_scheduled_start` but no native
timer reference. The method name alone does not establish a native timer.
The scheduler still performs
its existing native timer preflight at execution time.

Homebridge pause/delay policy remains in Homebridge. This dashboard is an admin
adapter over the existing schedule store, not a second scheduling engine. The
editor uses the existing dashboard theme and does not replace the setup wizard.

## Hardware test sequence

1. Verify the active robot map and room selection before testing a clean. Check
   the imported job count, timezone, room IDs, map reference and timer reference.
2. Choose one existing recurring schedule. Record its original time and days.
   Set a test time several minutes ahead, including the current weekday, and
   confirm the saved read-back and next run. Avoid another schedule's due time.
3. Observe the actual robot, the native timer-read/start replies and cleaning
   history. A job-task acceptance or calculated next run is not proof of a clean.
   Normal dispatch can occur up to 60 seconds after the scheduled minute.
4. Toggle an existing native schedule off and on in the dashboard. Verify both
   the stored enabled flag and the live native timer, then reopen the schedule
   list in the Roborock app. Include a job previously enabled only on the server.
   Test a later occurrence while disabled; it should not start. Re-enable for
   a future time and verify exactly one intended clean.
5. Restore the original time/days and enablement. Validate
   room-specific settings, offline/restart behavior and Homebridge pause/delay
   separately as described in [schedule support](schedules.md).

## Admin API and validation

`GET /admin/api/schedules` returns an allowlisted view grouped by vacuum.
`PATCH /admin/api/schedules/{duid}/{job_id}` accepts `revision` and one or more of
`cron`, `timeZoneId`, `enabled`, `repeated`, `settings`. `settings` accepts only `map_index`,
`segments`, `fan_power`, `water_box_mode`, `mop_mode`, `repeat`.
`GET /admin/api/schedules/{duid}/rooms` reads map/room metadata through the local
MQTT client. `POST` to that endpoint with `map_index` explicitly loads that floor
after checking the live idle/docked state and the available map list. It verifies
the loaded map before returning room bindings; it never starts a clean.
A room/map edit also requires its `room_revision`; the server reads
the catalog again before accepting that edit. Native enablement also requires
a live robot read-back. Other edits work without querying the vacuum.
All endpoints require the existing admin session. Writes
require JSON and reject cross-origin browser requests. The revision is checked
again against the expected job under the schedule store's inventory lock.

No new runtime dependency or database format is introduced. Python tests cover
authentication, field privacy, preservation, stale/racing updates, validation,
native timer matching, read-back, lost acknowledgements, offline failures,
one-time transitions and partial persistence errors. Browser tests cover the native listing,
form persistence, conflict recovery, advanced expressions, mobile layout and
text escaping, header enablement, named rooms, cleaning choices and room changes
during editing, plus per-vacuum navigation, MQTT reset, and draft preservation.
Scheduled execution and recovery scenarios require hardware validation.

## Updating an existing Compose installation

After fetching, switching to the desired branch and fast-forwarding the local
checkout, run `bash scripts/update-existing-compose.sh` from the repository.
This builds the exact checked-out commit while the old container runs, then
recreates only its Compose service and waits for Docker health. The helper reads
project/service/config paths and the image tag from the existing container.
It reuses mounts and environment files, including certificates and credentials;
it does not make backups. A failed build does not restart the service.

Defaults are container `roborock-local-server` and runtime directory
`/opt/local_roborock_server`; override with `ROBOROCK_CONTAINER_NAME` and
`ROBOROCK_RUNTIME_DIR`. The runtime `.env` is used when Compose has no recorded
environment-file label. The helper stops on tracked checkout changes, missing
Compose metadata or a configured image that differs from the running image.
