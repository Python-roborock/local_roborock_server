# Experimental schedule support

This implementation provides schedule storage, job APIs, time calculation, and dispatch. It does
not establish complete Roborock cloud compatibility on every model.

## Responsibilities and compatibility

Homebridge retains schedule switches, pause/delay decisions, original-time
restoration, daily reset, and recovery. The server provides the underlying APIs.

| Operation | Behavior in this branch |
| --- | --- |
| GET `/user/devices/{duid}/jobs` | Stored jobs with calculated UTC `nextFireTime` for enabled, valid jobs |
| POST to the collection | Persist a new job with a unique numeric ID |
| PUT/PATCH `/user/devices/{duid}/jobs/{id}` | Verify native enablement when supplied, then save; preserve omitted fields and unknown model fields |
| DELETE an item | Remove the stored job and its occurrence record |
| `get/set/upd/del_server_timer` | Forward unchanged to the robot, which owns these timer entries |
| Legacy `get/set/upd/del_timer` | Local compatibility view for jobs without a native timer name |
| Native scheduled execution | Verify the robot timer is on, then send `server_scheduled_start` with the complete settings entry |

A job's numeric `id` is different from the robot timer's string ID in
`param.params[0].name`. Imported or previously unsynchronized jobs can disagree with the native timer.
The server now reconciles enablement and still checks both before execution.
Native jobs are not duplicated in the legacy `get_timer` view; clients must read the jobs API to list native-linked jobs.

Time updates accept the existing-job JSON PUT used by Homebridge, without
requiring `id` or `nextFireTime` in the body. If `param` is supplied, it replaces
the previous object exactly, so app removal of an optional field is preserved.
Settings such as `clean_order_mode`, `mop_template_id`, `map_index`, room-list
strings, and unknown future options survive storage and native dispatch.
Invalid cron/timezone/body values are rejected. A persistence failure does not
receive a successful write acknowledgement.

## Enablement synchronization across clients

Native schedule on/off changes are synchronized by the server, independent of
whether Homebridge, LocalRock, the OEM app, or the dashboard made the change.
A forwarded `upd/set/del_server_timer` request prompts a fresh native timer read.
The request and the robot's reply remain unchanged; sending a request or receiving
an `ok` is not used as proof of the final state. No client-specific HTTP write is
required after a native toggle.

A background read also runs at startup and approximately every 30 seconds to
recover missed traffic, reconnects, and changes made directly over the LAN.
Successful reconciliation changes only `enabled` on existing, uniquely matched
jobs. It preserves IDs, cron/timezone, settings, unknown fields, and occurrence
claims. The dashboard's normal refresh shows the updated saved state. Other
clients see it on their next normal read; this is eventual synchronization,
not an unsolicited push into every app.

An HTTP job PUT/PATCH that supplies `enabled` verifies the matching native timer
before saving. A timer already in the requested state needs no extra write,
so the OEM app's native-update-then-PUT sequence remains compatible. A lost
acknowledgement is checked with one read-back, without repeating the write.
Time-only requests that omit `enabled` remain store-only edits.

Background reads and server edits share a per-vacuum lock. A native write that
overlaps a background read invalidates that read; edits/deletions during a read
are checked again before persistence. Missing, malformed, ambiguous or unreachable
timers leave the last saved state intact and never create replacement timers.
A normally polled, still-on timer does not re-enable a consumed one-time job.
An explicit native enable request can do so only after a fresh matching read;
that intent expires after two minutes. Unlinked server-only jobs retain their
existing behavior. Native timer time/settings edits are not imported into job
cron/settings by this enablement reconciliation.

## Execution and missed runs

The scheduler evaluates five-field cron expressions in each job's IANA timezone.
It checks approximately every 20 seconds, allowing less than 60 seconds of normal
dispatch latency. Startup establishes a fresh baseline; suspended/late ticks do
not drain historical jobs. Recurring jobs remain enabled for future occurrences.

Before dispatch, the server saves an occurrence claim in the persistent inventory
under `schedule_occurrences`. A repeated tick, restart, or backward clock change
cannot dispatch the same claimed occurrence again. If that write fails, no start
is attempted. This is an at-most-once policy: a crash after claiming but before
sending can miss a clean. Run only one server process against an inventory; the
inventory lock does not coordinate multiple containers or external file editors.
Cloud re-import replaces schedule definitions, so back up local edits before
refreshing. Occurrence claims are retained across that refresh.

A fresh native timer read must find exactly one matching `on` entry. Off, missing,
ambiguous, malformed, or unreachable timer state prevents a start. After that
network wait, dispatch rechecks the stored job and its deadline, so a concurrent
time edit or deletion cancels stale work. The remaining read-to-start race is
resolved by the robot's native command; real firmware behavior needs testing.

A refused or timed-out native scheduled start is never retried as `app_start` or
`app_segment_clean`, and action-locked native starts are not automatically retried.
A robot refusal can mean a disabled/deleted timer; substituting an ordinary clean
could bypass that state. Legacy jobs retain upstream's separate cleaning-command
path; they do not establish native timer support on other firmware.

## Provisional behavior and remaining validation

- Native dispatch preserves the job's method and complete settings entry.
  Validate room selection, map, cleaning order, mop mode and history on each model.
- DST policy currently skips nonexistent spring-forward times and runs only the
  first occurrence of an ambiguous fall-back time. Automated tests cover this
  policy; matching cloud behavior has not been established.
- One-time jobs are consumed when evaluated as due, including when dispatch
  subsequently fails. Expired imported one-time jobs and extended downtime need
  further investigation: a five-field cron has no year and can match again in a
  later year. Begin hardware testing with recurring jobs.
- Test create/edit/delete through the actual app, disabled/missing native timers,
  robot reboot, server/container restart, offline/reconnect, and busy/DND refusal.
- B01 and other scheduling protocols require separate model validation.
  Scene/routine scheduling is separate from these device job routes.
- A startup log saying a job task was accepted is not proof of a clean; check
  subsequent timer-read/start replies, robot status, and cleaning history.

## First hardware test

Build the selected Git commit into a versioned Docker image. Run `uv sync --locked --extra dev`
and `uv run pytest -q` to execute the Python test suite before deployment.

1. Prepare the runtime configuration, DNS/certificate path, data backup, and
   explicit cloud-to-local onboarding procedure. Start with one robot.
2. Import current jobs and verify every numeric job ID maps to the expected
   native timer name. Confirm local jobs reads and robot timer reads separately.
3. Disable a recurring test schedule through Homebridge. Confirm the robot timer
   reads off and the saved job becomes disabled without a separate HTTP update.
   Re-enable it and confirm both states agree and a later occurrence runs once.
4. Test a room schedule and a whole-home schedule. Compare settings, rooms, map,
   and history against the app. A refusal should stop dispatch, with no fallback
   ordinary clean.
5. Exercise Homebridge delay and cancellation/restoration. Confirm only intended
   times change, settings survive, and each resulting occurrence runs once.
6. Disconnect the robot across a due time and reconnect. Verify no replay, then
   a future occurrence. Repeat with a server restart across the due time and
   after a run. Test pending edits while a timer read is delayed.

Record image tag/commit, model and firmware, timezone, expected time, actual time,
timer state, settings, and relevant sanitized replies for each result. Returning
to the cloud requires the appropriate onboarding transition; stopping Docker is
not an automatic cloud/local switch.
