# Experimental schedule support

This implementation provides schedule storage, job APIs, time calculation, and dispatch. It does
not establish complete Roborock cloud compatibility on every model.

This work integrates [upstream PR #179 by virtitnerd](https://github.com/Python-roborock/local_roborock_server/pull/179)
at `59bf2e6de0a0f62b371ac58a41fb44bec5ddc603`, with additional changes based on
cloud captures from `roborock.vacuum.a15` and `roborock.vacuum.a27`. Those captures
verify protocol shapes and client behavior; a tester subsequently confirmed a scheduled start on an S7 (a15, firmware
02.16.12) using this local server, with LocalRock and the OEM Roborock app used
for schedule control. This confirms one scheduled-start scenario, not all
cleaning settings, failure cases, or other models. Raw captures and credentials are excluded.

## Responsibilities and compatibility

Homebridge retains schedule switches, pause/delay decisions, original-time
restoration, daily reset, and recovery. The server provides the underlying APIs.

| Operation | Behavior in this branch |
| --- | --- |
| GET `/user/devices/{duid}/jobs` | Stored jobs with calculated UTC `nextFireTime` for enabled, valid jobs |
| POST to the collection | Persist a new job with a unique numeric ID |
| PUT/PATCH `/user/devices/{duid}/jobs/{id}` | Update supplied fields; preserve omitted fields and unknown model fields |
| DELETE an item | Remove the stored job and its occurrence record |
| `get/set/upd/del_server_timer` | Forward unchanged to the robot, which owns these timer entries |
| Legacy `get/set/upd/del_timer` | Local compatibility view for jobs without a native timer name |
| Native scheduled execution | Verify the robot timer is on, then send `server_scheduled_start` with the complete settings entry |

A job's numeric `id` is different from the robot timer's string ID in
`param.params[0].name`. Cloud job `enabled: true` can coexist with a robot timer
that is off. The server checks both rather than assuming they are equivalent.
Native jobs are not duplicated in the legacy `get_timer` view; both captured
robots returned an empty legacy list while holding native timers.

Time updates accept the existing-job JSON PUT used by Homebridge, without
requiring `id` or `nextFireTime` in the body. If `param` is supplied, it replaces
the previous object exactly, so app removal of an optional field is preserved.
Settings such as `clean_order_mode`, `mop_template_id`, `map_index`, room-list
strings, and unknown future options survive storage and native dispatch.
Invalid cron/timezone/body values are rejected. A persistence failure does not
receive a successful write acknowledgement.

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

In the observed cloud offline experiment, a weekday 14:09 occurrence did not run
while the robot's internet access was blocked. The cloud advanced `nextFireTime`
to the following Monday, and no catch-up run was observed through 14:17 after
access was restored. This supports skipping that missed occurrence. It does not
prove all outage durations, server-restart semantics, or the exact cloud start
packet. Homebridge cannot observe another MQTT client's private command stream.

## Provisional behavior and remaining validation

- Native dispatch is based on the captured job's method/settings and upstream
  hardware reports. The exact cloud-to-robot start packet was not captured.
  Validate room selection, map, cleaning order, mop mode, and history on a15/a27.
- DST policy currently skips nonexistent spring-forward times and runs only the
  first occurrence of an ambiguous fall-back time. Automated tests cover this
  policy; matching cloud behavior has not been established.
- One-time jobs are consumed when evaluated as due, including when dispatch
  subsequently fails. Expired imported one-time jobs and extended downtime need
  further investigation: a five-field cron has no year and can match again in a
  later year. Begin hardware testing with recurring jobs.
- Test create/edit/delete through the actual app, disabled/missing native timers,
  robot reboot, server/container restart, offline/reconnect, and busy/DND refusal.
- B01 and other unobserved scheduling protocols are not established by these
  captures. Scene/routine scheduling is separate from these device job routes.
- A startup log saying a job task was accepted is not proof of a clean; check
  subsequent timer-read/start replies, robot status, and cleaning history.

## First hardware test

Build the selected Git commit into a versioned Docker image. The CI runs the full Python suite on 3.11 and
3.13 and builds an amd64 Docker image without publishing or deploying it.

1. Prepare the runtime configuration, DNS/certificate path, data backup, and
   explicit cloud-to-local onboarding procedure. Start with one robot.
2. Import current jobs and verify every numeric job ID maps to the expected
   native timer name. Confirm local jobs reads and robot timer reads separately.
3. Disable a recurring test schedule through Homebridge. Confirm the robot timer
   reads off and no clean begins at the scheduled time, even if job `enabled`
   remains true. Re-enable it and confirm a later occurrence runs exactly once.
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
