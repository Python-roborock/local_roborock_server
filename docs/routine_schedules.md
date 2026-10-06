# Local routine schedules

The standalone server can run a saved routine at a weekly time through its admin
API. For example, an existing kitchen vacuum-and-mop routine can run at 08:30 on
weekdays without Home Assistant or an open phone app. The server and its local
MQTT broker must be running, and the vacuum must already be onboarded locally.

A **routine** (called a **scene** in the API) contains the cleaning steps. A
**local routine schedule** chooses when the server starts that routine. These
schedules are separate from imported Roborock cloud jobs and robot-native timers
such as `set_timer`. This feature does not implement those timers, the official
app's scheduling screen, or a routine editor. It requires an existing saved
routine; routine creation/import continues to use the existing app/API workflow.

## Admin API

Use the standalone server's HTTPS address and your existing admin credentials.
The following shell examples save the login cookie in `cookies.txt`. Replace the
host and scene ID with your own values. Keep the cookie file private and remove
it when finished.

```sh
curl --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --data '{"password":"YOUR_ADMIN_PASSWORD"}' \
  https://api-roborock.example.com/admin/api/login

curl --cookie cookies.txt \
  https://api-roborock.example.com/admin/api/routines
```

Choose an `id` from the returned `routines` array. Create a schedule using all
five fields below. `weekdays` uses Monday = 0 through Sunday = 6; `time` is local
24-hour `HH:MM`. Specify an IANA time zone rather than a UTC offset so daylight
saving rules can be applied. `enabled` must be explicitly set to `true` or `false`.

```sh
curl --cookie cookies.txt \
  --header 'Content-Type: application/json' \
  --data '{"scene_id":7,"time":"08:30","timezone":"Australia/Brisbane","weekdays":[0,1,2,3,4],"enabled":true}' \
  https://api-roborock.example.com/admin/api/routine-schedules
```

The response contains the new schedule's `id`. Use it for updates and deletion:

| Method | Path | Result |
| --- | --- | --- |
| GET | `/admin/api/routines` | Saved routines and their scene IDs |
| GET | `/admin/api/routine-schedules` | Definitions, IDs, last local date attempted, and dispatch results |
| POST | `/admin/api/routine-schedules` | Create a schedule; returns HTTP 201 |
| PUT | `/admin/api/routine-schedules/{id}` | Replace all five definition fields |
| DELETE | `/admin/api/routine-schedules/{id}` | Delete a schedule |

To disable a schedule, PUT its complete definition with `enabled: false`.
Deleting or disabling a schedule does not stop a cleaning run already in progress.
All endpoints require an admin session. They are unavailable in protocol-only
mode (`--core-only`); that mode still executes previously saved schedules.
There are no scheduling controls in the dashboard yet.

## Execution and persistence

- The scheduler checks every 10 seconds and dispatches during the matching local
  minute. It never catches up a missed minute or retries a failed occurrence.
  Enabling or creating a schedule during its matching minute can run it immediately.
- Definitions and dispatch claims are stored in
  `state/routine_schedules.sqlite3` under `storage.data_dir`. Preserve this file
  across container restarts. It is independent of cloud inventory imports.
- Each schedule can dispatch at most once per local date. A committed claim
  precedes dispatch, so a crash in between can lose a run. Restarts, clock
  rollback, and same-day edits or disable/enable cycles do not replay claimed runs.
  Deleting and recreating a schedule creates a new identity and a fresh claim.
- A skipped daylight-saving time does not run. A repeated local time runs at most
  once, at the first matching occurrence observed by the running server.
- An active local routine on the same vacuum is left running, even if it is the
  same scene. Before sending cleaning commands, the scheduled runner queries live
  status and skips a vacuum that is not idle/ready or has unfinished cleaning.
  Unreachable vacuums fail without queuing a later cleaning run.
- Changing a routine's steps or target vacuum requires re-saving its schedule.
  Until then its occurrences are marked `scene_changed`. Renaming a routine does
  not require this. Missing, invalid, and disabled routines are not dispatched.
- `last_result` describes dispatch, not cleaning completion. `started` means the
  asynchronous runner was launched; consult server logs for the subsequent live
  status check, skipped runs, command errors, and completion. `claimed` can remain
  after an interrupted dispatch, and does not prove the vacuum started.
- Shutdown closes scheduled runner tasks. It does not send a stop command to the
  vacuum or resume an interrupted multi-step routine after restart.

Use one server instance per installation, as with the existing routine runner.
The scheduler and MQTT behavior have automated tests; this feature has not been
verified on physical hardware, including the S7 MaxV.
