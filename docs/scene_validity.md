# Scene validity reports

The app sends `PUT /user/scene/validity` with a JSON array of reports:

```json
[{"sceneId":"42","extra":"{\"invalidActions\":[1,2,3]}"}]
```

This reports the client's invalid action IDs. The Android app's
`PartialScene.decode` reads `extra.invalidActions` and marks actions with those
IDs disabled in its decoded scene. The server stores the reported list in the
existing scene's `extra` and its `home_scenes` copy. Existing object values retain
their type; other values are stored as JSON strings. An explicit empty list
clears the report. Other `extra` fields, scene parameters, action definitions,
scene order, and scene enablement are preserved. Unknown scene IDs are
acknowledged without creating scenes.

This endpoint does not verify map or device capabilities, remove actions,
or execute scenes. Runtime scene execution continues to use the saved action
definitions. When protocol authentication is enabled, the existing `/user/`
Hawk authentication gate applies.

The success response matches an authenticated replay to Roborock's US cloud
API on 2026-10-10. The original app request bytes were sent to
`PUT https://api-us.roborock.com/user/scene/validity` with a fresh Hawk timestamp
and nonce. The captured request signature was verified before replaying it.
The server returned HTTP **200**, `Content-Type: application/json`, and:

```json
{"api":null,"result":null,"status":"ok","success":true}
```

This response is retained as `tests/fixtures/scene_validity_cloud_success.json`.
The previous generic fallback's `code`, `msg`, `data`, and route echo are absent.
Further probes returned these responses (all with `Content-Type: application/json`):

| Request | HTTP status | Body status | `api` / `result` |
| --- | --- | --- | --- |
| Non-array JSON `{}` or malformed JSON `{` | 400 | `BAD_REQUEST` | Both absent |
| Unknown scene ID | 200 | `ok` | Both null |
| String `invalidActions` on that unknown scene | 200 | `ok` | Both null |
| Missing authentication | 401 | `UNAUTHORIZED` | Both absent |

The observed HTTP 400 body is:

```json
{"code":"parameter.error","msg":"parameter error","status":"BAD_REQUEST","timestamp":"2026-10-10T17:19:01.641+00:00"}
```

The observed HTTP 401 body is:

```json
{"code":"auth.err","msg":"auth.err.invalid.token","status":"UNAUTHORIZED","timestamp":"2026-10-10T17:19:02.266+00:00"}
```

Error timestamps vary. Captured responses are retained in
`tests/fixtures/scene_validity_cloud_errors.json`. The local endpoint uses the
observed 400 envelope for malformed/non-array bodies and the observed 401
envelope when its existing Hawk gate rejects authentication. Other endpoints'
authentication responses are unchanged.

These probes establish acknowledgement/error shapes, not whether the cloud
persisted metadata or would accept the same malformed action value for an
existing scene. A success acknowledgement does not mean actions are valid.

Unsupported individual entries are logged and skipped while valid entries
are saved. Missing `invalidActions` leaves stored reports unchanged. Blank or
null stored `extra` is treated as empty metadata; malformed stored metadata is
preserved and that record is skipped. Diagnostics identify entry positions
without logging raw IDs or metadata. Reported action IDs are persisted as
provided; the server does not infer whether they are invalid.
Inventory updates use the shared transaction lock and atomic writer. If the
write fails, a warning is logged while the observed cloud success acknowledgement
is preserved; the client cannot rely on that acknowledgement to prove persistence.
