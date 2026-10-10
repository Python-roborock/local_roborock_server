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

The success response preserves the acknowledgement accepted by the app when
this endpoint used the fallback handler: the usual success envelope containing
`{"ok":true,"route":"/user/scene/validity"}` in `data` and `result`. This is
local compatibility behavior; an upstream cloud response has not been captured
to establish its exact response body.

Bodies that are not JSON arrays receive a local error envelope
(`success:false`, `code:400`) before any inventory write. Unsupported individual
entries are logged and skipped while valid entries are saved. Missing
`invalidActions` leaves stored reports unchanged. Blank or null stored `extra`
is treated as empty metadata; malformed stored metadata is preserved and that
record is skipped. Diagnostics identify entry positions without logging raw
IDs or metadata. The route uses HTTP 200 for both success and error
envelopes; `code:400` is the JSON error code, rather than a transport status.
Reported action IDs
are persisted as provided; the server does not infer whether they are invalid.
Inventory updates use the shared transaction lock and atomic writer. If the
write fails, a warning is logged while the established success acknowledgement
is preserved; the client cannot rely on that acknowledgement to prove persistence.
