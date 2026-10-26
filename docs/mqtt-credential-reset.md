# Clear a vacuum's MQTT credentials

In the standalone `/admin` dashboard, choose the affected vacuum at the top and
open its **MQTT recovery** section. Choose **Clear MQTT credentials** and confirm
the vacuum name.
Use this when a vacuum returned from the Roborock cloud is rejected with
`invalid_mqtt_credentials` because the server still has its previous login.

The action clears only that vacuum's saved MQTT username and password, immediately
disconnects its MQTT sessions, and clears its active onboarding session. It keeps
the inventory entry, local key, recovered public key, schedules, certificates, other
vacuums and saved app logins. It creates no backup and requires no server restart.
The action is disabled when no MQTT credentials are saved for that vacuum.

After clearing, open **Server** and enable **Allow new connections**, reset only the vacuum's Wi-Fi,
and use **Add vacuum** in LocalRock to pair it to this server again. Check live
status in LocalRock before testing a schedule. A vacuum that already works does
not need its credentials cleared after installing this update.

The authenticated endpoint is
`DELETE /admin/api/vacuums/{duid}/mqtt-credentials`. It accepts an exact DUID,
rejects cross-origin browser requests, and returns only the reset status.
Old queued messages, stale pairing attempts and credential-record merges cannot
restore the deleted login. Fresh onboarding can save a replacement login.
