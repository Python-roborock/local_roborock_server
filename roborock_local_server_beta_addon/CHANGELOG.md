# Changelog

## 1.1.0-rc2

- Parse multipart NC form fields so the server can identify the vacuum, preserve its provisioning values, encrypt the reply with its recovered public key, and record the NC onboarding step.
- Keep existing Beta settings, samples, and recovered keys when updating. Retry pairing after the update; clearing state or repeating key recovery is not required for this fix.
- Full V2 onboarding and MQTT connectivity still require hardware validation. The V2 unsupported onboarding status remains in place, and the stable add-on stays on 1.0.2.

## 1.1.0-rc1

- Added an opt-in Beta add-on with its own configuration and persistent data. The existing stable add-on stays on 1.0.2.
- Added experimental RSA-4096 / SHA-384 public-key recovery for V2 `GET /region` onboarding requests observed on Saros a279.
- Preserve request version metadata, resume pending recovery after a server restart, and verify all captured samples before accepting a recovered V2 public key.
- Full V2 onboarding and MQTT connectivity still require hardware validation. The V2 unsupported onboarding status remains in place.
