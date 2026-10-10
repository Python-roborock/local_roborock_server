# Firmware device information uploads

`POST /devices/{did}/info` uploads the vacuum's serial number, model and feature
flags. This is a firmware endpoint; it is separate from the app's
`GET /user/devices/{duid}` endpoint.

The server now selects the `device_info` handler instead of `catchall`. The
previous generic HTTP 200 already acknowledged the upload on the firmware
inspected below. There is no evidence that this fallback blocked onboarding or
camera operation. The missing behavior was retaining the uploaded metadata.

## Handling and authentication

The verified firmware signs this exact ASCII form, in this order, using its
device RSA private key with PKCS#1 v1.5 and SHA-256:

```text
did=<numeric DID>&featureset=<decimal flags>&newfeatureset=<hex flags>&pid=<model>&sn=<serial>
```

It appends a URL-escaped base64 `signature`. The server checks the signature
against the device public key recovered during onboarding and checks that the
body DID matches the URL DID. Only unambiguous reports with one value per field
are persisted. Query parameters do not supply or override metadata.

This handler accepts exactly these six fields, nonempty metadata values of
1–128 ASCII letters, digits, dots, underscores or hyphens, decimal `featureset`,
and hexadecimal `newfeatureset`. These conservative limits match the observed
reports; authentic firmware variants outside them are acknowledged and logged as
unsupported without writing. They require further evidence before expanding the
accepted contract.

For an existing inventory device matched by DID, or by its runtime DID-to-DUID
link, verified reports update `sn`, `featureSet`, and `newFeatureSet` in
`web_api_inventory.json`. Hex feature flags stay as strings so leading zeroes
survive. The signature is not copied into inventory. Names, keys, product IDs and device
identities are preserved. Firmware `pid` is a model name in the inspected build;
it must not be assigned to the app's opaque `productId`.

Unknown devices are not created by this endpoint. Missing keys, unsupported
signatures, duplicate fields, malformed values and invalid signatures cause no
inventory changes. Their uploads still receive HTTP 200, preserving the old
acknowledgement behavior. Responses retain the previous fallback body, including
`data` and `result` containing `{"ok": true, "route": "/devices/{did}/info"}`.
The inspected G10S firmware ignores that body; preserving it avoids changing the
response contract for other models whose callback has not been audited.

There is no nonce or timestamp in this form. A valid recorded report can be
replayed; signature verification establishes its origin, not its freshness.
No replayed report can change identity or credentials through this handler.

The server logs the DID, an outcome (`stored`, `unchanged`, `unmatched`,
`malformed_fields`, `did_mismatch`, `unsupported_values`, `missing_key`, or
`invalid_signature`, or `write_failed`) and the number of records updated for each upload. These
diagnostics omit serial numbers, signatures and credentials.

Devices already acknowledged by the old fallback may not upload again until
their metadata changes. The inspected firmware saves a digest on success; whether
that digest survives a reboot has not been characterized. For devices with a
cloud snapshot, existing app response behavior still prefers snapshot serial and
feature fields over this inventory metadata.

## Evidence and limits

The local G10S `rriot_rr` ELF (SHA-256
`27cf67a4a03920e31647e677d8296bcf4f915801e1800d6db9527ccfe69ae752`)
provides these AArch64 virtual addresses:

| Address | Observed behavior |
| --- | --- |
| `0x16810–0x16834` | Formats the five metadata fields in the order above. |
| `0x16850–0x16894` | Calls signer `0x6010`, URL-escapes signature, appends it. |
| `0x5970–0x5a24` | SHA256 followed by RSA_sign with NID 672 (`sha256`). |
| `0x1696c–0x169a8` | Formats `/devices/%s/info`, starts POST with callback `0x16f60`. |
| `0x4bf8–0x4c60` | HTTP worker accepts status 200 or 201, returns success. |
| `0x4f44–0x4f54` | Passes worker status and response buffer to callback. |
| `0x16fec–0x1706c` | Callback checks worker status only, marks upload done and writes the metadata digest; does not parse the response. |

The S7 `rriot_rr` ELF (SHA-256
`824b3128856a3017085b391d690f210420be4e8023365a6e22597bc0f460ba3d`)
also contains the same five-field form and endpoint at file offsets `0x28730`
and `0x288c0`. Its callback has not been audited here.

All three persisted Qrevo MaxV uploads (October 1 and October 9, 2026 local time)
were independently verified with its recovered RSA public key against this
exact form and PKCS#1 v1.5/SHA-256 contract. No raw signatures, serial numbers or
keys are included here. This confirms the Qrevo's request authentication; its
response callback has not been disassembled. The handler preserves
acknowledgement for other contracts and refuses metadata writes when verification
fails. A cloud response capture is unnecessary
for the inspected G10S callback, but would be needed to describe the cloud's exact
response body or another model's response parser.
