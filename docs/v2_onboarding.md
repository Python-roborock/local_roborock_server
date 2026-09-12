# Experimental V2 public-key recovery

This branch adds automatic RSA public-key recovery for the V2 `GET /region`
request format observed on Saros model `roborock.vacuum.a279`. It does not yet
establish complete V2 onboarding or MQTT connectivity.

## Verified request format

The captured requests carry `v: v2`, nonce `n`, timestamp `t`, and signature `s`
headers. The Base64-decoded signature is 512 bytes. The signed message is:

```text
exact_query_without_&signature_suffix + ":" + header_n + ":" + header_t
```

Signatures use RSA-4096, public exponent 65537, and PKCS#1 v1.5 with SHA-384.
Query order, escaping, percent-escape case, and literal plus signs must remain
unchanged. A parsed query dictionary is not a substitute for the wire query.

Three saved requests from one owner's Saros recovered its public modulus.
All 14 available signatures verified against that modulus, including the 11
not used for recovery. Replaying those requests through the persistent cache
also recovered the same key after a cache reload. These were offline checks;
no vacuum or vendor service was contacted. The private captures are not included
in this branch.

This recovers the public key needed to encrypt server replies. It does not
recover the device's private key or a symmetric secret, and the demonstrated
method does not require a firmware dump.

## Server behavior

- The server records the request version with each header-signature sample.
- Complete V2 `GET /region` or `GET /.roborock.com/region` samples select SHA-384
  recovery. The cache starts recovery after at least two distinct samples.
- The worker uses up to three samples for modulus recovery, then verifies every
  sample in its snapshot before accepting the key.
- Pending recovery resumes when the persisted cache is loaded again.
- Legacy query-signature recovery keeps SHA-256 as its default.
- Unversioned header samples, POST requests, `/b/region`, and HMAC-sized tags
  are excluded from this V2 contract.

Old cache entries without version metadata cannot be automatically identified
as V2. New pairing attempts can supply versioned samples. Recovery may require
another pairing cycle once the public key is ready.

## Remaining hardware validation

The existing V2 unsupported onboarding status remains in place. In particular,
the UI still reports V2 as unsupported even after public-key recovery. This
branch is intended for protocol investigation, not confirmed V2 support.

The server still uses its existing RSA-OAEP/SHA-1 bootstrap response encryption.
SHA-384 request signatures alone do not establish the response encryption
format. A real V2 device must still demonstrate:

1. Acceptance of the encrypted `/region` reply and the supplied server URLs.
2. Progression to NC registration and acceptance of its device ID and local key.
3. TLS acceptance and authenticated MQTT connectivity.
4. Status messages, a command response, and reconnection after reboot.

The next useful hardware test is a pairing attempt after successful key
recovery, checking whether the device advances from `/region` to NC and MQTT.
Further protocol changes and onboarding-status updates depend on that result.

## Regression tests

```console
uv sync --extra dev
uv run pytest -q tests/test_rsa_sampling.py tests/test_v2_region_recovery.py tests/test_device_key_recovery.py tests/test_admin_api.py tests/test_runtime_state.py
```

The tests use synthetic signatures and temporary state. They cover RSA-2048 /
SHA-256 compatibility, RSA-4096 / SHA-384 recovery, exact query preservation,
protocol classification, version persistence, restart behavior, and rejection
of a modified signature holdout. They do not prove physical onboarding.
