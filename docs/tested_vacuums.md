# Tested Vacuums

Check this page alongside [Installation](installation.md) and [Onboarding](onboarding.md) if you are trying to confirm whether your model is expected to work.

For most users, start with ZeroSSL. Actalis is mainly recommended for older vacuums or for models that already have reports showing better compatibility with the Actalis chain. Some newer vacuums can also handle any cert you throw at it!

## Buying a New Vacuum?

If you're looking to buy a Roborock, consider using one of my affiliate links on the [Support This Project](support.md) page. It doesn't cost you anything extra and helps keep this project going!

## Unsupported Vacuums

The following vacuums are not supported and may never be supported.

- Roborock Q10 X5 / X5+
- Roborock Q7 M5 / M5+
- Roborock Q7 L5
- Roborock Q10 s5/ s5+

These vacuums likely all use a newer firmware version that uses a v2 of the region endpoint. In order to support them, we need to get a firmware dump. If you would like to disassemble your vac, we can likely get this. Please reach out.

- Roborock Saros 20 Sonic
- Roborock Qrevo Curv 2 Pro
- Saros 20

## Potentially Supported
These are (maybe) using the same firmware as the two above. Any vacuum released after Sep 2025 is likely not supported in its current form.  Please give it a try and let me know so I can update the docs.

- Roborock Qrevo Edge 2
- Roborock Qrevo S Pro
- Qrevo Curv 2 Flow
- Qrevo CurvX
- Saros Z70

## Supported Vacuums

The following vacuums are confirmed working:

Legend:

- Check mark: reported working
- Cross: reported not working
- Question mark: not reported yet

| Vacuum | Firmware | ZeroSSL / Cloudflare | Actalis | Let's Encrypt | SSL.com |
|---|---:|---:|---:|---:|---:|
| Roborock S5 Max | Not reported | ❌ | ✅ | ❌ | ❓ |
| Roborock S7 | Not reported | ❓ | ✅ | ❌ | ✅ |
| Roborock S7 Pro Ultra (a62) | Not reported | ❓ | ✅ | ❌ | ❓ |
| Roborock S7 MaxV | Not reported | ✅ | ❓ | ✅ | ❓ |
| Roborock S8 | Not reported | ❓ | ❓ | ❓ | ❓ |
| Roborock S8 MaxV Ultra | Not reported | ✅ | ❓ | ❓ | ❓ |
| Roborock S8 Pro Ultra (a70) | Not reported | ❓ | ❓ | ❓ | ❓ |
| Roborock Saros 10R | `02.52.32` | ✅ | ❓ | ✅ | ❓ |
| Roborock G30U | `02.52.32` | ✅ | ❓ | ❓ | ❓ |
| Roborock Qrevo S5V | Not reported | ❓ | ❓ | ❓ | ❓ |
| QRevo MaxV | Not reported | ✅ | ❓ | ✅ | ❓ |
| QRevo Master | Not reported | ❓ | ❓ | ❓ | ❓ |
| QRevo Plus | Not reported | ✅ | ❓ | ❓ | ❓ |

## Diagnosing cert rejection

When a vacuum rejects the TLS certificate, the failure pattern is **post-handshake close** rather than a TLS alert:

- `mqtt_server.log` shows `TLS handshake ok from <vacuum-ip>` immediately followed by `client closed before MQTT CONNECT`.
- `decompiled_http.jsonl` stays empty (the vacuum never sends an HTTP request to `:555`).
- Packet capture shows the vacuum doing repeated short TLS connections (~30 ms) with TCP FIN and no `tls.alert` in either direction.

This pattern indicates the vacuum completed the TLS handshake server-side but rejected the cert during its own validation (CA chain not trusted, or hostname mismatch). The vacuum then closes the TCP connection without sending any application data.

### Hostname verification

The vacuum uses the **stack hostname** (the `api-...` value from `config.toml` → `network.stack_fqdn`) for both SNI in ClientHello and hostname verification against the certificate. It does **not** use the value of the `r` field from the cfgwifi packet (which is the stack hostname with `api-` stripped).

This means a single-domain certificate covering only the stack hostname (e.g. `api-roborock.example.com`) is sufficient. You do **not** need a SAN for the stripped hostname (`roborock.example.com`) or a wildcard certificate. DNS resolution for the stripped hostname is also unnecessary.

## Unlisted Vacuums

If your model is not listed, start with ZeroSSL unless it is an older model that is likely to need a different trusted chain. If onboarding fails after the DNS and server checks pass, try Actalis or a provided certificate and report the result.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)
