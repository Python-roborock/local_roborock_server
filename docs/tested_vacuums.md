# Tested Vacuums

Check this page alongside [Installation](installation.md) and [Onboarding](onboarding.md) if you are trying to confirm whether your model is expected to work.

For most users, start with ZeroSSL. Actalis is mainly recommended for older vacuums or for models that already have reports showing better compatibility with the Actalis chain. Results below apply to the reported firmware and certificate chain; other versions or chains may behave differently.

## Buying a New Vacuum?

If you're looking to buy a Roborock, consider using one of my affiliate links on the [Support This Project](support.md) page. It doesn't cost you anything extra and helps keep this project going!

## Unsupported Vacuums

The following vacuums are not supported and may never be supported.

- Roborock Q10 X5 / X5+
- Roborock Q7 M5 / M5+
- Roborock Q7 L5
- Roborock Q10 s5/ s5+

## Potentially Supported
These models have not yet been confirmed working. Version `1.1.0` adds V2
onboarding support; please report your model, firmware, and certificate chain
if you try one.

- [Roborock Qrevo Curv 2 Pro](https://github.com/Python-roborock/local_roborock_server/issues/47)
- [Saros 20 / Saros 20X](https://github.com/Python-roborock/local_roborock_server/issues/47)
- [Roborock Qrevo S Pro](https://github.com/Python-roborock/local_roborock_server/issues/67)
- Qrevo Curv 2 Flow
- Saros Z70

Failing reports made before `1.1.0` need retesting on those devices and firmware versions.

The `roborock.vacuum.sc05` Q7 has a separate [experimental 03.01.80 no-dump
owner trial](q7_030180_owner_trial.md). One physical unit completed migration
and return; a second owner's unit has not yet been tested, so it is not in the
supported-vacuums table.

## Known Failures

These reports remain unresolved:

| Vacuum | Firmware | Result | Report |
|---|---|---|---|
| Roborock Q7 TF+ | Not reported | Onboarding fails; uses a different protocol from the V2 models supported in `1.1.0`. | [#48](https://github.com/Python-roborock/local_roborock_server/issues/48) |

## Supported Vacuums

The following vacuums are confirmed working:

Legend:

- Check mark: reported working
- Cross: reported not working with that certificate setup
- Question mark: certificate result not reported

Cloudflare can provide DNS validation for several certificate issuers. Its use alone does not establish which issuer was tested. Working reports without a named issuer retain question marks in the certificate columns.

| Vacuum | Firmware | ZeroSSL | Actalis | Let's Encrypt | SSL.com | Reports |
|---|---:|---:|---:|---:|---:|---|
| Roborock S5 Max | Not reported | ❌ | ❓ | ❌ | ❓ | [#3](https://github.com/Python-roborock/local_roborock_server/issues/3) |
| Roborock S5 Max | `02.16.62` | ❓ | ✅ | ❓ | ❓ | [#3](https://github.com/Python-roborock/local_roborock_server/issues/3#issuecomment-5450368775) |
| Roborock S7 | Not reported | ❓ | ✅ | ❌ | ✅ | [#3](https://github.com/Python-roborock/local_roborock_server/issues/3) |
| Roborock S7 MaxV | Not reported | ❓ | ❓ | ✅ | ❓ | — |
| Roborock S7 MaxV | `2.59.36` | ✅ | ❓ | ❓ | ❓ | [#49](https://github.com/Python-roborock/local_roborock_server/issues/49) |
| Roborock S7 Max Ultra | `02.26.80` | ❓ | ❓ | ✅ | ❓ | [#79](https://github.com/Python-roborock/local_roborock_server/issues/79#issuecomment-5637657592) |
| Roborock S7 Pro Ultra (a62) | Not reported | ❓ | ✅ | ❌ | ❓ | [#65](https://github.com/Python-roborock/local_roborock_server/pull/65) |
| Roborock S8 (a51) | `02.14.48` | ❌ | ❓ | ✅ | ❌ | [#46](https://github.com/Python-roborock/local_roborock_server/issues/46#issuecomment-5456737057) |
| Roborock S8 (a51) | `02.17.42` | ✅ | ❓ | ✅ | ❓ | [#46](https://github.com/Python-roborock/local_roborock_server/issues/46) |
| Roborock S8+ (a51) | `02.17.42` | ❓ | ❓ | ✅ | ❓ | [#66](https://github.com/Python-roborock/local_roborock_server/pull/66#issuecomment-5401631314) |
| Roborock S8 MaxV Ultra | `02.37.38` | ✅ | ❓ | ❓ | ❓ | [#49](https://github.com/Python-roborock/local_roborock_server/issues/49) |
| Roborock S8 Pro Ultra (a70) | Not reported | ❓ | ❓ | ❓ | ❓ | — |
| Roborock Saros 10R | `02.50.56` | ❓ | ❓ | ❓ | ❓ | [#78](https://github.com/Python-roborock/local_roborock_server/issues/78) |
| Roborock Saros 10R | `02.52.32` | ✅ | ❓ | ✅ | ❓ | — |
| Roborock Saros 10R (a144) | `02.52.86` | ❓ | ❓ | ✅ | ❓ | [#57](https://github.com/Python-roborock/local_roborock_server/issues/57), [#61](https://github.com/Python-roborock/local_roborock_server/issues/61) |
| Roborock Saros 20 Sonic (a279) | `02.42.52` | ✅ | ❓ | ❓ | ❓ | [#84](https://github.com/Python-roborock/local_roborock_server/pull/84#issuecomment-5701936113) |
| Roborock G30U | `02.52.32` | ✅ | ❓ | ❓ | ❓ | — |
| Roborock Q5 Pro | `2.04.06` | ❓ | ❓ | ✅ | ❓ | [#56](https://github.com/Python-roborock/local_roborock_server/issues/56) |
| Roborock Q8 Max | `02.06.86` | ❓ | ❓ | ✅ | ❓ | [#70](https://github.com/Python-roborock/local_roborock_server/issues/70) |
| QRevo | `02.20.60` | ❓ | ❓ | ✅ | ❓ | [#75](https://github.com/Python-roborock/local_roborock_server/pull/75) |
| QRevo Curv | `02.28.60` | ❓ | ❓ | ✅ | ❓ | [#60](https://github.com/Python-roborock/local_roborock_server/issues/60) |
| QRevo CurvX | `02.35.88` | ✅ | ❓ | ❓ | ❓ | [#64](https://github.com/Python-roborock/local_roborock_server/issues/64) |
| QRevo Edge | `02.22.52` | ❓ | ❓ | ✅ | ❓ | [#90](https://github.com/Python-roborock/local_roborock_server/issues/90) |
| QRevo Edge 2 Set (a298) | `02.15.44` | ❓ | ❓ | ✅ | ❓ | [#84](https://github.com/Python-roborock/local_roborock_server/pull/84#issuecomment-5684924538) |
| QRevo MaxV | Not reported | ✅ | ❓ | ✅ | ❓ | — |
| QRevo Master (a117) | `02.28.26` | ❓ | ❓ | ✅ | ✅ | [#57](https://github.com/Python-roborock/local_roborock_server/issues/57), [#82](https://github.com/Python-roborock/local_roborock_server/pull/82) |
| QRevo Plus | Not reported | ✅ | ❓ | ❓ | ❓ | — |
| QRevo S5V (a170) | `02.09.70` | ❓ | ❓ | ❓ | ❓ | [#52](https://github.com/Python-roborock/local_roborock_server/issues/52#issuecomment-4826867624) |
| QRevo S5V (a170) | `02.16.64` | ❓ | ❓ | ✅ | ❓ | [#52](https://github.com/Python-roborock/local_roborock_server/issues/52) |
| QX Revo Plus (Costco version) | Not reported | ❓ | ❓ | ✅ | ❓ | [#89](https://github.com/Python-roborock/local_roborock_server/pull/89) |

Setup notes:

- S7 Pro Ultra: the Actalis success used an RSA-2048 certificate. The Let's Encrypt failure was reported with an R3/E1 chain.
- Saros 10R `02.50.56`: the reported pfSense/HAProxy setup used provided certificates and the MITM redirect fix in [PR #77](https://github.com/Python-roborock/local_roborock_server/pull/77).
- QRevo Curv: the reporter worked around an app redirect port issue, also tracked by [PR #77](https://github.com/Python-roborock/local_roborock_server/pull/77).
- QRevo Master: the SSL.com result used a Sectigo Public Server Authentication CA DV R36 chain and a workaround for the proxy MQTT onboarding issue in [#83](https://github.com/Python-roborock/local_roborock_server/issues/83).

## Unlisted Vacuums

If your model is not listed, start with ZeroSSL unless it is an older model that is likely to need a different trusted chain. If onboarding fails after the DNS and server checks pass, try Actalis or a provided certificate and report the result.

## Report Your Result

Use the [compatibility report form](https://github.com/Python-roborock/local_roborock_server/issues/new?template=compatibility.yml) to share your exact model, firmware, server version, certificate issuer, and what worked or failed. Include any workarounds. You can also open a pull request updating this page with a link to your report.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)
