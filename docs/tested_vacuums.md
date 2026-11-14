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

- Saros Z70

Failing reports made before `1.1.0` need retesting on those devices and firmware versions.

## Known Failures

These reports remain unresolved:

| Vacuum | Firmware | Result | Report |
|---|---|---|---|
| Roborock Q7 TF+ | Not reported | Onboarding fails; uses a different protocol from the V2 models supported in `1.1.0`. | [#48](https://github.com/Python-roborock/local_roborock_server/issues/48) |
| Roborock G30 China (a146, Saros 10 equivalent) | `02.43.88` | Onboards and connects over MQTT, but the vacuum rejects commands with `-10002 rrcheck access denied`. The region-locked vacuum is not in the cloud import. | [#161](https://github.com/Python-roborock/local_roborock_server/issues/161), [#182](https://github.com/Python-roborock/local_roborock_server/issues/182) |

## Supported Vacuums

The following vacuums are confirmed working:

Legend:

- Check mark: reported working
- Cross: reported not working with that certificate setup
- Question mark: certificate result not reported

Cloudflare can provide DNS validation for several certificate issuers. Its use alone does not establish which issuer was tested. Working reports without a named issuer retain question marks in the certificate columns.

| Vacuum | Firmware | ZeroSSL | Actalis | Let's Encrypt | SSL.com | Reports |
|---|---:|---:|---:|---:|---:|---|
| Roborock S4 (s4) | `02.06.26` | ❓ | ✅ | ❓ | ❓ | [#257](https://github.com/Python-roborock/local_roborock_server/pull/257) |
| Roborock S5 Max | Not reported | ❌ | ❓ | ❌ | ❓ | [#3](https://github.com/Python-roborock/local_roborock_server/issues/3) |
| Roborock S5 Max | `02.16.62` | ❓ | ✅ | ❓ | ❓ | [#3](https://github.com/Python-roborock/local_roborock_server/issues/3#issuecomment-5450368775) |
| Roborock S5 Max (s5e) | `02.16.68` | ❓ | ✅ | ❓ | ❓ | [#146](https://github.com/Python-roborock/local_roborock_server/issues/146) |
| Roborock S6 | `02.33.88` (`3.5.8_2700`) | ❓ | ✅ | ❓ | ❓ | [#158](https://github.com/Python-roborock/local_roborock_server/issues/158) |
| Roborock S6 Pure (a08) | `02.13.68` | ❓ | ✅ | ❓ | ❓ | [#191](https://github.com/Python-roborock/local_roborock_server/issues/191) |
| Roborock S6 MaxV (a10) | `01.58.02` | ✅ | ❓ | ❌ | ❓ | [#122](https://github.com/Python-roborock/local_roborock_server/issues/122) |
| Roborock S6 MaxV (a10) | `01.60.52` | ❓ | ❓ | ❌ | ✅ | [#177](https://github.com/Python-roborock/local_roborock_server/issues/177) |
| Roborock S7 | Not reported | ❓ | ✅ | ❌ | ✅ | [#3](https://github.com/Python-roborock/local_roborock_server/issues/3) |
| Roborock S7 (a15) | `02.16.12` | ❓ | ✅ | ❓ | ❓ | [#257](https://github.com/Python-roborock/local_roborock_server/pull/257) |
| Roborock S7 MaxV | Not reported | ❓ | ❓ | ✅ | ❓ | — |
| Roborock S7 MaxV (a27) | `02.59.36` | ✅ | ❓ | ✅ | ❓ | [#49](https://github.com/Python-roborock/local_roborock_server/issues/49), [#118](https://github.com/Python-roborock/local_roborock_server/issues/118), [#129](https://github.com/Python-roborock/local_roborock_server/issues/129) |
| Roborock S7 Max Ultra | `02.26.80` | ❓ | ❓ | ✅ | ❓ | [#79](https://github.com/Python-roborock/local_roborock_server/issues/79#issuecomment-5637657592) |
| Roborock S7 Pro Ultra (a62) | Not reported | ❓ | ✅ | ❌ | ❓ | [#65](https://github.com/Python-roborock/local_roborock_server/pull/65) |
| Roborock S8 (a51) | `02.14.48` | ❌ | ❓ | ✅ | ❌ | [#46](https://github.com/Python-roborock/local_roborock_server/issues/46#issuecomment-5456737057) |
| Roborock S8 (a51) | `02.17.42` | ✅ | ❓ | ✅ | ❓ | [#46](https://github.com/Python-roborock/local_roborock_server/issues/46) |
| Roborock S8+ (a51) | `02.17.42` | ❓ | ❓ | ✅ | ❓ | [#66](https://github.com/Python-roborock/local_roborock_server/pull/66#issuecomment-5401631314) |
| Roborock S8 MaxV Ultra | `02.37.38` | ✅ | ❓ | ❓ | ❓ | [#49](https://github.com/Python-roborock/local_roborock_server/issues/49) |
| Roborock S8 MaxV Ultra (a97) | `02.39.48` | ✅ | ❓ | ❓ | ❓ | [#137](https://github.com/Python-roborock/local_roborock_server/issues/137) |
| Roborock S8 MaxV Ultra (a97) | `02.39.60` | ✅ | ❓ | ❓ | ❓ | [#197](https://github.com/Python-roborock/local_roborock_server/issues/197) |
| Roborock S8 Pro Ultra (a70) | `02.20.30` | ✅ | ❓ | ✅ | ❓ | [#130](https://github.com/Python-roborock/local_roborock_server/issues/130), [#178](https://github.com/Python-roborock/local_roborock_server/issues/178) |
| Roborock Saros 10 (a147) | `02.44.28` | ✅ | ❓ | ❓ | ❓ | [#127](https://github.com/Python-roborock/local_roborock_server/issues/127) |
| Roborock Saros 10R | `02.50.56` | ❓ | ❓ | ❓ | ❓ | [#78](https://github.com/Python-roborock/local_roborock_server/issues/78) |
| Roborock Saros 10R | `02.52.32` | ✅ | ❓ | ✅ | ❓ | — |
| Roborock Saros 10R (a144) | `02.52.86` | ❓ | ❓ | ✅ | ❓ | [#57](https://github.com/Python-roborock/local_roborock_server/issues/57), [#61](https://github.com/Python-roborock/local_roborock_server/issues/61) |
| Roborock Saros 20 | `02.55.44` | ❓ | ❓ | ✅ | ❓ | [#131](https://github.com/Python-roborock/local_roborock_server/issues/131) |
| Roborock Saros 20 Complete (a288) | `02.55.44` | ✅ | ❓ | ❓ | ❓ | [#98](https://github.com/Python-roborock/local_roborock_server/issues/98) |
| Roborock Saros 20 Flow Complete (a307) | `02.23.52` | ❓ | ❓ | ✅ | ❓ | [#151](https://github.com/Python-roborock/local_roborock_server/issues/151) |
| Roborock Saros 20 Neo (a296) | `02.27.04` | ❓ | ❓ | ✅ | ❓ | [#139](https://github.com/Python-roborock/local_roborock_server/issues/139) |
| Roborock Saros 20 Neo (a296) | `02.29.56` | ❓ | ❓ | ✅ | ❓ | [#139](https://github.com/Python-roborock/local_roborock_server/issues/139#issuecomment-6154525857), [#139](https://github.com/Python-roborock/local_roborock_server/issues/139#issuecomment-6247548897) |
| Roborock Saros 20 Sonic (a279) | `02.42.52` | ✅ | ❓ | ❓ | ❓ | [#84](https://github.com/Python-roborock/local_roborock_server/pull/84#issuecomment-5701936113) |
| Roborock Saros 20X (a288) | `02.55.44` | ✅ | ❓ | ✅ | ❓ | [#114](https://github.com/Python-roborock/local_roborock_server/issues/114) |
| Roborock G30U | `02.52.32` | ✅ | ❓ | ❓ | ❓ | — |
| Roborock Q5+ (a34) | `02.06.56` | ❌ | ✅ | ❌ | ❓ | [#117](https://github.com/Python-roborock/local_roborock_server/issues/117) |
| Roborock Q5 Pro | `02.04.66` | ❌ | ❓ | ✅ | ❓ | [#56](https://github.com/Python-roborock/local_roborock_server/issues/56), [#97](https://github.com/Python-roborock/local_roborock_server/issues/97) |
| Roborock Q8 Max | `02.06.86` | ❓ | ❓ | ✅ | ❓ | [#70](https://github.com/Python-roborock/local_roborock_server/issues/70) |
| Roborock QV 35A (a168) | `02.49.24` | ✅ | ❓ | ❓ | ❓ | [#119](https://github.com/Python-roborock/local_roborock_server/issues/119) |
| Roborock Qrevo C (a170) | `02.16.64` | ❓ | ❓ | ✅ | ❓ | [#95](https://github.com/Python-roborock/local_roborock_server/issues/95) |
| QRevo | `02.20.60` | ✅ | ❓ | ✅ | ❓ | [#75](https://github.com/Python-roborock/local_roborock_server/pull/75), [#94](https://github.com/Python-roborock/local_roborock_server/issues/94) |
| QRevo 2 Pro (a294) | `02.33.88` | ❓ | ❓ | ✅ | ❓ | [#192](https://github.com/Python-roborock/local_roborock_server/issues/192) |
| QRevo 2 Pro (a294) | `02.40.54` | ✅ | ❓ | ❓ | ❓ | [#160](https://github.com/Python-roborock/local_roborock_server/issues/160) |
| QRevo 3 Pro (a296) | `02.27.04` | ✅ | ❌ | ❌ | ❓ | [#170](https://github.com/Python-roborock/local_roborock_server/issues/170) |
| QRevo Curv | `02.28.60` | ❓ | ❓ | ✅ | ❓ | [#60](https://github.com/Python-roborock/local_roborock_server/issues/60) |
| QRevo Curv (a135) | `02.28.92` | ❓ | ❓ | ✅ | ❓ | [#110](https://github.com/Python-roborock/local_roborock_server/issues/110) |
| QRevo Curv 2 Pro | `02.45.78` | ❓ | ❓ | ✅ | ❓ | [#128](https://github.com/Python-roborock/local_roborock_server/issues/128) |
| QRevo Curv 2 Flow | `02.33.88` | ❓ | ❓ | ✅ | ❓ | [#141](https://github.com/Python-roborock/local_roborock_server/issues/141) |
| QRevo Curv 2 Flow (a245) | `02.35.52` | ❓ | ❓ | ✅ | ❓ | [#187](https://github.com/Python-roborock/local_roborock_server/issues/187) |
| QRevo CurvX | `02.35.88` | ✅ | ❓ | ❓ | ❓ | [#64](https://github.com/Python-roborock/local_roborock_server/issues/64) |
| QRevo Edge | `02.22.52` | ❓ | ❓ | ✅ | ❓ | [#90](https://github.com/Python-roborock/local_roborock_server/issues/90) |
| QRevo Edge | `02.28.60` | ❓ | ❓ | ✅ | ❓ | [#198](https://github.com/Python-roborock/local_roborock_server/issues/198) |
| QRevo Edge 2 Set (a298) | `02.15.44` | ❓ | ❓ | ✅ | ❓ | [#84](https://github.com/Python-roborock/local_roborock_server/pull/84#issuecomment-5684924538), [#59](https://github.com/Python-roborock/local_roborock_server/issues/59#issuecomment-5848488145) |
| QRevo Edge 5V1 / S5A (a187) | `02.29.08` | ❓ | ❓ | ✅ | ❓ | [#172](https://github.com/Python-roborock/local_roborock_server/issues/172) |
| QRevo MaxV | Not reported | ✅ | ❓ | ✅ | ❓ | — |
| QRevo Master (a117) | `02.28.26` | ❓ | ❓ | ✅ | ✅ | [#57](https://github.com/Python-roborock/local_roborock_server/issues/57), [#82](https://github.com/Python-roborock/local_roborock_server/pull/82) |
| QRevo Plus (a123) | `02.03.28` | ✅ | ❓ | ❓ | ❓ | [#112](https://github.com/Python-roborock/local_roborock_server/issues/112) |
| QRevo Pro (a101) | `02.15.26` | ❓ | ❓ | ✅ | ❓ | [#171](https://github.com/Python-roborock/local_roborock_server/issues/171) |
| QRevo S5V (a170) | `02.09.70` | ❓ | ❓ | ❓ | ❓ | [#52](https://github.com/Python-roborock/local_roborock_server/issues/52#issuecomment-4826867624) |
| QRevo S5V (a170) | `02.16.64` | ❓ | ❓ | ✅ | ❓ | [#52](https://github.com/Python-roborock/local_roborock_server/issues/52) |
| QRevo S5V (a170) | `02.33.88` | ❓ | ❓ | ✅ | ❓ | [#148](https://github.com/Python-roborock/local_roborock_server/issues/148) |
| QRevo S Pro (a326) | `02.35.88` | ❓ | ❓ | ✅ | ❓ | [#150](https://github.com/Python-roborock/local_roborock_server/issues/150) |
| QRevo S Pro (a326) | `02.36.38` | ❓ | ❓ | ✅ | ❓ | [#132](https://github.com/Python-roborock/local_roborock_server/issues/132) |
| QRevo S Pro (a326) | `02.49.24` | ✅ | ❓ | ✅ | ❓ | [#156](https://github.com/Python-roborock/local_roborock_server/issues/156), [#186](https://github.com/Python-roborock/local_roborock_server/issues/186) |
| QRevo Slim | `02.43.38` | ✅ | ❓ | ❓ | ❓ | [#175](https://github.com/Python-roborock/local_roborock_server/issues/175) |
| QX Revo Plus (Costco version) | Not reported | ❓ | ❓ | ✅ | ❓ | [#89](https://github.com/Python-roborock/local_roborock_server/pull/89) |
| QX Revo Plus (Costco version) | `02.49.24` | ✅ | ❓ | ❓ | ❓ | [#147](https://github.com/Python-roborock/local_roborock_server/issues/147) |
| QX Revo Ultra 2 (a298) | `02.15.44` | ❓ | ✅ | ❓ | ❓ | [#193](https://github.com/Python-roborock/local_roborock_server/issues/193) |

Setup notes:

- S4 `02.06.26` and S7 (a15) `02.16.12`: server 1.2.1 with a provided Actalis RSA-2048 certificate (chain ending at Actalis Authentication Root CA). Both onboarded with LocalRock in three cycles: the public key was recovered after the second and the vacuum connected over MQTT (TLSv1) on the third. Home Assistant (Region: Manual) exposed every entity the cloud integration had, including the maps.
- S4: the vacuum supports only 2.4 GHz Wi-Fi. Given a 5 GHz SSID during onboarding, it reports a Wi-Fi password failure and never tries to join.
- S5 Max `02.16.68`: the vacuum had been on Mi Home and was moved to a Roborock account before cloud import. The built-in Actalis option in the Home Assistant add-on hung; a provided Actalis certificate issued with Certbot worked.
- S6: the factory firmware `3.5.8_2076` ignores the custom API server sent during Wi-Fi setup. The reporter joined Wi-Fi through Xiaomi Home, updated to `3.5.8_2700` (`02.33.88`), then onboarded with `start_onboarding.py`.
- S6 Pure: Home Assistant did not expose the water box attached sensor or the mop mode select locally.
- S6 MaxV: initial LocalRock and Home Assistant controls worked, but the reporter noted intermittent connectivity shortly after onboarding and had not tested it long term.
- S6 MaxV `01.60.52`: the SSL.com certificate used an ECDSA key. With Let's Encrypt, query samples stayed at 0.
- S7 Pro Ultra: the Actalis success used an RSA-2048 certificate. The Let's Encrypt failure was reported with an R3/E1 chain.
- S8 MaxV Ultra `02.39.60`: camera live view worked on the LAN with provided TURN after re-pairing with a `token.r` of 15 characters or fewer (for example `--server api-r.vacex.cc:555`) and the normal `us` country domain. See [camera.md](camera.md).
- Saros 10: the reporter blocked the vacuum's Internet access to complete onboarding and kept it blocked afterward. Camera preview did not work.
- Saros 10R `02.50.56`: the reported pfSense/HAProxy setup used provided certificates and the MITM redirect fix in [PR #77](https://github.com/Python-roborock/local_roborock_server/pull/77).
- Saros 20: the onboarding script succeeded after pairing through the LocalRock app failed. The reporter could not enable or disable Matter control.
- Saros 20X: confirmed working with both ZeroSSL and Let's Encrypt on server v1.2.0. The reporter noted the vacuum attempts direct DNS queries to 8.8.8.8 until WAN access is blocked at the router, after which it correctly uses local DHCP DNS.
- Saros 20 Flow Complete: onboarding through LocalRock failed, and the onboarding scripts worked. Mopping only started after the mop mode was set once from the patched Roborock app; after that it worked from Home Assistant and LocalRock.
- Saros 20 Neo: block the vacuum's WAN access before onboarding. One reporter saw it rejoin Wi-Fi but never contact the server until WAN was blocked. Home Assistant shows the Vacuum then Mop cleaning mode as `unknown`. An EU cloud import imported 0 devices until `base_url` was set to `https://euiot.roborock.com`.
- Q5+: the Actalis success used a provided certificate. The built-in Actalis option was not tested; with ZeroSSL and Let's Encrypt, the vacuum received the certificate chain but did not complete onboarding.
- Q5 Pro: ZeroSSL was attempted and failed (MQTT broken pipe), while Let's Encrypt succeeded.
- Qrevo C: confirmed working with a GoDaddy-issued certificate and tested with the LocalRock Android app.
- QRevo 2 Pro `02.33.88`: on server 1.2.0 the vacuum began rejecting requests with `-10002 rrcheck access denied` about 48 hours after connecting. Server 1.2.1 fixed it once the vacuum made a new `POST /f/c` request, which a longer power-off triggered. Renaming rooms in LocalRock failed.
- QRevo 3 Pro: Actalis and Let's Encrypt did not onboard; ZeroSSL recovered the key almost immediately, but the vacuum took several minutes to show as online.
- QRevo Curv: the reporter worked around an app redirect port issue, also tracked by [PR #77](https://github.com/Python-roborock/local_roborock_server/pull/77).
- QRevo Curv 2 Pro: the map initially failed to load; regenerating the server public key and re-onboarding restored it.
- QRevo Curv 2 Flow: the vacuum only supports 2.4 GHz Wi-Fi.
- QRevo Pro: Home Assistant worked, but the admin page kept showing Region and NC Prepare as missing onboarding messages.
- QRevo S Pro `02.36.38`: the successful report used an RSA-2048 Let's Encrypt certificate. An [earlier attempt](https://github.com/Python-roborock/local_roborock_server/issues/67) on the same firmware stopped before Wi-Fi configuration was sent.
- QRevo S5V `02.33.88`: maps were not saved because `lab_status` was off and the LocalRock toggle was greyed out. Sending `set_lab_status` with `[{"lab_status": 1}]` from Home Assistant's `vacuum.send_command` enabled it.
- QRevo Slim: the certificate was issued through Pangolin (Traefik) and reported as ZeroSSL.
- QRevo Master: the SSL.com result used a Sectigo Public Server Authentication CA DV R36 chain and a workaround for the proxy MQTT onboarding issue in [#83](https://github.com/Python-roborock/local_roborock_server/issues/83).
- QX Revo Ultra 2: shares its model code and firmware with the QRevo Edge 2 Set. Public key recovery used header samples while query samples stayed at 0, which is expected.

## Unlisted Vacuums

If your model is not listed, start with ZeroSSL unless it is an older model that is likely to need a different trusted chain. If onboarding fails after the DNS and server checks pass, try Actalis or a provided certificate and report the result.

## Report Your Result

Use the [compatibility report form](https://github.com/Python-roborock/local_roborock_server/issues/new?template=compatibility.yml) to share your exact model, firmware, server version, certificate issuer, and what worked or failed. Include any workarounds. You can also open a pull request updating this page with a link to your report.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Mobile App Options](roborock_app.md)
