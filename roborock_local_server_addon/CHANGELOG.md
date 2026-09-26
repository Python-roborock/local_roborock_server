# Changelog

## 1.1.0

- Added V2 onboarding support, including automatic public-key recovery and multipart NC registration.
- Removed the obsolete V2 unsupported status from the dashboard and guided onboarding.
- Confirmed working on QRevo Edge 2 Set and Saros 20 Sonic. See the tested-vacuum list for firmware and certificate details.
- Fixed certificate renewal handling when acme.sh reports that renewal is not yet needed.
- Existing settings and recovered keys are retained when updating. The Beta add-on is currently unused; use the stable add-on for this release.

## 1.0.2

- Added external TLS support and basic reverse proxy support.
- Explicitly handle the unsupported `v2` `/region` flow so detection no longer falls through.
- Improved device id matching and routine resuming.

## 1.0.1

- Added support for the iOS app's `/v4/user/homes/{home_id}` home-data route so device lists no longer fall through to the generic catchall response.
- Protected `/v4/user/*` routes with the same Hawk authentication used by existing user API versions.

## 0.0.2-rc8

- Initial Home Assistant add-on manifest using the shared GHCR image.
