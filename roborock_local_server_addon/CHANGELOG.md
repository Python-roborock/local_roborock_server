# Changelog

## 1.0.2

- Added external TLS support and basic reverse proxy support.
- Explicitly handle the unsupported `v2` `/region` flow so detection no longer falls through.
- Improved device id matching and routine resuming.

## 1.0.1

- Added support for the iOS app's `/v4/user/homes/{home_id}` home-data route so device lists no longer fall through to the generic catchall response.
- Protected `/v4/user/*` routes with the same Hawk authentication used by existing user API versions.

## 0.0.2-rc8

- Initial Home Assistant add-on manifest using the shared GHCR image.
