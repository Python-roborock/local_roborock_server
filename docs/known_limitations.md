# Known Limitations

I have tried to copy over most functionality into this server, but some is not 100% completed. There are a few features I know are not currently working

- Vacuum camera live streaming — supported with a TURN relay and a short camera bootstrap hostname; see [camera.md](camera.md). Verified on the Saros 10R and Qrevo MaxV; other camera models may bootstrap differently and need validation.
- Firmware updates: the app can see whether an update is available (the server asks Roborock's cloud with the login stored at sign-in, so it needs one email-code sign-in first), and the Update button can install it when `[ota] enable_install = true` (or `ROBOROCK_SERVER_OTA_ENABLE_INSTALL=true`). Off by default, the upgrade request is refused with an error. See [Firmware updates](firmware_updates.md).
- Schedules (Routines/Scenes do work though)
- China-market devices do not work outside of China. Their firmware checks the region they are used in (via `rrcheck`), and after local onboarding they reject ordinary commands such as `get_status` with `-10002 / rrcheck access denied`. See [#81](https://github.com/Python-roborock/local_roborock_server/issues/81).
    - Some users have gotten China-market vacuums working outside China on the official cloud by routing the robot's traffic through a VPN that exits in China (the robot's WAN IP is what matters, not the phone's). See [this comment](https://github.com/iobroker-community-adapters/ioBroker.mihome-vacuum/issues/842#issuecomment-1736230673). This has not been tested with this local server yet, so it may or may not help.
