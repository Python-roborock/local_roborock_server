# Known Limitations

I have tried to copy over most functionality into this server, but some is not 100% completed. There are a few features I know are not currently working

- Vacuum camera live streaming
- Firmware Updates
- Schedules (Routines/Scenes do work though)
- You must have a Roborock account and have added the device to the account at least once. This is a limitation I would like to remove but haven't done yet. We need to preload a bunch of cloud information that I would otherwise have to make dynamically which is much harder.
- China-market devices do not work outside of China. Their firmware checks the region they are used in (via `rrcheck`), and after local onboarding they reject ordinary commands such as `get_status` with `-10002 / rrcheck access denied`. See [#81](https://github.com/Python-roborock/local_roborock_server/issues/81).
    - Some users have gotten China-market vacuums working outside China on the official cloud by routing the robot's traffic through a VPN that exits in China (the robot's WAN IP is what matters, not the phone's). See [this comment](https://github.com/iobroker-community-adapters/ioBroker.mihome-vacuum/issues/842#issuecomment-1736230673). This has not been tested with this local server yet, so it may or may not help.
