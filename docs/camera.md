# Camera (live video)

Robots with a camera can stream live video to a local WebRTC consumer (for example
[go2rtc](https://github.com/AlexxIT/go2rtc) with its `roborock://` source) without
reaching the Roborock cloud. Three things are required.

## 1. A short onboarding region

When the app requests a preview, the firmware derives the host it fetches the TURN
configuration from as `region[:15] + "iot.roborock.com"`. For that host to resolve
to this server, the onboarding region must be **14 characters or fewer plus a
trailing `/`** (15 total), e.g. `rrgui.v6.rocks/`. The robot then posts to
`https://<your-host>/iot.roborock.com/fwapi/createca` instead of the real cloud.
A region string without a port makes the robot use 443, so the fwapi host must be
reachable on 443 (see the reverse-proxy notes below).

## 2. A TURN/STUN server

The firmware will not start the WebRTC session until it receives a TURN config.
Run a TURN server reachable by the robot (coturn works well) and point this server
at it in `config.toml`:

```toml
[turn]
enabled = true
host = "192.168.1.10"      # the TURN server's address, reachable by the robot
port = 3478
username = "rrturn"
password = "a-long-random-secret"
realm = "rrgui.v6.rocks"
ttl = 86400
```

A minimal coturn config:

```
listening-port=3478
realm=rrgui.v6.rocks
lt-cred-mech
user=rrturn:a-long-random-secret
min-port=49160
max-port=49200
```

With `[turn].enabled = true`, the `/fwapi/createca` route answers the robot with
these credentials. With it false (the default) the request falls through to the
catchall and the camera stays unavailable, so enabling the TURN server is the only
behaviour change.

## 3. Reaching the createca host on 443

The fwapi/createca request arrives on port 443 of the region-derived host. Route it
to this server, either by having the server (or a reverse proxy in front of it)
listen on 443 for that host and forward `/iot.roborock.com/fwapi/createca` to the
stack. See [reverse_proxy.md](reverse_proxy.md).

## Activating the camera on the robot

On the tested Saros 10R (`roborock.vacuum.a144`, FCC/US firmware) the camera must be
armed with the two-key flow before a preview works: set the remote-view PIN
(`set_homesec_password`), request activation via `set_camera_status` with the
two-key request bits set and the monitor bit off, then press the Power button on the
robot within ~60s. The firmware then enables the monitor and the preview can start.
This is a per-model UX step; the `createca`/TURN handling above is model-independent.

## Status

Verified end to end on a Saros 10R: the robot completes the WebRTC handshake against
coturn and go2rtc receives frames. The exact `createca` response shape and the
region-host rule look like general firmware behaviour; the two-key activation is
model-specific. See issue #18 for the original investigation.
