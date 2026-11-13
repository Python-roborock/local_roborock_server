# Matter

Many Roborock robots can join a Matter controller (Apple Home, Google Home, Alexa, SmartThings, Home Assistant, or
a router with Matter support). To do that the robot first needs a Matter key, which Roborock's cloud issues. A robot
paired to this server asks this server for it, so two things are needed: a DNS name the robot can find, and a way to
reach Roborock for the key.

## How the robot asks

When it is told to download its key (`matter.dnld_key`), the robot sends `GET /iot.roborock.com/fwapi/matter/key`
to the server it was paired to. It builds the host name from the server name it was given during pairing, with the
`api-` prefix removed: a server called `api-vac.example.com` is reached as `vac.example.com`. The same rule applies
to the camera (see [Camera](camera.md)).

1. **Add a DNS record for the stripped name**, pointing at this server. If your stack is `api-vac.example.com`, add
   `vac.example.com`. Without it the robot cannot connect, and its Matter status goes from `KeyDownloading` to
   `KeyDownloadFailure` within seconds without a single request reaching the server.
2. **Make sure the certificate covers that name.** A wildcard for the base domain does.
3. **Let the server forward the request to Roborock.** It is off by default, because it passes the robot's own
   request, with its own headers, to Roborock:

```toml
[matter]
key_proxy = true
```

or `ROBOROCK_SERVER_MATTER_KEY_PROXY=true`, which wins when it is set. The request goes to the regional cloud host
(`https://<region>iot.roborock.com/fwapi/matter/key`, region from `network.region`) and the answer goes back to the
robot unchanged. The server logs the header and query names it forwarded and the answer's status and size, never the
values and never the key.

Without the proxy, the robot's request reaches the catch-all route and the robot reports `KeyCorrupt`, because it got
something that is not a key.

## Reading the robot's progress

The robot answers `matter.get_status` with one of `KeyNotExit`, `KeyDownloading`, `KeyDownloadSuccess`,
`KeyDownloadFailure`, `KeyCorrupt`, `Preparing`, `Ready`, `Joined` or `RPCError`. `Ready` and `Joined` come with a
`ManualPairingCode` and a `QrCode` (`MT:...`) that stay valid for 15 minutes. A new key request (`matter.dnld_key`)
produces a fresh code.

## Joining a controller

Use the code or the QR text in the controller's add-device flow. A controller has to be able to find the robot on the
network: Matter discovery uses multicast DNS and IPv6, which do not cross VLANs unless the network forwards mDNS. A
robot on a separate VLAN from the controller is the usual reason a valid code does nothing.

A robot that has joined one controller reports `Joined`. To add it to a second controller, request a new code and use
it while it is valid, or share the robot from the controller that joined it.

## Notes

- This does not change how the robot is controlled by the server. Matter is an additional way in.
- Whether the robot needs Roborock again after it has joined is not known. It keeps the key it downloaded.
