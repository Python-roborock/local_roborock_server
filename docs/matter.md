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
3. **Let the server forward the request to Roborock.** It is off by default, because it sends data to Roborock:

```toml
[matter]
key_proxy = true
```

or `ROBOROCK_SERVER_MATTER_KEY_PROXY=true`, which wins when it is set. The request goes to the regional cloud host
(`https://<region>iot.roborock.com/fwapi/matter/key`, with `network.region` one of `us`, `eu`, `cn` or `ru`) and the
answer goes back to the robot unchanged.

### What is sent to Roborock

The robot's own request, as it arrived: its query string (which may name the robot by `did` or `duid` and carry
its signature) and its headers, minus hop-by-hop and proxy headers (`Host`, `Connection`, `Cookie`,
`X-Forwarded-*`, `Forwarded`, `Via` and similar). Roborock also sees this server's public IP address. Nothing from
the app account, the admin password or other robots is added.

### What is checked first

The route is open to anything that can reach the server, so it only forwards a request when it names a paired robot
(a `did` or `duid` in the query that this server knows) or, when it names none, when it comes from the address of a
robot that has connected to this server. Anything else gets 403, and a malformed or oversized query gets 400. The
destination host and path are fixed, so this is never a general proxy. The address check is the weaker of the two:
a request without a robot id from a machine at a robot's address passes it.

### What is logged

The shared request log (`http_jsonl`) normally stores every header and query value. For this route it keeps only the
header and query names, the path without its query string, the response status and size, and the robot id if the
request carried one. The console log has the same names and the answer's status and size. The key itself is never
logged. Two things outside this route still see the robot's signed query: the device key cache, which stores signed
queries for key recovery as for any robot request, and the request log of a server that has the proxy switched off,
which treats the request like any other unknown path.

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
