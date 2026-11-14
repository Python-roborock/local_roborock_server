# Voice Packs

A robot changes its voice when an app sends it `dnld_install_sound` with a URL to download the pack
from. The official Roborock app takes that URL from Roborock's own list, so the robot is told to fetch
the pack from Roborock's servers. A robot whose internet access is blocked, as it usually is in a
local setup, cannot do that and the voice change fails.

This server keeps its own copy of the list and the packs and serves them from your stack, so a client
can hand the robot a URL on your server instead.

## How it works

- `GET https://<stack_fqdn>/voice-pkg/<bucket>/info` returns Roborock's list for a product, with every
  pack, picture and preview URL rewritten to point at this server.
- `GET https://<stack_fqdn>/voice-pkg/<bucket>/{package,pic,wav}/<file>` serves a file. The first
  request fetches it from Roborock, checks it against the checksum Roborock's storage sends with it (when there is one), and keeps it under
  `<data_dir>/voice_packs/<bucket>/`; later requests are served from that copy.
- The first time a bucket's list is asked for, the server starts downloading every pack in it in the
  background, so later voice changes need no internet at all.
- The list is refreshed from Roborock at most once a day. When Roborock can't be reached, the last
  stored list is used.

The routes need no login, as the robot downloads without credentials (Roborock's own copies are
public too). Only bucket names and plain file names from the list are accepted.

The upstream host follows `network.region` (`eu`, `us` or `cn`; other regions use `eu`).

## Buckets

Roborock keeps each product's voice packs in a folder named after the product's code name in its
device plugin:

| Bucket | Models |
|---|---|
| `vida` | Saros 20 Neo (`roborock.vacuum.a295`, `roborock.vacuum.a296`) |

Other products' buckets can be found in their device plugin (the `bucket` value next to the
voice-pack page). Add them here when you confirm one.

## Clients

The official Roborock app reads the list from Roborock directly, so it still sends Roborock's URLs
and voice changes from it keep failing on a robot without internet access. A client that wants to
use this mirror reads `/voice-pkg/<bucket>/info` and sends the robot:

```json
{"method": "dnld_install_sound", "params": {"sid": <voice_id>, "url": "<voice_pkg_url>", "md5": "<voice_pkg_md5>", "sver": <version>}}
```

with the values of one `voice_list` entry, then follows progress with `get_sound_progress`.
`voice_pkg_md5` is passed to the robot exactly as listed (it is not the MD5 of the file).

## Configuration

```toml
[voice_packs]
mode = "mirror"   # mirror | offline | disabled
```

- `mirror` (default): fetch from Roborock on first use and keep copies, as described above.
- `offline`: serve only the copies already stored and never contact Roborock. Use this after the
  packs have been mirrored once, or after copying a `voice_packs` folder into `<data_dir>` yourself.
- `disabled`: the `/voice-pkg` routes answer 404.

In the Home Assistant add-on the same choice is the `voice_packs_mode` option.
