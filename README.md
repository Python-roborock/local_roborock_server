# Roborock Local Server

[![GHCR][badge-ghcr]][link-ghcr]
[![Docs](https://img.shields.io/badge/docs-read%20now-success)](https://python-roborock.github.io/local_roborock_server/)
[![GitHub stars](https://img.shields.io/github/stars/Python-roborock/local_roborock_server?style=social)](https://github.com/Python-roborock/local_roborock_server/stargazers)

Run Roborock's cloud backend on your own local network. Your vacuum keeps live maps and local controls on an isolated LAN without internet access, requiring no hardware modifications or firmware rooting.

---

## Why this exists

While Home Assistant communicates with Roborock vacuums over a local protocol, two constraints previously prevented running them completely offline:

1. **Cloud-locked maps:** Roborock routes all map data strictly through their cloud servers (despite the vacuum storing the map locally).
2. **Cloud health checks:** If a vacuum cannot reach Roborock's servers, it repeatedly restarts its network interface, dropping local communication.

Upstream cloud authentication changes are also the most frequent point of failure for third-party integrations.

Roborock Local Server provides an on-premises HTTPS and MQTT stack. By redirecting DNS and completing an initial onboarding handshake, the vacuum connects to your local server instead of the official cloud.

---

## Features

- **Local map streaming:** Live maps and room cleanups work without cloud access.
- **No hardware modifications:** No disassembly, soldering, or bootloader unlocking required.
- **Greenfield onboarding:** Supports new vacuums out of the box without prior cloud registration.
- **Reversible:** Resetting the vacuum's Wi-Fi returns it to factory pairing mode.
- **Frontend options:** Works with Home Assistant (Add-on available), [LocalRock](https://github.com/DonSidro/LocalRock) (open-source mobile app), or the official app (via Android APK patch or iOS MITM profile).

---

## Compatibility

- **Supported:** Most Roborock vacuums, including modern v2 protocol models (based on firmware research by Dennis Giese).
- **Currently unsupported:** The entry-level Q series (such as the Q7; not to be confused with QRevo) due to differences in certificate validation.
- See the [Tested Vacuums List](https://python-roborock.github.io/local_roborock_server/tested_vacuums/) for specific model reports.

---

## Requirements

- A domain you control with local DNS rewriting (Pi-hole, AdGuard Home, or router DNS).
- A place to run the stack on your LAN (Docker Compose or Home Assistant installation that supports add-ons).
- A valid SSL certificate for your domain (automated via Cloudflare DNS-01 or generated manually).
- A secondary computer with Wi-Fi for initial onboarding.

---

## Getting Started

Start here if this is your first time setting up the stack:

1. [Installation](docs/installation.md) for the shared requirements, network setup, and Docker Compose install path.
2. [Home Assistant](docs/home_assistant.md) if you want to install the stack as a Home Assistant add-on instead of Docker Compose.
3. [Cloudflare setup](docs/cloudflare_setup.md) if you want Cloudflare DNS-01 auto-renew for certificates.
4. [Onboarding](docs/onboarding.md) to pair a vacuum from a second machine after the server is running.
5. [Updating](docs/updating.md) if you already have an install and are moving to a newer stable release.

Before choosing a certificate path, check [Tested vacuums](docs/tested_vacuums.md). Different models do not all accept the same certificate chains. For most users, start with ZeroSSL. Use Actalis mainly for older vacuums or models that are already known to trust that chain more reliably.

Additional docs:
- [Docs index](docs/index.md)
- [Technical Writeup: How Reverse Engineering Works](https://python-roborock.github.io/local_roborock_server/technical_writeup/)
- [Known limitations](docs/known_limitations.md)
- [Tested vacuums](docs/tested_vacuums.md)
- [Home Assistant](docs/home_assistant.md) for the add-on install path and integration setup
- [Mobile App Options](docs/roborock_app.md)
- [Custom MQTT](docs/custom_mqtt.md)
- [Custom certificate management](docs/custom_cert_management.md)

---

## Container Image

Published image:

```sh
docker pull ghcr.io/python-roborock/local_roborock_server:latest
```

---

## Contributing

If you would like to contribute, help in these areas is especially welcome:

1. Code is always welcome that you have fully tested.
2. Video walkthroughs and setup tutorials.
3. Documentation improvements and network configuration guides.

---

## Acknowledgements

- [Dennis Giese (@dgiese)](https://dontvacuum.me/) whose research and papers inspired much of the work on reverse-engineering Roborock vacuums.
- [Sören Beye (@Hypfer)](https://github.com/Hypfer) creator of [Valetudo](https://valetudo.cloud/), whose work on cloud-free vacuum control has been foundational for this whole space.
- [@rovo89](https://github.com/rovo89) who has been VERY helpful through this process, giving lots of tips and advice.
- [python-miio](https://github.com/rytilahti/python-miio) - Their repo was the basis for a lot of python-roborock's logic.
- [@humbertogontijo](https://github.com/humbertogontijo) who first created the python-roborock repo.
- [@allenporter](https://github.com/allenporter) who has taken up a significant role in the maintenance of the python-roborock library as well as the Roborock integration. The improvements Allen has made to the repository cannot be overstated.
- [@rccoleman](https://github.com/rccoleman) who was the first beta tester and helped work out some kinks!

---

## Support the Project

If this repository worked for you, consider giving it a star on GitHub to help others find it!

If you are purchasing a Roborock device and want to support continued development, consider using an affiliate link:

[![Amazon Affiliate][badge-amazon]][link-amazon]
[![Roborock Affiliate][badge-roborock-affiliate]][link-roborock-affiliate]

Direct donations:

[![Buy Me a Coffee][badge-bmac]][link-bmac]
[![PayPal][badge-paypal]][link-paypal]

---

## Disclaimer

This software is provided "as is", without warranty of any kind. Running this stack involves modifying how your Roborock vacuum communicates with the network. You are solely responsible for any damage to your hardware, data loss, network exposure, or other consequences. Use at your own risk. This project is not affiliated with, endorsed by, or sponsored by Roborock.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

[link-bmac]: https://buymeacoffee.com/lashl
[badge-bmac]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-yellow?style=for-the-badge&logo=buymeacoffee&logoColor=black
[link-paypal]: https://paypal.me/LLashley304
[badge-paypal]: https://img.shields.io/badge/PayPal-donate-00457C?style=for-the-badge&logo=paypal&logoColor=white
[link-roborock-discount]: https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3D1%252Fp%252BWrcqT1xRYq8L%252BUYzTWBIY60X%252B2PG0yz8rsSeSmY%253D
[badge-roborock-discount]: https://img.shields.io/badge/Roborock-5%25%20Off-C00000?style=for-the-badge
[link-roborock-affiliate]: https://roborock.pxf.io/B0VYV9
[badge-roborock-affiliate]: https://img.shields.io/badge/Roborock-affiliate-B22222?style=for-the-badge
[link-amazon]: https://amzn.to/4cx8zg3
[badge-amazon]: https://img.shields.io/badge/Amazon-affiliate-FF9900?style=for-the-badge&logo=amazon&logoColor=white
[link-ghcr]: https://github.com/python-roborock/local_roborock_server/pkgs/container/local_roborock_server
[badge-ghcr]: https://img.shields.io/badge/GHCR-local_roborock_server-blue?logo=github
