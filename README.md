# Roborock Local Server

[![GHCR][badge-ghcr]][link-ghcr]

The best way to support this project is the next time you are buying a Roborock device come back here and use one of my affiliate links where I will receive a commission.

[![Amazon Affiliate][badge-amazon]][link-amazon]
[![Roborock Affiliate][badge-roborock-affiliate]][link-roborock-affiliate]
[![Roborock 5 Off][badge-roborock-discount]][link-roborock-discount]

You can also support via BMAC or paypal:

[![Buy Me a Coffee][badge-bmac]][link-bmac]
[![PayPal][badge-paypal]][link-paypal]

Roborock Local Server is a private Roborock HTTPS and MQTT stack you run on your own system.

This service is meant to stay private. Point your own DNS at your server's LAN IP. If you want this to work away from your home network, the server does handle auth and lets you disable new devices from connecting. BUT there is ALWAYS a risk when you make a self-hosted service publicly accessible, so please only do it if you know what you are doing. If your workflow is fine with local-only access, that will always be better. If you find any vulnerabilities, please let me know.

## Container Image

Published image:

```sh
docker pull ghcr.io/python-roborock/local_roborock_server:latest
```

## Contributing

If you would like to contribute there are a few ways that would be great!

1. Code is always welcome that you have fully tested.
2. Video walkthroughs of how to actually set this up would be great.
3. Documentation. I hate documentation and it's something I find myself often pushing off to AI so that I can focus more on the harder problems. But I find that human written documentation always 'feels' better.

## Requirements

- a domain you control
- a place to run the stack on your LAN
- either Docker Compose or a Home Assistant installation that supports add-ons
- a second machine for onboarding later
- a Cloudflare API token with DNS edit access for the zone if you want automatic certificate renewal

## Getting Started

Start here if this is your first time setting up the stack:

1. [Installation](docs/installation.md) for the shared requirements, network setup, and Docker Compose install path.
2. [Home Assistant](docs/home_assistant.md) if you want to install the stack as a Home Assistant add-on instead of Docker Compose.
3. [Cloudflare setup](docs/cloudflare_setup.md) if you want Cloudflare DNS-01 auto-renew for certificates.
4. [Onboarding](docs/onboarding.md) to pair a vacuum from a second machine after the server is running.

Before choosing a certificate path, check [Tested vacuums](docs/tested_vacuums.md). Different models do not all accept the same certificate chains. For most users, start with ZeroSSL. Use Actalis mainly for older vacuums or models that are already known to trust that chain more reliably.

Additional docs:

- [Docs index](docs/index.md)
- [Known limitations](docs/known_limitations.md)
- [Tested vacuums](docs/tested_vacuums.md)
- [Home Assistant](docs/home_assistant.md) for the add-on install path and Home Assistant integration rewiring
- [Using the Roborock App](docs/roborock_app.md)
- [Custom MQTT](docs/custom_mqtt.md)
- [Custom certificate management](docs/custom_cert_management.md)



## Acknowledgements

- [Dennis Giese (@dgiese)](https://dontvacuum.me/) whose research and papers inspired much of the work on reverse-engineering Roborock vacuums
- [Sören Beye (@Hypfer)](https://github.com/Hypfer) creator of [Valetudo](https://valetudo.cloud/), whose work on cloud-free vacuum control has been foundational for this whole space.
- [@rovo89](https://github.com/rovo89) who has been VERY helpful through this process, giving lots of tips and advice.
- [python-miio](https://github.com/rytilahti/python-miio) - Their repo was the basis for a lot of python-roborock's logic.
- [@humbertogontijo](https://github.com/humbertogontijo) who first created the python-roborock repo.
- [@allenporter](https://github.com/allenporter) who has taken up a significant role in the maintenance of the python-roborock library as well as the Roborock integration. The improvements Allen has made to the repository cannot be overstated.
- [@rccoleman](https://github.com/rccoleman) who was the first beta tester and helped work out some kinks!

## Disclaimer

This software is provided "as is", without warranty of any kind. Running this stack involves modifying how your Roborock vacuum communicates with the network. You are solely responsible for any damage to your hardware, data loss, network exposure, or other consequences. Use at your own risk. This project is not affiliated with, endorsed by, or sponsored by Roborock.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

[link-bmac]: https://buymeacoffee.com/lashl
[badge-bmac]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-yellow?style=for-the-badge&logo=buymeacoffee&logoColor=black
[link-paypal]: https://paypal.me/LLashley304
[badge-paypal]: https://img.shields.io/badge/PayPal-donate-00457C?style=for-the-badge&logo=paypal&logoColor=white
[link-roborock-discount]: https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3DEQe6p1jdZczHEN4Q0nbsG9sZRm0RK1gW5eSM%252FCzcW4Q%253D
[badge-roborock-discount]: https://img.shields.io/badge/Roborock-5%25%20Off-C00000?style=for-the-badge
[link-roborock-affiliate]: https://roborock.pxf.io/B0VYV9
[badge-roborock-affiliate]: https://img.shields.io/badge/Roborock-affiliate-B22222?style=for-the-badge
[link-amazon]: https://amzn.to/4cx8zg3
[badge-amazon]: https://img.shields.io/badge/Amazon-affiliate-FF9900?style=for-the-badge&logo=amazon&logoColor=white
[link-ghcr]: https://github.com/python-roborock/local_roborock_server/pkgs/container/local_roborock_server
[badge-ghcr]: https://img.shields.io/badge/GHCR-local_roborock_server-blue?logo=github
