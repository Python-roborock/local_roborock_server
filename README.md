# Roborock Local Server
The best way to support this project is the next time you are buying a Roborock device come back here and use one of my affiliate links where I will receive a commission.

[![Amazon Affiliate][badge-amazon]][link-amazon]
[![Roborock 5 Off][badge-roborock-discount]][link-roborock-discount]
[![Roborock Affiliate][badge-roborock-affiliate]][link-roborock-affiliate]


You can also support via BMAC or paypal:

[![Buy Me a Coffee][badge-bmac]][link-bmac]
[![PayPal][badge-paypal]][link-paypal]

Roborock Local Server is a private Roborock HTTPS and MQTT stack you run on your own system.

This service is meant to stay private. Point your own DNS at your server's LAN IP and do **NOT** expose it directly to the public internet. In its current state it does not handle internet exposure safely enough. For now, keep it on your LAN only. In the future, I plan to reuse Roborock's auth natively which should make everything secure enough.

This project is in VERY EARLY BETA!!! Do not use this repository unless you are sure you know what you are doing and are rather technical.

## Requirements

- Docker with `docker compose`
- `uv`
- a Linux server or Linux VM on your LAN
- a domain you control
- a Cloudflare API token with DNS edit access for the zone if you want automatic certificate renewal

## Getting Started

Start here if this is your first time setting up the stack:

1. [Installation](docs/installation.md) for requirements, network setup, configuration, and starting the stack.
2. [Cloudflare setup](docs/cloudflare_setup.md) if you want Cloudflare DNS-01 auto-renew for certificates.
3. [Onboarding](docs/onboarding.md) to pair a vacuum from a second machine after the server is running.

Additional docs:

- [Docs index](docs/index.md)
- [Tested vacuums](docs/tested_vacuums.md)
- [Home Assistant](docs/home_assistant.md)
- [Using the Roborock App](docs/roborock_app.md)
- [Custom MQTT](docs/custom_mqtt.md)
- [Custom certificate management](docs/custom_cert_management.md)



## Acknowledgements

- [Dennis Giese (@dgiese)](https://dontvacuum.me/) whose research and papers inspired much of the work on reverse-engineering Roborock vacuums
- [@rovo89](https://github.com/rovo89) who has been VERY helpful through this process, giving lots of tips and advice.
- [python-miio](https://github.com/rytilahti/python-miio) - Their repo was the basis for a lot of python-roborock's logic.
- [@humbertogontijo](https://github.com/humbertogontijo) who first created the python-roborock repo.
- [@allenporter](https://github.com/allenporter) who has taken up a significant role in the maintenance of the python-roborock library as well as the Roborock integration. The improvements Allen has made to the repository cannot be overstated.
- [@rccoleman](https://github.com/rccoleman) who was the first beta tester and helped work out some kinks!

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
