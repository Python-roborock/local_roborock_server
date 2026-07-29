# Roborock Local Server
[![GHCR][badge-ghcr]][link-ghcr]

## Introduction

**Roborock Local Server** is a private, self-hosted alternative to Roborock's cloud infrastructure. This project enables you to run a complete HTTPS and MQTT stack on your own network, giving you full control over your Roborock vacuum's communication and operations without relying on external cloud services. While the vacuum can still connect to some Roborock's owned services, this stack provides all necessary functionality for your vacuum to work with almost no compromise. 

After installation, you can block internet access entirely and the vacuum will continue to function on your local network. The stack is also fully compatible with Home Assistant and the Roborock app, so you can seamlessly repoint them to your local server for integrated control.

## Support
If you appreciate this project, the best way to support it is by using my affiliate links when purchasing a Roborock device. It helps support development at no cost to you.

[![Amazon Affiliate][badge-amazon]][link-amazon] [![Roborock Affiliate][badge-roborock-affiliate]][link-roborock-affiliate]

Alternatively, you can also donate directly to support the project:

[![Buy Me a Coffee][badge-bmac]][link-bmac] [![PayPal][badge-paypal]][link-paypal]


For those who want to contribute in other ways, here are things that would be helpful:

- Tested code contributions are always welcome.
- Video walkthroughs showing how to set this up would be greatly appreciated.
- Documentation is also helpful. I often put it off to AI so I can focus on the harder problems, but human-written documentation always feels better.
- Lastly, if you have a vacuum that is not yet tested with this stack, testing it and reporting your results would be very helpful to the community. See [Tested Vacuums](tested_vacuums.md) for more information.

## Getting Started

For the installation process, go to [installation.md](installation.md). That guide walks through the initial setup, required components, and the order in which to configure each part of the stack so you can get up and running with minimal friction.

## Additional docs

- [Tested vacuums](docs/tested_vacuums.md) - List of vacuums that have been tested with this stack
- [Known limitations](docs/known_limitations.md) - Information about known issues with specific vacuum models
- [Home Assistant](docs/home_assistant.md) - for the add-on install path and Home Assistant integration rewiring
- [Repointing the Roborock App](docs/roborock_app.md) - How to repoint the Roborock app to your local server
- [Updating](docs/updating.md) - Procedures for updating an existing installation
- [Custom MQTT](docs/custom_mqtt.md) - Instructions for using a custom MQTT broker
- [Custom certificate management](docs/custom_cert_management.md) - Guidance for using your own certificate files


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
[link-roborock-discount]: https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3D1%252Fp%252BWrcqT1xRYq8L%252BUYzTWBIY60X%252B2PG0yz8rsSeSmY%253D
[badge-roborock-discount]: https://img.shields.io/badge/Roborock-5%25%20Off-C00000?style=for-the-badge
[link-roborock-affiliate]: https://roborock.pxf.io/B0VYV9
[badge-roborock-affiliate]: https://img.shields.io/badge/Roborock-affiliate-B22222?style=for-the-badge
[link-amazon]: https://amzn.to/4cx8zg3
[badge-amazon]: https://img.shields.io/badge/Amazon-affiliate-FF9900?style=for-the-badge&logo=amazon&logoColor=white
[link-ghcr]: https://github.com/python-roborock/local_roborock_server/pkgs/container/local_roborock_server
[badge-ghcr]: https://img.shields.io/badge/GHCR-local_roborock_server-blue?logo=github
