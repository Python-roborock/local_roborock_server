# Home Assistant

Use this after [Installation](installation.md) and [Onboarding](onboarding.md) if you want Home Assistant to talk to your local stack.

To use this server with Home Assistant, edit your config entry at `config/.storage/core.config_entries`.

Find `"roborock.com"` and replace the endpoint values with your local stack URLs:

- `base_url` -> `https://api-roborock.example.com:555`
- `"a"` -> `https://api-roborock.example.com:555`
- `"l"` -> `https://api-roborock.example.com:555`
- `"m"` -> `ssl://mqtt-roborock.example.com:8881`

If you changed `network.https_port` or `network.mqtt_tls_port`, use those values instead.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)
