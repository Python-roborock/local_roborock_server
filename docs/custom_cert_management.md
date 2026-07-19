# Custom certificate management

Use this if you do not want Cloudflare DNS-01 automation and instead want to provide the TLS certificate files yourself during [Installation](installation.md).

Check [Tested Vacuums](tested_vacuums.md) first. This is the right path when your vacuum works better with a certificate chain other than the built-in `zerossl` or `actalis` options, or when you already have certs you want to reuse. Older vacuums are less likely to support certs from places like LetsEncrypt. Newer vacuums may work, but this is not tested. Please report back any findings you have via a PR to the tested_vacuums page.

## Required Config

Set the TLS section in `config.toml` to the provided-certificate mode:

```toml
[tls]
mode = "provided"
cert_file = "/data/certs/fullchain.pem"
key_file = "/data/certs/privkey.pem"
```

If you use the setup wizard and answer no to Cloudflare, it will write these values for you. You then need to place your certificate files at `data/certs/fullchain.pem` and `data/certs/privkey.pem` before starting the stack.

## Which hostname to cover

The vacuum uses the **stack hostname** (the `api-...` value from `config.toml` → `network.stack_fqdn`) for both SNI in ClientHello and hostname verification against the certificate. It does **not** use the value of the `r` field from the cfgwifi packet (which is the stack hostname with `api-` stripped).

In practice this means:

- A **single-domain** certificate covering only `api-roborock.example.com` is sufficient.
- You do **not** need a SAN for the stripped hostname `roborock.example.com`, nor a wildcard.
- DNS resolution for the stripped hostname is also unnecessary — only `api-roborock.example.com` needs to resolve to the server's LAN IP.

If you are migrating from a multi-domain cert and want to switch to a cheaper single-domain CA (e.g. Actalis free DV quota which issues one hostname per EAB), issue for the stack hostname only.

See [Tested Vacuums](tested_vacuums.md) for a diagnosis flowchart when the vacuum rejects a cert.

## Related Docs

- [Installation](installation.md)
- [Cloudflare setup](cloudflare_setup.md)
- [Onboarding](onboarding.md)
- [Tested Vacuums](tested_vacuums.md)
