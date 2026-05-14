# Cloudflare setup

Use this optional guide if you want Cloudflare DNS-01 certificate issuance and automatic renewal during [Installation](installation.md). If you would rather provide your own certificate files, see [Custom certificate management](custom_cert_management.md).

Cloudflare is used for DNS-01 validation against your zone so that the stack can request and renew certificates automatically. The ACME CA is configurable. The default is ZeroSSL, and Home Assistant users can also switch to `actalis` if an older vacuum trusts that chain more reliably.

If you choose `acme_server = actalis`, you must also provide `acme_eab_kid` and `acme_eab_hmac_key` from your Actalis ACME account. Generated configs store those in separate secret files instead of embedding them directly in `config.toml`.

The automated issuance shape differs by ACME CA:

- `zerossl` requests `base_domain` plus `*.base_domain`
- `actalis` requests only `stack_fqdn`

## Create the Cloudflare Token

Create a user API token in Cloudflare for the zone you will use in `tls.base_domain`.

1. Sign in to the Cloudflare dashboard.
2. Open `My Profile` -> `API Tokens`.
3. Select `Create Token`.
4. Start from the `Edit Zone DNS` template.
5. Give the token a clear name such as `roborock-local-server-example-com`.
6. Scope the token to only the zone you will use for this project.
7. Review the summary and create the token.
8. Copy the token secret immediately. Cloudflare only shows it once.

For this project, keep the token limited to the single zone you are using. Do not use a global API key.

## Related Docs

- [Installation](installation.md)
- [Custom certificate management](custom_cert_management.md)
- [Onboarding](onboarding.md)
