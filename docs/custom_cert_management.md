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

### Docker Container Paths vs Host Paths

Paths in `config.toml` are evaluated **inside the container**.

With the default `compose.yaml`, the host directory `./data` is mounted to `/data` in the container (`- ./data:/data`).

- Place your certificate files on the host inside the repository's `data/certs/` directory (e.g. `./data/certs/fullchain.pem` and `./data/certs/privkey.pem`).
- In `config.toml`, refer to them using their container path: `/data/certs/fullchain.pem` and `/data/certs/privkey.pem`.
- **Do not** specify host-absolute paths (such as `/etc/letsencrypt/live/...` or `~/.acme.sh/...`) in `config.toml` unless you also mount those directories as volumes in `compose.yaml`.
- If a path is specified that does not exist inside the container, the server will exit on startup with:
  ```text
  FileNotFoundError: Provided TLS cert not found: <path>
  ```
  Because `docker compose up -d` starts the container in the background, this error will not appear on your terminal directly. If the container stops immediately, inspect the logs:
  ```bash
  docker compose logs roborock-local-server
  ```

If you manage certificates externally on the host (for example via `acme.sh` or `certbot`), either:
1. Configure your host tool's deploy/copy hook to write certificates to `./data/certs/`, or
2. Add an additional volume mount to `compose.yaml` (e.g. `- /etc/letsencrypt:/etc/letsencrypt:ro`) and set `cert_file` to the corresponding container path.

## Related Docs

- [Installation](installation.md)
- [Cloudflare setup](cloudflare_setup.md)
- [Onboarding](onboarding.md)

