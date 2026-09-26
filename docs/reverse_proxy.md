# Reverse Proxy

Reverse proxy support is mainly useful when public or LAN clients reach the stack on different ports than the backend listeners, or when you already run a proxy (Caddy, Traefik, nginx) that owns your TLS certificates. I do not use a reverse proxy for my own setup, so please report any issues.

Whatever endpoint a vacuum or the Roborock app connects to **must present a valid, trusted TLS certificate** — vacuums refuse to connect otherwise. That endpoint can be the server itself or the proxy in front of it; the rest of this page is about choosing which one terminates TLS.

## Advertised Ports

Use these when the proxy maps public ports to different backend listener ports. The server binds the `*_port` listeners but advertises the `advertised_*` ports to the Roborock app, vacuums, and Home Assistant.

```toml
[network]
stack_fqdn = "api-roborock.example.com"
bind_host = "0.0.0.0"

# Backend listener ports.
https_port = 555
mqtt_tls_port = 8881

# Public ports advertised to clients.
advertised_https_port = 443
advertised_mqtt_tls_port = 8883
```

With that config the server listens on `*:555` / `*:8881`, but responses advertise:

- `https://api-roborock.example.com`
- `ssl://api-roborock.example.com:8883`

## TLS Termination Modes

### `local_tls` (default) — the server terminates TLS

The server runs its own TLS listeners; the proxy forwards encrypted traffic to them. The proxy must preserve the original `Host` header. For MQTT, use a TCP/stream proxy (a normal HTTP location is not enough because MQTT is not HTTP).

If you already manage certificates in the proxy, point the server at the same certificate chain so both present an identical, valid cert:

```toml
[network]
listener_mode = "local_tls"

[tls]
mode = "provided"
cert_file = "/path/to/proxy/fullchain.pem"
key_file = "/path/to/proxy/privkey.pem"
```

### `external_tls` — the proxy terminates TLS

The proxy terminates TLS and forwards plain HTTP/TCP to the server, which holds no certificates at all. The proxy is responsible for presenting a valid cert to clients.

```toml
[network]
listener_mode = "external_tls"

[tls]
# No certificate material is required in this mode.
mode = "provided"
```

Requirements:

- HTTPS: the proxy terminates TLS, preserves the original `Host` header, and forwards plain HTTP to `https_port`.
- MQTT: a **stream / layer-4** proxy must terminate TLS with a valid cert on the public MQTT port and forward plain TCP to `mqtt_tls_port`. An HTTP reverse proxy alone cannot do this.
- `tls.mode` must be `"provided"`. `external_tls` never issues or renews certificates, so `cloudflare_acme` is rejected to avoid a silent no-op.

> **Do not expose the backend ports publicly.** In `external_tls` the server speaks plain, unencrypted HTTP and MQTT on `https_port` / `mqtt_tls_port`. Bind them to localhost or an internal Docker network reachable only by the proxy — never publish them to the host or the internet. With the bundled `compose.yaml`, the `ports:` mappings publish the backend ports; remove or restrict them so only the proxy reaches the server. If you run the proxy in the same Compose project, drop the `ports:` entries entirely and reference the service by name (e.g. `roborock-local-server:555`).
>
> The Docker healthcheck defaults to `https`. In `external_tls` set `ROBOROCK_SERVER_HEALTHCHECK_SCHEME=http` so it probes the plain-HTTP listener.

Example Caddy config (HTTPS via the standard reverse proxy, MQTT via the [layer4 plugin](https://github.com/mholt/caddy-l4)):

```caddyfile
api-roborock.example.com {
    reverse_proxy roborock-local-server:555
}
```

```caddyfile
# layer4 app (Caddy JSON / global block) terminating MQTT TLS on 8883
:8883 {
    route {
        tls
        proxy {
            upstream roborock-local-server:8881
        }
    }
}
```

## Trusted Proxies and Onboarding

When onboarding a new vacuum, the server links its MQTT login to the `/region` and `/nc` HTTP requests that came just before it. It does this by checking that both came from the same IP address. With a proxy in front of the server, that check fails: the HTTP requests show the proxy's address and MQTT may show a different one (e.g. a Kubernetes node doing SNAT).

List every proxy or SNAT address that forwards traffic to the server in `trusted_proxies` (IPs or CIDR networks):

```toml
[network]
# Default: ["127.0.0.1", "::1"]
trusted_proxies = ["10.42.0.0/16", "10.1.1.10"]
```

- **HTTP:** requests from a trusted proxy use the `X-Forwarded-For` header to find the vacuum's real IP. The header is ignored from any other client, so it can't be spoofed. Traefik and Caddy set it by default; nginx needs `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
- **MQTT:** during an active onboarding session, a new MQTT login is normally accepted only from the IP that completed `/region` and `/nc`. A connection from a trusted proxy is also accepted, because a stream proxy hides the vacuum's address. The session must still have completed `/region` and `/nc`, and the first publish must be on that vacuum's topic.

> Only list addresses that are actually proxies. Any client that connects from a trusted address during onboarding can claim the vacuum being onboarded. Keep onboarding windows short, and turn off new connections when you are not adding a device.

## What Is Not Supported

Path-prefix hosting is not supported. The Roborock protocol and the admin API expect the stack at the hostname root, for example `/region`, `/api/...`, and `/admin`.

`external_tls` is intended for Docker / standalone deployments. The Home Assistant add-on always terminates its own TLS and does not expose this option.
