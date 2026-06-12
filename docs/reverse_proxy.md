# Reverse Proxy

Reverse proxy support is mainly useful when public or LAN clients reach the stack on different ports than the backend listeners. The server still runs its own TLS listeners for both HTTPS and MQTT/TLS; the proxy forwards traffic to those listeners. I do not use a reverse proxy for my own setup, so please report any issues.

## Supported Layout

Use this when:

- HTTPS reaches the proxy on `443`, then forwards to the stack HTTPS listener such as `555`
- MQTT/TLS reaches a TCP/stream proxy on `8883`, then forwards to the stack MQTT/TLS listener such as `8881`
- the proxy preserves the original `Host` header

Example:

```toml
[network]
stack_fqdn = "api-roborock.example.com"
bind_host = "0.0.0.0"

# Backend listener ports.
https_port = 555
mqtt_tls_port = 8881

# Public ports advertised to the Roborock app, vacuums, and Home Assistant.
advertised_https_port = 443
advertised_mqtt_tls_port = 8883
```

With that config the server listens on `https://*:555` and `ssl://*:8881`, but responses advertise:

- `https://api-roborock.example.com`
- `ssl://api-roborock.example.com:8883`

## Proxy Requirements

For HTTPS admin/API traffic, the proxy must forward the original `Host` header unchanged:

```text
Host: $host
```

For MQTT/TLS, use TCP or stream proxying. A normal HTTP reverse proxy location is not enough because MQTT is not HTTP. The proxy must forward raw TCP from the public MQTT/TLS port to `mqtt_tls_port`.

## What Is Not Supported

Path-prefix hosting is not supported. The Roborock protocol and the admin API expect the stack at the hostname root, for example `/region`, `/api/...`, and `/admin`.

Plain HTTP backends are not supported. If you already manage certificates in a proxy, point `tls.cert_file` and `tls.key_file` at those certificate files so the backend TLS listener uses the same certificate chain.
