FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/python-roborock/local_roborock_server" \
  org.opencontainers.image.description="Private Roborock HTTPS and MQTT stack for local LAN use" \
  org.opencontainers.image.licenses="MIT"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    mosquitto \
    openssl \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/acme.sh \
  && curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz \
  | tar -xz --strip-components=1 -C /opt/acme.sh \
  && chmod +x /opt/acme.sh/acme.sh \
  && ln -sf /opt/acme.sh/acme.sh /usr/local/bin/acme.sh

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir /app

EXPOSE 555 8881

CMD ["python", "-m", "roborock_local_server.container_entrypoint"]
