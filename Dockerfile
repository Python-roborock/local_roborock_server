FROM python:3.11-slim

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

EXPOSE 443 8883

CMD ["roborock-local-server", "serve", "--config", "/app/config.toml"]
