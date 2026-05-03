ARG BUILD_ARCH=aarch64
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base:latest

RUN apk add --no-cache python3 py3-pip tailscale ca-certificates

COPY rootfs /

RUN python3 -m venv /opt/ha_expert/venv \
    && /opt/ha_expert/venv/bin/pip install --no-cache-dir aiohttp
