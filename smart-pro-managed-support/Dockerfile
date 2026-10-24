FROM debian:bookworm-slim

ARG BUILD_VERSION="3.19.1"
ARG BUILD_ARCH

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY run.sh /run.sh
COPY app.py /opt/smart-pro/app.py
RUN chmod 0755 /run.sh /opt/smart-pro/app.py

ENV SMART_PRO_MANAGED_VERSION="${BUILD_VERSION}" \
    SMART_PRO_MANAGED_ARCH="${BUILD_ARCH}"

LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"

CMD [ "/run.sh" ]
