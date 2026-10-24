FROM alpine:3.22

ARG BUILD_VERSION="0.0.0"
ENV APP_VERSION="${BUILD_VERSION}"

RUN apk add --no-cache \
      iproute2 \
      python3 \
      wireguard-go \
      wireguard-tools

COPY run.sh /
COPY tunnel.py /
RUN chmod 0755 /run.sh

CMD [ "/run.sh" ]
