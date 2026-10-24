FROM alpine:latest

ARG BUILD_VERSION="0.0.0"
ENV ADDON_VERSION="${BUILD_VERSION}"

RUN apk add --no-cache bash curl python3 py3-boto3

COPY run.sh /
COPY index.html /
COPY style.css /
COPY script.js /
COPY app.py /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
