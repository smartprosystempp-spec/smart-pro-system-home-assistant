FROM python:3.13-alpine
ARG BUILD_VERSION=0.2.0
ARG BUILD_ARCH=amd64
LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/smart-pro-access-qa
COPY app.py /opt/smart-pro-access-qa/app.py
COPY ha_readback.py /opt/smart-pro-access-qa/ha_readback.py
RUN chmod 0444 /opt/smart-pro-access-qa/app.py /opt/smart-pro-access-qa/ha_readback.py \
  && addgroup -S qauser && adduser -S qauser -G qauser
USER qauser
CMD ["python3", "-B", "/opt/smart-pro-access-qa/app.py"]
