FROM python:3.13-alpine
ARG BUILD_VERSION=0.6.0
ARG BUILD_ARCH=amd64
LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir "PyNaCl==1.6.2"
WORKDIR /opt/smart-pro-access-qa
COPY app.py /opt/smart-pro-access-qa/app.py
COPY ha_readback.py /opt/smart-pro-access-qa/ha_readback.py
COPY probe.js /opt/smart-pro-access-qa/probe.js
COPY consent_qa.py /opt/smart-pro-access-qa/consent_qa.py
COPY core_session_qa.py /opt/smart-pro-access-qa/core_session_qa.py
COPY persistent_qa.py /opt/smart-pro-access-qa/persistent_qa.py
COPY credential_lab_qa.py /opt/smart-pro-access-qa/credential_lab_qa.py
COPY secure_handoff_qa.py /opt/smart-pro-access-qa/secure_handoff_qa.py
RUN chmod 0444 /opt/smart-pro-access-qa/*.py \
  && addgroup -S qauser && adduser -S qauser -G qauser
USER qauser
CMD ["python3", "-B", "/opt/smart-pro-access-qa/app.py"]
