FROM alpine:latest

ARG BUILD_VERSION="0.0.0"
ENV ADDON_VERSION="${BUILD_VERSION}"

RUN apk add --no-cache bash curl ca-certificates python3 py3-boto3 py3-pynacl

COPY run.sh /
COPY index.html /
COPY style.css /
COPY script.js /
COPY customer_ui.css /
COPY customer_ui.js /
COPY recovery_verifier.py /
COPY recovery_stage.py /
COPY ha_credential_handoff_qa_agent.py /
COPY sp_customer_admin_access.py /
COPY sp_customer_admin_access.js /
COPY ha_readback.py /
COPY core_session_qa.py /
COPY app.py /
COPY sps_http_security.py /

# Additive UI inclusion at build time: the original index.html and business
# logic remain byte-identical in the repository; fail the build if not included.
RUN sed -i \
  -e 's@</head>@<link rel="stylesheet" href="customer_ui.css?v=3035"></head>@' \
  -e 's@</body>@<script defer src="customer_ui.js?v=3035"></script></body>@' \
  /index.html \
  && grep -q 'customer_ui.css?v=3035' /index.html \
  && grep -q 'customer_ui.js?v=3035' /index.html \
  && chmod a+x /run.sh

CMD [ "/run.sh" ]
