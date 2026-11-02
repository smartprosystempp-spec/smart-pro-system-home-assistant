FROM alpine:latest

ARG BUILD_VERSION="0.0.0"
ENV ADDON_VERSION="${BUILD_VERSION}"

RUN apk add --no-cache bash curl ca-certificates python3 py3-boto3 py3-pynacl

COPY run.sh /
COPY index.html /
COPY style.css /
COPY script.js /
COPY recovery_verifier.py /
COPY recovery_stage.py /
COPY ha_credential_handoff_qa_agent.py /
COPY sp_customer_admin_access.py /
COPY sp_customer_admin_access.js /
COPY ha_readback.py /
COPY core_session_qa.py /
COPY app.py /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
