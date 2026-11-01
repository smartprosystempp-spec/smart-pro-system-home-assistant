"""Customer support admin confirmation: read-only Stage-1 test policy.

This is a TEST-ONLY, NOT-RUNTIME module. It is deliberately outside all
Home Assistant add-on directories and cannot create accounts or transfer
credentials. The caller must retrieve `ha_users` server-side from the local
Home Assistant authenticated admin proxy, NEVER from a Portal/browser payload.

Do not wire this function into a production action without an independent
authenticated, bounded customer consent and one-time request system.
"""

import hmac
import re
from collections.abc import Mapping, Sequence

TRUSTED_INGRESS_PEER = "172.30.32.2"
INSTALLATION_RE = re.compile(r"ID-[0-9]{1,12}\\Z")
USER_ID_RE = re.compile(r"[A-Za-z0-9_-]{16,128}\\Z")


def _denied(reason):
    return {"eligible_for_next_step": False, "reason_code": reason}


def evaluate_local_admin_preflight(
    *,
    peer_ip,
    ingress_headers,
    ha_users,
    paired_installation_id,
    requested_installation_id,
):
    """Classify HA ingress administrator identity, without granting anything.

    `peer_ip` MUST come from the socket address (not X-Forwarded-For).
    `ingress_headers` MUST be those received on the internal Supervisor ingress
    request, which strips and reissues X-Remote-User-*.
    `ha_users` MUST be obtained independently through a trusted local
    Home Assistant admin API read. Neither the browser nor the Portal can
    supply or override its content.

    Returning eligible is NOT consent, does NOT create a one-time approval,
    and does NOT permit any account/credential operation.
    """
    if peer_ip != TRUSTED_INGRESS_PEER:
        return _denied("not_supervisor_ingress")
    if not isinstance(ingress_headers, Mapping):
        return _denied("ingress_headers_invalid")
    headers = {str(k).lower(): v for k, v in ingress_headers.items()}

    ingress_path = headers.get("x-ingress-path")
    if not isinstance(ingress_path, str) or not re.fullmatch(
        r"/api/hassio_ingress/[A-Za-z0-9_-]{8,256}/?", ingress_path
    ):
        return _denied("ingress_session_unverified")

    identity = headers.get("x-remote-user-id")
    if not isinstance(identity, str) or not USER_ID_RE.fullmatch(identity):
        return _denied("ha_identity_missing")

    if not isinstance(paired_installation_id, str) or not INSTALLATION_RE.fullmatch(
        paired_installation_id
    ):
        return _denied("installation_binding_missing")
    if not isinstance(requested_installation_id, str) or not INSTALLATION_RE.fullmatch(
        requested_installation_id
    ):
        return _denied("installation_request_invalid")
    if not hmac.compare_digest(paired_installation_id, requested_installation_id):
        return _denied("installation_mismatch")

    if (not isinstance(ha_users, Sequence) or isinstance(ha_users, (str, bytes))
            or len(ha_users) == 0 or len(ha_users) > 500):
        return _denied("ha_user_readback_invalid")
    matches = [
        user for user in ha_users
        if isinstance(user, Mapping) and user.get("id") == identity
    ]
    if len(matches) != 1:
        return _denied("ha_identity_not_found_or_ambiguous")
    user = matches[0]
    if user.get("system_generated") is not False:
        return _denied("ha_service_identity_not_allowed")
    if user.get("is_active") is not True:
        return _denied("ha_user_inactive")

    groups = user.get("group_ids")
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        return _denied("ha_groups_invalid")
    if user.get("is_owner") is not True and "system-admin" not in groups:
        return _denied("ha_user_not_administrator")

    return {
        "eligible_for_next_step": True,
        "reason_code": "ha_admin_identity_verified_read_only",
    }
