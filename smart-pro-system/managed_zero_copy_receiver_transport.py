"""Narrow Supervisor-pinned local discovery for Managed receiver public key.

No user-supplied URL, redirect handling, port mapping, credential transfer,
add-on start, identity claim, or MeshAgent operation. The Supervisor token is
sent ONLY to the literal internal Supervisor hostname.
"""
import http.client
import ipaddress
import json
import os
import re
from managed_zero_copy_device_proof import build_receiver_binding_proof

ADDON_SLUG = "4e9b161d_smart_pro_managed_support"
PUBLIC_ENDPOINT = "/internal/zero-copy/receiver-public"
INTERNAL_NETWORK = ipaddress.ip_network("172.30.32.0/23")
PUBLIC_CONTRACT = "smart-pro-managed-zero-copy-receiver-public-v1"
MAX_READ = 4096
PORT = 8098


def validated_ip_from_supervisor(reply):
    if not isinstance(reply, dict) or reply.get("result") != "ok":
        return None
    data = reply.get("data")
    if (not isinstance(data, dict) or data.get("slug") != ADDON_SLUG
            or data.get("state") != "started"
            or data.get("ingress_port") != PORT
            or data.get("host_network") is not False):
        return None
    raw = data.get("ip_address")
    if not isinstance(raw, str):
        return None
    try:
        parsed = ipaddress.ip_address(raw)
        if (parsed.version != 4 or parsed not in INTERNAL_NETWORK
                or raw in ("172.30.32.0", "172.30.32.1", "172.30.32.2", "172.30.33.255")):
            return None
    except ValueError:
        return None
    return str(parsed)


def validate_public_receiver(packet, offer, iid, architecture, now):
    if not isinstance(packet, dict) or not isinstance(offer, dict):
        return None
    if (packet.get("contract") != PUBLIC_CONTRACT
            or packet.get("installation_id") != iid
            or packet.get("request_ref") != offer.get("request_ref")
            or packet.get("expires_at") != offer.get("expires_at")
            or packet.get("architecture") != architecture
            or packet.get("read_only") is not True
            or packet.get("claim_authorized") is not False
            or packet.get("identity_created") is not False
            or packet.get("runtime_authorized") is not False
            or packet.get("technician_access_granted") is not False
            or type(packet.get("expires_at")) is not int
            or packet["expires_at"] <= now):
        return None
    pub = packet.get("receiver_public_key_hex")
    if not isinstance(pub, str) or re.fullmatch(r"[a-f0-9]{64}", pub) is None:
        return None
    return pub


def _json_get(host, port, path, headers=None, *, connection_factory=None):
    factory = connection_factory or http.client.HTTPConnection
    connection = factory(host, port, timeout=3)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        if response.status != 200 or not str(response.getheader("Content-Type", "")).lower().startswith("application/json"):
            return None
        raw = response.read(MAX_READ + 1)
        if len(raw) > MAX_READ:
            return None
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, TimeoutError, UnicodeError, ValueError,
            http.client.HTTPException):
        return None
    finally:
        connection.close()


def get_receiver_public(offer, iid, architecture, *, supervisor_token=None,
                        connection_factory=None, now=None):
    import time
    now = int(time.time() if now is None else now)
    token = supervisor_token if supervisor_token is not None else os.environ.get("SUPERVISOR_TOKEN", "")
    if (not isinstance(token, str) or not token or len(token) > 4096
            or not isinstance(offer, dict)
            or offer.get("contract") != "smart-pro-managed-zero-copy-local-offer-v1"
            or offer.get("installation_id") != iid
            or offer.get("status") != "pending_handoff"
            or offer.get("read_only") is not True
            or offer.get("claim_authorized") is not False
            or offer.get("identity_created") is not False
            or offer.get("runtime_authorized") is not False
            or offer.get("technician_access_granted") is not False
            or type(offer.get("expires_at")) is not int
            or offer["expires_at"] <= now
            or architecture not in ("amd64", "aarch64")):
        return None
    supervisor = _json_get("supervisor", 80,
                           f"/addons/{ADDON_SLUG}/info",
                           {"Authorization": "Bearer " + token},
                           connection_factory=connection_factory)
    target_ip = validated_ip_from_supervisor(supervisor)
    if target_ip is None:
        return None
    # Deliberately no Supervisor authorization forwarded to another add-on.
    packet = _json_get(target_ip, PORT, PUBLIC_ENDPOINT,
                       {"Accept": "application/json"},
                       connection_factory=connection_factory)
    return validate_public_receiver(packet, offer, iid, architecture, now)


def build_pinned_receiver_proof(offer, iid, architecture, *,
                                key_path=None, supervisor_token=None,
                                connection_factory=None, now=None):
    public = get_receiver_public(offer, iid, architecture,
                                 supervisor_token=supervisor_token,
                                 connection_factory=connection_factory, now=now)
    if public is None:
        return None
    kw = {"now": now}
    if key_path is not None:
        kw["key_path"] = key_path
    return build_receiver_binding_proof(offer, iid, public, architecture, **kw)
