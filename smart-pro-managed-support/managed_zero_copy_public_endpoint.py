"""Read-only local-public-key discovery for the paired Smart Pro System app.

Accessible only from the Home Assistant host gateway. Never accepts remote
credentials, sends private material, creates Managed nodes, or starts MeshAgent.
The strict peer IP is based on HA's documented internal gateway topology.
"""
import json
import os
import stat
import time
from pathlib import Path
from managed_zero_copy_receiver import prepare_receiver

OFFER_PATH = Path("/share/smart-pro-system/managed-enrollment-offer.json")
HOST_GATEWAY_PEER = "172.30.32.1"
MAX_SIZE = 2048

def public_receiver_offer(peer_ip, policy_snapshot, existing_identity, arch,
                          *, offer_path=OFFER_PATH, key_path=None, now=None):
    now = int(time.time() if now is None else now)
    # This endpoint must not be callable via Supervisor ingress or other add-ons.
    if peer_ip != HOST_GATEWAY_PEER:
        return None
    if arch not in ("amd64", "aarch64") or existing_identity is not None:
        return None
    if not isinstance(policy_snapshot, dict) or policy_snapshot.get("allowed_local") is not True:
        return None
    policy = policy_snapshot.get("policy")
    if not isinstance(policy, dict):
        return None
    iid = str(policy.get("installation_id") or "").strip().upper()
    if not iid or policy.get("manual_pause") is True:
        return None
    try:
        path = Path(offer_path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not (0 < info.st_size <= MAX_SIZE):
            return None
        offer = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    kwargs = {"now": now}
    if key_path is not None:
        kwargs["key_path"] = key_path
    public = prepare_receiver(offer, iid, **kwargs)
    if public is None:
        return None
    return {
        "contract": "smart-pro-managed-zero-copy-receiver-public-v1",
        "installation_id": iid,
        "request_ref": public["request_ref"],
        "receiver_public_key_hex": public["public_key_hex"],
        "architecture": arch,
        "expires_at": int(offer["expires_at"]),
        "read_only": True,
        "claim_authorized": False,
        "identity_created": False,
        "runtime_authorized": False,
        "technician_access_granted": False,
    }
