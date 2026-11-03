"""Private zero-copy Managed receiver, crypto only; NOT an enrollment action.

Only a future separately authenticated flow may use the returned in-memory
candidate. This module NEVER creates nodes, persists Managed identity, starts
MeshAgent, enables unattended access or modifies local policy.
"""
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

from nacl.public import PrivateKey, SealedBox
from nacl.exceptions import CryptoError

KEY_CONTRACT = "smart-pro-managed-zero-copy-receiver-key-v1"
ENVELOPE_CONTRACT = "smart-pro-managed-zero-copy-sealed-identity-v1"
CONTENT_CONTRACT = "smart-pro-managed-zero-copy-identity-content-v1"
LOCAL_OFFER_CONTRACT = "smart-pro-managed-zero-copy-local-offer-v1"
PRIVATE_CONTEXT_CONTRACT = "smart-pro-managed-zero-copy-private-delivery-context-v1"
PRIVATE_KEY = Path("/data/managed-zero-copy-receiver-key.json")
IID_RE = re.compile(r"^ID-[0-9]{5}$")
REF_RE = re.compile(r"^SPMZ-[A-F0-9]{32}$")
HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
NODE_RE = re.compile(r"^SPMN-[A-F0-9]{32}$")
SECRET_RE = re.compile(r"^SPMS-[A-Za-z0-9_-]{43}$")
MAX_TTL = 600


def _offer_ok(offer, iid, now):
    return (isinstance(offer, dict)
            and offer.get("contract") == LOCAL_OFFER_CONTRACT
            and offer.get("installation_id") == iid
            and isinstance(offer.get("request_ref"), str)
            and REF_RE.fullmatch(offer["request_ref"]) is not None
            and offer.get("status") == "pending_handoff"
            and offer.get("read_only") is True
            and offer.get("claim_authorized") is False
            and offer.get("identity_created") is False
            and offer.get("runtime_authorized") is False
            and offer.get("technician_access_granted") is False
            and type(offer.get("expires_at")) is int
            and now < offer["expires_at"] <= now + MAX_TTL)


def _read_private(path):
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077)
                or info.st_size <= 0 or info.st_size > 1024):
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def prepare_receiver(offer, installation_id, *, key_path=PRIVATE_KEY, now=None):
    """Create a request-bound receiver key once; do not silently reseed.

    Returns ONLY public metadata; the caller must separately authenticate and
    bind this key to the verified Portal device proof before Broker issuance.
    """
    now = int(time.time() if now is None else now)
    iid = str(installation_id or "").strip().upper()
    if not IID_RE.fullmatch(iid) or not _offer_ok(offer, iid, now):
        return None
    path = Path(key_path)
    if not path.exists():
        key = PrivateKey.generate()
        data = {"contract": KEY_CONTRACT, "installation_id": iid,
                "request_ref": offer["request_ref"],
                "private_key_hex": bytes(key).hex(),
                "public_key_hex": bytes(key.public_key).hex(),
                "created_at": now, "offer_expires_at": offer["expires_at"]}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(data, output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            pass
        except OSError:
            return None
    data = _read_private(path)
    if (not data or data.get("contract") != KEY_CONTRACT
            or data.get("installation_id") != iid
            or data.get("request_ref") != offer["request_ref"]
            or data.get("offer_expires_at") != offer["expires_at"]
            or not isinstance(data.get("private_key_hex"), str)
            or not HEX64_RE.fullmatch(data["private_key_hex"])
            or not isinstance(data.get("public_key_hex"), str)
            or not HEX64_RE.fullmatch(data["public_key_hex"])):
        return None
    try:
        key = PrivateKey(bytes.fromhex(data["private_key_hex"]))
        if bytes(key.public_key).hex() != data["public_key_hex"]:
            return None
    except (TypeError, ValueError):
        return None
    return {"contract": KEY_CONTRACT, "installation_id": iid,
            "request_ref": offer["request_ref"],
            "public_key_hex": data["public_key_hex"],
            "read_only": True, "claim_authorized": False,
            "identity_created": False}



def _delivery_context_ok(context, iid, now):
    """Private bounded *context*, never a grant. Broker remains authoritative."""
    if _offer_ok(context, iid, now):
        return True
    if (not isinstance(context, dict)
            or context.get("contract") != PRIVATE_CONTEXT_CONTRACT
            or context.get("installation_id") != iid
            or not isinstance(context.get("request_ref"), str)
            or REF_RE.fullmatch(context["request_ref"]) is None
            or context.get("status") != "delivery_recovery"
            or context.get("read_only") is not True
            or context.get("claim_authorized") is not False
            or context.get("identity_created") is not False
            or context.get("runtime_authorized") is not False
            or context.get("technician_access_granted") is not False
            or context.get("not_a_bearer_grant") is not True
            or type(context.get("expires_at")) is not int):
        return False
    return now < context["expires_at"] <= now + MAX_TTL


def private_delivery_context(installation_id, request_ref, *,
                             key_path=PRIVATE_KEY, now=None):
    """Recover the approved request binding after Tools clears its pending offer.

    The private receiver record may be read only until the ORIGINAL offer expiry.
    It is not an approval, token, signature, API permission or identity.
    """
    now = int(time.time() if now is None else now)
    iid = str(installation_id or "").strip().upper()
    if (not IID_RE.fullmatch(iid)
            or not isinstance(request_ref, str)
            or REF_RE.fullmatch(request_ref) is None):
        return None
    data = _read_private(Path(key_path))
    if (not data or data.get("contract") != KEY_CONTRACT
            or data.get("installation_id") != iid
            or data.get("request_ref") != request_ref):
        return None
    created, expires = data.get("created_at"), data.get("offer_expires_at")
    if (type(created) is not int or type(expires) is not int
            or created <= 0 or created > now + 30
            or not created < expires <= created + MAX_TTL
            or expires <= now):
        return None
    secret, public = data.get("private_key_hex"), data.get("public_key_hex")
    if (not isinstance(secret, str) or not HEX64_RE.fullmatch(secret)
            or not isinstance(public, str) or not HEX64_RE.fullmatch(public)):
        return None
    try:
        key = PrivateKey(bytes.fromhex(secret))
        if bytes(key.public_key).hex() != public:
            return None
    except (TypeError, ValueError):
        return None
    return {
        "contract": PRIVATE_CONTEXT_CONTRACT,
        "installation_id": iid,
        "request_ref": request_ref,
        "status": "delivery_recovery",
        "expires_at": expires,
        "receiver_public_key_hex": public,
        "not_a_bearer_grant": True,
        "read_only": True,
        "claim_authorized": False,
        "identity_created": False,
        "runtime_authorized": False,
        "technician_access_granted": False,
    }


def open_candidate_envelope(envelope, offer, installation_id, architecture,
                            *, key_path=PRIVATE_KEY, now=None):
    """Decrypt a candidate in-memory, WITHOUT saving or authorizing it."""
    now = int(time.time() if now is None else now)
    iid = str(installation_id or "").strip().upper()
    if not IID_RE.fullmatch(iid) or not _delivery_context_ok(offer, iid, now):
        return None
    if architecture not in ("amd64", "aarch64") or not isinstance(envelope, dict):
        return None
    data = _read_private(Path(key_path))
    if (not data or data.get("contract") != KEY_CONTRACT
            or data.get("installation_id") != iid
            or data.get("request_ref") != offer["request_ref"]
            or not isinstance(data.get("private_key_hex"), str)
            or not HEX64_RE.fullmatch(data["private_key_hex"])
            or not isinstance(data.get("public_key_hex"), str)
            or not HEX64_RE.fullmatch(data["public_key_hex"])):
        return None
    public = data["public_key_hex"]
    if (envelope.get("contract") != ENVELOPE_CONTRACT
            or envelope.get("installation_id") != iid
            or envelope.get("request_ref") != offer["request_ref"]
            or envelope.get("receiver_public_key_hex") != public
            or envelope.get("architecture") != architecture
            or envelope.get("runtime_authorized") is not False
            or envelope.get("technician_access_granted") is not False):
        return None
    issued, expires = envelope.get("issued_at"), envelope.get("expires_at")
    if (type(issued) is not int or type(expires) is not int or issued <= 0
            or expires <= issued or expires > issued + MAX_TTL
            or issued > now + 30 or not now < expires
            or expires > offer["expires_at"]):
        return None
    hex_box = envelope.get("sealed_box_hex")
    if (not isinstance(hex_box, str) or len(hex_box) > 4096
            or len(hex_box) < 200 or len(hex_box) % 2
            or re.fullmatch(r"[a-f0-9]+", hex_box) is None):
        return None
    try:
        key = PrivateKey(bytes.fromhex(data["private_key_hex"]))
        if bytes(key.public_key).hex() != public:
            return None
        plaintext = SealedBox(key).decrypt(bytes.fromhex(hex_box))
        if len(plaintext) > 2048:
            return None
        def unique_keys(pairs):
            result = {}
            for k, v in pairs:
                if k in result:
                    raise ValueError("duplicate key")
                result[k] = v
            return result
        content = json.loads(plaintext.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, TypeError, UnicodeError, CryptoError, OSError):
        return None
    if not isinstance(content, dict):
        return None
    expected = {"contract": CONTENT_CONTRACT, "installation_id": iid,
                "request_ref": offer["request_ref"], "receiver_public_key_hex": public,
                "architecture": architecture, "issued_at": issued, "expires_at": expires}
    if any(content.get(k) != v for k, v in expected.items()):
        return None
    node_id, node_secret = content.get("node_id"), content.get("node_secret")
    if (not isinstance(node_id, str) or not NODE_RE.fullmatch(node_id)
            or not isinstance(node_secret, str) or not SECRET_RE.fullmatch(node_secret)):
        return None
    # Future coordinator must verify durable server claim before writing /data.
    return {"installation_id": iid, "request_ref": offer["request_ref"],
            "node_id": node_id, "node_secret": node_secret,
            "verified_cryptographically": True,
            "server_authorized": False, "identity_persisted": False,
            "runtime_authorized": False}
