"""Scoped Ed25519 device proof; NO Managed identity minting or runtime grant.

The existing Portal installation token authenticates bootstrap enrollment.
The pinned private Ed25519 key adds device continuity, not independent hardware
attestation. Proofs are only created after a valid non-authorizing Portal offer.
"""
import json
import os
import re
import secrets
import time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTRACT = "smart-pro-managed-zero-copy-device-proof-v1"
KEY_CONTRACT = "smart-pro-managed-zero-copy-device-key-v1"
KEY_FILE = Path("/data/managed-zero-copy-device-key.json")
CHALLENGE_FILE = Path("/data/managed-zero-copy-device-challenge.json")
IID_RE = re.compile(r"^ID-[0-9]{5}$")
REF_RE = re.compile(r"^SPMZ-[A-F0-9]{32}$")
HEX64_RE = re.compile(r"^[a-f0-9]{64}$")


def _load_private(path):
    try:
        info = path.lstat()
        if info.st_mode & 0o077 or not path.is_file() or not (0 < info.st_size <= 2048):
            return None
        parsed = json.loads(path.read_text(encoding="utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def _save_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, separators=(",", ":"))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _key_for(iid, path):
    if not IID_RE.fullmatch(iid):
        return None
    if not path.exists():
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(serialization.Encoding.Raw,
                                 serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        data = {"contract": KEY_CONTRACT, "installation_id": iid,
                "private_seed_hex": seed.hex(), "public_key_hex": public}
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(json.dumps(data, separators=(",", ":")))
                out.flush()
                os.fsync(out.fileno())
        except FileExistsError:
            pass
    stored = _load_private(path)
    if not stored or stored.get("contract") != KEY_CONTRACT or stored.get("installation_id") != iid:
        return None
    seed, pub = stored.get("private_seed_hex"), stored.get("public_key_hex")
    if (not isinstance(seed, str) or not HEX64_RE.fullmatch(seed)
            or not isinstance(pub, str) or not HEX64_RE.fullmatch(pub)):
        return None
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    current = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return (key, pub) if current == pub else None


def _valid_offer(offer, iid, now):
    return (isinstance(offer, dict)
            and offer.get("contract") == "smart-pro-managed-zero-copy-local-offer-v1"
            and offer.get("installation_id") == iid
            and offer.get("status") == "pending_handoff"
            and offer.get("read_only") is True
            and offer.get("claim_authorized") is False
            and offer.get("identity_created") is False
            and offer.get("runtime_authorized") is False
            and offer.get("technician_access_granted") is False
            and isinstance(offer.get("request_ref"), str)
            and REF_RE.fullmatch(offer["request_ref"]) is not None
            and type(offer.get("expires_at")) is int and now < offer["expires_at"])


def build_proof_payload(offer, installation_id, *, key_path=KEY_FILE,
                        challenge_path=CHALLENGE_FILE, now=None):
    """Registration or one short-lived challenge signature, NO claim."""
    iid = str(installation_id or "").strip().upper()
    now = int(time.time() if now is None else now)
    if not _valid_offer(offer, iid, now):
        return None
    try:
        result = _key_for(iid, Path(key_path))
        if result is None:
            return None
        key, pub = result
        ref = offer["request_ref"]
        pending = _load_private(Path(challenge_path))
        if (pending and pending.get("contract") == CONTRACT
                and pending.get("installation_id") == iid
                and pending.get("request_ref") == ref
                and isinstance(pending.get("challenge"), str)
                and HEX64_RE.fullmatch(pending["challenge"])
                and type(pending.get("expires_at")) is int
                and now < pending["expires_at"] <= now + 300):
            challenge = pending["challenge"]
            message = f"SPMZ1|challenge|{iid}|{ref}|{challenge}".encode("ascii")
            return {
                "contract": CONTRACT, "action": "challenge_response",
                "installation_id": iid, "request_ref": ref,
                "public_key_hex": pub, "challenge": challenge,
                "signature_hex": key.sign(message).hex(),
            }
        nonce = secrets.token_hex(16)
        message = f"SPMZ1|registration|{iid}|{ref}|{pub}|{now}|{nonce}".encode("ascii")
        return {
            "contract": CONTRACT, "action": "register",
            "installation_id": iid, "request_ref": ref,
            "public_key_hex": pub, "issued_at": now, "nonce": nonce,
            "signature_hex": key.sign(message).hex(),
        }
    except (OSError, ValueError):
        return None


def accept_challenge_response(response, offer, installation_id, *,
                              path=CHALLENGE_FILE, now=None):
    """Persist only an authenticated, bounded challenge; no bearer credential."""
    iid = str(installation_id or "").strip().upper()
    now = int(time.time() if now is None else now)
    if (not _valid_offer(offer, iid, now) or not isinstance(response, dict)
            or response.get("installation_id") != iid):
        return False
    data = response.get("managed_zero_copy_device")
    if not isinstance(data, dict) or data.get("contract") != CONTRACT:
        return False
    if data.get("status") == "verified":
        if data.get("request_ref") == offer["request_ref"]:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        return False
    challenge, expires = data.get("challenge"), data.get("expires_at")
    if (data.get("status") != "challenge_ready"
            or data.get("request_ref") != offer["request_ref"]
            or not isinstance(challenge, str) or not HEX64_RE.fullmatch(challenge)
            or type(expires) is not int or not (now < expires <= now + 300)):
        return False
    try:
        _save_private(Path(path), {
            "contract": CONTRACT, "installation_id": iid,
            "request_ref": offer["request_ref"], "challenge": challenge,
            "expires_at": expires,
        })
        return True
    except (OSError, ValueError):
        return False
