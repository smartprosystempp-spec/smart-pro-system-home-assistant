"""Offline-only, zero-copy original sealed envelope recovery.

Decrypts a short-lived Broker recipient challenge, proves ownership of the
existing X25519 key and verifies EXACT original committed ciphertext bytes.
NEVER creates or persists an identity, opens remote access or calls Broker.
"""
import hashlib
import json
import re
import time
from pathlib import Path
from nacl.public import PrivateKey, SealedBox
from nacl.exceptions import CryptoError
from managed_zero_copy_receiver import (
    PRIVATE_KEY, _offer_ok, _read_private, open_candidate_envelope,
)

CHALLENGE_CONTRACT = "smart-pro-managed-zero-copy-delivery-challenge-v1"
CHALLENGE_CONTENT = "smart-pro-managed-zero-copy-delivery-challenge-content-v1"
DELIVERY_CONTRACT = "smart-pro-managed-zero-copy-original-delivery-v1"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
CIPHER = re.compile(r"^[a-f0-9]{200,4096}$")


def _strict_json(raw):
    def unique(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate property")
            output[key] = value
        return output
    return json.loads(raw, object_pairs_hook=unique)


def prove_receiver_challenge(challenge, offer, installation_id, architecture,
                             *, key_path=PRIVATE_KEY, now=None):
    now = int(time.time() if now is None else now)
    iid = str(installation_id or "").strip().upper()
    if not _offer_ok(offer, iid, now) or architecture not in ("amd64", "aarch64"):
        return None
    if not isinstance(challenge, dict):
        return None
    stored = _read_private(Path(key_path))
    if (not isinstance(stored, dict) or stored.get("installation_id") != iid
            or stored.get("request_ref") != offer.get("request_ref")):
        return None
    pub, secret = stored.get("public_key_hex"), stored.get("private_key_hex")
    if (not isinstance(pub, str) or not HEX64.fullmatch(pub)
            or not isinstance(secret, str) or not HEX64.fullmatch(secret)):
        return None
    if (challenge.get("contract") != CHALLENGE_CONTRACT
            or challenge.get("installation_id") != iid
            or challenge.get("request_ref") != offer.get("request_ref")
            or challenge.get("receiver_public_key_hex") != pub
            or challenge.get("architecture") != architecture
            or any(challenge.get(k) is not False for k in
                   ("identity_created", "runtime_authorized", "technician_access_granted"))):
        return None
    issued, expires = challenge.get("issued_at"), challenge.get("expires_at")
    if (type(issued) is not int or type(expires) is not int
            or issued <= 0 or issued > now + 30
            or expires <= issued or expires > issued + 90
            or expires > offer["expires_at"] or now >= expires):
        return None
    digest, box_hex = challenge.get("envelope_sha256"), challenge.get("sealed_box_hex")
    if (not isinstance(digest, str) or not HEX64.fullmatch(digest)
            or not isinstance(box_hex, str) or len(box_hex) % 2
            or not CIPHER.fullmatch(box_hex)):
        return None
    try:
        key = PrivateKey(bytes.fromhex(secret))
        if bytes(key.public_key).hex() != pub:
            return None
        plaintext = SealedBox(key).decrypt(bytes.fromhex(box_hex))
        if len(plaintext) > 2048:
            return None
        inner = _strict_json(plaintext.decode("utf-8"))
    except (CryptoError, OSError, UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(inner, dict):
        return None
    expected = {
        "contract": CHALLENGE_CONTENT, "installation_id": iid,
        "request_ref": offer["request_ref"], "receiver_public_key_hex": pub,
        "architecture": architecture, "envelope_sha256": digest,
        "issued_at": issued, "expires_at": expires,
    }
    if any(inner.get(k) != value for k, value in expected.items()):
        return None
    nonce = inner.get("nonce_hex")
    if not isinstance(nonce, str) or not HEX64.fullmatch(nonce):
        return None
    proof = hashlib.sha256(
        f"SPMZ1|delivery_proof|{iid}|{offer['request_ref']}|{pub}|{digest}|{nonce}".encode("ascii")
    ).hexdigest()
    return {
        "contract": "smart-pro-managed-zero-copy-delivery-proof-v1",
        "installation_id": iid, "request_ref": offer["request_ref"],
        "receiver_public_key_hex": pub, "architecture": architecture,
        "envelope_sha256": digest, "proof_hex": proof,
        "expires_at": expires, "identity_persisted": False,
        "runtime_authorized": False,
    }


def verify_original_delivery(delivery, proof, offer, installation_id, architecture,
                             *, key_path=PRIVATE_KEY, now=None):
    now = int(time.time() if now is None else now)
    iid = str(installation_id or "").strip().upper()
    if (not _offer_ok(offer, iid, now) or architecture not in ("amd64", "aarch64")
            or not isinstance(delivery, dict) or not isinstance(proof, dict)):
        return None
    if (delivery.get("contract") != DELIVERY_CONTRACT
            or delivery.get("installation_id") != iid
            or delivery.get("request_ref") != offer.get("request_ref")
            or delivery.get("architecture") != architecture
            or delivery.get("receiver_public_key_hex") != proof.get("receiver_public_key_hex")
            or delivery.get("envelope_sha256") != proof.get("envelope_sha256")
            or proof.get("contract") != "smart-pro-managed-zero-copy-delivery-proof-v1"
            or proof.get("installation_id") != iid
            or proof.get("request_ref") != offer.get("request_ref")
            or proof.get("architecture") != architecture
            or type(proof.get("expires_at")) is not int or proof["expires_at"] <= now
            or any(delivery.get(k) is not False for k in (
                "identity_reissued", "identity_persisted",
                "runtime_authorized", "technician_access_granted"))):
        return None
    original = delivery.get("original_envelope_json")
    if not isinstance(original, str) or not 300 <= len(original.encode("utf-8")) <= 5000:
        return None
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
    if digest != proof["envelope_sha256"]:
        return None
    try:
        packet = _strict_json(original)
    except (UnicodeError, ValueError, TypeError):
        return None
    candidate = open_candidate_envelope(
        packet, offer, iid, architecture, key_path=key_path, now=now)
    if not isinstance(candidate, dict) or candidate.get("server_authorized") is not False:
        return None
    candidate["delivery_proof_verified"] = True
    candidate["original_envelope_sha256"] = digest
    candidate["identity_persisted"] = False
    candidate["runtime_authorized"] = False
    return candidate
