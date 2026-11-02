"""Explicit, local-admin-consented, ONE-TIME QA credential handoff.

Portal admin arms a specific 15-minute request and transfers the short-lived
bearer ticket manually into the trusted HA Supervisor Ingress QA panel. A fresh
Core-admin check and separate consent are required BEFORE any HA account write.
The actual password never passes through JS, local files, Heartbeat or logs.
The only HTTP request containing the password is an E2E sealed ciphertext.

TEST HOME ASSISTANT ONLY. Do not deploy to customer installations.
"""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request

from credential_lab_qa import create_lab, LabCredentialError

CONTRACT = 'smart-pro-ha-admin-credential-handoff-v1'
PORTAL = 'https://smart-pro-system.gr'
TICKET_PATTERN = re.compile(r'(ID-[0-9]{1,12}):([a-f0-9]{64})\Z')
HEX32 = re.compile(r'[a-f0-9]{32}\Z')
HEX64 = re.compile(r'[a-f0-9]{64}\Z')

class HandoffError(RuntimeError):
    """Contains fixed safe error codes only, never sensitive values."""

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        raise HandoffError('handoff_redirect_rejected_no_write')

_OPENER = urllib.request.build_opener(_NoRedirect()).open


def _portal_post(endpoint: str, payload: dict, *, opener=_OPENER) -> dict:
    url = PORTAL + '/wp-json/smart-pro/v1/ha-credential-handoff-real/' + endpoint
    request = urllib.request.Request(
        url, method='POST',
        headers={'Content-Type':'application/json','Accept':'application/json'},
        data=json.dumps(payload,separators=(',',':'),ensure_ascii=False).encode('utf-8'))
    try:
        with opener(request, timeout=12) as result:
            if result.geturl() != url or getattr(result, 'status', 200) != 200:
                raise HandoffError('handoff_response_invalid')
            raw = result.read(4097)
            if len(raw)>4096: raise HandoffError('handoff_response_invalid')
        obj=json.loads(raw.decode('utf-8','strict'))
        if not isinstance(obj,dict) or obj.get('contract')!=CONTRACT:
            raise HandoffError('handoff_response_invalid')
        return obj
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError,
            ValueError, UnicodeDecodeError) as e:
        raise HandoffError('handoff_remote_unavailable') from None


def preflight(ticket: str, *, transport=_portal_post, now=None) -> dict:
    match=TICKET_PATTERN.fullmatch(ticket) if isinstance(ticket,str) else None
    if not match: raise HandoffError('handoff_ticket_invalid_no_write')
    installation, cap=match.groups()
    info=transport('ticket-poll',{
        'contract':CONTRACT,'installation_id':installation,'ticket':cap})
    now=int(time.time()) if now is None else int(now)
    if not isinstance(info,dict) or info.get('status')!='queued' or info.get('installation_id')!=installation:
        raise HandoffError('handoff_preflight_denied_no_write')
    request_id=info.get('request_id')
    challenge=info.get('challenge')
    expiry=info.get('expires_at')
    pubkey=info.get('public_key')
    if not isinstance(request_id,str) or not HEX32.fullmatch(request_id) \
        or not isinstance(challenge,str) or not HEX64.fullmatch(challenge) \
        or type(expiry) is not int or expiry <= now+10 or expiry > now+900 \
        or not isinstance(pubkey,str) or len(pubkey)>64:
        raise HandoffError('handoff_preflight_denied_no_write')
    try:
        public=base64.b64decode(pubkey,validate=True)
    except (ValueError,TypeError):
        raise HandoffError('handoff_preflight_denied_no_write') from None
    if len(public)!=32: raise HandoffError('handoff_preflight_denied_no_write')
    return {'installation_id':installation, 'ticket':cap,
            'request_id':request_id,'challenge':challenge,'expires_at':expiry,'public_key':public}


def deliver_laboratory_account(ticket: str, *, supervisor_token: str,
                               preflight_fn=preflight, create_fn=create_lab,
                               transport=_portal_post, now=None, seal_fn=None) -> str:
    # Every preflight guard occurs before CREATE. A failure here does not mutate HA.
    info=preflight_fn(ticket)
    if not isinstance(info,dict): raise HandoffError('handoff_preflight_denied_no_write')
    if seal_fn is None:
        try:
            from nacl.public import PublicKey, SealedBox
        except ImportError:
            raise HandoffError('handoff_crypto_unavailable_no_write') from None
        def seal_fn(public_key: bytes, plaintext: bytes) -> bytes:
            return SealedBox(PublicKey(public_key)).encrypt(plaintext)
    # Validate dependency and public key shape before creating the user.
    if not isinstance(info.get('public_key'),bytes) or len(info['public_key'])!=32:
        raise HandoffError('handoff_preflight_denied_no_write')
    # Precheck that encrypted crypto actually works BEFORE HA account mutation.
    try:
        test=seal_fn(info['public_key'], b'qa-crypto-precheck')
        if not isinstance(test,bytes) or len(test) < 48:
            raise ValueError('invalid sealed box')
    except Exception:
        raise HandoffError('handoff_crypto_unavailable_no_write') from None
    if not isinstance(supervisor_token,str) or not supervisor_token:
        raise HandoffError('handoff_core_auth_unavailable_no_write')
    try:
        result=create_fn(supervisor_token=supervisor_token)
    except LabCredentialError as exc:
        # Return only fixed safe codes from existing audited account lifecycle.
        raise HandoffError(str(exc) if str(exc).startswith('qa_login_') else 'handoff_create_unknown') from None
    if not isinstance(result,dict) or result.get('code')!='qa_login_admin_created_credentials_linked':
        raise HandoffError('handoff_create_uncertain_check_ha_users')
    # Create a sealed envelope in RAM only. No plaintext in response, logs, files.
    plaintext=json.dumps({'contract':CONTRACT,'installation_id':info['installation_id'],
        'request_id':info['request_id'],'username':result['username'],
        'password':result['password']},separators=(',',':')).encode('utf-8')
    try:
        sealed=seal_fn(info['public_key'],plaintext)
        envelope={'contract':CONTRACT,'installation_id':info['installation_id'],
            'ticket':info['ticket'],'request_id':info['request_id'],
            'challenge':info['challenge'], 'sent_at':int(time.time()) if now is None else int(now),
            'ciphertext':base64.b64encode(sealed).decode('ascii')}
        reply=transport('ticket-deliver',envelope)
        if not isinstance(reply,dict) or reply.get('contract')!=CONTRACT or reply.get('status')!='received':
            raise HandoffError('handoff_delivery_uncertain_check_both_sides')
        return 'handoff_real_qa_admin_created_and_encrypted_received'
    except Exception:
        # HA user already exists. NEVER retry or auto-delete after ambiguous delivery.
        raise HandoffError('handoff_delivery_uncertain_check_both_sides') from None
    finally:
        del plaintext
        result.clear()
