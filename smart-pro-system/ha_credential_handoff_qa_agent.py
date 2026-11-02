#!/usr/bin/env python3
"""Smart Pro HA Credential Handoff: opt-in SYNTHETIC agent, no real secrets.

Runs alongside existing Smart Pro Tools; reads the same existing paired local
installation identity. OFF by default. Sends ONLY exact fake constants. No HA
user API, credential generation, storage, server listener or long-lived token.
NEVER use this agent to deliver real credentials.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

CONTRACT = 'smart-pro-ha-admin-handoff-qa-agent-v2'
FAKE_USERNAME = 'SP_QA_AGENT_FAKE_USERNAME'
FAKE_PASSWORD = 'QA-AGENT-FAKE-PASSWORD-NOT-REAL'
OPTIONS_PATH = Path('/data/options.json')
CONNECTION_PATH = Path('/data/portal_connection.json')
INSTALLATION_PATTERN = re.compile(r'ID-[0-9]{1,12}\Z')
TOKEN_PATTERN = re.compile(r'[0-9a-fA-F]{64}\Z')
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
VERSION = '3.0.29'

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('qa_redirect_disallowed')

_SAFE_OPENER = urllib.request.build_opener(_NoRedirect()).open


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _validated_settings(options: dict, connection: dict):
    # Must be explicitly enabled, not a truthy string, and must be paired.
    if options.get('ha_credential_handoff_qa_enabled') is not True:
        return None
    url = options.get('portal_url', '')
    if not isinstance(url, str):
        return None
    parsed = urllib.parse.urlsplit(url.rstrip('/'))
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        return None
    installation = connection.get('installation_id')
    token = connection.get('installation_token')
    if not isinstance(installation, str) or not INSTALLATION_PATTERN.fullmatch(installation):
        return None
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        return None
    basic_user = options.get('portal_basic_username', '')
    basic_password = options.get('portal_basic_password', '')
    if not isinstance(basic_user, str) or not isinstance(basic_password, str):
        return None
    return url.rstrip('/'), installation, token, basic_user, basic_password


def _post(base_url: str, endpoint: str, payload: dict,
          token: str, basic_user: str, basic_password: str,
          opener=_SAFE_OPENER) -> dict:
    headers = {'Content-Type': 'application/json', 'Accept':'application/json',
               'X-Smart-Pro-Token':token}
    if basic_user:
        encoded = base64.b64encode((basic_user + ':' + basic_password).encode()).decode('ascii')
        headers['Authorization'] = 'Basic ' + encoded
    url = base_url + '/wp-json/smart-pro/v1/ha-credential-handoff-qa/' + endpoint
    req = urllib.request.Request(url,
         data=json.dumps(payload, separators=(',',':')).encode('utf-8'),
         headers=headers, method='POST')
    with opener(req, timeout=10) as response:
        if response.geturl() != url:  # no redirects, including token-bearing redirects
            raise ValueError('qa_redirect_disallowed')
        if getattr(response, 'status', 200) != 200:
            raise ValueError('qa_http_failure')
        raw = response.read(4096 + 1)
        if len(raw) > 4096:
            raise ValueError('qa_oversized_reply')
        decoded = json.loads(raw.decode('utf-8'))
        if not isinstance(decoded, dict) or decoded.get('contract') != CONTRACT:
            raise ValueError('qa_invalid_reply')
        return decoded


def run_once(options: dict, connection: dict, *, now=None,
             transport=_post) -> str:
    settings = _validated_settings(options, connection)
    if settings is None:
        return 'off_or_unpaired'
    base_url, installation, token, basic_user, basic_password = settings
    standard = {'contract':CONTRACT,'installation_id':installation,'agent_version':VERSION}
    reply = transport(base_url, 'poll', standard, token, basic_user, basic_password)
    if reply.get('status') == 'idle':
        return 'idle'
    if reply.get('status') != 'queued' or reply.get('installation_id') != installation:
        return 'invalid_qa_instruction'
    req_id = reply.get('request_id')
    challenge = reply.get('challenge')
    exp = reply.get('expires_at')
    time_now = int(time.time()) if now is None else int(now)
    if (not isinstance(req_id, str) or not HEX32.fullmatch(req_id) or
        not isinstance(challenge, str) or not HEX64.fullmatch(challenge) or
        not isinstance(exp, int) or exp <= time_now or exp > time_now + 610):
        return 'invalid_qa_instruction'
    # Fake constants are compiled in this source. No parameters for actual secrets.
    delivery = {**standard,'request_id':req_id,'challenge':challenge,
                'sent_at':time_now,'username':FAKE_USERNAME,'password':FAKE_PASSWORD}
    outcome = transport(base_url, 'deliver', delivery, token, basic_user, basic_password)
    return ('synthetic_received' if outcome.get('status') in ('synthetic_received','already_received')
            else 'delivery_unconfirmed')


def main():
    # The QA worker is inert unless explicitly enabled in add-on configuration.
    last = None
    while True:
        options = _read_json(OPTIONS_PATH)
        connection = _read_json(CONNECTION_PATH)
        try:
            code = run_once(options, connection)
        except (OSError, ValueError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            code = 'network_or_validation_failure'
        except Exception:
            code = 'unexpected_qa_failure'
        if code != last and code not in ('off_or_unpaired','idle'):
            # Never log URL, token, installation ID, challenge or usernames/passwords.
            print('[SP Handoff QA] ' + code, flush=True)
        last = code
        time.sleep(15 if code != 'off_or_unpaired' else 30)


if __name__ == '__main__':
    main()
