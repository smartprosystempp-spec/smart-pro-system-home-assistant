#!/usr/bin/env python3
"""Lab-only persistent non-login HA administrator lifecycle.

0.4.0: explicit, independently consented creation and revocation; no username,
password, token custody, Portal or remote technician login integration.
Never install on production.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping
from urllib.parse import urlsplit

from ha_readback import AdminReadbackError, read_ha_admin_users
from consent_qa import (APPROVAL_WORD, REVOKE_WORD, issue, consume, attempted,
                        allow_one_attempt, strict_origin)
from persistent_qa import (inspect_retained, create_retained, revoke_retained,
                           RetainedAccountError)

APP_VERSION = "0.4.0"
ROUND_TRIP_LOCK = threading.Lock()
PORT = 8107
SUPERVISOR_INGRESS_PEER = ipaddress.ip_address("172.30.32.2")
USER_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
ADMIN_GROUP = "system-admin"
MAX_GROUPS_HEADER = 1024


def verify_ingress_admin(peer_ip: str, headers: Mapping[str, str]) -> dict[str, str | bool]:
    """Verify trusted Supervisor ingress role headers, without state or writes.

    Security assumptions: the host port is NOT published; the app checks the
    kernel-observed socket peer, never X-Forwarded-For. The Supervisor removes
    client-supplied X-Remote-User-{Id,Groups} and supplies its own values.
    No role data from browser form, URL, JSON body or query string is trusted.
    """
    deny = lambda reason: {"is_admin": False, "reason": reason}
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return deny("untrusted_source")
    if peer != SUPERVISOR_INGRESS_PEER:
        return deny("untrusted_source")

    lowered = {str(key).lower(): value for key, value in headers.items()}
    user_id = lowered.get("x-remote-user-id", "")
    group_header = lowered.get("x-remote-user-groups", "")
    if not isinstance(user_id, str) or USER_ID_PATTERN.fullmatch(user_id) is None:
        return deny("identity_unavailable")
    if not isinstance(group_header, str) or len(group_header) > MAX_GROUPS_HEADER:
        return deny("groups_unavailable")
    if not group_header or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-," for char in group_header):
        return deny("groups_unavailable")
    groups = group_header.split(",")
    if any(not group for group in groups) or len(groups) > 40:
        return deny("groups_unavailable")
    if ADMIN_GROUP not in groups:
        return deny("non_admin")

    # This is preflight eligibility only. It never grants or records approval.
    return {"is_admin": True, "reason": "admin_detected"}



def verify_live_core_admin(peer_ip: str, headers: Mapping[str, str], *,
                           token_supplier=None, user_reader=read_ha_admin_users) -> dict[str, str | bool]:
    """Check trust *twice*: Supervisor ingress and fresh HA Core admin list.

    The Core list is used only in RAM and never returned or logged. This is
    neither approval nor provisioning. Normal users fail *before* the privileged
    token is accessed. The token supplier is injectable solely for offline QA.
    """
    baseline = verify_ingress_admin(peer_ip, headers)
    if baseline["is_admin"] is not True:
        return baseline

    identity_values = [v for k, v in headers.items() if str(k).lower() == "x-remote-user-id"]
    if len(identity_values) != 1:
        return {"is_admin": False, "reason": "identity_unavailable"}
    user_id = identity_values[0]
    if not isinstance(user_id, str) or USER_ID_PATTERN.fullmatch(user_id) is None:
        return {"is_admin": False, "reason": "identity_unavailable"}
    if token_supplier is None:
        token_supplier = lambda: os.environ.get("SUPERVISOR_TOKEN", "")
    try:
        token = token_supplier()
        users = user_reader(supervisor_token=token)
    except AdminReadbackError as exc:
        # Fixed opaque failure codes. No username, user IDs or token ever leaked.
        if str(exc) in ("ha_user_list_denied", "ha_auth_failed", "local_ha_token_unavailable"):
            return {"is_admin": False, "reason": "core_authority_denied"}
        return {"is_admin": False, "reason": "core_readback_failed"}
    except Exception:
        return {"is_admin": False, "reason": "core_readback_failed"}

    if not isinstance(users, list):
        return {"is_admin": False, "reason": "core_invalid_reply"}
    matches = [u for u in users if isinstance(u, dict) and u.get("id") == user_id]
    if len(matches) != 1:
        return {"is_admin": False, "reason": "core_identity_not_matched"}
    u = matches[0]
    groups = u.get("group_ids")
    if (u.get("is_active") is not True or u.get("system_generated") is not False
            or not isinstance(groups, list)
            or not all(isinstance(g, str) for g in groups)
            or (u.get("is_owner") is not True and ADMIN_GROUP not in groups)):
        return {"is_admin": False, "reason": "core_user_not_admin"}
    return {"is_admin": True, "reason": "admin_and_core_verified_read_only"}




def _single_header(headers: Mapping[str, str], name: str) -> str | None:
    values = [v for k, v in headers.items() if str(k).lower() == name.lower()]
    if len(values) != 1 or not isinstance(values[0], str):
        return None
    return values[0]


def classify_request_metadata(headers: Mapping[str, str]) -> dict[str, str]:
    """Report only fixed classifications, never header values, URLs or user IDs.

    This is deliberately diagnostic-only. The result is NOT an origin grant,
    and must never be used to authorize a privileged operation.
    """
    host = _single_header(headers, 'Host')
    origin = _single_header(headers, 'Origin')
    fetch_site = _single_header(headers, 'Sec-Fetch-Site')
    custom = _single_header(headers, 'X-Smart-Pro-QA-Probe')
    if not origin:
        origin_shape = 'missing'
        origin_authority = None
    elif origin == 'null':
        origin_shape = 'null'
        origin_authority = None
    else:
        try:
            parsed = urlsplit(origin)
            if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                    parsed.username or parsed.password or parsed.path or
                    parsed.query or parsed.fragment or
                    origin != parsed.scheme + '://' + parsed.netloc):
                origin_shape, origin_authority = 'invalid', None
            else:
                origin_shape, origin_authority = 'valid', parsed.netloc
        except ValueError:
            origin_shape, origin_authority = 'invalid', None

    if fetch_site is None:
        fetch_class = 'missing'
    elif fetch_site in ('same-origin', 'same-site', 'cross-site', 'none'):
        fetch_class = fetch_site
    else:
        fetch_class = 'other'

    host_class = 'same' if origin_authority is not None and origin_authority == host else (
        'different' if origin_authority and host else 'unknown')
    return {
        'code': 'request_metadata_observed_no_write',
        'origin': origin_shape,
        'fetch_site': fetch_class,
        'origin_host': host_class,
        'custom_header': 'yes' if custom == 'v1' else 'no',
    }



def render_page(outcome: dict[str, str | bool], *, retained_state: str = 'unknown',
                create_token: str = '', revoke_token: str = '',
                classification: dict[str, str] | None = None) -> bytes:
    """Never render target IDs, access secrets, or a write action for non-admins."""
    ok = outcome['is_admin'] is True
    title = ('Διαχειριστής Home Assistant — επιβεβαιώθηκε και από το Core'
             if ok else 'Δεν επιβεβαιώθηκε διαχειριστής')
    description = ('Η ταυτότητα και τα δικαιώματα διαχειριστή επαληθεύτηκαν.'
                   if ok else 'Ο τρέχων λογαριασμός δεν επαληθεύτηκε ως διαχειριστής.')
    result_html = ''
    if classification:
        labels = {
            'code': 'Αποτέλεσμα', 'origin': 'Browser Origin',
            'fetch_site': 'Browser Fetch Metadata', 'origin_host': 'Origin / Proxy Host',
            'custom_header': 'Ειδική κεφαλίδα browser',
        }
        result_html = '<section><h2>Έλεγχος επικοινωνίας</h2>' + ''.join(
            '<p><strong>' + html.escape(labels[k]) + ':</strong> '
            + html.escape(classification[k]) + '</p>' for k in labels
        ) + '</section>'
    panel = ''
    if ok:
        status_text = {
            'absent':'Δεν υπάρχει ο ειδικός δοκιμαστικός λογαριασμός.',
            'retained_no_login':'Ο ειδικός δοκιμαστικός διαχειριστής υπάρχει, χωρίς στοιχεία σύνδεσης.',
            'review_required':'Βρέθηκε αμφίβολη εγγραφή. Μόνο χειροκίνητος έλεγχος στη λίστα χρηστών.',
            'readback_unavailable':'Δεν έγινε ασφαλής ανάγνωση. Καμία ενέργεια δεν επιτρέπεται.',
        }.get(retained_state, 'Άγνωστη κατάσταση. Καμία ενέργεια δεν επιτρέπεται.')
        panel = '<section><h2>Κατάσταση δοκιμαστικού διαχειριστή</h2><p>' + html.escape(status_text) + '</p></section>'
        panel += """<section><h2>1. Δοκιμή επικοινωνίας — χωρίς αλλαγές</h2>
<form method="post" action="origin-check" id="origin-probe-form">
<button type="submit" class="probe-button">Έλεγχος επικοινωνίας χωρίς αλλαγές</button>
</form><output id="probe-result" role="status" aria-live="polite"></output></section>"""
        if retained_state == 'absent' and create_token:
            panel += f"""<section><h2>2. Δημιουργία και διατήρηση QA admin — χωρίς δυνατότητα login</h2>
<p>Δημιουργείται ένας πραγματικός λογαριασμός Home Assistant με ομάδα διαχειριστών.
Παραμένει μετά από κλείσιμο ή επανεκκίνηση του πρόσθετου. <strong>Δεν έχει username ή password,
άρα δεν μπορεί ακόμη να χρησιμοποιηθεί για σύνδεση.</strong> Είναι μόνο για την ελεγχόμενη εγκατάσταση QA.</p>
<form method="post" action="retain-admin" id="retained-create-form">
<input type="hidden" name="csrf" value="{html.escape(create_token, quote=True)}">
<label for="create-confirm">Πληκτρολόγησε <strong>{APPROVAL_WORD}</strong>:</label>
<input id="create-confirm" name="confirm" autocomplete="off" maxlength="24" required>
<button type="submit" class="create-button">Δημιουργία δοκιμαστικού admin (διατηρείται)</button>
</form><output id="retained-create-result" role="status" aria-live="polite"></output></section>"""
        if retained_state == 'retained_no_login' and revoke_token:
            panel += f"""<section><h2>3. Ανάκληση του δοκιμαστικού admin</h2>
<p>Η πράξη διαγράφει μόνο τον ειδικό λογαριασμό <code>Smart Pro QA RETAINED NO LOGIN</code>.
Αν έχει τροποποιηθεί, η αυτόματη διαγραφή απορρίπτεται.</p>
<form method="post" action="revoke-admin" id="retained-revoke-form">
<input type="hidden" name="csrf" value="{html.escape(revoke_token, quote=True)}">
<label for="revoke-confirm">Πληκτρολόγησε <strong>{REVOKE_WORD}</strong>:</label>
<input id="revoke-confirm" name="confirm" autocomplete="off" maxlength="24" required>
<button type="submit" class="revoke-button">Διαγραφή μόνο του δοκιμαστικού admin</button>
</form><output id="retained-revoke-result" role="status" aria-live="polite"></output></section>"""
    return f"""<!doctype html><html lang="el"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>Smart Pro Access — QA 0.4.0</title>
<style>
:root{{color-scheme:light dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#101722;color:#e9eef7;font:16px/1.55 system-ui,-apple-system,sans-serif}}
main{{max-width:670px;margin:6vh auto;padding:26px;border:1px solid #354254;border-radius:16px;background:#172232}}
h1{{font-size:1.36rem;line-height:1.35;margin:.5rem 0 1rem}}
h2{{font-size:1.05rem;margin:0 0 10px}}p{{color:#c7d2e1}}.k{{font-weight:700;color:#b6c6da;font-size:.78rem}}
.status{{border-radius:100px;padding:5px 11px;font-size:.82rem;font-weight:700}}
.ok{{background:#173d32;color:#a8f1c5}}.blocked{{background:#50302d;color:#ffcbc3}}
.note{{font-size:.86rem;padding-top:12px;border-top:1px solid #354254}}
section{{margin-top:18px;padding:16px;border:1px solid #5d718d;border-radius:12px}}
section p{{margin:7px 0}}button{{background:#1b6f67;color:white;border:0;border-radius:8px;padding:11px;font-weight:700;cursor:pointer}}
.create-button{{background:#367ecb}}.revoke-button{{background:#994c50}}
button:disabled{{opacity:.5;cursor:default}}
input{{display:block;width:100%;padding:9px;border:1px solid #7e8ea2;background:white;color:#141b26;border-radius:7px;margin:10px 0}}
output{{display:block;margin-top:8px;white-space:pre-wrap;overflow-wrap:anywhere}}
</style><script src="probe.js" defer></script></head><body>
<main><div class="k">SMART PRO SYSTEM · ΑΠΟΚΛΕΙΣΤΙΚΑ ΔΟΚΙΜΑΣΤΙΚΟ</div>
<h1>{html.escape(title)}</h1><span class="status {'ok' if ok else 'blocked'}">{'ΕΠΙΤΥΧΙΑ' if ok else 'ΔΕΝ ΕΓΚΡΙΝΕΤΑΙ'}</span>
<p>{html.escape(description)}</p><p class="note">Έκδοση QA {APP_VERSION}. Μόνο στην ελεγχόμενη εγκατάσταση.
Το άνοιγμα της σελίδας δεν δημιουργεί λογαριασμό. Δεν συνδέεται με Portal ή Managed Support.
Κανένας κωδικός ή μέθοδος σύνδεσης δεν δημιουργείται από αυτή την έκδοση.</p>
{panel}{result_html}</main></body></html>""".encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    server_version = 'SmartProQA'
    sys_version = ''

    def log_message(self, *_args: object) -> None:
        return  # no request URLs, identity headers, secrets or user identifiers

    def _write(self, status: int, data: bytes, ctype: str) -> None:
        self.send_response(status)
        for k, v in (
            ('Content-Type', ctype), ('Content-Length', str(len(data))),
            ('Cache-Control', 'no-store, private, max-age=0'), ('Pragma', 'no-cache'),
            ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'SAMEORIGIN'),
            ('Referrer-Policy', 'no-referrer'),
            ('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'"),
        ):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == '/probe.js':
            if self.client_address[0] != '172.30.32.2':
                self._write(HTTPStatus.FORBIDDEN, b'Forbidden', 'text/plain')
            else:
                self._write(HTTPStatus.OK, SCRIPT_BYTES, 'text/javascript; charset=utf-8')
            return
        if path not in ('/', '/status'):
            self._write(HTTPStatus.NOT_FOUND, b'Not found', 'text/plain')
            return
        outcome = verify_live_core_admin(self.client_address[0], self.headers)
        status = HTTPStatus.OK if outcome['is_admin'] else HTTPStatus.FORBIDDEN
        if path == '/status':
            body = json.dumps({'version':APP_VERSION, **outcome}, separators=(',', ':')).encode()
            self._write(status, body, 'application/json; charset=utf-8')
            return
        state = 'unknown'
        create_token = revoke_token = ''
        if outcome['is_admin']:
            state = inspect_retained(supervisor_token=os.environ.get('SUPERVISOR_TOKEN',''))
            identity = _single_header(self.headers, 'X-Remote-User-Id')
            if identity and state == 'absent' and not attempted('create'):
                create_token = issue(identity, action='create')
            elif identity and state == 'retained_no_login' and not attempted('revoke'):
                revoke_token = issue(identity, action='revoke')
        self._write(status, render_page(outcome, retained_state=state,
                    create_token=create_token, revoke_token=revoke_token),
                    'text/html; charset=utf-8')

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in ('/origin-check', '/retain-admin', '/revoke-admin'):
            self._write(HTTPStatus.METHOD_NOT_ALLOWED, b'Unsupported action', 'text/plain')
            return
        outcome = verify_live_core_admin(self.client_address[0], self.headers)
        if outcome['is_admin'] is not True:
            self._write(HTTPStatus.FORBIDDEN, b'Administrator required', 'text/plain')
            return
        if path == '/origin-check':
            try:
                length = int(self.headers.get('Content-Length','0'))
            except ValueError:
                length = -1
            if not (0 <= length <= 256):
                self._write(HTTPStatus.BAD_REQUEST, b'Invalid probe length', 'text/plain')
                return
            if length:
                self.rfile.read(length)
            classification = classify_request_metadata(self.headers)
            if _single_header(self.headers, 'X-Smart-Pro-QA-Probe') == 'v1':
                self._write(HTTPStatus.OK, json.dumps(classification,separators=(',',':')).encode(),
                            'application/json; charset=utf-8')
            else:
                self._write(HTTPStatus.OK, render_page(outcome,classification=classification),
                            'text/html; charset=utf-8')
            return
        # Privileged actions have their own independently scoped, single-use
        # approval. Origin-only or browser-only claims are NEVER sufficient.
        if not strict_origin(self.headers):
            self._write(HTTPStatus.FORBIDDEN, b'origin_gate_denied_no_write','text/plain')
            return
        if _single_header(self.headers, 'X-Smart-Pro-QA-Action') != 'v1':
            self._write(HTTPStatus.FORBIDDEN, b'action_header_missing_no_write','text/plain')
            return
        if _single_header(self.headers, 'Content-Type') != 'application/json':
            self._write(HTTPStatus.BAD_REQUEST, b'invalid_content_type_no_write','text/plain')
            return
        try:
            length = int(_single_header(self.headers, 'Content-Length') or '')
            if not 0 < length <= 512:
                raise ValueError()
            payload = json.loads(self.rfile.read(length).decode('utf-8','strict'))
            if not isinstance(payload,dict) or set(payload) != {'csrf','confirm'}:
                raise ValueError()
            if not isinstance(payload['csrf'],str) or not isinstance(payload['confirm'],str):
                raise ValueError()
        except (ValueError,UnicodeDecodeError,json.JSONDecodeError):
            self._write(HTTPStatus.BAD_REQUEST,b'invalid_payload_no_write','text/plain')
            return
        action = 'create' if path == '/retain-admin' else 'revoke'
        identity = _single_header(self.headers,'X-Remote-User-Id')
        if not identity or not consume(payload['csrf'],identity,payload['confirm'],action=action):
            self._write(HTTPStatus.FORBIDDEN,b'approval_invalid_no_write','text/plain')
            return
        if not ROUND_TRIP_LOCK.acquire(blocking=False):
            self._write(HTTPStatus.CONFLICT,b'qa_action_busy_no_write','text/plain')
            return
        try:
            if not allow_one_attempt(action):
                self._write(HTTPStatus.CONFLICT,b'qa_already_attempted_no_write','text/plain')
                return
            try:
                token=os.environ.get('SUPERVISOR_TOKEN','')
                code = (create_retained(supervisor_token=token) if action == 'create'
                        else revoke_retained(supervisor_token=token))
            except RetainedAccountError as e:
                known = {
                    'qa_retained_account_already_exists_stop',
                    'qa_create_uncertain_inspect_users',
                    'qa_create_identity_uncertain_inspect_users',
                    'qa_retained_validation_failed_inspect_users',
                    'qa_revoke_target_mismatch_manual_review',
                    'qa_revoke_not_confirmed_check_users',
                    'qa_revoke_uncertain_check_users',
                }
                code = str(e) if str(e) in known else 'qa_unknown_outcome_inspect_users'
            except Exception:
                code = 'qa_unknown_outcome_inspect_users'
            self._write(HTTPStatus.OK,json.dumps({'code':code},separators=(',',':')).encode(),
                        'application/json; charset=utf-8')
        finally:
            ROUND_TRIP_LOCK.release()

    def do_PUT(self) -> None:
        self._write(HTTPStatus.METHOD_NOT_ALLOWED,b'Unsupported method','text/plain')

    do_PATCH = do_PUT
    do_DELETE = do_PUT


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


SCRIPT_PATH = os.path.join(os.path.dirname(__file__),'probe.js')
with open(SCRIPT_PATH,'rb') as _file:
    SCRIPT_BYTES=_file.read()
assert len(SCRIPT_BYTES) < 12000


def main() -> None:
    with Server(('0.0.0.0',PORT),Handler) as server:
        print(f'[smart-pro-access-qa] {APP_VERSION} ready; lab-only retained non-login user lifecycle',flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
