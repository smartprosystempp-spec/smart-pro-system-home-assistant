#!/usr/bin/env python3
"""Strictly isolated, test-only HA user API round-trip; NOT customer access.

QA 0.3.1 only: fresh admin Core proof, explicit one-use confirmation,
then create and immediately delete a named temporary admin with NO credentials.
Not Portal-integrated, not a permanent Smart Pro credential or grant.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import threading
from urllib.parse import parse_qs
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping
from urllib.parse import urlsplit

from ha_readback import AdminReadbackError, read_ha_admin_users
from consent_qa import APPROVAL_WORD, issue, consume, allow_one_attempt, same_origin, attempted
from account_roundtrip import run_qa_roundtrip, RoundTripError

APP_VERSION = "0.3.1"
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


def render_page(outcome: dict[str, str | bool], consent_token: str = "", result_message: str = "") -> bytes:
    ok = outcome["is_admin"] is True
    if ok:
        title = "Διαχειριστής Home Assistant — επιβεβαιώθηκε και από το Core"
        description = (
            "Το Home Assistant αναγνώρισε τον διαχειριστή και επέτρεψε την ασφαλή ανάγνωση "
            "των δικαιωμάτων χρηστών μέσω Core API. " +
            ("Η δοκιμή δημιουργίας/διαγραφής εκτελέστηκε· το αποτέλεσμα εμφανίζεται παρακάτω. "
             if result_message else "Κανένας χρήστης δεν δημιουργήθηκε ή τροποποιήθηκε.")
        )
        badge_class = "ok"
    else:
        title = "Δεν επιβεβαιώθηκε διαχειριστής"
        if outcome["reason"] == "non_admin":
            description = "Ο τρέχων λογαριασμός δεν έχει δικαιώματα διαχειριστή."
        elif outcome["reason"] == "untrusted_source":
            description = "Ανοίξτε αυτό το εργαλείο μόνο από το Home Assistant."
        elif str(outcome["reason"]).startswith("core_"):
            description = (
                "Η αρχική ταυτότητα ήταν διαχειριστή, αλλά δεν επιβεβαιώθηκε η πρόσβαση "
                "στο προστατευμένο Core API. Δεν πραγματοποιήθηκε καμία αλλαγή. "
                "Κωδικός ελέγχου: " + str(outcome["reason"])
            )
        else:
            description = "Το Home Assistant δεν επέστρεψε επαρκή στοιχεία για ασφαλή επιβεβαίωση."
        badge_class = "blocked"
    consent_panel = ""
    if ok and consent_token:
        consent_panel = f"""<section class='qa-action'>
<h2>Δοκιμή δημιουργίας και άμεσης διαγραφής (μόνο στο test HA)</h2>
<p>Η ενέργεια δημιουργεί προσωρινό μη-owner λογαριασμό με ομάδα διαχειριστών, αλλά <strong>χωρίς username ή κωδικό</strong>,
ελέγχει την εγγραφή και τη διαγράφει αμέσως. Δεν δίνει δυνατότητα login στη Smart Pro.
Σε διακοπή σύνδεσης μπορεί να παραμείνει εγγραφή, οπότε απαιτείται χειροκίνητος έλεγχος στην καρτέλα Χρήστες.</p>
<form method='post' action='origin-check'>
<button type='submit' class='probe-button'>1. Έλεγχος φόρμας χωρίς δημιουργία χρήστη</button>
</form>
<p class='note'>Πρώτα ελέγξτε την υποβολή χωρίς αλλαγές· στη συνέχεια, αν περάσει, ανανεώστε τη σελίδα πριν δοκιμάσετε τη δημιουργία.</p>
<form method='post' action=''>
<input type='hidden' name='csrf' value='{html.escape(consent_token, quote=True)}'>
<label for='confirm'>Πληκτρολόγησε <b>{APPROVAL_WORD}</b> για εφάπαξ δοκιμή:</label>
<input id='confirm' name='confirm' autocomplete='off' maxlength='20' required>
<button type='submit'>Έγκριση ελεγχόμενης δοκιμής</button>
</form></section>"""
    if result_message:
        consent_panel = "<section class='qa-action'><p><strong>Αποτέλεσμα:</strong> " + html.escape(result_message) + "</p><p>Ελέγξτε τη λίστα χρηστών του Home Assistant πριν από νέα δοκιμή.</p></section>"
    return f"""<!doctype html>
<html lang="el"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Smart Pro Access — QA</title>
<style>
:root{{color-scheme:light dark}}*{{box-sizing:border-box}}body{{margin:0;background:#101722;color:#e9eef7;font:16px/1.55 system-ui,-apple-system,sans-serif}}
main{{max-width:610px;margin:8vh auto;padding:26px;border:1px solid #354254;border-radius:16px;background:#172232}}
h1{{font-size:1.42rem;line-height:1.35;margin:.5rem 0 1rem}}.k{{font-weight:700;letter-spacing:.05em;color:#b6c6da;font-size:.78rem}}
.status{{display:inline-block;border-radius:100px;padding:5px 11px;font-size:.82rem;font-weight:700}}.ok{{background:#173d32;color:#a8f1c5}}.blocked{{background:#50302d;color:#ffcbc3}}
p{{color:#c7d2e1}}.note{{font-size:.88rem;padding-top:15px;border-top:1px solid #354254}}
.qa-action{{margin-top:20px;padding:16px;border:1px solid #5d718d;border-radius:12px}}
.qa-action h2{{font-size:1.08rem;margin:0 0 10px}}
.qa-action label{{display:block;font-size:.9rem;margin-bottom:8px}}
.qa-action input{{display:block;width:100%;border:1px solid #7389a2;border-radius:8px;padding:10px;color:#111;background:#fff;font-size:1rem}}
.qa-action button{{margin-top:12px;background:#3c83d5;color:white;border:0;border-radius:8px;padding:12px;font-weight:700}}
.qa-action .probe-button{{background:#1b6f67;cursor:pointer}}
</style></head><body><main><div class="k">SMART PRO SYSTEM · ΔΟΚΙΜΑΣΤΙΚΟΣ ΕΛΕΓΧΟΣ</div>
<h1>{html.escape(title)}</h1><span class="status {badge_class}">{'ΕΠΙΤΥΧΙΑ' if ok else 'ΔΕΝ ΕΓΚΡΙΝΕΤΑΙ'}</span>
<p>{html.escape(description)}</p><p class="note">Πρόκειται μόνο για δοκιμή ταυτότητας και ανάγνωσης δικαιωμάτων του Core. Δεν μεταφέρονται κωδικοί.
Δεν συνδέεται με το Portal και δεν αλλάζει το Managed Support. Η δημιουργία/διαγραφή QA χρήστη απαιτεί ξεχωριστή ρητή έγκριση.</p>
{consent_panel}
<p class="note">Έκδοση QA {APP_VERSION} · Για επανέλεγχο ανανεώστε τη σελίδα.</p></main></body></html>""".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartProQA"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        # Never log query parameters, user IDs or identity headers.
        return

    def _write(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, private, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/", "/status"):
            self._write(HTTPStatus.NOT_FOUND, b"Not found", "text/plain")
            return
        outcome = verify_live_core_admin(self.client_address[0], self.headers)
        status = HTTPStatus.OK if outcome["is_admin"] else HTTPStatus.FORBIDDEN
        if path == "/status":
            # Status contains only boolean and fixed reason, no user identifiers.
            body = json.dumps({"version": APP_VERSION, **outcome}, separators=(",", ":")).encode()
            self._write(status, body, "application/json; charset=utf-8")
        else:
            if outcome["is_admin"]:
                values = [v for k, v in self.headers.items() if k.lower() == "x-remote-user-id"]
                token = issue(values[0]) if len(values) == 1 and not attempted() else ""
            else:
                token = ""
            self._write(status, render_page(outcome, token), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/", "/origin-check"):
            self._write(HTTPStatus.NOT_FOUND, b"Not found", "text/plain")
            return
        # ALWAYS perform a fresh local HA admin readback before touching consent.
        outcome = verify_live_core_admin(self.client_address[0], self.headers)
        if outcome["is_admin"] is not True:
            self._write(HTTPStatus.FORBIDDEN, b"Administrator verification required", "text/plain")
            return
        if not same_origin(self.headers):
            self._write(HTTPStatus.FORBIDDEN, render_page(
                outcome, result_message="origin_proof_rejected_no_write"),
                "text/html; charset=utf-8")
            return
        if path == "/origin-check":
            # Deliberately NO calls to consume(), allow_one_attempt() or
            # run_qa_roundtrip(). The admin only tests the browser POST path.
            self._write(HTTPStatus.OK, render_page(
                outcome, result_message="origin_probe_passed_no_write"),
                "text/html; charset=utf-8")
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            self._write(HTTPStatus.BAD_REQUEST, b"Invalid request content type", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 0 < length <= 512:
                raise ValueError()
            values = parse_qs(self.rfile.read(length).decode("utf-8", "strict"),
                              keep_blank_values=True, strict_parsing=True, max_num_fields=3)
        except (ValueError, UnicodeDecodeError):
            self._write(HTTPStatus.BAD_REQUEST, b"Invalid request body", "text/plain")
            return
        if set(values) != {"csrf", "confirm"} or any(len(v) != 1 for v in values.values()):
            self._write(HTTPStatus.BAD_REQUEST, b"Invalid request fields", "text/plain")
            return
        identity_values = [v for k, v in self.headers.items() if k.lower() == "x-remote-user-id"]
        if len(identity_values) != 1 or not consume(values["csrf"][0], identity_values[0], values["confirm"][0]):
            self._write(HTTPStatus.FORBIDDEN, b"Approval expired or invalid", "text/plain")
            return
        if not ROUND_TRIP_LOCK.acquire(blocking=False):
            self._write(HTTPStatus.CONFLICT, b"Another QA operation in progress", "text/plain")
            return
        try:
            if not allow_one_attempt():
                self._write(HTTPStatus.CONFLICT, b"QA attempt already used; inspect users first", "text/plain")
                return
            try:
                code = run_qa_roundtrip(supervisor_token=os.environ.get("SUPERVISOR_TOKEN", ""))
            except RoundTripError as error:
                known_codes = {
                    "qa_suffix_invalid", "core_auth_unavailable", "core_challenge_invalid",
                    "core_auth_denied", "command_not_allowed", "core_reply_invalid",
                    "core_command_rejected", "inventory_invalid", "existing_qa_account_stop",
                    "create_result_uncertain_check_users", "create_id_uncertain_check_users",
                    "created_user_readback_mismatch", "created_user_permissions_mismatch",
                    "unexpected_credentials_attached", "cleanup_uncertain_check_users",
                    "cleanup_not_confirmed_check_users", "core_roundtrip_failed_check_users",
                }
                code = str(error) if str(error) in known_codes else "unexpected_error_check_users"
            except Exception:
                code = "unexpected_error_check_users"
            # Fixed, nonsecret outcome; never print HA IDs or inventory.
            self._write(HTTPStatus.OK, render_page(outcome, result_message=code),
                        "text/html; charset=utf-8")
        finally:
            ROUND_TRIP_LOCK.release()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    # Deliberately no host port publication; Supervisor ingress is the sole path.
    with Server(("0.0.0.0", PORT), Handler) as server:
        print(f"[smart-pro-access-qa] {APP_VERSION} ready; TEST-ONLY one-use user roundtrip; ingress-only", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
