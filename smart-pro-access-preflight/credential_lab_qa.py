"""TEST-ONLY Home Assistant account login credential lifecycle.

Never deploy to production. This module generates a random password in RAM,
attaches it to an exact one-off QA admin via HA Core, and returns it exactly
once to the authenticated local HA administrator. No database, disk, Portal,
logs, cookie or background agent sees the plaintext. The administrator must
revoke the account after testing. Core stores its own password hash.
"""
from __future__ import annotations

import secrets
from typing import Any

from core_session_qa import SupervisorCoreSession, RoundTripError, _inventory

LAB_NAME = 'Smart Pro QA LOGIN LAB'
LAB_PREFIX = LAB_NAME
LAB_USERNAME = 'smartpro_qa_login_lab'
ADMIN_GROUP = 'system-admin'

class LabCredentialError(RuntimeError):
    """Opaque nonsecret code only."""


def _candidates(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [u for u in users if isinstance(u.get('name'), str)
            and u['name'].startswith(LAB_PREFIX)]


def _safe_user(u: dict[str, Any], *, credentialed: bool) -> bool:
    """Only an unmodified user with exact lab identity may be touched."""
    credentials = u.get('credentials')
    expected = [{'type': 'homeassistant'}] if credentialed else []
    return (u.get('name') == LAB_NAME
            and isinstance(u.get('id'), str) and 16 <= len(u['id']) <= 128
            and u.get('is_owner') is False and u.get('system_generated') is False
            and u.get('is_active') is True and u.get('local_only') is True
            and u.get('group_ids') == [ADMIN_GROUP]
            and u.get('username') == (LAB_USERNAME if credentialed else None)
            and credentials == expected)


def _read_state(users: list[dict[str, Any]]) -> str:
    matches = _candidates(users)
    # An existing account carrying the target username always blocks creation.
    username_owners = [u for u in users if u.get('username') == LAB_USERNAME]
    if not matches and not username_owners:
        return 'absent'
    if len(matches) != 1 or len(username_owners) > 1:
        return 'review_required'
    match = matches[0]
    if not username_owners and _safe_user(match, credentialed=False):
        return 'incomplete_no_login'
    if len(username_owners) == 1 and username_owners[0].get('id') == match.get('id') \
            and _safe_user(match, credentialed=True):
        return 'login_ready'
    return 'review_required'


def inspect_lab(*, supervisor_token: str, session_factory=SupervisorCoreSession) -> str:
    try:
        with session_factory(supervisor_token) as core:
            return _read_state(_inventory(core.command('config/auth/list')))
    except Exception:
        return 'readback_unavailable'


def create_lab(*, supervisor_token: str, session_factory=SupervisorCoreSession,
               password_factory=lambda: secrets.token_urlsafe(36)) -> dict[str, str]:
    """Create a local-only QA admin login; secret returned ONCE, never persisted.

    On any uncertain response the account is NOT silently deleted. The caller
    must stop, inspect Home Assistant users, and revoke through a separately
    approved action. Explicit code paths never retry a credential write.
    """
    try:
        with session_factory(supervisor_token) as core:
            before = _inventory(core.command('config/auth/list'))
            if _read_state(before) != 'absent':
                raise LabCredentialError('qa_login_existing_account_or_username_stop')
            password = password_factory()
            if not isinstance(password, str) or len(password) < 40 or len(password) > 128:
                raise LabCredentialError('qa_login_random_password_invalid')
            if not password.isascii() or not password.isprintable():
                raise LabCredentialError('qa_login_random_password_invalid')
            created = core.command('config/auth/create', name=LAB_NAME,
                                   group_ids=[ADMIN_GROUP], local_only=True)
            if not isinstance(created, dict) or not isinstance(created.get('user'), dict):
                raise LabCredentialError('qa_login_create_uncertain_inspect_users')
            uid = created['user'].get('id')
            if not isinstance(uid, str) or not 16 <= len(uid) <= 128:
                raise LabCredentialError('qa_login_create_identity_uncertain_inspect_users')
            intermediate = _inventory(core.command('config/auth/list'))
            matches = _candidates(intermediate)
            if len(matches) != 1 or matches[0].get('id') != uid or _read_state(intermediate) != 'incomplete_no_login':
                raise LabCredentialError('qa_login_precredential_mismatch_inspect_users')
            core.command('config/auth_provider/homeassistant/create', user_id=uid,
                         username=LAB_USERNAME, password=password)
            after = _inventory(core.command('config/auth/list'))
            matches = _candidates(after)
            if (len(matches) != 1 or matches[0].get('id') != uid
                    or _read_state(after) != 'login_ready'):
                raise LabCredentialError('qa_login_credential_result_uncertain_inspect_users')
            return {'code': 'qa_login_admin_created_credentials_linked',
                    'username': LAB_USERNAME, 'password': password}
    except LabCredentialError:
        raise
    except (RoundTripError, OSError, TimeoutError, ValueError, TypeError):
        raise LabCredentialError('qa_login_write_uncertain_inspect_users') from None


def revoke_lab(*, supervisor_token: str, session_factory=SupervisorCoreSession) -> str:
    """Delete only the unchanged QA login account; Core removes credentials/tokens.

    In HA Core, auth.async_remove_user removes linked credentials via
    async_remove_credentials (including provider password) and revokes tokens.
    This is still a separately confirmed destructive lab action.
    """
    try:
        with session_factory(supervisor_token) as core:
            before = _inventory(core.command('config/auth/list'))
            state = _read_state(before)
            if state == 'absent':
                return 'qa_login_admin_already_absent'
            if state not in ('login_ready', 'incomplete_no_login'):
                raise LabCredentialError('qa_login_revoke_manual_review_required')
            matches = _candidates(before)
            if len(matches) != 1 or not _safe_user(matches[0], credentialed=(state == 'login_ready')):
                raise LabCredentialError('qa_login_revoke_manual_review_required')
            uid = matches[0]['id']
            core.command('config/auth/delete', user_id=uid)
            after = _inventory(core.command('config/auth/list'))
            if (_read_state(after) != 'absent'
                    or any(u.get('id') == uid for u in after)):
                raise LabCredentialError('qa_login_revoke_uncertain_inspect_users')
            return 'qa_login_admin_revoked_verified'
    except LabCredentialError:
        raise
    except (RoundTripError, OSError, TimeoutError, ValueError, TypeError):
        raise LabCredentialError('qa_login_revoke_uncertain_inspect_users') from None
