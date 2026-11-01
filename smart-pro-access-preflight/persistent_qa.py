"""Isolated lab-only HA administrator retention, without login credentials.

Never use this as production enrollment. A Home Assistant user record is real
and persists in Core even if this add-on stops, but it CANNOT be used to log in
without a separately added auth-provider credential.

A single reserved exact name is the only supported target for create/revoke.
The command parameters are never supplied by a browser or by the Portal.
"""
from __future__ import annotations

from typing import Any

from core_session_qa import SupervisorCoreSession, RoundTripError, _inventory

NAME = "Smart Pro QA RETAINED NO LOGIN"
NAME_PREFIX = "Smart Pro QA RETAINED NO LOGIN"
ADMIN_GROUP = "system-admin"


class RetainedAccountError(RuntimeError):
    """A fixed public error code. Never expose HA user IDs."""


def _find(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [u for u in users if isinstance(u.get("name"), str)
            and u["name"].startswith(NAME_PREFIX)]


def _safe_target(u: dict[str, Any]) -> bool:
    """Never touch a user whose identity, role or credentials have changed."""
    return (u.get("name") == NAME
            and isinstance(u.get("id"), str) and 16 <= len(u["id"]) <= 128
            and u.get("is_owner") is False
            and u.get("system_generated") is False
            and type(u.get("is_active")) is bool
            and u.get("local_only") is True
            and isinstance(u.get("group_ids"), list)
            and u["group_ids"] == [ADMIN_GROUP]
            and u.get("credentials") == [])


def inspect_retained(*, supervisor_token: str,
                     session_factory=SupervisorCoreSession) -> str:
    """Read-only and deliberately returns no user identifier."""
    try:
        with session_factory(supervisor_token) as core:
            hits = _find(_inventory(core.command("config/auth/list")))
            if not hits:
                return "absent"
            if len(hits) == 1 and _safe_target(hits[0]):
                return "retained_no_login"
            return "review_required"
    except Exception:
        return "readback_unavailable"


def create_retained(*, supervisor_token: str,
                    session_factory=SupervisorCoreSession) -> str:
    """Create one real, persistent HA admin WITHOUT an authentication method.

    If the create outcome is uncertain, do NOT retry. Inspect users manually.
    The user is intentionally NOT deleted by this routine.
    """
    try:
        with session_factory(supervisor_token) as core:
            before = _inventory(core.command("config/auth/list"))
            if _find(before):
                raise RetainedAccountError("qa_retained_account_already_exists_stop")
            # This is the ONLY create path. No username/password is attached.
            created = core.command("config/auth/create", name=NAME,
                                   group_ids=[ADMIN_GROUP], local_only=True)
            if not isinstance(created, dict) or not isinstance(created.get("user"), dict):
                raise RetainedAccountError("qa_create_uncertain_inspect_users")
            uid = created["user"].get("id")
            if not isinstance(uid, str) or not 16 <= len(uid) <= 128:
                raise RetainedAccountError("qa_create_identity_uncertain_inspect_users")
            after = _inventory(core.command("config/auth/list"))
            hits = _find(after)
            if len(hits) != 1 or hits[0].get("id") != uid or not _safe_target(hits[0]):
                raise RetainedAccountError("qa_retained_validation_failed_inspect_users")
            return "qa_retained_admin_created_no_login"
    except RetainedAccountError:
        raise
    except (RoundTripError, OSError, TimeoutError, ValueError, TypeError):
        raise RetainedAccountError("qa_create_uncertain_inspect_users") from None


def revoke_retained(*, supervisor_token: str,
                    session_factory=SupervisorCoreSession) -> str:
    """Delete only the exact lab account, after another explicit approval.

    Refuse any account with credentials, nonlocal access, owner/system status,
    altered roles, duplicate names, or ambiguous identity. A normal admin can
    always remove this QA user through the Home Assistant Users UI.
    """
    try:
        with session_factory(supervisor_token) as core:
            before = _inventory(core.command("config/auth/list"))
            hits = _find(before)
            if not hits:
                return "qa_retained_admin_already_absent"
            if len(hits) != 1 or not _safe_target(hits[0]):
                raise RetainedAccountError("qa_revoke_target_mismatch_manual_review")
            uid = hits[0]["id"]
            core.command("config/auth/delete", user_id=uid)
            after = _inventory(core.command("config/auth/list"))
            if _find(after) or any(u.get("id") == uid for u in after):
                raise RetainedAccountError("qa_revoke_not_confirmed_check_users")
            return "qa_retained_admin_revoked_verified"
    except RetainedAccountError:
        raise
    except (RoundTripError, OSError, TimeoutError, ValueError, TypeError):
        raise RetainedAccountError("qa_revoke_uncertain_check_users") from None
