import http.server
import http.client
import socketserver
import socket
import struct
import json
import smtplib
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
import ssl
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
import base64
import hashlib
import hmac
import html
import re
from datetime import datetime, timedelta, timezone
import os
import random
import recovery_verifier
import recovery_stage
import secrets
import ipaddress
import math
from pathlib import Path

PORT = 8099
OFFLINE_DEVICES = {}
LOW_BATTERY_DEVICES = {}
last_api_check = 0
GUARDIAN_CONTRACT_ID = 'smart-pro-guardian-v2'
GUARDIAN_STATE_FILE = '/data/guardian_state.json'
GUARDIAN_STATE_LOCK = threading.RLock()
GUARDIAN_ALERT_RETRY_SECONDS = 60
GUARDIAN_EMAIL_RETRY_SECONDS = 15 * 60
GUARDIAN_STATUS_LOCK = threading.Lock()
GUARDIAN_STATUS = {
    'contract': GUARDIAN_CONTRACT_ID,
    'enabled': True,
    'status': 'waiting',
    'reason_code': 'starting',
    'last_check_at': 0,
    'last_successful_check_at': 0,
    'offline_count': 0,
    'low_battery_count': 0,
    'pending_offline_count': 0,
    'alerted_offline_count': 0,
    'retry_pending_count': 0,
    'active_alert': False,
    'last_alert_at': 0,
    'last_alert_request_code': '',
    'last_recovery_at': 0,
    'last_recovery_count': 0,
    'last_error_at': 0,
    'monitoring_scope_count': 0,
    'email_configured': False,
    'email_retry_pending_count': 0,
    'last_email_sent_at': 0,
    'last_email_error_at': 0,
}
TECH_SETTINGS_FILE = '/data/tech_settings.json'
TECHNICIAN_CENTER_CONTRACT_ID = 'smart-pro-technician-center-v1'
TECH_SETTINGS_LOCK = threading.RLock()
CONTROL_PLANE_CONTRACT_ID = 'smart-pro-command-channel-v1'
CONTROL_PLANE_CAPABILITIES_CONTRACT_ID = 'smart-pro-control-plane-capabilities-v1'
CONTROL_PLANE_FREEZE_CONTRACT_ID = 'smart-pro-control-plane-freeze-v1'
CONTROL_PLANE_FREEZE_ID = 'generation-1-20260927'
CONTROL_PLANE_STATE_FILE = Path('/data/control_plane_channel.json')
CONTROL_PLANE_LOCK = threading.RLock()
CONTROL_PLANE_MAX_TTL_SECONDS = 120
CONTROL_PLANE_CLOCK_SKEW_SECONDS = 30

# Managed Backup 2.4.40 storage-handoff readiness milestone. Identity, policy receive
# and local-readiness remain intact. This release can execute exactly one signed,
# Portal-originated local-only Managed Backup job plus provider-neutral source handoff readiness. Upload/storage/retention/restore/delete
# authority remains unavailable.
MANAGED_BACKUP_AGENT_CONTRACT_ID = 'smart-pro-managed-backup-agent-v1'
MANAGED_BACKUP_AGENT_STATE_FILE = Path('/data/managed_backup_agent.json')
MANAGED_BACKUP_AGENT_LOCK = threading.RLock()
MANAGED_BACKUP_AGENT_CAPABILITIES = ('node_identity', 'policy_receive', 'local_backup_readiness', 'local_backup_create', 'storage_handoff_readiness', 'primary_storage_upload', 'primary_presigned_upload', 'primary_presigned_upload_execute', 'recovery_download_sha256', 'recovery_supervisor_stage')
MANAGED_BACKUP_AGENT_RUNTIME_KEYS = (
    'backup_jobs_authorized',
    'backup_io_authorized',
    'storage_authorized',
    'restore_authorized',
    'delete_authorized',
)

# Managed External URL 2.4.43 read-only Tunnel enrollment + Gateway observation foundation; HA transport hotfix 2.4.44.
# The dedicated local identity/proof remains unchanged. Smart Pro Tools may now
# accept one bounded, non-secret Gateway Registry observation from the already
# authenticated Portal heartbeat. The observation is informational only: it is
# kept in memory, grants no runtime authority, starts no tunnel, changes no DNS,
# and cannot mutate the Gateway Registry.
EXTERNAL_ACCESS_AGENT_CONTRACT_ID = 'smart-pro-external-access-agent-v1'
EXTERNAL_ACCESS_GATEWAY_OBSERVATION_CONTRACT_ID = 'smart-pro-external-access-gateway-observation-v1'
EXTERNAL_ACCESS_AGENT_STATE_FILE = Path('/data/external_access_agent.json')
EXTERNAL_ACCESS_TUNNEL_ENROLLMENT_CONTRACT_ID = 'smart-pro-tunnel-enrollment-material-v1'
EXTERNAL_ACCESS_TUNNEL_ENROLLMENT_FILE = Path('/share/smart-pro/tunnel/enrollment.json')
EXTERNAL_ACCESS_TUNNEL_RUNTIME_FILE = Path('/share/smart-pro/tunnel/runtime-status.json')
EXTERNAL_ACCESS_AGENT_LOCK = threading.RLock()
EXTERNAL_ACCESS_GATEWAY_OBSERVATION_LOCK = threading.RLock()
EXTERNAL_ACCESS_AGENT_CAPABILITIES = (
    'external_access_identity',
    'home_assistant_target_probe',
    'gateway_observation_read_only',
    'tunnel_enrollment_read_only',
    'tunnel_runtime_status_v1',
    'tunnel_supervisor_control_v1',
    'fail_closed_runtime',
)
EXTERNAL_ACCESS_GATEWAY_STATES = frozenset((
    'reserved',
    'tunnel_pending',
    'gateway_ready',
    'dns_pending',
    'public_pending',
    'active',
))
EXTERNAL_ACCESS_GATEWAY_OBSERVATION_MAX_AGE_SECONDS = 300
EXTERNAL_ACCESS_HOSTNAME_PATTERN = re.compile(
    r'[a-z2-7]{26}\.connect\.smart-pro-system\.com'
)
EXTERNAL_ACCESS_TUNNEL_NETWORK = ipaddress.ip_network('10.203.0.0/16')
EXTERNAL_ACCESS_RESERVED_GATEWAY_NETWORK = ipaddress.ip_network('10.203.0.0/24')

# vNext 3.0.8 replacement-device companion recovery pilot. The Smart Pro System
# may install and perform one initial identity-only start of the official Smart Pro
# Tunnel app when the verified Portal heartbeat says Managed External URL is
# entitled and the Tunnel is absent. Runtime provisioning remains exclusively on
# the existing signed Control Plane. No private key or Gateway credential is
# generated, copied or persisted by this recovery layer.
SMART_PRO_TUNNEL_RECOVERY_CONTRACT_ID = 'smart-pro-tunnel-recovery-v1'
SMART_PRO_TUNNEL_RECOVERY_STATE_FILE = Path('/data/smart_pro_tunnel_recovery.json')
SMART_PRO_TUNNEL_RECOVERY_STATE_LOCK = threading.RLock()
SMART_PRO_TUNNEL_RECOVERY_WORKER_LOCK = threading.Lock()
SMART_PRO_TUNNEL_RECOVERY_BACKOFF_SECONDS = 15 * 60
SMART_PRO_TUNNEL_OFFICIAL_REPOSITORY_URL = 'https://github.com/smartprosystempp-spec/smart-pro-system-home-assistant'
SMART_PRO_TUNNEL_MIN_RECOVERY_VERSION = (0, 1, 7)


def _external_access_gateway_observation_default():
    return {
        'contract': EXTERNAL_ACCESS_GATEWAY_OBSERVATION_CONTRACT_ID,
        'status': 'unavailable',
        'installation_id': '',
        'registry_sha256': '',
        'registry_state': 'unknown',
        'canonical_hostname': '',
        'peer_address': '',
        'source': 'portal_gateway_registry',
        'read_only': True,
        'runtime_authority': False,
        'observed_at': 0,
        'received_at': 0,
    }


EXTERNAL_ACCESS_GATEWAY_OBSERVATION = _external_access_gateway_observation_default()


def _external_access_agent_default_state():
    return {
        'version': 1,
        'node_id': '',
        'created_at': 0,
        'updated_at': 0,
    }


def load_external_access_agent_state():
    with EXTERNAL_ACCESS_AGENT_LOCK:
        state = _external_access_agent_default_state()
        if EXTERNAL_ACCESS_AGENT_STATE_FILE.exists():
            try:
                raw = json.loads(EXTERNAL_ACCESS_AGENT_STATE_FILE.read_text(encoding='utf-8'))
                if isinstance(raw, dict):
                    node_id = str(raw.get('node_id', '') or '').strip().lower()
                    if re.fullmatch(r'[0-9a-f]{64}', node_id):
                        state['node_id'] = node_id
                    state['created_at'] = max(0, int(raw.get('created_at', 0) or 0))
                    state['updated_at'] = max(0, int(raw.get('updated_at', 0) or 0))
            except Exception:
                pass
        return state


def save_external_access_agent_state(state):
    with EXTERNAL_ACCESS_AGENT_LOCK:
        safe = _external_access_agent_default_state()
        node_id = str((state or {}).get('node_id', '') or '').strip().lower()
        if re.fullmatch(r'[0-9a-f]{64}', node_id):
            safe['node_id'] = node_id
        safe['created_at'] = max(0, int((state or {}).get('created_at', 0) or 0))
        safe['updated_at'] = max(0, int((state or {}).get('updated_at', 0) or 0))
        EXTERNAL_ACCESS_AGENT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = EXTERNAL_ACCESS_AGENT_STATE_FILE.with_suffix('.tmp')
        tmp.write_text(json.dumps(safe, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        os.chmod(tmp, 0o600)
        os.replace(tmp, EXTERNAL_ACCESS_AGENT_STATE_FILE)
        os.chmod(EXTERNAL_ACCESS_AGENT_STATE_FILE, 0o600)
        return safe


def _external_access_agent_ensure_node_id():
    state = load_external_access_agent_state()
    node_id = str(state.get('node_id', '') or '').strip().lower()
    if re.fullmatch(r'[0-9a-f]{64}', node_id):
        return node_id
    node_id = secrets.token_hex(32)
    now = int(time.time())
    state['node_id'] = node_id
    state['created_at'] = now
    state['updated_at'] = now
    save_external_access_agent_state(state)
    print(f'[EXTURL] External Access node identity created: {node_id[:8]}…{node_id[-6:]}', flush=True)
    return node_id


def _external_access_control_secret():
    state = load_control_plane_state()
    key_id = str(state.get('key_id', '') or '').strip().lower()
    secret_b64 = str(state.get('secret_b64', '') or '').strip()
    if not re.fullmatch(r'[0-9a-f]{16}', key_id) or not secret_b64:
        return b''
    try:
        secret = base64.b64decode(secret_b64.encode('ascii'), validate=True)
    except Exception:
        return b''
    if len(secret) != 32 or hashlib.sha256(secret).hexdigest()[:16] != key_id:
        return b''
    return secret


def _external_access_node_key_id(node_id):
    node_id = str(node_id or '').strip().lower()
    installation_id = str(paired_installation_id() or '').strip().upper()
    if not re.fullmatch(r'[0-9a-f]{64}', node_id) or not installation_id:
        return ''
    secret = _external_access_control_secret()
    if len(secret) != 32:
        return ''
    message = f'external-access-node-v1|{installation_id}|{node_id}'.encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()[:16]


def _external_access_normalize_peer_address(value):
    raw = str(value or '').strip()
    try:
        interface = ipaddress.ip_interface(raw)
    except ValueError as exc:
        raise ValueError('gateway_observation_peer_address_invalid') from exc
    if interface.version != 4 or interface.network.prefixlen != 32:
        raise ValueError('gateway_observation_peer_address_invalid')
    if interface.ip not in EXTERNAL_ACCESS_TUNNEL_NETWORK:
        raise ValueError('gateway_observation_peer_address_invalid')
    if interface.ip in EXTERNAL_ACCESS_RESERVED_GATEWAY_NETWORK:
        raise ValueError('gateway_observation_peer_address_invalid')
    return f'{interface.ip}/32'


def _external_access_normalize_gateway_observation(observation):
    if not isinstance(observation, dict):
        raise ValueError('gateway_observation_missing')
    if str(observation.get('contract', '') or '') != EXTERNAL_ACCESS_GATEWAY_OBSERVATION_CONTRACT_ID:
        raise ValueError('gateway_observation_contract_invalid')

    expected_installation_id = str(paired_installation_id() or '').strip().upper()
    installation_id = str(observation.get('installation_id', '') or '').strip().upper()
    if not expected_installation_id or installation_id != expected_installation_id:
        raise ValueError('gateway_observation_installation_mismatch')

    registry_sha256 = str(observation.get('registry_sha256', '') or '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', registry_sha256):
        raise ValueError('gateway_observation_registry_sha256_invalid')

    registry_state = str(observation.get('registry_state', '') or '').strip().lower()
    if registry_state not in EXTERNAL_ACCESS_GATEWAY_STATES:
        raise ValueError('gateway_observation_registry_state_invalid')

    canonical_hostname = str(observation.get('canonical_hostname', '') or '').strip().lower().rstrip('.')
    if not EXTERNAL_ACCESS_HOSTNAME_PATTERN.fullmatch(canonical_hostname):
        raise ValueError('gateway_observation_hostname_invalid')

    peer_address = _external_access_normalize_peer_address(observation.get('peer_address'))

    if str(observation.get('source', '') or '') != 'portal_gateway_registry':
        raise ValueError('gateway_observation_source_invalid')
    if observation.get('read_only') is not True:
        raise ValueError('gateway_observation_read_only_required')
    if observation.get('runtime_authority') is not False:
        raise ValueError('gateway_observation_runtime_authority_forbidden')

    now = int(time.time())
    observed_at = int(observation.get('observed_at', 0) or 0)
    if observed_at <= 0 or observed_at > now + CONTROL_PLANE_CLOCK_SKEW_SECONDS:
        raise ValueError('gateway_observation_timestamp_invalid')

    return {
        'contract': EXTERNAL_ACCESS_GATEWAY_OBSERVATION_CONTRACT_ID,
        'status': 'observed',
        'installation_id': installation_id,
        'registry_sha256': registry_sha256,
        'registry_state': registry_state,
        'canonical_hostname': canonical_hostname,
        'peer_address': peer_address,
        'source': 'portal_gateway_registry',
        'read_only': True,
        'runtime_authority': False,
        'observed_at': observed_at,
        'received_at': now,
    }


def external_access_gateway_observation_snapshot():
    with EXTERNAL_ACCESS_GATEWAY_OBSERVATION_LOCK:
        observation = dict(EXTERNAL_ACCESS_GATEWAY_OBSERVATION)
    paired_id = str(paired_installation_id() or '').strip().upper()
    now = int(time.time())
    if (
        observation.get('status') == 'observed'
        and paired_id
        and observation.get('installation_id') == paired_id
    ):
        age = max(0, now - int(observation.get('observed_at', 0) or 0))
        observation['age_seconds'] = age
        observation['fresh'] = age <= EXTERNAL_ACCESS_GATEWAY_OBSERVATION_MAX_AGE_SECONDS
        if not observation['fresh']:
            observation['status'] = 'stale'
    else:
        observation['age_seconds'] = None
        observation['fresh'] = False
    return observation


def _external_access_tunnel_enrollment_snapshot():
    unavailable = {
        'contract': EXTERNAL_ACCESS_TUNNEL_ENROLLMENT_CONTRACT_ID,
        'status': 'unavailable',
        'public_key': '',
        'tunnel_version': '',
        'source': 'smart_pro_tunnel_local_share',
        'private_key_exposed': False,
        'runtime_authority': False,
        'observed_at': 0,
    }
    try:
        path = EXTERNAL_ACCESS_TUNNEL_ENROLLMENT_FILE
        st = path.stat()
        if (st.st_mode & 0o077) != 0:
            return unavailable | {'status': 'unsafe_permissions'}
        raw = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            return unavailable | {'status': 'invalid'}
        if str(raw.get('contract', '') or '') != EXTERNAL_ACCESS_TUNNEL_ENROLLMENT_CONTRACT_ID:
            return unavailable | {'status': 'invalid_contract'}
        public_key = str(raw.get('public_key', '') or '').strip()
        try:
            decoded = base64.b64decode(public_key.encode('ascii'), validate=True)
        except Exception:
            return unavailable | {'status': 'invalid_public_key'}
        if len(decoded) != 32:
            return unavailable | {'status': 'invalid_public_key'}
        if str(raw.get('source', '') or '') != 'smart_pro_tunnel_local_share':
            return unavailable | {'status': 'invalid_source'}
        if raw.get('private_key_exposed') is not False or raw.get('runtime_authority') is not False:
            return unavailable | {'status': 'unsafe_flags'}
        tunnel_version = str(raw.get('version', '') or '').strip()[:32]
        observed_at = max(0, int(raw.get('updated_at', 0) or 0))
        return {
            'contract': EXTERNAL_ACCESS_TUNNEL_ENROLLMENT_CONTRACT_ID,
            'valid': True,
            'status': 'ready',
            'public_key': public_key,
            'public_key_sha256': hashlib.sha256(public_key.encode('utf-8')).hexdigest(),
            'tunnel_version': tunnel_version,
            'source': 'smart_pro_tunnel_local_share',
            'private_key_exposed': False,
            'runtime_authority': False,
            'observed_at': observed_at,
        }
    except FileNotFoundError:
        return unavailable
    except Exception:
        return unavailable | {'status': 'invalid'}


def _external_access_tunnel_runtime_snapshot():
    default = {'status':'off','state':'off','peer_address':'','private_proxy_state':'off','home_assistant_target_reachable':False,'updated_at':0}
    try:
        raw=json.loads(EXTERNAL_ACCESS_TUNNEL_RUNTIME_FILE.read_text(encoding='utf-8'))
        if not isinstance(raw,dict) or str(raw.get('contract',''))!='smart-pro-tunnel-runtime-status-v1': return default
        state=str(raw.get('state','') or '').strip().lower()
        if state not in {'identity_ready','starting','up_no_handshake','connected','handshake_stale','stopped','failed'}: state='off'
        peer=_external_access_normalize_peer_address(raw.get('peer_address')) or ''
        return {'status':'ready','state':state,'peer_address':peer,'private_proxy_state':str(raw.get('private_proxy_state','off') or 'off')[:32],'home_assistant_target_reachable':bool(raw.get('home_assistant_target_reachable',False)),'handshake_age_seconds':raw.get('handshake_age_seconds'),'updated_at':max(0,int(raw.get('updated_at',0) or 0))}
    except Exception:
        return default

def external_access_agent_heartbeat_snapshot():
    node_id = _external_access_agent_ensure_node_id()
    connection = load_portal_connection()
    installation_binding_present = bool(str(connection.get('installation_id', '') or '').strip() and str(connection.get('installation_token', '') or '').strip())
    ha_target_ready = bool(os.getenv('SUPERVISOR_TOKEN') or load_addon_options().get('ha_token'))
    tunnel_rt = _external_access_tunnel_runtime_snapshot()
    tunnel_state = str(tunnel_rt.get('state','off') or 'off')
    gateway_state = 'private_ready' if tunnel_state == 'connected' and str(tunnel_rt.get('private_proxy_state','')) == 'listening' else ('configuring' if tunnel_state not in ('off','identity_ready','stopped','failed') else 'not_configured')
    return {
        'contract': EXTERNAL_ACCESS_AGENT_CONTRACT_ID,
        'supported': True,
        'tools_version': ADDON_VERSION,
        'node_id': node_id,
        'node_key_id': _external_access_node_key_id(node_id),
        'capabilities': list(EXTERNAL_ACCESS_AGENT_CAPABILITIES),
        'installation_binding_present': installation_binding_present,
        'home_assistant_target_ready': ha_target_ready,
        'gateway_observation': external_access_gateway_observation_snapshot(),
        'tunnel_enrollment': _external_access_tunnel_enrollment_snapshot(),
        'tunnel_runtime': tunnel_state,
        'gateway_state': gateway_state,
        'public_route_state': 'not_issued',
        'runtime_authority': False,
        'router_mutation': 'none',
        'inbound_listener': 'off',
        'checked_at': int(time.time()),
    }


def _normalize_external_access_portal_state(external):
    """Minimize Portal-owned External URL state for read-only customer presentation."""
    default = {
        'eligible': False,
        'eligibility_source': 'none',
        'package_eligible': False,
        'standalone': {
            'status': 'not_configured',
            'eligible': False,
            'starts_at': 0,
            'ends_at': 0,
            'cycle': '',
        },
        'publication': {
            'status': 'unknown',
            'public_ready': False,
            'hostname': '',
        },
    }
    if not isinstance(external, dict):
        return default

    entitlement = external.get('entitlement') if isinstance(external.get('entitlement'), dict) else {}
    customer = external.get('customer_state') if isinstance(external.get('customer_state'), dict) else {}

    source = str(entitlement.get('eligibility_source', customer.get('eligibility_source', external.get('eligibility_source', 'none'))) or 'none').strip().lower()
    if source not in {'none', 'package', 'standalone', 'package_and_standalone'}:
        source = 'none'

    # Accept both raw Portal schemas and the already-normalized state persisted
    # in portal_connection.json. This makes the normalizer idempotent and avoids
    # losing standalone/publication detail on the customer-summary read path.
    persisted_standalone = external.get('standalone') if isinstance(external.get('standalone'), dict) else {}
    raw_standalone = entitlement.get('standalone') if isinstance(entitlement.get('standalone'), dict) else {}
    customer_standalone = customer.get('standalone') if isinstance(customer.get('standalone'), dict) else {}
    standalone = dict(persisted_standalone)
    standalone.update(customer_standalone)
    standalone.update(raw_standalone)
    standalone_status = str(standalone.get('status', 'not_configured') or 'not_configured').strip().lower()
    if standalone_status not in {'not_configured', 'pending', 'active', 'grace', 'expired', 'suspended', 'revoked'}:
        standalone_status = 'not_configured'
    cycle = str(standalone.get('cycle', '') or '').strip().lower()
    if cycle not in {'', 'monthly', 'annual'}:
        cycle = ''

    persisted_publication = external.get('publication') if isinstance(external.get('publication'), dict) else {}
    publication = customer.get('publication') if isinstance(customer.get('publication'), dict) else persisted_publication
    publication_status = str(publication.get('status', 'unknown') or 'unknown').strip().lower()
    allowed_publication_states = {
        'unknown', 'awaiting_gateway_observation', 'inactive_no_observation',
        'gateway_observation_stale', 'active_in_sync',
        'active_without_effective_entitlement', 'provisioning_in_progress',
        'provisioning_without_effective_entitlement', 'gateway_state_unresolved',
    }
    if publication_status not in allowed_publication_states:
        publication_status = 'unknown'
    hostname = str(publication.get('hostname', '') or '').strip().lower().rstrip('.')
    if hostname and not EXTERNAL_ACCESS_HOSTNAME_PATTERN.fullmatch(hostname):
        hostname = ''
    public_ready = bool(publication.get('public_ready', False)) and publication_status == 'active_in_sync' and bool(hostname)

    customer_eligible = bool(customer.get('entitlement_eligible', False))
    package_eligible = bool(entitlement.get('package_eligible', customer.get('package_eligible', external.get('package_eligible', False))))
    standalone_eligible = bool(standalone.get('eligible', False))
    eligible = bool(external.get('eligible', False)) or bool(entitlement.get('eligible', False)) or customer_eligible or package_eligible or standalone_eligible

    return {
        'eligible': eligible,
        'eligibility_source': source,
        'package_eligible': package_eligible,
        'standalone': {
            'status': standalone_status,
            'eligible': standalone_eligible,
            'starts_at': max(0, int(standalone.get('starts_at', 0) or 0)),
            'ends_at': max(0, int(standalone.get('ends_at', 0) or 0)),
            'cycle': cycle,
        },
        'publication': {
            'status': publication_status,
            'public_ready': public_ready,
            'hostname': hostname,
        },
    }


def _portal_maybe_process_external_access(response):
    external = response.get('external_access') if isinstance(response, dict) else None
    customer_bridge = response.get('external_access_customer') if isinstance(response, dict) else None

    external_valid = isinstance(external, dict) and str(external.get('contract', '') or '') == EXTERNAL_ACCESS_AGENT_CONTRACT_ID
    bridge_valid = isinstance(customer_bridge, dict) and str(customer_bridge.get('contract', '') or '') == 'smart-pro-external-access-customer-state-v1'

    if external_valid:
        portal_state = _normalize_external_access_portal_state(external)
    else:
        portal_state = _normalize_external_access_portal_state({})

    # 3.0.5: the customer bridge is intentionally separate from the runtime
    # authority contract. It survives older External Access response schemas and
    # carries only read-only entitlement/publication presentation truth.
    if bridge_valid:
        if customer_bridge.get('read_only') is True and customer_bridge.get('runtime_authority') is False:
            bridge_state = _normalize_external_access_portal_state({'customer_state': customer_bridge})
            portal_state = bridge_state
        else:
            print('[EXTURL] Customer heartbeat bridge advertised unsafe flags; ignored.', flush=True)

    if not external_valid:
        return portal_state if bridge_valid else None

    runtime = external.get('runtime') if isinstance(external.get('runtime'), dict) else {}
    forbidden = (
        'tunnel_transport_authorized',
        'gateway_connect_authorized',
        'route_publish_authorized',
        'dns_authorized',
        'public_ingress_authorized',
    )
    if any(bool(runtime.get(key, False)) for key in forbidden):
        print('[EXTURL] Portal advertised External URL runtime authority outside the signed control-plane path; refused fail-closed.', flush=True)
        return portal_state

    observation = external.get('gateway_observation')
    if observation is None:
        return portal_state

    try:
        normalized = _external_access_normalize_gateway_observation(observation)
    except Exception as exc:
        print(f'[EXTURL] Read-only Gateway observation rejected: {str(exc)[:96]}', flush=True)
        return portal_state

    with EXTERNAL_ACCESS_GATEWAY_OBSERVATION_LOCK:
        EXTERNAL_ACCESS_GATEWAY_OBSERVATION.clear()
        EXTERNAL_ACCESS_GATEWAY_OBSERVATION.update(normalized)
    return portal_state


# Generation-1 authority manifest. This is the single source of truth for both
# command execution and the read-only capability declaration sent to Portal.
CONTROL_PLANE_ALLOWED_CAPABILITIES = {
    ('probe', 'control_plane_probe'),
    ('settings_update', 'guardian_settings_manage'),
    ('settings_update', 'guardian_scope_manage'),
    ('settings_update', 'guardian_master_manage'),
    ('settings_update', 'guardian_safe_test_policy_manage'),
    ('settings_update', 'smart_updates_policy_manage'),
    ('settings_update', 'smart_updates_master_manage'),
    ('settings_update', 'vacation_policy_manage'),
    ('settings_update', 'vacation_master_manage'),
    ('action', 'smart_updates_safe_test_run'),
    ('action', 'guardian_safe_test_start'),
    ('action', 'guardian_safe_test_cancel'),
    ('action', 'guardian_email_test'),
    ('action', 'external_url_tunnel_configure_start'),
}
CONTROL_PLANE_FAMILIES = (
    'control_plane_probe',
    'guardian_policy',
    'guardian_scope',
    'guardian_actions',
    'guardian_master',
    'guardian_safe_test_policy',
    'smart_updates_policy',
    'smart_updates_master',
    'smart_updates_safe_test',
    'vacation_policy',
    'vacation_master',
    'managed_external_url_private_tunnel',
)
CONTROL_PLANE_LOCAL_ONLY_BOUNDARIES = (
    'smtp_credentials',
    'guardian_safe_test_device_name',
    'vacation_entity_selections',
    'managed_support_manual_pause',
    'pairing_recovery_identity',
    'home_assistant_token',
    'meshcentral_secrets',
    'privileged_recovery_actions',
    'mesh_banner_local_presentation',
    'manual_remote_banner',
    'legacy_subscription_fallback',
)
CONTROL_PLANE_SECURITY_GUARDS = (
    'hmac_signature',
    'installation_binding',
    'key_binding',
    'capability_allowlist',
    'ttl',
    'clock_skew',
    'nonce_replay',
    'command_id_reuse',
)

TECH_SESSION_TTL_SECONDS = 15 * 60
TECH_SESSION_LOCK = threading.Lock()
TECH_SESSIONS = {}

WATCHDOG_TEST_LOCK = threading.Lock()
WATCHDOG_TEST_STATE = {
    'status': 'idle',
    'message': 'Δεν εκτελείται δοκιμή.',
}

SMART_UPDATES_TEST_LOCK = threading.Lock()
SMART_UPDATES_TEST_STATE = {
    'status': 'idle',
    'message': 'Δεν έχει εκτελεστεί ασφαλής δοκιμή Smart Updates.',
    'steps': [],
    'real_actions_executed': False,
}
SMART_UPDATES_TEST_SCENARIOS = {
    'notify_only': 'Μόνο ειδοποίηση',
    'success': 'Επιτυχής ενημέρωση',
    'backup_failure': 'Αποτυχία backup',
    'update_failure': 'Αποτυχία εγκατάστασης',
    'rollback_success': 'Πρόβλημα υγείας — επιτυχές rollback',
    'rollback_failure': 'Πρόβλημα υγείας — αποτυχία rollback',
}

PORTAL_CONNECTION_FILE = Path('/data/portal_connection.json')
ADDON_VERSION = os.getenv('ADDON_VERSION') or '3.0.14'
PORTAL_HEARTBEAT_DEFAULT = 30
PORTAL_STATE_LOCK = threading.Lock()

# 2.4.21 Fresh Diagnostic Check contract: a Portal heartbeat response may
# request one forced local read-only HA diagnostics refresh. Smart Pro Tools
# acknowledges the exact request on a second heartbeat; no HA mutation, remote
# access grant or automation action is performed by this path.
# Smart Pro Diagnostics contract: Home Assistant collection is deliberately
# independent from Guardian/Smart Updates. Only aggregate, non-secret facts are
# placed on the Portal heartbeat; the HA token and raw entity identifiers remain
# local to the installation.
HA_DIAGNOSTICS_CONTRACT_ID = 'smart-pro-home-assistant-diagnostics-v7'
HA_ERROR_LOG_MAX_BYTES = 64 * 1024
HA_ERROR_LOG_MAX_LINES = 24
HA_ERROR_LOG_MAX_LINE_CHARS = 360
HA_DIAGNOSTICS_REFRESH_SECONDS = 60
HA_DIAGNOSTICS_BATTERY_THRESHOLD = 15.0
HA_DIAGNOSTICS_LOCK = threading.RLock()
HA_DIAGNOSTICS_STATE = {
    'contract': HA_DIAGNOSTICS_CONTRACT_ID,
    'monitored': False,
    'configured': False,
    'health_state': 'waiting',
    'reason_code': 'not_collected',
    'collected_at': 0,
    'home_assistant_version': '',
    'core_state': '',
    'safe_mode': False,
    'total_entities': 0,
    'unavailable_entities': 0,
    'unknown_entities': 0,
    'low_battery_entities': 0,
    'updates_pending': 0,
    'updates_detected': 0,
    'updates_skipped': 0,
    'repairs_available': False,
    'repairs_active': 0,
    'repairs_warning': 0,
    'repairs_error': 0,
    'repairs_critical': 0,
    'repairs_fixable': 0,
    'repairs_collection_status': 'not_collected',
    'device_registry_available': False,
    'devices_total': 0,
    'devices_disabled': 0,
    'devices_attention': 0,
    'devices_unavailable': 0,
    'devices_unknown': 0,
    'devices_low_battery': 0,
    'attention_entities_without_device': 0,
    'entity_registry_total': 0,
    'entity_registry_disabled': 0,
    'device_registry_collection_status': 'not_collected',
    'entity_registry_collection_status': 'not_collected',
    'integration_diagnostics_available': False,
    'integration_entries_total': 0,
    'integration_domains_total': 0,
    'integration_loaded_entries': 0,
    'integration_disabled_entries': 0,
    'integration_attention_entries': 0,
    'integration_setup_error_entries': 0,
    'integration_retry_entries': 0,
    'integration_migration_error_entries': 0,
    'integration_failed_unload_entries': 0,
    'integration_not_loaded_entries': 0,
    'integration_collection_status': 'not_collected',
    'supervisor_diagnostics_available': False,
    'supervisor_version': '',
    'supervisor_healthy': False,
    'supervisor_supported': False,
    'supervisor_update_available': False,
    'addons_diagnostics_available': False,
    'addons_total': 0,
    'addons_running': 0,
    'addons_stopped': 0,
    'addons_error': 0,
    'addons_unknown': 0,
    'addons_update_available': 0,
    'addons_unavailable': 0,
    'addons_system_managed': 0,
    'supervisor_addons_collection_status': 'not_collected',
    'backup_diagnostics_available': False,
    'backups_total': 0,
    'backups_homeassistant': 0,
    'backups_full': 0,
    'backups_partial': 0,
    'backups_protected': 0,
    'backup_days_until_stale': 0,
    'backup_latest_at': 0,
    'backup_latest_age_seconds': 0,
    'backup_latest_type': '',
    'backup_latest_protected': False,
    'backup_latest_stale': False,
    'backup_collection_status': 'not_collected',
    'error_log_available': False,
    'error_log_collection_status': 'not_collected',
    'error_log_observed_lines': 0,
    'error_log_selected_count': 0,
    'error_log_truncated': False,
    'error_log_fingerprint': '',
    'error_log_entries': [],
    'battery_threshold_percent': HA_DIAGNOSTICS_BATTERY_THRESHOLD,
}

SUBSCRIPTION_SCHEMA_VERSION = 1
SUBSCRIPTION_VERIFICATION_TOLERANCE_DEFAULT = 72 * 60 * 60
SUBSCRIPTION_VERIFICATION_TOLERANCE_MIN = 60 * 60
SUBSCRIPTION_VERIFICATION_TOLERANCE_MAX = 7 * 24 * 60 * 60
SUBSCRIPTION_PLANS = {'none', 'care', 'advanced', 'complete'}
SUBSCRIPTION_STATUSES = {'pending_activation', 'active', 'grace', 'expired', 'suspended'}
SUBSCRIPTION_ENTITLEMENTS = {
    'managed_remote_support',
    'guardian_monitoring',
    'backup_health',
    'support_requests',
    'update_guidance',
    'advanced_diagnostics',
    'technical_reports',
    'limited_changes',
}

MANAGED_POLICY_VERSION = 1
MANAGED_POLICY_CONTRACT_ID = 'smart-pro-managed-policy-v1'
MANAGED_POLICY_REFRESH_SECONDS = 30
MANAGED_TOOLS_LEASE_SECONDS = 120
MANAGED_POLICY_FILE = Path('/share/smart-pro-system/managed-policy.json')

MANAGED_NETWORK_VERSION = 1
MANAGED_NETWORK_CONTRACT_ID = 'smart-pro-managed-network-v1'
MANAGED_NETWORK_REFRESH_SECONDS = MANAGED_POLICY_REFRESH_SECONDS
MANAGED_NETWORK_LEASE_SECONDS = MANAGED_TOOLS_LEASE_SECONDS
MANAGED_NETWORK_FILE = Path('/share/smart-pro-system/managed-network.json')
MANAGED_NETWORK_ROUTE_FILE = Path('/proc/net/route')
MANAGED_NETWORK_PRIVATE_V4 = (
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
)

SMTP_SERVER = 'mail.smart-pro-system.gr'
SMTP_PORT = 465
ALERT_EMAIL = 'alert@smart-pro-system.gr'
WATCHDOG_TERMINAL_STATUSES = {'completed', 'cancelled', 'failed', 'expired'}

class PortalAPIError(Exception):
    def __init__(self, message, status=0, code='portal_error'):
        super().__init__(message)
        self.status = status
        self.code = code

def clean_portal_error_message(value, fallback='Σφάλμα επικοινωνίας με το Portal.'):
    text = html.unescape(str(value or ''))
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if not text:
        return fallback
    return text[:500]

def load_addon_options():
    try:
        with open('/data/options.json', encoding='utf-8') as file:
            return json.load(file)
    except Exception:
        return {}

def normalize_portal_url(value):
    url = str(value or '').strip().rstrip('/')
    if not url:
        url = 'https://smart-pro-system.gr'
    if not url.startswith(('https://', 'http://')):
        url = 'https://' + url
    return url

def load_portal_connection():
    with PORTAL_STATE_LOCK:
        if not PORTAL_CONNECTION_FILE.exists():
            return {}
        try:
            return json.loads(PORTAL_CONNECTION_FILE.read_text(encoding='utf-8'))
        except Exception:
            return {}

def save_portal_connection(data):
    with PORTAL_STATE_LOCK:
        PORTAL_CONNECTION_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = PORTAL_CONNECTION_FILE.with_suffix('.tmp')
        tmp_file.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        os.chmod(tmp_file, 0o600)
        tmp_file.replace(PORTAL_CONNECTION_FILE)
        os.chmod(PORTAL_CONNECTION_FILE, 0o600)

def clear_portal_connection():
    with PORTAL_STATE_LOCK:
        try:
            PORTAL_CONNECTION_FILE.unlink(missing_ok=True)
        except Exception:
            pass

def _subscription_optional_int(value):
    if value is None or value == '':
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_portal_subscription(value):
    """Validate and minimize the subscription contract returned by the Portal."""
    if not isinstance(value, dict):
        return None

    plan = str(value.get('plan', 'none') or 'none').strip().lower()
    status = str(value.get('status', '') or '').strip().lower()
    if plan not in SUBSCRIPTION_PLANS or status not in SUBSCRIPTION_STATUSES:
        return None

    schema_version = _subscription_optional_int(value.get('schema_version')) or SUBSCRIPTION_SCHEMA_VERSION
    if schema_version != SUBSCRIPTION_SCHEMA_VERSION:
        return None

    tolerance = _subscription_optional_int(value.get('verification_tolerance_seconds'))
    if tolerance is None:
        tolerance = SUBSCRIPTION_VERIFICATION_TOLERANCE_DEFAULT
    tolerance = max(
        SUBSCRIPTION_VERIFICATION_TOLERANCE_MIN,
        min(tolerance, SUBSCRIPTION_VERIFICATION_TOLERANCE_MAX),
    )

    raw_entitlements = value.get('entitlements') if isinstance(value.get('entitlements'), dict) else {}
    entitlements = {
        key: bool(raw_entitlements.get(key, False))
        for key in sorted(SUBSCRIPTION_ENTITLEMENTS)
    }
    raw_package_entitlements = value.get('package_entitlements') if isinstance(value.get('package_entitlements'), dict) else {}
    package_entitlements = {
        key: bool(raw_package_entitlements.get(key, False))
        for key in sorted(SUBSCRIPTION_ENTITLEMENTS)
    }

    raw_access = value.get('service_access') if isinstance(value.get('service_access'), dict) else {}
    access_contract = str(raw_access.get('contract_version', '') or '').strip()[:80]
    access_state = str(raw_access.get('state', '') or '').strip().lower()[:48]
    allowed_access_states = {
        'trial', 'active', 'grace', 'expired', 'suspended',
        'pending_activation', 'trial_expired',
    }
    if access_state not in allowed_access_states:
        access_state = status
    is_trial = access_state == 'trial'
    if is_trial:
        # 2.4.56: Trial is an onboarding/presentation state, not a paid package.
        # Fail closed locally even if an older Portal snapshot advertised package
        # entitlements during Trial. Pairing/heartbeat remain available outside
        # these paid service gates.
        entitlements = {key: False for key in sorted(SUBSCRIPTION_ENTITLEMENTS)}
    service_access = {
        'contract_version': access_contract,
        'state': access_state,
        'state_label': clean_portal_error_message(raw_access.get('state_label'), access_state)[:120],
        'platform_services_active': False if is_trial else bool(raw_access.get('platform_services_active', value.get('services_active', status in {'active', 'grace'}))),
        'paid_services_active': False if is_trial else bool(raw_access.get('paid_services_active', status in {'active', 'grace'})),
        'trial_active': bool(raw_access.get('trial_active', is_trial)),
        'managed_relationship_retained': bool(raw_access.get('managed_relationship_retained', True)),
        'support_wallet_paid_only': True if is_trial else bool(raw_access.get('support_wallet_paid_only', True)),
        'trial_end_at': _subscription_optional_int(raw_access.get('trial_end_at')),
    }

    days_remaining = _subscription_optional_int(value.get('days_remaining'))
    if days_remaining is not None:
        days_remaining = max(0, days_remaining)

    return {
        'schema_version': schema_version,
        'plan': plan,
        'plan_label': clean_portal_error_message(value.get('plan_label'), plan)[:120],
        'status': status,
        'status_label': clean_portal_error_message(value.get('status_label'), status)[:120],
        'services_active': bool(value.get('services_active', status in {'active', 'grace'})),
        'start_at': _subscription_optional_int(value.get('start_at')),
        'expires_at': _subscription_optional_int(value.get('expires_at')),
        'grace_until': _subscription_optional_int(value.get('grace_until')),
        'days_remaining': days_remaining,
        'entitlements': entitlements,
        'package_entitlements': package_entitlements,
        'service_access': service_access,
        'last_changed_at': _subscription_optional_int(value.get('last_changed_at')),
        'grace_days': max(0, _subscription_optional_int(value.get('grace_days')) or 7),
        'verification_tolerance_seconds': tolerance,
        'pairing_retained': bool(value.get('pairing_retained', True)),
    }


def update_portal_subscription(connection, response, verified_at=None):
    """Persist a valid Portal subscription snapshot without deleting the last good one."""
    subscription = normalize_portal_subscription(
        response.get('subscription') if isinstance(response, dict) else None
    )
    if not subscription:
        return False

    connection['subscription'] = subscription
    connection['subscription_verified_at'] = int(verified_at or time.time())
    return True


def portal_subscription_public(connection, now=None):
    """Return the cached Portal contract plus its 72-hour verification state."""
    subscription = normalize_portal_subscription(connection.get('subscription'))
    if not subscription:
        return {'available': False, 'enforcement_active': False}

    now_ts = int(now or time.time())
    verified_at = int(connection.get('subscription_verified_at', 0) or 0)
    tolerance = int(
        subscription.get(
            'verification_tolerance_seconds',
            SUBSCRIPTION_VERIFICATION_TOLERANCE_DEFAULT,
        )
    )
    age = max(0, now_ts - verified_at) if verified_at > 0 else None
    verification_valid = bool(verified_at > 0 and age is not None and age <= tolerance)
    has_sync_error = bool(str(connection.get('last_error', '') or '').strip())

    if not verification_valid:
        verification_state = 'verification_required'
        verification_label = 'Απαιτείται επαλήθευση'
    elif has_sync_error:
        verification_state = 'cached'
        verification_label = 'Αποθηκευμένη κατάσταση'
    else:
        verification_state = 'verified'
        verification_label = 'Επαληθευμένη από το Portal'

    public = dict(subscription)
    public.update({
        'available': True,
        'verified_at': verified_at or None,
        'verification_age_seconds': age,
        'verification_deadline': verified_at + tolerance if verified_at > 0 else None,
        'verification_valid': verification_valid,
        'verification_state': verification_state,
        'verification_label': verification_label,
        'using_cached_state': verification_state == 'cached',
        # 2.4.35 activates the Portal-owned service-access contract for
        # subscription-gated platform services. Managed enrollment remains
        # intentionally independent and is NOT gated here.
        'enforcement_active': bool(verification_valid),
    })
    return public


def portal_subscription_available():
    connection = load_portal_connection()
    return bool(normalize_portal_subscription(connection.get('subscription')))


def subscription_service_access(entitlement_key=None, tech_config=None, now=None):
    """Return the authoritative Portal service gate for one platform capability.

    Active/Grace can enable platform services through the Portal contract.
    Trial is onboarding-only and fails closed for paid/runtime entitlements.
    Expired/Suspended/Trial-expired/pending states fail closed. A cached Portal
    snapshot remains usable only while its existing verification tolerance is valid.
    Managed enrollment is deliberately not evaluated by this helper.
    """
    connection = load_portal_connection()
    subscription = portal_subscription_public(connection, now=now)
    tech_config = tech_config or load_tech_settings()

    if not subscription.get('available'):
        # Rolling-compatibility fallback for an installation that has never paired
        # with a Portal capable of the subscription contract.
        legacy_allowed = bool(tech_config.get('subscription_active', True))
        return {
            'allowed': legacy_allowed,
            'reason_code': 'legacy_local_allowed' if legacy_allowed else 'legacy_local_inactive',
            'state': 'legacy',
            'entitlement': entitlement_key or '',
            'source': 'legacy_local',
        }

    if not subscription.get('verification_valid'):
        return {
            'allowed': False,
            'reason_code': 'verification_required',
            'state': str((subscription.get('service_access') or {}).get('state') or subscription.get('status') or ''),
            'entitlement': entitlement_key or '',
            'source': 'portal',
        }

    access = subscription.get('service_access') if isinstance(subscription.get('service_access'), dict) else {}
    state = str(access.get('state') or subscription.get('status') or '').strip().lower()
    if state == 'trial':
        return {
            'allowed': False,
            'reason_code': 'trial_no_paid_entitlements',
            'state': state,
            'entitlement': entitlement_key or '',
            'source': 'portal',
        }
    platform_active = bool(access.get('platform_services_active', subscription.get('services_active', False)))
    if not platform_active:
        return {
            'allowed': False,
            'reason_code': f'service_state_{state or "inactive"}',
            'state': state,
            'entitlement': entitlement_key or '',
            'source': 'portal',
        }

    if entitlement_key:
        entitlements = subscription.get('entitlements') if isinstance(subscription.get('entitlements'), dict) else {}
        if not bool(entitlements.get(entitlement_key, False)):
            return {
                'allowed': False,
                'reason_code': 'entitlement_missing',
                'state': state,
                'entitlement': entitlement_key,
                'source': 'portal',
            }

    return {
        'allowed': True,
        'reason_code': 'allowed_cached' if subscription.get('using_cached_state') else 'allowed_verified',
        'state': state,
        'entitlement': entitlement_key or '',
        'source': 'portal',
    }


def subscription_runtime_allowed(tech_config):
    """Compatibility wrapper for generic subscription-gated platform runtime."""
    return bool(subscription_service_access(None, tech_config).get('allowed'))


def subscription_entitlement_allowed(entitlement_key, tech_config=None):
    return bool(subscription_service_access(entitlement_key, tech_config).get('allowed'))


def _managed_policy_min_deadline(*values):
    deadlines = []
    for value in values:
        parsed = _subscription_optional_int(value)
        if parsed and parsed > 0:
            deadlines.append(parsed)
    return min(deadlines) if deadlines else None


def managed_policy_snapshot(now=None):
    """Build the local Managed Remote Support policy without changing existing Tools behavior."""
    now_ts = int(now or time.time())
    connection = load_portal_connection()
    tech_config = load_tech_settings()
    subscription = portal_subscription_public(connection, now=now_ts)
    installation_id = str(
        connection.get('installation_id')
        or tech_config.get('installation_id')
        or ''
    ).strip()
    paired = bool(connection.get('installation_token'))
    manual_pause = bool(tech_config.get('managed_remote_support_manual_pause', False))

    status = str(subscription.get('status', '') or '').strip().lower() if subscription.get('available') else ''
    entitlements = subscription.get('entitlements') if isinstance(subscription.get('entitlements'), dict) else {}
    entitled = bool(entitlements.get('managed_remote_support', False))
    services_active = bool(subscription.get('services_active', False)) if subscription.get('available') else False
    verification_valid = bool(subscription.get('verification_valid', False)) if subscription.get('available') else False
    using_cached = bool(subscription.get('using_cached_state', False)) if subscription.get('available') else False

    # 2.4.8 — Persistent Managed relationship policy.
    #
    # Subscription/payment state remains diagnostic/accounting context and no
    # longer defines whether the Managed agent may stay connected. The local gate
    # proves Portal pairing + canonical Installation ID + recent verified Portal
    # sync + Tools liveness. Explicit de-enrollment/revoke remains authoritative
    # on the Broker side, while manual_pause remains a local fail-closed control.
    verification_deadline = _subscription_optional_int(subscription.get('verification_deadline'))
    status_deadline = None
    authorization_valid_until = verification_deadline

    allowed = False
    reason_code = 'policy_denied'
    reason_label = 'Η Managed απομακρυσμένη υποστήριξη δεν επιτρέπεται.'

    if not paired:
        reason_code = 'not_paired'
        reason_label = 'Δεν υπάρχει ενεργό pairing με το Smart Pro Portal.'
    elif not installation_id:
        reason_code = 'installation_id_missing'
        reason_label = 'Δεν υπάρχει έγκυρο Installation ID.'
    elif not subscription.get('available'):
        reason_code = 'subscription_unavailable'
        reason_label = 'Δεν υπάρχει έγκυρη επαλήθευση Portal για την εγκατάσταση.'
    elif not verification_valid:
        reason_code = 'verification_required'
        reason_label = 'Η εγκατάσταση χρειάζεται νέα επαλήθευση από το Portal.'
    elif manual_pause:
        reason_code = 'manual_pause'
        reason_label = 'Η Managed απομακρυσμένη υποστήριξη είναι σε χειροκίνητη παύση.'
    elif authorization_valid_until and now_ts > authorization_valid_until:
        reason_code = 'authorization_expired'
        reason_label = 'Η τοπική επαλήθευση Portal για το Managed connection έχει λήξει.'
    else:
        allowed = True
        if using_cached:
            reason_code = 'allowed_cached'
            reason_label = 'Η Managed σύνδεση επιτρέπεται προσωρινά με την τελευταία έγκυρη επαλήθευση Portal.'
        else:
            reason_code = 'allowed_verified'
            reason_label = 'Η Managed σύνδεση επιτρέπεται από ενεργό Portal pairing και επαληθευμένη εγκατάσταση.'

    portal_error = str(connection.get('last_error', '') or '').strip()
    tools_lease_until = now_ts + MANAGED_TOOLS_LEASE_SECONDS

    return {
        'contract_id': MANAGED_POLICY_CONTRACT_ID,
        'policy_version': MANAGED_POLICY_VERSION,
        'generated_at': now_ts,
        'source': {
            'addon': 'smart_pro_tools',
            'addon_version': ADDON_VERSION,
        },
        'installation_id': installation_id,
        'allowed': allowed,
        'reason_code': reason_code,
        'reason_label': reason_label,
        'manual_pause': manual_pause,
        'policy_basis': 'managed_relationship',
        'subscription_gate_enforced': False,
        'entitlement': {
            'managed_remote_support': entitled,
        },
        'subscription': {
            'plan': subscription.get('plan') if subscription.get('available') else None,
            'status': status or None,
            'services_active': services_active,
            'verification_state': subscription.get('verification_state') if subscription.get('available') else None,
            'using_cached_state': using_cached,
            'verified_at': subscription.get('verified_at') if subscription.get('available') else None,
            'verification_deadline': verification_deadline,
        },
        'authorization': {
            'valid_until': authorization_valid_until,
            'status_deadline': status_deadline,
        },
        'tools_liveness': {
            'refresh_seconds': MANAGED_POLICY_REFRESH_SECONDS,
            'lease_seconds': MANAGED_TOOLS_LEASE_SECONDS,
            'lease_until': tools_lease_until,
        },
        'health': {
            'tools_online': True,
            'portal_paired': paired,
            'portal_sync_healthy': bool(paired and not portal_error),
            'portal_last_heartbeat': int(connection.get('last_heartbeat', 0) or 0) or None,
            'portal_last_error_code': str(connection.get('last_error_code', '') or '') or None,
            'bridge_state': 'policy_foundation',
        },
    }



def _managed_network_decode_gateway(raw_value):
    """Decode the little-endian IPv4 gateway used by /proc/net/route."""
    value = str(raw_value or '').strip()
    if not re.fullmatch(r'[0-9A-Fa-f]{8}', value):
        raise ValueError('invalid_gateway_hex')
    packed = bytes.fromhex(value)
    return str(ipaddress.IPv4Address(packed[::-1]))


def _managed_network_is_private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(str(value or '').strip())
    except Exception:
        return False
    return any(address in network for network in MANAGED_NETWORK_PRIVATE_V4)


def _managed_network_parse_default_route(route_text):
    """Return the best private IPv4 default gateway from Linux /proc/net/route text."""
    candidates = []
    lines = str(route_text or '').splitlines()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        interface, destination, gateway, flags_raw = fields[:4]
        if destination.upper() != '00000000' or gateway.upper() == '00000000':
            continue
        try:
            flags = int(flags_raw, 16)
            metric = int(fields[6])
            gateway_ipv4 = _managed_network_decode_gateway(gateway)
        except Exception:
            continue
        # Require RTF_UP (0x1) and RTF_GATEWAY (0x2). Never expose a non-RFC1918 target.
        if (flags & 0x3) != 0x3 or not _managed_network_is_private_ipv4(gateway_ipv4):
            continue
        candidates.append((metric, interface, gateway_ipv4))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    metric, interface, gateway_ipv4 = candidates[0]
    return {
        'interface': interface,
        'gateway_ipv4': gateway_ipv4,
        'metric': metric,
    }


def managed_network_snapshot(now=None, route_file=None):
    """Build a non-secret, fail-closed local network discovery contract for Managed Support."""
    now_ts = int(now or time.time())
    connection = load_portal_connection()
    tech_config = load_tech_settings()
    installation_id = str(
        connection.get('installation_id')
        or tech_config.get('installation_id')
        or ''
    ).strip()
    route_path = Path(route_file) if route_file is not None else MANAGED_NETWORK_ROUTE_FILE

    state = 'unavailable'
    reason_code = 'installation_id_missing'
    route = None
    source_readable = False

    if not installation_id:
        reason_code = 'installation_id_missing'
    else:
        try:
            route_text = route_path.read_text(encoding='utf-8', errors='replace')
            source_readable = True
            route = _managed_network_parse_default_route(route_text)
            if route is None:
                reason_code = 'private_default_gateway_not_found'
            else:
                state = 'ready'
                reason_code = 'private_default_gateway_ready'
        except Exception:
            reason_code = 'route_read_error'

    lease_until = now_ts + MANAGED_NETWORK_LEASE_SECONDS
    return {
        'contract_id': MANAGED_NETWORK_CONTRACT_ID,
        'network_version': MANAGED_NETWORK_VERSION,
        'generated_at': now_ts,
        'source': {
            'addon': 'smart_pro_tools',
            'addon_version': ADDON_VERSION,
            'discovery': 'linux_proc_net_route_host_network',
        },
        'installation_id': installation_id,
        'state': state,
        'reason_code': reason_code,
        'router_candidate': route if state == 'ready' else None,
        'liveness': {
            'refresh_seconds': MANAGED_NETWORK_REFRESH_SECONDS,
            'lease_seconds': MANAGED_NETWORK_LEASE_SECONDS,
            'lease_until': lease_until,
        },
        'health': {
            'host_network_expected': True,
            'route_source_readable': source_readable,
        },
    }


def write_managed_network_file(now=None):
    """Atomically refresh the non-secret network discovery contract consumed read-only by Managed Support."""
    try:
        network = managed_network_snapshot(now=now)
        MANAGED_NETWORK_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(MANAGED_NETWORK_FILE.parent, 0o750)
        except OSError:
            pass
        temp_path = MANAGED_NETWORK_FILE.with_suffix('.tmp')
        temp_path.write_text(
            json.dumps(network, ensure_ascii=False, separators=(',', ':')),
            encoding='utf-8',
        )
        os.chmod(temp_path, 0o640)
        os.replace(temp_path, MANAGED_NETWORK_FILE)
        os.chmod(MANAGED_NETWORK_FILE, 0o640)
        return True
    except Exception as error:
        print(f'[MANAGED NETWORK] Could not refresh local network contract: {error}', flush=True)
        return False

def managed_policy_public_status(now=None):
    policy = managed_policy_snapshot(now=now)
    return {
        'policy_version': policy['policy_version'],
        'allowed': policy['allowed'],
        'reason_code': policy['reason_code'],
        'reason_label': policy['reason_label'],
        'manual_pause': policy['manual_pause'],
        'entitled': bool(policy['entitlement'].get('managed_remote_support')),
        'valid_until': policy['authorization'].get('valid_until'),
        'tools_lease_until': policy['tools_liveness'].get('lease_until'),
    }


def write_managed_policy_file(now=None):
    """Atomically refresh the local read-only contract consumed by the future Managed add-on."""
    try:
        policy = managed_policy_snapshot(now=now)
        MANAGED_POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(MANAGED_POLICY_FILE.parent, 0o750)
        except OSError:
            pass
        temp_path = MANAGED_POLICY_FILE.with_suffix('.tmp')
        temp_path.write_text(
            json.dumps(policy, ensure_ascii=False, separators=(',', ':')),
            encoding='utf-8',
        )
        os.chmod(temp_path, 0o640)
        os.replace(temp_path, MANAGED_POLICY_FILE)
        os.chmod(MANAGED_POLICY_FILE, 0o640)
        return True
    except Exception as error:
        print(f'[MANAGED POLICY] Could not refresh local policy: {error}', flush=True)
        return False


def managed_policy_refresh_loop():
    while True:
        write_managed_policy_file()
        write_managed_network_file()
        time.sleep(MANAGED_POLICY_REFRESH_SECONDS)


def _guardian_state_default():
    return {
        'version': 2,
        'offline': {},
        'low_battery': {},
        'last_alert_at': 0,
        'last_alert_request_code': '',
        'last_recovery_at': 0,
        'last_recovery_count': 0,
        'last_successful_check_at': 0,
        'last_error_at': 0,
        'last_error_code': '',
        'last_email_sent_at': 0,
        'last_email_error_at': 0,
    }


def _guardian_epoch(value, default=0):
    if isinstance(value, datetime):
        return int(value.timestamp())
    try:
        return max(0, int(float(value or default)))
    except (TypeError, ValueError):
        return int(default or 0)


def _guardian_json_info(info):
    if not isinstance(info, dict):
        return {}
    result = {}
    for key, value in info.items():
        if isinstance(value, datetime):
            result[key] = int(value.timestamp())
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value
    return result


def _guardian_runtime_info(info):
    if not isinstance(info, dict):
        return {}
    result = dict(info)
    if 'time_down' in result:
        epoch = _guardian_epoch(result.get('time_down'))
        result['time_down'] = datetime.fromtimestamp(epoch) if epoch else datetime.now()
    return result


def load_guardian_state():
    with GUARDIAN_STATE_LOCK:
        state = _guardian_state_default()
        if os.path.exists(GUARDIAN_STATE_FILE):
            try:
                with open(GUARDIAN_STATE_FILE, 'r', encoding='utf-8') as file:
                    stored = json.load(file)
                if isinstance(stored, dict):
                    state.update(stored)
            except Exception as error:
                print(f'[GUARDIAN] Could not read persistent state: {error}', flush=True)
        if not isinstance(state.get('offline'), dict):
            state['offline'] = {}
        if not isinstance(state.get('low_battery'), dict):
            state['low_battery'] = {}
        return state


def save_guardian_state(extra=None):
    with GUARDIAN_STATE_LOCK:
        current = load_guardian_state()
        current['version'] = 2
        current['offline'] = {
            str(entity_id): _guardian_json_info(info)
            for entity_id, info in OFFLINE_DEVICES.items()
            if isinstance(info, dict) and not info.get('simulated')
        }
        current['low_battery'] = {
            str(entity_id): _guardian_json_info(info)
            for entity_id, info in LOW_BATTERY_DEVICES.items()
            if isinstance(info, dict)
        }
        if isinstance(extra, dict):
            for key, value in extra.items():
                if key not in ('offline', 'low_battery'):
                    current[key] = value
        temp_path = GUARDIAN_STATE_FILE + '.tmp'
        with open(temp_path, 'w', encoding='utf-8') as file:
            json.dump(current, file, ensure_ascii=False, separators=(',', ':'))
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, GUARDIAN_STATE_FILE)
        os.chmod(GUARDIAN_STATE_FILE, 0o600)
        return current


def restore_guardian_runtime_state():
    state = load_guardian_state()
    OFFLINE_DEVICES.clear()
    LOW_BATTERY_DEVICES.clear()
    for entity_id, info in state.get('offline', {}).items():
        runtime = _guardian_runtime_info(info)
        runtime['simulated'] = False
        OFFLINE_DEVICES[str(entity_id)] = runtime
    for entity_id, info in state.get('low_battery', {}).items():
        LOW_BATTERY_DEVICES[str(entity_id)] = dict(info) if isinstance(info, dict) else {}
    update_guardian_status(
        last_successful_check_at=state.get('last_successful_check_at', 0),
        last_alert_at=state.get('last_alert_at', 0),
        last_alert_request_code=state.get('last_alert_request_code', ''),
        last_recovery_at=state.get('last_recovery_at', 0),
        last_recovery_count=state.get('last_recovery_count', 0),
        last_error_at=state.get('last_error_at', 0),
        last_email_sent_at=state.get('last_email_sent_at', 0),
        last_email_error_at=state.get('last_email_error_at', 0),
    )
    return state


def guardian_safe_device_ref(entity_id):
    entity_id = str(entity_id or '').strip()
    domain = entity_id.split('.', 1)[0] if '.' in entity_id else 'entity'
    digest = hashlib.sha256(entity_id.encode('utf-8')).hexdigest()[:8] if entity_id else 'unknown'
    return f'{domain} · ref {digest}'


def update_guardian_status(**updates):
    allowed_statuses = {'healthy', 'attention', 'disabled', 'waiting', 'error'}
    string_keys = {'reason_code', 'last_alert_request_code'}
    bool_keys = {'enabled', 'active_alert', 'email_configured'}
    int_keys = {
        'last_check_at', 'last_successful_check_at', 'offline_count', 'low_battery_count',
        'pending_offline_count', 'alerted_offline_count', 'retry_pending_count',
        'last_alert_at', 'last_recovery_at', 'last_recovery_count', 'last_error_at',
        'monitoring_scope_count', 'email_retry_pending_count',
        'last_email_sent_at', 'last_email_error_at',
    }
    with GUARDIAN_STATUS_LOCK:
        GUARDIAN_STATUS['contract'] = GUARDIAN_CONTRACT_ID
        for key in bool_keys:
            if key in updates:
                GUARDIAN_STATUS[key] = bool(updates[key])
        if 'status' in updates:
            status = str(updates['status'] or '').strip().lower()
            GUARDIAN_STATUS['status'] = status if status in allowed_statuses else 'waiting'
        for key in string_keys:
            if key in updates:
                GUARDIAN_STATUS[key] = str(updates[key] or '').strip()[:120]
        for key in int_keys:
            if key in updates:
                try:
                    GUARDIAN_STATUS[key] = max(0, int(updates[key] or 0))
                except (TypeError, ValueError):
                    GUARDIAN_STATUS[key] = 0


def guardian_status_snapshot():
    tech_config = load_tech_settings()
    with GUARDIAN_STATUS_LOCK:
        snapshot = {
            'contract': GUARDIAN_CONTRACT_ID,
            'enabled': bool(GUARDIAN_STATUS.get('enabled', True)),
            'status': str(GUARDIAN_STATUS.get('status', 'waiting') or 'waiting'),
            'reason_code': str(GUARDIAN_STATUS.get('reason_code', 'waiting') or 'waiting'),
            'last_check_at': int(GUARDIAN_STATUS.get('last_check_at', 0) or 0),
            'last_successful_check_at': int(GUARDIAN_STATUS.get('last_successful_check_at', 0) or 0),
            'offline_count': int(GUARDIAN_STATUS.get('offline_count', 0) or 0),
            'low_battery_count': int(GUARDIAN_STATUS.get('low_battery_count', 0) or 0),
            'pending_offline_count': int(GUARDIAN_STATUS.get('pending_offline_count', 0) or 0),
            'alerted_offline_count': int(GUARDIAN_STATUS.get('alerted_offline_count', 0) or 0),
            'retry_pending_count': int(GUARDIAN_STATUS.get('retry_pending_count', 0) or 0),
            'active_alert': bool(GUARDIAN_STATUS.get('active_alert', False)),
            'last_alert_at': int(GUARDIAN_STATUS.get('last_alert_at', 0) or 0),
            'last_alert_request_code': str(GUARDIAN_STATUS.get('last_alert_request_code', '') or ''),
            'last_recovery_at': int(GUARDIAN_STATUS.get('last_recovery_at', 0) or 0),
            'last_recovery_count': int(GUARDIAN_STATUS.get('last_recovery_count', 0) or 0),
            'last_error_at': int(GUARDIAN_STATUS.get('last_error_at', 0) or 0),
            'monitoring_scope_count': int(GUARDIAN_STATUS.get('monitoring_scope_count', 0) or 0),
            'email_configured': bool(GUARDIAN_STATUS.get('email_configured', False)),
            'email_retry_pending_count': int(GUARDIAN_STATUS.get('email_retry_pending_count', 0) or 0),
            'last_email_sent_at': int(GUARDIAN_STATUS.get('last_email_sent_at', 0) or 0),
            'last_email_error_at': int(GUARDIAN_STATUS.get('last_email_error_at', 0) or 0),
            'check_interval_min': float(tech_config.get('check_interval_min', 5.0) or 5.0),
            'alert_delay_min': float(tech_config.get('alert_delay_min', 15.0) or 15.0),
            'battery_limit': float(tech_config.get('battery_limit', 15.0) or 15.0),
            'low_battery_policy': 'ha_notification_only',
        }
    return snapshot


def managed_support_runtime_public_status(now=None):
    """Return non-secret read-only installation/runtime state for Smart Pro Managed Support.

    This intentionally does not infer service entitlement or technician authorization.
    It only reports whether the dedicated Home Assistant add-on is installed and whether
    Supervisor currently reports it as running. The /addons result is cached briefly to
    avoid polling Supervisor on every 15-second Portal UI refresh.
    """
    now_ts = int(now or time.time())
    cached = getattr(managed_support_runtime_public_status, '_cache', None)
    if isinstance(cached, dict) and now_ts - int(cached.get('at', 0) or 0) < 45:
        value = cached.get('value')
        if isinstance(value, dict):
            return dict(value)

    result = {
        'state': 'unavailable',
        'installed': False,
        'running': False,
        'version': '',
        'update_available': False,
    }
    addons_result, addons_error = _supervisor_api_json('/addons', 'GET')
    if not addons_error:
        if isinstance(addons_result, dict):
            items = addons_result.get('addons') if isinstance(addons_result.get('addons'), list) else []
        elif isinstance(addons_result, list):
            items = addons_result
        else:
            items = []

        matched = None
        for item in items:
            if not isinstance(item, dict):
                continue
            candidate = str(item.get('slug', '') or '')
            name = str(item.get('name', '') or '')
            if candidate.endswith('smart_pro_managed_support') or name == 'Smart Pro Managed Support':
                matched = item
                break

        if matched is None:
            result['state'] = 'not_installed'
        else:
            raw_state = str(matched.get('state', '') or '').strip().lower()
            running = raw_state in ('started', 'running')
            if running:
                state = 'running'
            elif raw_state == 'stopped':
                state = 'stopped'
            elif raw_state in ('error', 'failed'):
                state = 'error'
            else:
                state = 'installed_unknown'
            result.update({
                'state': state,
                'installed': True,
                'running': running,
                'version': str(matched.get('version', '') or '')[:32],
                'update_available': bool(matched.get('update_available', False)),
            })

    managed_support_runtime_public_status._cache = {'at': now_ts, 'value': dict(result)}
    return result


def smart_pro_tunnel_runtime_public_status(now=None):
    """Return non-secret read-only installation/runtime state for Smart Pro Tunnel.

    This is presentation-only inventory derived from Supervisor /addons. It never starts,
    stops, configures or enrolls the Tunnel and never reads Tunnel key material.
    """
    now_ts = int(now or time.time())
    cached = getattr(smart_pro_tunnel_runtime_public_status, '_cache', None)
    if isinstance(cached, dict) and now_ts - int(cached.get('at', 0) or 0) < 45:
        value = cached.get('value')
        if isinstance(value, dict):
            return dict(value)

    transport = _external_access_tunnel_runtime_snapshot()
    result = {
        'state': 'unavailable',
        'installed': False,
        'running': False,
        'version': '',
        'update_available': False,
        'transport_state': str(transport.get('state', 'off') or 'off')[:32],
        'private_proxy_state': str(transport.get('private_proxy_state', 'off') or 'off')[:32],
        'home_assistant_target_reachable': bool(transport.get('home_assistant_target_reachable', False)),
        'handshake_age_seconds': transport.get('handshake_age_seconds'),
        'recovery': smart_pro_tunnel_recovery_public_status(),
    }
    addons_result, addons_error = _supervisor_api_json('/addons', 'GET')
    if not addons_error:
        if isinstance(addons_result, dict):
            items = addons_result.get('addons') if isinstance(addons_result.get('addons'), list) else []
        elif isinstance(addons_result, list):
            items = addons_result
        else:
            items = []

        matched = None
        for item in items:
            if not isinstance(item, dict):
                continue
            candidate = str(item.get('slug', '') or '')
            name = str(item.get('name', '') or '')
            if candidate.endswith('smart_pro_tunnel') or name == 'Smart Pro Tunnel':
                matched = item
                break

        if matched is None:
            result['state'] = 'not_installed'
        else:
            raw_state = str(matched.get('state', '') or '').strip().lower()
            running = raw_state in ('started', 'running')
            if running:
                state = 'running'
            elif raw_state == 'stopped':
                state = 'stopped'
            elif raw_state in ('error', 'failed'):
                state = 'error'
            else:
                state = 'installed_unknown'
            result.update({
                'state': state,
                'installed': True,
                'running': running,
                'version': str(matched.get('version', '') or '')[:32],
                'update_available': bool(matched.get('update_available', False)),
            })

    smart_pro_tunnel_runtime_public_status._cache = {'at': now_ts, 'value': dict(result)}
    return result


def managed_backup_customer_summary():
    """Sanitized customer-facing Managed Backup state for the vNext home screen."""
    snapshot = managed_backup_agent_public_snapshot()
    policy = snapshot.get('policy') if isinstance(snapshot.get('policy'), dict) else {}
    storage = snapshot.get('storage_credentials') if isinstance(snapshot.get('storage_credentials'), dict) else {}
    local_result = snapshot.get('local_job_result') if isinstance(snapshot.get('local_job_result'), dict) else {}
    upload_result = snapshot.get('primary_upload_result') if isinstance(snapshot.get('primary_upload_result'), dict) else {}
    return {
        'supported': True,
        'policy_state': str(snapshot.get('policy_state', '') or '')[:24],
        'service_state': str(snapshot.get('service_state', '') or '')[:48],
        'frequency': str(policy.get('frequency', '') or '')[:24],
        'retention_days': max(0, int(policy.get('retention_days', 0) or 0)),
        'storage_configured': bool(storage.get('configured', False)),
        'local_result_state': str(local_result.get('state', '') or '')[:48],
        'local_result_at': max(0, int(local_result.get('executed_at', 0) or 0)),
        'upload_result_state': str(upload_result.get('state', '') or '')[:48],
        'upload_result_at': max(0, int(upload_result.get('executed_at', upload_result.get('uploaded_at', 0)) or 0)),
    }


def external_access_customer_summary():
    """Sanitized read-only Managed External URL state for the vNext home screen."""
    connection = load_portal_connection()
    portal_entitlement = _normalize_external_access_portal_state(connection.get('external_access_portal'))
    publication = portal_entitlement.get('publication') if isinstance(portal_entitlement.get('publication'), dict) else {}
    observation = external_access_gateway_observation_snapshot()
    tunnel = _external_access_tunnel_runtime_snapshot()
    tunnel_state = str(tunnel.get('state', 'off') or 'off')
    gateway_state = (
        'private_ready'
        if tunnel_state == 'connected' and str(tunnel.get('private_proxy_state', '')) == 'listening'
        else ('configuring' if tunnel_state not in ('off', 'identity_ready', 'stopped', 'failed') else 'not_configured')
    )
    hostname = str(observation.get('canonical_hostname', '') or '').strip().lower()
    if hostname and not EXTERNAL_ACCESS_HOSTNAME_PATTERN.fullmatch(hostname):
        hostname = ''
    portal_hostname = str(publication.get('hostname', '') or '').strip().lower()
    if portal_hostname and not EXTERNAL_ACCESS_HOSTNAME_PATTERN.fullmatch(portal_hostname):
        portal_hostname = ''
    portal_public_ready = bool(publication.get('public_ready', False)) and bool(portal_hostname)
    if portal_public_ready:
        hostname = portal_hostname
    return {
        'supported': True,
        'installation_binding_present': bool(str(connection.get('installation_id', '') or '').strip() and str(connection.get('installation_token', '') or '').strip()),
        'gateway_state': gateway_state,
        'tunnel_runtime': tunnel_state,
        'registry_state': str(observation.get('registry_state', '') or '')[:32],
        'observation_status': str(observation.get('status', '') or '')[:32],
        'hostname': hostname,
        'fresh': bool(observation.get('fresh', False)),
        'portal_public_status': str(publication.get('status', 'unknown') or 'unknown')[:48],
        'portal_public_ready': portal_public_ready,
        'entitlement_eligible': bool(portal_entitlement.get('eligible', False)),
        'eligibility_source': str(portal_entitlement.get('eligibility_source', 'none') or 'none')[:32],
        'package_eligible': bool(portal_entitlement.get('package_eligible', False)),
        'standalone_entitlement': dict(portal_entitlement.get('standalone') or {}),
    }


def portal_public_status():
    data = load_portal_connection()
    options = load_addon_options()
    return {
        'connected': bool(data.get('installation_token')),
        'installation_id': data.get('installation_id', ''),
        'installation_name': data.get('installation_name', ''),
        'customer_name': data.get('customer_name', ''),
        'paired_at': data.get('paired_at', 0),
        'last_heartbeat': data.get('last_heartbeat', 0),
        'last_error': data.get('last_error', ''),
        'portal_url': normalize_portal_url(options.get('portal_url')),
        'addon_version': ADDON_VERSION,
        'open_request_count': int(data.get('open_request_count', 0) or 0),
        'manual_open_request_count': int(data.get('manual_open_request_count', data.get('open_request_count', 0)) or 0),
        'automatic_alert_count': int(data.get('automatic_alert_count', 0) or 0),
        'latest_request': data.get('latest_request'),
        'subscription': portal_subscription_public(data),
        'managed_policy': managed_policy_public_status(),
        'managed_support_runtime': managed_support_runtime_public_status(),
        'smart_pro_tunnel_runtime': smart_pro_tunnel_runtime_public_status(),
        'managed_backup_summary': managed_backup_customer_summary(),
        'external_access_summary': external_access_customer_summary(),
        'guardian_summary': guardian_status_snapshot(),
    }

def portal_headers(token=''):
    options = load_addon_options()
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': f'Smart-Pro-Tools/{ADDON_VERSION}',
    }
    basic_user = str(options.get('portal_basic_username', '')).strip()
    basic_password = str(options.get('portal_basic_password', ''))
    if basic_user:
        raw = f'{basic_user}:{basic_password}'.encode('utf-8')
        headers['Authorization'] = 'Basic ' + base64.b64encode(raw).decode('ascii')
    if token:
        headers['X-Smart-Pro-Token'] = token
    return headers

def portal_api_request(path, payload, token=''):
    options = load_addon_options()
    base_url = normalize_portal_url(options.get('portal_url'))
    url = base_url + '/wp-json/smart-pro/v1/' + path.lstrip('/')
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    request = urllib.request.Request(url, data=body, headers=portal_headers(token), method='POST')
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode('utf-8')
            return json.loads(raw or '{}')
    except urllib.error.HTTPError as error:
        raw = error.read().decode('utf-8', errors='replace')
        try:
            data = json.loads(raw)
            message = clean_portal_error_message(data.get('message'), f'HTTP {error.code}')
            code = data.get('code') or 'http_error'
        except Exception:
            message = clean_portal_error_message(raw, f'HTTP {error.code}')
            code = 'http_error'
        raise PortalAPIError(message, error.code, code) from error
    except urllib.error.URLError as error:
        raise PortalAPIError(f'Αδυναμία σύνδεσης με το Portal: {error.reason}', 0, 'network_error') from error
    except Exception as error:
        raise PortalAPIError(f'Σφάλμα επικοινωνίας με το Portal: {error}', 0, 'portal_error') from error

def pair_portal(code):
    normalized = str(code or '').strip().upper().replace(' ', '')
    if not normalized.startswith('SP-') or len(normalized) != 9:
        raise PortalAPIError('Ο προσωρινός κωδικός δεν έχει σωστή μορφή.', 400, 'invalid_code')
    response = portal_api_request('pair', {
        'code': normalized,
        'addon_version': ADDON_VERSION,
        'device_name': 'Home Assistant',
    })
    token = str(response.get('installation_token', '')).strip()
    if not token:
        raise PortalAPIError('Το Portal δεν επέστρεψε Installation Token.', 500, 'missing_token')
    now = int(time.time())
    connection = {
        'installation_token': token,
        'installation_id': str(response.get('installation_id', '')),
        'installation_name': str(response.get('installation_name', '')),
        'customer_name': str(response.get('customer_name', '')),
        'heartbeat_seconds': int(response.get('heartbeat_seconds', PORTAL_HEARTBEAT_DEFAULT)),
        'paired_at': now,
        'last_heartbeat': now,
        'last_error': '',
    }
    update_portal_subscription(connection, response, verified_at=now)
    external_portal_state = _portal_maybe_process_external_access(response)
    if isinstance(external_portal_state, dict):
        connection['external_access_portal'] = external_portal_state
    save_portal_connection(connection)
    tech_config = load_tech_settings()
    if connection['installation_id']:
        tech_config['installation_id'] = connection['installation_id']
        tech_config['customer_name'] = connection['installation_id']
        save_tech_settings(tech_config)
    write_managed_policy_file()
    return portal_public_status()

def create_portal_request(category, message, source='smart_pro_tools', severity='normal', event_key=''):
    connection = load_portal_connection()
    token = str(connection.get('installation_token', '')).strip()
    if not token:
        raise PortalAPIError('Η εγκατάσταση δεν είναι συνδεδεμένη με το Portal.', 409, 'not_connected')

    response = portal_api_request('requests', {
        'category': str(category or 'general'),
        'message': str(message or '').strip(),
        'source': str(source or 'smart_pro_tools'),
        'severity': str(severity or 'normal'),
        'event_key': str(event_key or ''),
        'addon_version': ADDON_VERSION,
    }, token=token)

    request_data = response.get('request') or {}
    connection['open_request_count'] = int(response.get('open_request_count', 0) or 0)
    connection['manual_open_request_count'] = int(response.get('manual_open_request_count', response.get('open_request_count', 0)) or 0)
    connection['automatic_alert_count'] = int(response.get('automatic_alert_count', 0) or 0)
    connection['latest_request'] = request_data
    connection['last_error'] = ''
    save_portal_connection(connection)
    return response


def fetch_portal_requests(limit=20):
    connection = load_portal_connection()
    token = str(connection.get('installation_token', '')).strip()
    if not token:
        return {'status': 'disconnected', 'requests': [], 'open_request_count': 0, 'manual_open_request_count': 0, 'automatic_alert_count': 0, 'latest_request': None}

    response = portal_api_request('requests/list', {'limit': int(limit)}, token=token)
    connection['open_request_count'] = int(response.get('open_request_count', 0) or 0)
    connection['manual_open_request_count'] = int(response.get('manual_open_request_count', response.get('open_request_count', 0)) or 0)
    connection['automatic_alert_count'] = int(response.get('automatic_alert_count', 0) or 0)
    connection['latest_request'] = response.get('latest_request')
    connection['last_error'] = ''
    save_portal_connection(connection)
    if connection['manual_open_request_count'] == 0:
        save_tech_settings({'pending_request_time': 0})
    return response



def _control_plane_default_state():
    return {'version': 1, 'key_id': '', 'secret_b64': '', 'seen': [], 'last_ack': None}


def load_control_plane_state():
    with CONTROL_PLANE_LOCK:
        state = _control_plane_default_state()
        if CONTROL_PLANE_STATE_FILE.exists():
            try:
                stored = json.loads(CONTROL_PLANE_STATE_FILE.read_text(encoding='utf-8'))
                if isinstance(stored, dict):
                    state.update(stored)
            except Exception as error:
                print(f'[CONTROL] Could not read command-channel state: {error}', flush=True)
        if not isinstance(state.get('seen'), list):
            state['seen'] = []
        if not isinstance(state.get('last_ack'), dict):
            state['last_ack'] = None
        return state


def save_control_plane_state(state):
    with CONTROL_PLANE_LOCK:
        safe = _control_plane_default_state()
        if isinstance(state, dict):
            safe.update(state)
        seen = []
        now = int(time.time())
        for item in safe.get('seen') or []:
            if not isinstance(item, dict):
                continue
            executed_at = int(item.get('executed_at', 0) or 0)
            if executed_at and executed_at < now - 86400:
                continue
            seen.append(item)
        safe['seen'] = seen[-50:]
        CONTROL_PLANE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CONTROL_PLANE_STATE_FILE.with_suffix('.tmp')
        tmp.write_text(json.dumps(safe, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONTROL_PLANE_STATE_FILE)
        os.chmod(CONTROL_PLANE_STATE_FILE, 0o600)
        return safe


def command_channel_snapshot():
    state = load_control_plane_state()
    ack = state.get('last_ack') if isinstance(state.get('last_ack'), dict) else None
    return {
        'contract': CONTROL_PLANE_CONTRACT_ID,
        'supported': True,
        'key_id': str(state.get('key_id', '') or '')[:32],
        'reported_at': int(time.time()),
        'last_ack': ack,
    }


def _managed_backup_agent_default_state():
    return {
        'version': 1,
        'node_id': '',
        'created_at': 0,
        'last_reported_at': 0,
        'portal_state': 'waiting',
        'service_state': 'blocked',
        'control_plane_ready': False,
        'policy_state': 'none',
        'policy': None,
        'runtime_authority_present': False,
        'local_job': None,
        'storage_target_state': 'not_received',
        'storage_target': None,
        'primary_upload': None,
        'updated_at': 0,
    }


def load_managed_backup_agent_state():
    with MANAGED_BACKUP_AGENT_LOCK:
        state = _managed_backup_agent_default_state()
        if MANAGED_BACKUP_AGENT_STATE_FILE.exists():
            try:
                stored = json.loads(MANAGED_BACKUP_AGENT_STATE_FILE.read_text(encoding='utf-8'))
                if isinstance(stored, dict):
                    state.update(stored)
            except Exception as error:
                print(f'[BACKUP] Could not read Managed Backup agent state: {error}', flush=True)
        node_id = str(state.get('node_id', '') or '').strip().lower()
        if not re.fullmatch(r'[0-9a-f]{64}', node_id):
            state['node_id'] = ''
        if not isinstance(state.get('policy'), dict):
            state['policy'] = None
        if not isinstance(state.get('local_job'), dict):
            state['local_job'] = None
        if not isinstance(state.get('storage_target'), dict):
            state['storage_target'] = None
        if not isinstance(state.get('primary_upload'), dict):
            state['primary_upload'] = None
        return state


def save_managed_backup_agent_state(state):
    with MANAGED_BACKUP_AGENT_LOCK:
        safe = _managed_backup_agent_default_state()
        if isinstance(state, dict):
            safe.update(state)
        node_id = str(safe.get('node_id', '') or '').strip().lower()
        safe['node_id'] = node_id if re.fullmatch(r'[0-9a-f]{64}', node_id) else ''
        if not isinstance(safe.get('policy'), dict):
            safe['policy'] = None
        if not isinstance(safe.get('local_job'), dict):
            safe['local_job'] = None
        if not isinstance(safe.get('storage_target'), dict):
            safe['storage_target'] = None
        if not isinstance(safe.get('primary_upload'), dict):
            safe['primary_upload'] = None
        MANAGED_BACKUP_AGENT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = MANAGED_BACKUP_AGENT_STATE_FILE.with_suffix('.tmp')
        tmp.write_text(json.dumps(safe, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        os.chmod(tmp, 0o600)
        os.replace(tmp, MANAGED_BACKUP_AGENT_STATE_FILE)
        os.chmod(MANAGED_BACKUP_AGENT_STATE_FILE, 0o600)
        return safe


def _managed_backup_agent_ensure_node_id():
    state = load_managed_backup_agent_state()
    node_id = str(state.get('node_id', '') or '').strip().lower()
    if re.fullmatch(r'[0-9a-f]{64}', node_id):
        return node_id
    node_id = secrets.token_hex(32)
    state['node_id'] = node_id
    state['created_at'] = int(time.time())
    state['updated_at'] = int(time.time())
    save_managed_backup_agent_state(state)
    print(f'[BACKUP] Managed Backup node identity created: {node_id[:8]}…{node_id[-6:]}', flush=True)
    return node_id


def _managed_backup_agent_control_secret():
    state = load_control_plane_state()
    key_id = str(state.get('key_id', '') or '').strip().lower()
    secret_b64 = str(state.get('secret_b64', '') or '').strip()
    if not re.fullmatch(r'[0-9a-f]{16}', key_id) or not secret_b64:
        return b''
    try:
        secret = base64.b64decode(secret_b64.encode('ascii'), validate=True)
    except Exception:
        return b''
    if len(secret) != 32 or hashlib.sha256(secret).hexdigest()[:16] != key_id:
        return b''
    return secret


def _managed_backup_agent_node_key_id(node_id):
    node_id = str(node_id or '').strip().lower()
    installation_id = str(paired_installation_id() or '').strip().upper()
    if not re.fullmatch(r'[0-9a-f]{64}', node_id) or not installation_id:
        return ''
    secret = _managed_backup_agent_control_secret()
    if len(secret) != 32:
        return ''
    message = f'managed-backup-node-v1|{installation_id}|{node_id}'.encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()[:16]


def managed_backup_local_readiness_snapshot():
    """Return a bounded read-only preflight for future Managed Backup creation.

    This function does not create a backup and does not call any mutation service.
    It reuses the already collected Supervisor backup inventory signal to prove
    that the authenticated local agent can read the HA backup subsystem before
    any future backup job writer is enabled.
    """
    state = load_managed_backup_agent_state()
    policy = state.get('policy') if isinstance(state.get('policy'), dict) else None
    options = load_addon_options()
    configured_token = str(options.get('ha_token', '') or '').strip()
    ha_credential_available = _ha_api_credential_available(configured_token)
    diagnostics = home_assistant_diagnostics_snapshot()
    backup_collection_status = str(diagnostics.get('backup_collection_status', '') or '')[:48]
    backup_api_readable = bool(diagnostics.get('backup_diagnostics_available', False)) and backup_collection_status == 'ready'
    policy_ready = str(state.get('policy_state', '') or '') == 'sync' and isinstance(policy, dict)
    schedule_ready = bool(
        policy_ready
        and str(policy.get('frequency', '') or '') == 'daily'
        and str(policy.get('timezone', '') or '').strip()
        and re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', str(policy.get('slot_local', '') or '').strip())
    )
    node_id = str(state.get('node_id', '') or '').strip().lower()
    node_ready = bool(re.fullmatch(r'[0-9a-f]{64}', node_id))
    control_plane_ready = bool(state.get('control_plane_ready', False))
    runtime_authority_present = bool(state.get('runtime_authority_present', False))

    reason_code = 'ready'
    if not node_ready:
        reason_code = 'node_identity_missing'
    elif not control_plane_ready:
        reason_code = 'control_plane_not_ready'
    elif not policy_ready:
        reason_code = 'policy_not_ready'
    elif not schedule_ready:
        reason_code = 'schedule_not_ready'
    elif not ha_credential_available:
        reason_code = 'ha_token_missing'
    elif not backup_api_readable:
        reason_code = 'backup_inventory_unavailable'
    elif runtime_authority_present:
        reason_code = 'unexpected_runtime_authority'

    ready = reason_code == 'ready'
    return {
        'contract': 'smart-pro-managed-backup-local-readiness-v1',
        'state': 'ready' if ready else 'blocked',
        'reason_code': reason_code,
        'node_ready': node_ready,
        'control_plane_ready': control_plane_ready,
        'policy_ready': policy_ready,
        'schedule_ready': schedule_ready,
        # Legacy field name retained for Portal contract compatibility; True now
        # means an HA API credential is available (scoped Supervisor or fallback).
        'ha_token_configured': ha_credential_available,
        'backup_api_readable': backup_api_readable,
        'backup_collection_status': backup_collection_status or 'not_collected',
        'data_plane_authorized': False,
        'checked_at': int(time.time()),
    }


def _managed_backup_local_job_public_result():
    state = load_managed_backup_agent_state()
    job = state.get('local_job') if isinstance(state.get('local_job'), dict) else None
    if not job:
        return None
    job_id = str(job.get('job_id', '') or '').strip().lower()
    result_state = str(job.get('state', '') or '').strip().lower()
    if not re.fullmatch(r'mbj_[0-9a-f]{32}', job_id) or result_state not in ('local_verified', 'failed'):
        return None
    digest = str(job.get('backup_ref_digest', '') or '').strip().lower()
    if result_state == 'local_verified' and not re.fullmatch(r'[0-9a-f]{64}', digest):
        return None
    if result_state == 'failed' and digest and not re.fullmatch(r'[0-9a-f]{64}', digest):
        digest = ''
    return {
        'contract': 'smart-pro-managed-backup-local-job-result-v1',
        'job_id': job_id,
        'state': result_state,
        'result_code': str(job.get('result_code', '') or '')[:64],
        'verified': bool(job.get('verified', False)) if result_state == 'local_verified' else False,
        'executed_at': int(job.get('executed_at', 0) or 0),
        'backup_ref_digest': digest,
        'backup_type': str(job.get('backup_type', '') or '')[:24],
    }


def _managed_backup_storage_credentials_snapshot():
    options = load_addon_options()
    access_key = str(options.get('managed_backup_s3_access_key', '') or '').strip()
    secret_key = str(options.get('managed_backup_s3_secret_key', '') or '').strip()
    ready = bool(access_key and secret_key and len(access_key) <= 256 and len(secret_key) <= 512)
    return {
        'contract': 'smart-pro-managed-backup-storage-credentials-v1',
        'provider_id': 'ovh_s3_primary_mil_v1',
        'configured': ready,
        'access_key_present': bool(access_key),
        'secret_key_present': bool(secret_key),
        'checked_at': int(time.time()),
    }


def _managed_backup_storage_handoff_snapshot():
    """Re-verify the local backup source without requiring provider credentials on-device.

    3.0.13 changes only the readiness contract: the source can be declared ready for a
    future Portal-issued presigned transfer while provider credentials remain absent from
    Smart Pro System. No upload grant or storage authority is created here.
    """
    state = load_managed_backup_agent_state()
    job = state.get('local_job') if isinstance(state.get('local_job'), dict) else None
    target = state.get('storage_target') if isinstance(state.get('storage_target'), dict) else None
    target_state = str(state.get('storage_target_state', '') or '').strip().lower()
    creds = _managed_backup_storage_credentials_snapshot()
    now = int(time.time())
    base = {
        'contract': 'smart-pro-managed-backup-storage-handoff-v2',
        'state': 'blocked',
        'reason_code': 'local_job_missing',
        'job_id': '',
        'source_verified': False,
        'backup_ref_digest': '',
        'backup_type': '',
        'destination_state': target_state if target_state else 'not_received',
        'transport_mode': 'portal_presigned',
        'credential_mode': 'portal_vault',
        'upload_grant_present': False,
        'upload_authorized': False,
        'storage_authorized': False,
        'replication_authorized': False,
        'provider_credentials_present': bool(creds.get('configured')),
        'checked_at': now,
    }
    if not job:
        return base
    job_id = str(job.get('job_id', '') or '').strip().lower()
    digest = str(job.get('backup_ref_digest', '') or '').strip().lower()
    backup_type = str(job.get('backup_type', '') or '').strip().lower()[:24]
    base['job_id'] = job_id if re.fullmatch(r'mbj_[0-9a-f]{32}', job_id) else ''
    base['backup_ref_digest'] = digest if re.fullmatch(r'[0-9a-f]{64}', digest) else ''
    base['backup_type'] = backup_type
    if str(job.get('state', '') or '') != 'local_verified' or not bool(job.get('verified', False)):
        base['reason_code'] = 'local_job_not_verified'
        return base
    if not base['job_id'] or not base['backup_ref_digest']:
        base['reason_code'] = 'local_job_identity_invalid'
        return base
    if target_state != 'provider_configured' or not isinstance(target, dict):
        base['reason_code'] = 'storage_target_not_configured'
        return base
    if bool(state.get('runtime_authority_present', False)):
        base['reason_code'] = 'unexpected_runtime_authority'
        return base
    slug = str(job.get('backup_slug', '') or '').strip()
    options = load_addon_options()
    token = str(options.get('ha_token', '') or '').strip()
    verified, verify_type, result_code = _managed_backup_verify_local_slug(token, slug)
    if not verified:
        base['reason_code'] = 'source_' + str(result_code or 'verify_failed')[:48]
        return base
    if verify_type:
        base['backup_type'] = verify_type[:24]
    base['state'] = 'ready'
    base['reason_code'] = 'source_ready'
    base['source_verified'] = True
    return base


def _managed_backup_storage_target_normalize(raw):
    if not isinstance(raw, dict):
        return None
    old_allowed = {
        'contract', 'state', 'provider_id', 'upload_grant', 'upload_authorized',
        'storage_authorized', 'replication_authorized',
    }
    if set(raw.keys()) == old_allowed:
        if str(raw.get('contract', '') or '') != 'smart-pro-managed-backup-storage-target-v1':
            return None
        if str(raw.get('state', '') or '').strip().lower() != 'provider_unconfigured':
            return None
        if str(raw.get('provider_id', '') or '').strip() != '' or raw.get('upload_grant') is not None:
            return None
        if bool(raw.get('upload_authorized', False)) or bool(raw.get('storage_authorized', False)) or bool(raw.get('replication_authorized', False)):
            return None
        return {
            'contract': 'smart-pro-managed-backup-storage-target-v1',
            'state': 'provider_unconfigured',
            'provider_id': '',
        }
    allowed = {
        'contract', 'state', 'provider_id', 'endpoint', 'region', 'bucket',
        'object_lock_mode', 'upload_authorized', 'storage_authorized', 'replication_authorized',
    }
    if set(raw.keys()) != allowed:
        return None
    if str(raw.get('contract', '') or '') != 'smart-pro-managed-backup-storage-target-v1':
        return None
    if str(raw.get('state', '') or '').strip().lower() != 'provider_configured':
        return None
    provider_id = str(raw.get('provider_id', '') or '').strip()
    endpoint = str(raw.get('endpoint', '') or '').strip().rstrip('/')
    region = str(raw.get('region', '') or '').strip()
    bucket = str(raw.get('bucket', '') or '').strip()
    object_lock_mode = str(raw.get('object_lock_mode', '') or '').strip().lower()
    if provider_id != 'ovh_s3_primary_mil_v1':
        return None
    if endpoint != 'https://s3.eu-south-mil.io.cloud.ovh.net' or region != 'eu-south-mil':
        return None
    if bucket != 'smartpro-managed-backup-primary-mil' or object_lock_mode != 'governance':
        return None
    if bool(raw.get('upload_authorized', False)) or bool(raw.get('storage_authorized', False)) or bool(raw.get('replication_authorized', False)):
        return None
    return {
        'contract': 'smart-pro-managed-backup-storage-target-v1',
        'state': 'provider_configured',
        'provider_id': provider_id,
        'endpoint': endpoint,
        'region': region,
        'bucket': bucket,
        'object_lock_mode': object_lock_mode,
    }


def _managed_backup_primary_upload_public_result():
    state = load_managed_backup_agent_state()
    result = state.get('primary_upload') if isinstance(state.get('primary_upload'), dict) else None
    if not result:
        return None
    job_id = str(result.get('job_id', '') or '').strip().lower()
    state_name = str(result.get('state', '') or '').strip().lower()
    sha256 = str(result.get('object_sha256', '') or '').strip().lower()
    if not re.fullmatch(r'mbj_[0-9a-f]{32}', job_id) or state_name not in ('primary_verified', 'failed'):
        return None
    if state_name == 'primary_verified' and not re.fullmatch(r'[0-9a-f]{64}', sha256):
        return None
    return {
        'contract': 'smart-pro-managed-backup-primary-upload-result-v1',
        'job_id': job_id,
        'state': state_name,
        'result_code': str(result.get('result_code', '') or '')[:64],
        'verified': bool(result.get('verified', False)) if state_name == 'primary_verified' else False,
        'executed_at': max(0, int(result.get('executed_at', 0) or 0)),
        'provider_id': str(result.get('provider_id', '') or '')[:64],
        'bucket': str(result.get('bucket', '') or '')[:128],
        'object_key': str(result.get('object_key', '') or '')[:512],
        'object_version_id': str(result.get('object_version_id', '') or '')[:256],
        'object_sha256': sha256,
        'object_size': max(0, int(result.get('object_size', 0) or 0)),
        'object_lock_mode': str(result.get('object_lock_mode', '') or '')[:24],
        'retain_until': max(0, int(result.get('retain_until', 0) or 0)),
        'readback_verified': bool(result.get('readback_verified', False)),
    }


def _managed_backup_supervisor_download(slug, destination):
    slug = str(slug or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', slug):
        return None, 'backup_slug_invalid'
    token = str(os.getenv('SUPERVISOR_TOKEN', '') or '').strip()
    if not token:
        return None, 'supervisor_token_missing'
    request = urllib.request.Request(
        'http://supervisor/backups/' + urllib.parse.quote(slug, safe='') + '/download',
        method='GET',
        headers={'Authorization': f'Bearer {token}', 'Accept': 'application/octet-stream'},
    )
    hasher = hashlib.sha256()
    total = 0
    max_bytes = 20 * 1024 * 1024 * 1024
    try:
        with urllib.request.urlopen(request, timeout=60) as response, open(destination, 'wb') as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None, 'backup_too_large'
                hasher.update(chunk)
                out.write(chunk)
        os.chmod(destination, 0o600)
    except urllib.error.HTTPError as error:
        return None, f'supervisor_download_http_{int(getattr(error, "code", 0) or 0)}'
    except Exception:
        return None, 'supervisor_download_failed'
    if total <= 0:
        return None, 'backup_download_empty'
    return {'sha256': hasher.hexdigest(), 'size': total}, ''




def _managed_backup_s3_failure_code(error, stage='s3'):
    """Return a bounded, credential-safe S3 failure code for Portal/log telemetry."""
    raw_code = ''
    operation = ''
    try:
        response = getattr(error, 'response', None)
        if isinstance(response, dict):
            err = response.get('Error') if isinstance(response.get('Error'), dict) else {}
            raw_code = str(err.get('Code', '') or '')
        operation = str(getattr(error, 'operation_name', '') or '')
    except Exception:
        pass

    text = str(error or '')
    if not raw_code:
        match = re.search(r'An error occurred \(([^)]+)\) when calling the ([A-Za-z0-9_]+) operation', text, re.I)
        if match:
            raw_code = match.group(1)
            if not operation:
                operation = match.group(2)

    # Common botocore transport/auth classes do not always expose response.Error.
    if not raw_code:
        cls = type(error).__name__ if error is not None else ''
        known = {
            'NoCredentialsError': 'no_credentials',
            'PartialCredentialsError': 'partial_credentials',
            'EndpointConnectionError': 'endpoint_connection',
            'ConnectTimeoutError': 'connect_timeout',
            'ReadTimeoutError': 'read_timeout',
            'SSLError': 'ssl_error',
            'ParamValidationError': 'parameter_validation',
            'S3UploadFailedError': 'upload_failed',
        }
        raw_code = known.get(cls, cls or 'unknown')

    def _safe(value):
        return re.sub(r'[^a-z0-9]+', '_', str(value or '').lower()).strip('_')

    code = _safe(raw_code) or 'unknown'
    op = _safe(operation) or _safe(stage) or 's3'
    return f's3_{code}_{op}'[:96]


def _managed_backup_presigned_url_parts(url, bucket, object_key, expected_signed_headers):
    try:
        parsed = urllib.parse.urlsplit(str(url or ''))
    except Exception:
        return None
    if parsed.scheme != 'https' or (parsed.hostname or '').lower() != 's3.eu-south-mil.io.cloud.ovh.net' or parsed.port not in (None, 443):
        return None
    expected_path = '/' + urllib.parse.quote(str(bucket), safe='') + '/' + '/'.join(
        urllib.parse.quote(part, safe='') for part in str(object_key).split('/')
    )
    if parsed.path != expected_path or not parsed.query:
        return None
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    required = ('X-Amz-Algorithm','X-Amz-Credential','X-Amz-Date','X-Amz-Expires','X-Amz-SignedHeaders','X-Amz-Signature')
    if any(len(query.get(key, [])) != 1 for key in required):
        return None
    if query['X-Amz-Algorithm'][0] != 'AWS4-HMAC-SHA256':
        return None
    if query['X-Amz-SignedHeaders'][0] != expected_signed_headers:
        return None
    try:
        expires = int(query['X-Amz-Expires'][0])
        issued = int(datetime.strptime(query['X-Amz-Date'][0], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        return None
    if expires < 30 or expires > 120 or issued <= 0:
        return None
    return {'host': parsed.hostname, 'target': parsed.path + '?' + parsed.query, 'issued_at': issued, 'expires_at': issued + expires}


def _managed_backup_parse_s3_time(value):
    raw = str(value or '').strip()
    if not raw:
        return 0
    try:
        dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        try:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except Exception:
            return 0


def _managed_backup_file_md5_b64(path):
    try:
        digest = hashlib.md5(usedforsecurity=False)
    except TypeError:
        digest = hashlib.md5()
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return base64.b64encode(digest.digest()).decode('ascii')


def _managed_backup_execute_presigned_primary_upload(job):
    if not isinstance(job, dict):
        return False
    required = {
        'contract','job_id','action','installation_id','node_id','policy_hash','backup_ref_digest','object_key',
        'retention_days','retain_until','provider_id','endpoint','region','bucket','object_lock_mode','transport_mode',
        'put_url','head_url','get_url','put_headers','nonce','issued_at','expires_at','upload_authorized',
        'storage_authorized','replication_authorized','restore_point_authorized','signature',
    }
    if set(job.keys()) != required or str(job.get('contract') or '') != 'smart-pro-managed-backup-presigned-upload-job-v1':
        return False
    if str(job.get('action') or '') != 'upload_verified_backup_presigned' or str(job.get('transport_mode') or '') != 'portal_presigned':
        return False
    installation_id = str(paired_installation_id() or '').strip().upper()
    state = load_managed_backup_agent_state()
    node_id = str(state.get('node_id', '') or '').strip().lower()
    if str(job.get('installation_id') or '').strip().upper() != installation_id or str(job.get('node_id') or '').strip().lower() != node_id:
        return False
    job_id = str(job.get('job_id') or '').strip().lower()
    nonce = str(job.get('nonce') or '').strip().lower()
    if not re.fullmatch(r'mbj_[0-9a-f]{32}', job_id) or not re.fullmatch(r'[0-9a-f]{32}', nonce):
        return False
    try:
        issued_at = int(job.get('issued_at', 0) or 0); expires_at = int(job.get('expires_at', 0) or 0)
        retention_days = int(job.get('retention_days', 0) or 0); retain_until = int(job.get('retain_until', 0) or 0)
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    if issued_at <= 0 or expires_at <= issued_at or expires_at - issued_at > 120 or now < issued_at - 30 or now > expires_at + 30:
        return False
    if retention_days not in range(1, 367) or abs(retain_until - (issued_at + retention_days * 86400)) > 5 or retain_until <= now:
        return False
    local_job = state.get('local_job') if isinstance(state.get('local_job'), dict) else None
    if not local_job or str(local_job.get('job_id') or '').strip().lower() != job_id or str(local_job.get('state') or '') != 'local_verified' or not bool(local_job.get('verified', False)):
        return False
    local_digest = str(local_job.get('backup_ref_digest') or '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', local_digest) or not hmac.compare_digest(local_digest, str(job.get('backup_ref_digest') or '').strip().lower()):
        return False
    policy = state.get('policy') if isinstance(state.get('policy'), dict) else None
    if not policy or str(policy.get('policy_hash') or '').strip().lower() != str(job.get('policy_hash') or '').strip().lower() or retention_days != int(policy.get('retention_days', 0) or 0):
        return False
    target = state.get('storage_target') if isinstance(state.get('storage_target'), dict) else None
    if not target or str(target.get('state') or '') != 'provider_configured':
        return False
    for key in ('provider_id','endpoint','region','bucket','object_lock_mode'):
        if str(job.get(key) or '').lower() != str(target.get(key) or '').lower():
            return False
    if not bool(job.get('upload_authorized')) or not bool(job.get('storage_authorized')) or bool(job.get('replication_authorized')) or not bool(job.get('restore_point_authorized')):
        return False
    object_key = str(job.get('object_key') or '').strip()
    if not re.fullmatch(r'managed-backup-presigned/[0-9a-f]{24}/mbj_[0-9a-f]{32}\.tar', object_key):
        return False
    put_headers = job.get('put_headers') if isinstance(job.get('put_headers'), dict) else None
    expected_retain_header = datetime.fromtimestamp(retain_until, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    expected_put_headers = {
        'if-none-match': '*',
        'x-amz-object-lock-mode': 'GOVERNANCE',
        'x-amz-object-lock-retain-until-date': expected_retain_header,
    }
    if put_headers != expected_put_headers:
        return False
    put_parts = _managed_backup_presigned_url_parts(job.get('put_url'), str(target['bucket']), object_key, 'host;if-none-match;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date')
    head_parts = _managed_backup_presigned_url_parts(job.get('head_url'), str(target['bucket']), object_key, 'host')
    get_parts = _managed_backup_presigned_url_parts(job.get('get_url'), str(target['bucket']), object_key, 'host')
    if not put_parts or not head_parts or not get_parts:
        return False
    if any(parts['expires_at'] > expires_at + 5 or parts['issued_at'] < issued_at - 5 for parts in (put_parts, head_parts, get_parts)):
        return False
    secret = _managed_backup_agent_control_secret()
    signature = str(job.get('signature') or '').strip().lower()
    expected = _managed_backup_job_signature(job, secret)
    if not expected or not hmac.compare_digest(expected, signature):
        return False
    existing = state.get('primary_upload') if isinstance(state.get('primary_upload'), dict) else None
    if existing and str(existing.get('job_id') or '').strip().lower() == job_id:
        if str(existing.get('state') or '').strip().lower() in ('uploading','primary_verified'):
            return False
        if str(existing.get('nonce') or '').strip().lower() == nonce:
            return False

    result = {
        'job_id': job_id, 'nonce': nonce, 'state': 'uploading', 'result_code': 'uploading', 'verified': False,
        'executed_at': 0, 'provider_id': str(job.get('provider_id') or ''), 'bucket': str(job.get('bucket') or ''),
        'object_key': object_key, 'object_version_id': '', 'object_sha256': '', 'object_size': 0,
        'object_lock_mode': 'governance', 'retain_until': retain_until, 'readback_verified': False,
    }
    state['primary_upload'] = result; state['updated_at'] = now; save_managed_backup_agent_state(state)
    transfer_dir = Path('/data/managed_backup_transfer')
    transfer_dir.mkdir(parents=True, exist_ok=True); os.chmod(transfer_dir, 0o700)
    temp_path = transfer_dir / f'{job_id}.tar'
    stage = 'download'
    try:
        download, error = _managed_backup_supervisor_download(str(local_job.get('backup_slug') or ''), temp_path)
        if error or not isinstance(download, dict):
            raise RuntimeError(error or 'backup_download_failed')
        content_md5 = _managed_backup_file_md5_b64(temp_path)
        stage = 'presigned_put'
        conn = http.client.HTTPSConnection(put_parts['host'], 443, timeout=180, context=ssl.create_default_context())
        try:
            with open(temp_path, 'rb') as body:
                headers = dict(expected_put_headers)
                headers.update({'Content-Length': str(int(download['size'])), 'Content-MD5': content_md5, 'Connection': 'close'})
                conn.request('PUT', put_parts['target'], body=body, headers=headers)
                response = conn.getresponse(); response.read(65536)
                if int(response.status) not in (200, 201):
                    raise RuntimeError(f'presigned_put_http_{int(response.status)}')
        finally:
            conn.close()
        stage = 'presigned_head'
        conn = http.client.HTTPSConnection(head_parts['host'], 443, timeout=60, context=ssl.create_default_context())
        try:
            conn.request('HEAD', head_parts['target'], headers={'Connection':'close'})
            response = conn.getresponse(); response.read()
            if int(response.status) != 200:
                raise RuntimeError(f'presigned_head_http_{int(response.status)}')
            head_size = int(response.getheader('Content-Length') or -1)
            version_id = str(response.getheader('x-amz-version-id') or '')
            lock_mode = str(response.getheader('x-amz-object-lock-mode') or '').upper()
            retain_header = str(response.getheader('x-amz-object-lock-retain-until-date') or '')
        finally:
            conn.close()
        if head_size != int(download['size']):
            raise RuntimeError('object_size_mismatch')
        if lock_mode != 'GOVERNANCE':
            raise RuntimeError('object_lock_mode_mismatch')
        retain_epoch = _managed_backup_parse_s3_time(retain_header)
        if retain_epoch <= 0 or abs(retain_epoch - retain_until) > 300:
            raise RuntimeError('object_lock_retention_mismatch')
        stage = 'presigned_get'
        conn = http.client.HTTPSConnection(get_parts['host'], 443, timeout=180, context=ssl.create_default_context())
        try:
            conn.request('GET', get_parts['target'], headers={'Connection':'close'})
            response = conn.getresponse()
            if int(response.status) != 200:
                response.read(65536)
                raise RuntimeError(f'presigned_get_http_{int(response.status)}')
            verify_hash = hashlib.sha256(); verify_size = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                verify_size += len(chunk); verify_hash.update(chunk)
        finally:
            conn.close()
        if verify_size != int(download['size']) or verify_hash.hexdigest() != str(download['sha256']):
            raise RuntimeError('object_readback_hash_mismatch')
        result.update({
            'state':'primary_verified','result_code':'primary_object_verified','verified':True,'executed_at':int(time.time()),
            'object_version_id':version_id,'object_sha256':str(download['sha256']),'object_size':int(download['size']),
            'object_lock_mode':'governance','retain_until':retain_epoch,'readback_verified':True,
        })
    except Exception as error:
        result.update({'state':'failed','result_code':_managed_backup_s3_failure_code(error, stage),'executed_at':int(time.time())})
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass
    state = load_managed_backup_agent_state(); state['primary_upload'] = result; state['updated_at'] = int(time.time()); save_managed_backup_agent_state(state)
    print(f"[BACKUP] Managed Backup presigned primary upload {job_id} -> {result['state']} / {result['result_code']}", flush=True)
    return True


def _managed_backup_execute_primary_upload(job):
    if not isinstance(job, dict):
        return False
    required = {
        'contract', 'job_id', 'action', 'installation_id', 'node_id', 'policy_hash',
        'backup_ref_digest', 'object_key', 'retention_days', 'provider_id', 'endpoint',
        'region', 'bucket', 'object_lock_mode', 'nonce', 'issued_at', 'expires_at',
        'upload_authorized', 'storage_authorized', 'replication_authorized',
        'restore_point_authorized', 'signature',
    }
    if set(job.keys()) != required:
        return False
    if str(job.get('contract', '') or '') != 'smart-pro-managed-backup-primary-upload-job-v1':
        return False
    if str(job.get('action', '') or '') != 'upload_verified_backup':
        return False
    installation_id = str(paired_installation_id() or '').strip().upper()
    node_id = str(load_managed_backup_agent_state().get('node_id', '') or '').strip().lower()
    if str(job.get('installation_id', '') or '').strip().upper() != installation_id:
        return False
    if str(job.get('node_id', '') or '').strip().lower() != node_id:
        return False
    job_id = str(job.get('job_id', '') or '').strip().lower()
    nonce = str(job.get('nonce', '') or '').strip().lower()
    if not re.fullmatch(r'mbj_[0-9a-f]{32}', job_id) or not re.fullmatch(r'[0-9a-f]{32}', nonce):
        return False
    now = int(time.time())
    try:
        issued_at = int(job.get('issued_at', 0) or 0)
        expires_at = int(job.get('expires_at', 0) or 0)
        retention_days = int(job.get('retention_days', 0) or 0)
    except (TypeError, ValueError):
        return False
    if issued_at <= 0 or expires_at <= issued_at or expires_at - issued_at > 120 or now < issued_at - 30 or now > expires_at + 30:
        return False
    state = load_managed_backup_agent_state()
    local_job = state.get('local_job') if isinstance(state.get('local_job'), dict) else None
    if not local_job or str(local_job.get('job_id', '') or '').lower() != job_id:
        return False
    if str(local_job.get('state', '') or '') != 'local_verified' or not bool(local_job.get('verified', False)):
        return False
    local_digest = str(local_job.get('backup_ref_digest', '') or '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', local_digest) or not hmac.compare_digest(local_digest, str(job.get('backup_ref_digest', '') or '').strip().lower()):
        return False
    policy = state.get('policy') if isinstance(state.get('policy'), dict) else None
    if not policy or str(policy.get('policy_hash', '') or '').strip().lower() != str(job.get('policy_hash', '') or '').strip().lower():
        return False
    if retention_days != int(policy.get('retention_days', 0) or 0) or retention_days not in range(1, 367):
        return False
    target = state.get('storage_target') if isinstance(state.get('storage_target'), dict) else None
    if not target or str(target.get('state', '') or '') != 'provider_configured':
        return False
    for key in ('provider_id', 'endpoint', 'region', 'bucket', 'object_lock_mode'):
        if str(job.get(key, '') or '') != str(target.get(key, '') or ''):
            return False
    if not bool(job.get('upload_authorized')) or not bool(job.get('storage_authorized')):
        return False
    if bool(job.get('replication_authorized')) or not bool(job.get('restore_point_authorized')):
        return False
    secret = _managed_backup_agent_control_secret()
    expected = _managed_backup_job_signature(job, secret)
    signature = str(job.get('signature', '') or '').strip().lower()
    if not expected or not hmac.compare_digest(expected, signature):
        return False
    existing = state.get('primary_upload') if isinstance(state.get('primary_upload'), dict) else None
    if existing and str(existing.get('job_id', '') or '').lower() == job_id:
        existing_nonce = str(existing.get('nonce', '') or '').lower()
        existing_state = str(existing.get('state', '') or '').lower()
        if existing_state == 'primary_verified':
            return False
        if existing_nonce == nonce and existing_state in ('uploading', 'failed'):
            return False
        if existing_state not in ('uploading', 'failed'):
            return False

    creds = _managed_backup_storage_credentials_snapshot()
    options = load_addon_options()
    access_key = str(options.get('managed_backup_s3_access_key', '') or '').strip()
    secret_key = str(options.get('managed_backup_s3_secret_key', '') or '').strip()
    result = {
        'job_id': job_id, 'nonce': nonce, 'state': 'uploading', 'result_code': 'uploading',
        'verified': False, 'executed_at': 0, 'provider_id': str(job.get('provider_id', '') or ''),
        'bucket': str(job.get('bucket', '') or ''), 'object_key': str(job.get('object_key', '') or ''),
        'object_version_id': '', 'object_sha256': '', 'object_size': 0,
        'object_lock_mode': str(job.get('object_lock_mode', '') or ''), 'retain_until': 0,
        'readback_verified': False,
    }
    state['primary_upload'] = result
    state['updated_at'] = now
    save_managed_backup_agent_state(state)
    if not bool(creds.get('configured')):
        result.update({'state': 'failed', 'result_code': 'provider_credentials_missing', 'executed_at': int(time.time())})
    else:
        transfer_dir = Path('/data/managed_backup_transfer')
        transfer_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(transfer_dir, 0o700)
        temp_path = transfer_dir / f'{job_id}.tar'
        try:
            download, error = _managed_backup_supervisor_download(str(local_job.get('backup_slug', '') or ''), temp_path)
            if error or not isinstance(download, dict):
                raise RuntimeError(error or 'backup_download_failed')
            try:
                import boto3
                from botocore.config import Config
            except Exception:
                raise RuntimeError('boto3_unavailable')
            client = boto3.client(
                's3', endpoint_url=str(target['endpoint']), region_name=str(target['region']),
                aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                config=Config(signature_version='s3v4', s3={'addressing_style': 'path'}),
            )
            stage = 'list_objects'
            # Read-only credential / endpoint / bucket-policy preflight. This runs before
            # downloading the local HA backup so obvious S3 failures fail fast.
            client.list_objects_v2(Bucket=str(target['bucket']), MaxKeys=1)
            retain_until_dt = datetime.now(timezone.utc) + timedelta(days=retention_days)
            extra = {
                'ContentType': 'application/octet-stream',
                'Metadata': {
                    'smartpro-contract': 'managed-backup-primary-v1',
                    'smartpro-job': job_id,
                    'smartpro-source-sha256': str(download['sha256']),
                },
                'ObjectLockMode': 'GOVERNANCE',
                'ObjectLockRetainUntilDate': retain_until_dt,
            }
            stage = 'put_object'
            client.upload_file(str(temp_path), str(target['bucket']), str(job['object_key']), ExtraArgs=extra)
            stage = 'head_object'
            head = client.head_object(Bucket=str(target['bucket']), Key=str(job['object_key']))
            if int(head.get('ContentLength', -1)) != int(download['size']):
                raise RuntimeError('object_size_mismatch')
            metadata = head.get('Metadata') if isinstance(head.get('Metadata'), dict) else {}
            if str(metadata.get('smartpro-source-sha256', '') or '').lower() != str(download['sha256']).lower():
                raise RuntimeError('object_metadata_digest_mismatch')
            stage = 'get_object'
            body = client.get_object(Bucket=str(target['bucket']), Key=str(job['object_key']))['Body']
            verify_hash = hashlib.sha256()
            verify_size = 0
            while True:
                chunk = body.read(1024 * 1024)
                if not chunk:
                    break
                verify_size += len(chunk)
                verify_hash.update(chunk)
            body.close()
            if verify_size != int(download['size']) or verify_hash.hexdigest() != str(download['sha256']):
                raise RuntimeError('object_readback_hash_mismatch')
            mode = str(head.get('ObjectLockMode', '') or '').upper()
            if mode != 'GOVERNANCE':
                raise RuntimeError('object_lock_mode_mismatch')
            retain_head = head.get('ObjectLockRetainUntilDate')
            retain_epoch = int(retain_head.timestamp()) if hasattr(retain_head, 'timestamp') else int(retain_until_dt.timestamp())
            result.update({
                'state': 'primary_verified', 'result_code': 'primary_object_verified', 'verified': True,
                'executed_at': int(time.time()), 'object_version_id': str(head.get('VersionId', '') or ''),
                'object_sha256': str(download['sha256']), 'object_size': int(download['size']),
                'object_lock_mode': 'governance', 'retain_until': retain_epoch, 'readback_verified': True,
            })
        except Exception as error:
            code = _managed_backup_s3_failure_code(error, locals().get('stage', 'primary_upload'))
            result.update({'state': 'failed', 'result_code': code, 'executed_at': int(time.time())})
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
    state = load_managed_backup_agent_state()
    state['primary_upload'] = result
    state['updated_at'] = int(time.time())
    save_managed_backup_agent_state(state)
    print(f"[BACKUP] Managed Backup primary upload {job_id} -> {result['state']} / {result['result_code']}", flush=True)
    return True


def _managed_backup_job_unsigned(job):
    return {key: value for key, value in job.items() if key != 'signature'}


def _managed_backup_job_signature(job, secret):
    if not isinstance(job, dict) or len(secret) != 32:
        return ''
    canonical = _control_plane_canonical(_managed_backup_job_unsigned(job)).encode('utf-8')
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def _managed_backup_verify_local_slug(token, slug):
    slug = str(slug or '').strip()
    if not slug:
        return False, '', 'backup_slug_missing'
    result, error = _supervisor_api_json('/backups/info', 'GET')
    if error or not isinstance(result, dict) or not isinstance(result.get('backups'), list):
        return False, '', 'backup_inventory_verify_failed'
    for backup in result.get('backups', []):
        if not isinstance(backup, dict) or str(backup.get('slug', '') or '').strip() != slug:
            continue
        content = backup.get('content') if isinstance(backup.get('content'), dict) else {}
        if not bool(content.get('homeassistant', False)):
            return False, '', 'backup_missing_homeassistant_content'
        backup_type = str(backup.get('type', '') or '').strip().lower()
        if backup_type not in ('full', 'partial'):
            backup_type = 'unknown'
        return True, backup_type, 'local_backup_verified'
    return False, '', 'backup_slug_not_found'


def _managed_backup_execute_local_job(job):
    if not isinstance(job, dict):
        return False
    required_keys = {
        'contract', 'job_id', 'action', 'installation_id', 'node_id', 'policy_hash', 'nonce',
        'issued_at', 'expires_at', 'local_only', 'upload_authorized', 'storage_authorized',
        'restore_point_authorized', 'signature',
    }
    if set(job.keys()) != required_keys:
        return False
    if str(job.get('contract', '') or '') != 'smart-pro-managed-backup-local-job-v1':
        return False
    if str(job.get('action', '') or '') != 'create_local_backup':
        return False
    job_id = str(job.get('job_id', '') or '').strip().lower()
    node_id = str(job.get('node_id', '') or '').strip().lower()
    policy_hash = str(job.get('policy_hash', '') or '').strip().lower()
    nonce = str(job.get('nonce', '') or '').strip().lower()
    signature = str(job.get('signature', '') or '').strip().lower()
    installation_id = str(job.get('installation_id', '') or '').strip().upper()
    if not re.fullmatch(r'mbj_[0-9a-f]{32}', job_id):
        return False
    if not re.fullmatch(r'[0-9a-f]{64}', node_id) or not re.fullmatch(r'[0-9a-f]{64}', policy_hash):
        return False
    if not re.fullmatch(r'[0-9a-f]{32}', nonce) or not re.fullmatch(r'[0-9a-f]{64}', signature):
        return False
    try:
        issued_at = int(job.get('issued_at', 0) or 0)
        expires_at = int(job.get('expires_at', 0) or 0)
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    if issued_at <= 0 or expires_at <= issued_at or expires_at - issued_at > 120:
        return False
    if now < issued_at - 30 or now > expires_at:
        return False
    if not bool(job.get('local_only', False)) or bool(job.get('upload_authorized', False)) or bool(job.get('storage_authorized', False)) or bool(job.get('restore_point_authorized', False)):
        return False
    if installation_id != str(paired_installation_id() or '').strip().upper():
        return False
    state = load_managed_backup_agent_state()
    current_node = str(state.get('node_id', '') or '').strip().lower()
    policy = state.get('policy') if isinstance(state.get('policy'), dict) else None
    if current_node != node_id or not isinstance(policy, dict) or str(policy.get('policy_hash', '') or '').strip().lower() != policy_hash:
        return False
    if not bool(state.get('control_plane_ready', False)) or bool(state.get('runtime_authority_present', False)):
        return False
    readiness = managed_backup_local_readiness_snapshot()
    if str(readiness.get('state', '') or '') != 'ready' or str(readiness.get('reason_code', '') or '') != 'ready':
        return False
    secret = _managed_backup_agent_control_secret()
    expected = _managed_backup_job_signature(job, secret)
    if not expected or not hmac.compare_digest(expected, signature):
        return False

    existing = state.get('local_job') if isinstance(state.get('local_job'), dict) else None
    if existing:
        existing_id = str(existing.get('job_id', '') or '').strip().lower()
        existing_nonce = str(existing.get('nonce', '') or '').strip().lower()
        existing_state = str(existing.get('state', '') or '').strip().lower()
        if existing_id == job_id:
            if existing_nonce != nonce:
                return False
            if existing_state in ('local_verified', 'failed'):
                return False
            # A prior process may have died after persisting "creating". Fail closed
            # rather than creating a duplicate local backup on a replay.
            if existing_state == 'creating':
                existing['state'] = 'failed'
                existing['result_code'] = 'local_job_interrupted'
                existing['verified'] = False
                existing['executed_at'] = now
                existing['backup_ref_digest'] = ''
                existing['backup_type'] = ''
                state['local_job'] = existing
                state['updated_at'] = now
                save_managed_backup_agent_state(state)
                return True
        else:
            # 2.4.55: sequential daily jobs are allowed only after the previous
            # local job reached a terminal state. A verified local job additionally
            # requires its matching primary upload to have been fully verified,
            # preventing the scheduler from advancing past an unfinished off-site cycle.
            if existing_state not in ('local_verified', 'failed'):
                return False
            if existing_state == 'local_verified':
                prior_primary = state.get('primary_upload') if isinstance(state.get('primary_upload'), dict) else None
                if not prior_primary:
                    return False
                if str(prior_primary.get('job_id', '') or '').strip().lower() != existing_id:
                    return False
                if str(prior_primary.get('state', '') or '').strip().lower() != 'primary_verified':
                    return False

    local_job = {
        'job_id': job_id,
        'nonce': nonce,
        'state': 'creating',
        'result_code': 'creating',
        'verified': False,
        'started_at': now,
        'executed_at': 0,
        'backup_slug': '',
        'backup_ref_digest': '',
        'backup_type': '',
    }
    state['local_job'] = local_job
    state['updated_at'] = now
    save_managed_backup_agent_state(state)

    options = load_addon_options()
    token = str(options.get('ha_token', '') or '').strip()
    result = call_ha_service_with_response(
        token,
        'hassio',
        'backup_full',
        {'name': f'SmartPro_Managed_{job_id[-8:]}'},
        timeout=900,
    )
    local_job['executed_at'] = int(time.time())
    if not result.get('success'):
        local_job['state'] = 'failed'
        local_job['result_code'] = 'backup_create_failed'
    else:
        slug = extract_backup_slug(result.get('response'))
        if not slug:
            local_job['state'] = 'failed'
            local_job['result_code'] = 'backup_slug_missing'
        else:
            verified, backup_type, result_code = _managed_backup_verify_local_slug(token, slug)
            local_job['backup_slug'] = slug
            local_job['backup_ref_digest'] = hashlib.sha256(slug.encode('utf-8')).hexdigest()
            local_job['backup_type'] = backup_type
            local_job['state'] = 'local_verified' if verified else 'failed'
            local_job['result_code'] = result_code
            local_job['verified'] = bool(verified)
    state = load_managed_backup_agent_state()
    state['local_job'] = local_job
    state['updated_at'] = int(time.time())
    save_managed_backup_agent_state(state)
    print(f"[BACKUP] Managed Backup local job {job_id} -> {local_job['state']} / {local_job['result_code']}", flush=True)
    return True


def _managed_backup_note_local_job_delivery(job, accepted):
    """Report whether the *authenticated response* contained a local job.

    This is not a dispatcher, not an execution acknowledgement, and grants no
    additional authority. A rejection is not retried here. The full job envelope,
    signature and key are never stored in the observation.
    """
    if not isinstance(job, dict):
        return False
    job_id = str(job.get('job_id') or '').strip().lower()
    nonce = str(job.get('nonce') or '').strip().lower()
    if not re.fullmatch(r'mbj_[0-9a-f]{32}', job_id) or not re.fullmatch(r'[0-9a-f]{32}', nonce):
        return False
    state = load_managed_backup_agent_state()
    previous = state.get('local_delivery_observation') if isinstance(state.get('local_delivery_observation'), dict) else {}
    local = state.get('local_job') if isinstance(state.get('local_job'), dict) else {}
    same_terminal = local.get('job_id') == job_id and local.get('state') in ('local_verified', 'failed')
    status = 'processed' if accepted else ('already_terminal' if same_terminal else 'not_accepted')
    if previous.get('job_id') == job_id and previous.get('nonce') == nonce:
        # Preserve first positive observation; a subsequent response may contain
        # an idempotent replay of an already completed job.
        if previous.get('status') == 'processed' or previous.get('status') == status:
            return False
    state['local_delivery_observation'] = {
        'contract': 'smart-pro-managed-backup-local-delivery-observation-v1',
        'job_id': job_id,
        'nonce': nonce,
        'status': status,
        'observed_at': int(time.time()),
    }
    state['updated_at'] = int(time.time())
    save_managed_backup_agent_state(state)
    return True


def _managed_backup_local_delivery_public_observation():
    state = load_managed_backup_agent_state()
    observation = state.get('local_delivery_observation') if isinstance(state.get('local_delivery_observation'), dict) else {}
    if (observation.get('contract') != 'smart-pro-managed-backup-local-delivery-observation-v1'
            or observation.get('status') not in ('processed', 'already_terminal', 'not_accepted')):
        return None
    return dict(observation)


def managed_backup_agent_heartbeat_snapshot():
    node_id = _managed_backup_agent_ensure_node_id()
    key_proof = _managed_backup_agent_node_key_id(node_id)
    return {
        'contract': MANAGED_BACKUP_AGENT_CONTRACT_ID,
        'supported': True,
        'node_id': node_id,
        'node_key_id': key_proof,
        'capabilities': list(MANAGED_BACKUP_AGENT_CAPABILITIES),
        'readiness': managed_backup_local_readiness_snapshot(),
        'job_result': _managed_backup_local_job_public_result(),
        'local_delivery_observation': _managed_backup_local_delivery_public_observation(),
        'storage_handoff': _managed_backup_storage_handoff_snapshot(),
        'storage_credentials': _managed_backup_storage_credentials_snapshot(),
        'primary_upload_result': _managed_backup_primary_upload_public_result(),
        'recovery_download_result': recovery_verifier.public_result(),
        'supervisor_stage_result': recovery_stage.public_result(),
        'reported_at': int(time.time()),
    }


def _managed_backup_policy_normalize(raw):
    if not isinstance(raw, dict):
        return None
    frequency = str(raw.get('frequency', '') or '').strip().lower()
    if frequency != 'daily':
        return None
    try:
        retention_days = int(raw.get('retention_days', 0) or 0)
    except (TypeError, ValueError):
        return None
    timezone = str(raw.get('timezone', '') or '').strip()
    window_start = str(raw.get('window_start', '') or '').strip()
    window_end = str(raw.get('window_end', '') or '').strip()
    slot_local = str(raw.get('slot_local', '') or '').strip()
    policy_hash = str(raw.get('policy_hash', '') or '').strip().lower()
    time_re = r'(?:[01]\d|2[0-3]):[0-5]\d'
    if retention_days < 1 or retention_days > 366:
        return None
    if not timezone or len(timezone) > 96:
        return None
    if not re.fullmatch(time_re, window_start) or not re.fullmatch(time_re, window_end) or not re.fullmatch(time_re, slot_local):
        return None
    if not re.fullmatch(r'[0-9a-f]{64}', policy_hash):
        return None
    return {
        'frequency': frequency,
        'retention_days': retention_days,
        'timezone': timezone,
        'window_start': window_start,
        'window_end': window_end,
        'slot_local': slot_local,
        'policy_hash': policy_hash,
    }


def _portal_maybe_process_managed_backup(response):
    managed = response.get('managed_backup') if isinstance(response, dict) else None
    if not isinstance(managed, dict) or str(managed.get('contract', '') or '') != MANAGED_BACKUP_AGENT_CONTRACT_ID:
        return False
    state = load_managed_backup_agent_state()
    changed = False
    enrollment_state = str(managed.get('enrollment_state', '') or '').strip().lower()[:48]
    service_state = str(managed.get('service_state', '') or '').strip().lower()[:48]
    control_plane_ready = bool(managed.get('control_plane_ready', False))
    runtime = managed.get('runtime') if isinstance(managed.get('runtime'), dict) else {}
    runtime_authority_present = any(bool(runtime.get(key, False)) for key in MANAGED_BACKUP_AGENT_RUNTIME_KEYS)

    policy_raw = managed.get('policy')
    policy = _managed_backup_policy_normalize(policy_raw) if isinstance(policy_raw, dict) else None
    policy_state = 'none'
    if policy_raw is not None:
        policy_state = 'sync' if policy is not None else 'invalid'

    storage_target_raw = managed.get('storage_target')
    storage_target = _managed_backup_storage_target_normalize(storage_target_raw) if isinstance(storage_target_raw, dict) else None
    if storage_target_raw is not None and storage_target is None:
        storage_target_state = 'invalid'
        storage_target = None
    elif storage_target is None:
        storage_target = state.get('storage_target') if isinstance(state.get('storage_target'), dict) else None
        storage_target_state = str(state.get('storage_target_state', '') or 'not_received')
    else:
        storage_target_state = str(storage_target.get('state', '') or 'not_received')

    updates = {
        'portal_state': enrollment_state or 'waiting',
        'service_state': service_state or 'blocked',
        'control_plane_ready': control_plane_ready,
        'policy_state': policy_state,
        'policy': policy,
        'runtime_authority_present': runtime_authority_present,
        'storage_target_state': storage_target_state,
        'storage_target': storage_target,
        'updated_at': int(time.time()),
    }
    for key, value in updates.items():
        if state.get(key) != value:
            state[key] = value
            changed = True
    if changed:
        save_managed_backup_agent_state(state)
    if runtime_authority_present:
        print('[BACKUP] Portal advertised unsupported persistent data-plane authority; Tools 2.4.40 refused it.', flush=True)
        return changed
    job_changed = False
    delivery_observed = False
    if isinstance(managed.get('job'), dict):
        job_changed = _managed_backup_execute_local_job(managed.get('job'))
        delivery_observed = _managed_backup_note_local_job_delivery(managed.get('job'), job_changed)
    upload_changed = False
    if isinstance(managed.get('upload_job'), dict):
        upload_changed = _managed_backup_execute_primary_upload(managed.get('upload_job'))
    presigned_upload_changed = False
    if isinstance(managed.get('presigned_upload_job'), dict):
        presigned_upload_changed = _managed_backup_execute_presigned_primary_upload(managed.get('presigned_upload_job'))
    recovery_started=False
    if isinstance(managed.get('recovery_job'),dict):
        recovery_started=recovery_verifier.maybe_start(managed['recovery_job'],{
            'installation_id':str(paired_installation_id() or '').strip().upper(),
            'node_id':str(state.get('node_id') or ''),
            'secret':_managed_backup_agent_control_secret(),
        })
    stage_started=False
    if isinstance(managed.get('supervisor_stage_job'),dict):
        stage_started=recovery_stage.maybe_start(managed['supervisor_stage_job'],{
            'installation_id':str(paired_installation_id() or '').strip().upper(),
            'node_id':str(state.get('node_id') or ''),
            'secret':_managed_backup_agent_control_secret(),
        })
    return changed or job_changed or delivery_observed or upload_changed or presigned_upload_changed or recovery_started or stage_started


def managed_backup_agent_public_snapshot():
    state = load_managed_backup_agent_state()
    node_id = str(state.get('node_id', '') or '').strip().lower()
    policy = state.get('policy') if isinstance(state.get('policy'), dict) else None
    return {
        'contract': MANAGED_BACKUP_AGENT_CONTRACT_ID,
        'supported': True,
        'node_hint': f'{node_id[:8]}…{node_id[-6:]}' if re.fullmatch(r'[0-9a-f]{64}', node_id) else '',
        'portal_state': str(state.get('portal_state', '') or '')[:48],
        'service_state': str(state.get('service_state', '') or '')[:48],
        'control_plane_ready': bool(state.get('control_plane_ready', False)),
        'policy_state': str(state.get('policy_state', '') or '')[:24],
        'policy': policy,
        'runtime_authority_present': bool(state.get('runtime_authority_present', False)),
        'local_readiness': managed_backup_local_readiness_snapshot(),
        'local_job_result': _managed_backup_local_job_public_result(),
        'storage_handoff': _managed_backup_storage_handoff_snapshot(),
        'storage_credentials': _managed_backup_storage_credentials_snapshot(),
        'primary_upload_result': _managed_backup_primary_upload_public_result(),
        'recovery_download_result': recovery_verifier.public_result(),
        'supervisor_stage_result': recovery_stage.public_result(),
        'local_backup_create_capable': True,
        'storage_handoff_readiness_capable': True,
        'primary_storage_upload_capable': True,
        'backup_io_authorized': False,
        'storage_authorized': False,
        'restore_authorized': False,
    }


def _control_plane_canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _control_plane_unsigned_command(command):
    return {key: value for key, value in command.items() if key != 'signature'}


def _control_plane_ack(command, status, result_code, message):
    return {
        'command_id': str(command.get('command_id', '') or '')[:80],
        'key_id': str(command.get('key_id', '') or '')[:32],
        'nonce': str(command.get('nonce', '') or '')[:80],
        'kind': str(command.get('kind', '') or '')[:32],
        'status': str(status or 'failed')[:24],
        'result_code': str(result_code or 'failed')[:64],
        'message': str(message or '')[:220],
        'executed_at': int(time.time()),
    }


def _control_plane_store_ack(state, command, ack):
    seen = list(state.get('seen') or [])
    seen.append({
        'command_id': ack['command_id'],
        'nonce': ack['nonce'],
        'executed_at': ack['executed_at'],
        'ack': ack,
    })
    state['seen'] = seen
    state['last_ack'] = ack
    save_control_plane_state(state)


def _control_plane_apply_provision(provision):
    if not isinstance(provision, dict):
        return False
    key_id = str(provision.get('key_id', '') or '').strip().lower()
    secret_b64 = str(provision.get('secret_b64', '') or '').strip()
    issued_at = int(provision.get('issued_at', 0) or 0)
    now = int(time.time())
    if not re.fullmatch(r'[0-9a-f]{16}', key_id):
        return False
    if issued_at <= 0 or abs(now - issued_at) > 600:
        return False
    try:
        secret = base64.b64decode(secret_b64.encode('ascii'), validate=True)
    except Exception:
        return False
    if len(secret) != 32 or hashlib.sha256(secret).hexdigest()[:16] != key_id:
        return False
    state = load_control_plane_state()
    if str(state.get('key_id', '') or '') == key_id and str(state.get('secret_b64', '') or '') == secret_b64:
        return False
    state['key_id'] = key_id
    state['secret_b64'] = secret_b64
    state['seen'] = []
    state['last_ack'] = None
    save_control_plane_state(state)
    print(f'[CONTROL] Secure command key provisioned: {key_id}', flush=True)
    return True


def _control_plane_guardian_values(raw):
    """Validate the first remotely managed Guardian settings family.

    Only the three low-risk numeric policy values are accepted in Milestone 3.
    The function is deliberately strict so unknown/new fields fail closed.
    """
    if not isinstance(raw, dict):
        return None, 'guardian_values_invalid'
    required = {'check_interval_min', 'alert_delay_min', 'battery_limit'}
    if set(raw.keys()) != required:
        return None, 'guardian_keys_invalid'
    bounds = {
        'check_interval_min': (1.0, 60.0),
        'alert_delay_min': (1.0, 1440.0),
        'battery_limit': (1.0, 100.0),
    }
    clean = {}
    for key, (lower, upper) in bounds.items():
        value = raw.get(key)
        if isinstance(value, bool):
            return None, f'{key}_invalid'
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None, f'{key}_invalid'
        if not math.isfinite(number) or number < lower or number > upper:
            return None, f'{key}_out_of_range'
        clean[key] = round(number, 2)
    return clean, ''


def _control_plane_guardian_current():
    settings = load_tech_settings()
    return {
        'check_interval_min': round(float(settings.get('check_interval_min', 5.0) or 5.0), 2),
        'alert_delay_min': round(float(settings.get('alert_delay_min', 15.0) or 15.0), 2),
        'battery_limit': round(float(settings.get('battery_limit', 15.0) or 15.0), 2),
    }


def _control_plane_guardian_equal(left, right):
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    for key in ('check_interval_min', 'alert_delay_min', 'battery_limit'):
        try:
            if abs(float(left.get(key)) - float(right.get(key))) > 0.001:
                return False
        except (TypeError, ValueError):
            return False
    return True


_CONTROL_PLANE_GUARDIAN_SCOPE_MAP = (
    ('light', 'domain_light'),
    ('switch', 'domain_switch'),
    ('binary_sensor', 'domain_binary_sensor'),
    ('climate', 'domain_climate'),
    ('cover', 'domain_cover'),
    ('camera', 'domain_camera'),
    ('lock', 'domain_lock'),
    ('water_heater', 'domain_water_heater'),
)


def _control_plane_guardian_scope_values(raw, require_nonempty=True):
    """Validate the controlled Guardian monitoring-scope family.

    Only the eight categories already visible in the local Technician Center
    may be changed remotely. The hidden generic sensor domain remains outside
    this milestone and is never modified here.
    """
    if not isinstance(raw, dict) or set(raw.keys()) != {'domains'}:
        return None, 'guardian_scope_values_invalid'
    domains = raw.get('domains')
    if not isinstance(domains, list):
        return None, 'guardian_scope_domains_invalid'
    allowed = [domain for domain, _setting_key in _CONTROL_PLANE_GUARDIAN_SCOPE_MAP]
    clean_seen = set()
    for item in domains:
        if not isinstance(item, str) or item not in allowed or item in clean_seen:
            return None, 'guardian_scope_domain_invalid'
        clean_seen.add(item)
    clean = [domain for domain in allowed if domain in clean_seen]
    if require_nonempty and not clean:
        return None, 'guardian_scope_empty'
    return {'domains': clean}, ''


def _control_plane_guardian_scope_current():
    settings = load_tech_settings()
    domains = []
    for domain, setting_key in _CONTROL_PLANE_GUARDIAN_SCOPE_MAP:
        if bool(settings.get(setting_key, DEFAULT_TECH_SETTINGS.get(setting_key, False))):
            domains.append(domain)
    return {'domains': domains}


def _control_plane_guardian_scope_equal(left, right):
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    left_clean, left_error = _control_plane_guardian_scope_values(left, require_nonempty=False)
    right_clean, right_error = _control_plane_guardian_scope_values(right, require_nonempty=False)
    if left_error or right_error:
        return False
    return left_clean['domains'] == right_clean['domains']


def _control_plane_guardian_scope_settings(scope):
    enabled = set((scope or {}).get('domains') or [])
    return {
        setting_key: domain in enabled
        for domain, setting_key in _CONTROL_PLANE_GUARDIAN_SCOPE_MAP
    }


def _control_plane_guardian_master_current():
    settings = load_tech_settings()
    return {'enabled': bool(settings.get('watchdog_enabled', True))}


def _control_plane_guardian_safe_test_policy_values(raw):
    if not isinstance(raw, dict) or set(raw.keys()) != {'delay_sec', 'clear_sec', 'send_email'}:
        return None, 'guardian_safe_test_policy_invalid'
    if isinstance(raw.get('delay_sec'), bool) or isinstance(raw.get('clear_sec'), bool):
        return None, 'guardian_safe_test_policy_numeric_invalid'
    try:
        delay_sec = int(raw.get('delay_sec'))
        clear_sec = int(raw.get('clear_sec'))
    except (TypeError, ValueError):
        return None, 'guardian_safe_test_policy_numeric_invalid'
    if delay_sec < 3 or delay_sec > 300 or clear_sec < 5 or clear_sec > 600:
        return None, 'guardian_safe_test_policy_out_of_range'
    if not isinstance(raw.get('send_email'), bool):
        return None, 'guardian_safe_test_policy_email_invalid'
    return {
        'delay_sec': delay_sec,
        'clear_sec': clear_sec,
        'send_email': bool(raw.get('send_email')),
    }, ''


def _control_plane_guardian_safe_test_policy_current():
    settings = load_tech_settings()
    return {
        'delay_sec': int(settings.get('watchdog_test_delay_sec', 10) or 10),
        'clear_sec': int(settings.get('watchdog_test_clear_sec', 30) or 30),
        'send_email': bool(settings.get('watchdog_test_send_email', False)),
    }


def _control_plane_guardian_safe_test_policy_equal(left, right):
    left_clean, left_error = _control_plane_guardian_safe_test_policy_values(left)
    right_clean, right_error = _control_plane_guardian_safe_test_policy_values(right)
    return not left_error and not right_error and left_clean == right_clean


def _control_plane_guardian_safe_test_policy_settings(values):
    return {
        'watchdog_test_delay_sec': int(values.get('delay_sec', 10)),
        'watchdog_test_clear_sec': int(values.get('clear_sec', 30)),
        'watchdog_test_send_email': bool(values.get('send_email', False)),
    }


def _control_plane_guardian_test_active():
    status = str(watchdog_test_public_status().get('status', 'idle') or 'idle')
    return status in ('scheduled', 'running', 'request_created'), status


_CONTROL_PLANE_SMART_UPDATE_TARGET_MAP = (
    ('core', 'update_core'),
    ('os', 'update_os'),
    ('addons', 'update_addons'),
)


def _control_plane_smart_updates_values(raw, require_targets=True):
    """Validate the controlled Smart Updates policy family.

    The master enable/disable switch remains outside this milestone. Only the
    policy that governs an already-enabled/disabled local Smart Updates engine
    may be changed remotely.
    """
    expected_keys = {
        'targets', 'wait_days', 'backup_wait_min', 'evaluation_min',
        'rollback_offline_count', 'notify_only',
    }
    if not isinstance(raw, dict) or set(raw.keys()) != expected_keys:
        return None, 'smart_updates_values_invalid'

    targets = raw.get('targets')
    if not isinstance(targets, list):
        return None, 'smart_updates_targets_invalid'
    allowed = [name for name, _key in _CONTROL_PLANE_SMART_UPDATE_TARGET_MAP]
    seen = set()
    for item in targets:
        if not isinstance(item, str) or item not in allowed or item in seen:
            return None, 'smart_updates_target_invalid'
        seen.add(item)
    clean_targets = [name for name in allowed if name in seen]
    if require_targets and not clean_targets:
        return None, 'smart_updates_targets_empty'

    def strict_int(key, minimum, maximum):
        value = raw.get(key)
        if isinstance(value, bool):
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        if str(value).strip() not in {str(number), f'{number}.0'} and not isinstance(value, int):
            try:
                if float(value) != number:
                    return None
            except Exception:
                return None
        if number < minimum or number > maximum:
            return None
        return number

    wait_days = strict_int('wait_days', 0, 365)
    backup_wait_min = strict_int('backup_wait_min', 1, 180)
    evaluation_min = strict_int('evaluation_min', 1, 240)
    rollback_offline_count = strict_int('rollback_offline_count', 1, 1000)
    if None in (wait_days, backup_wait_min, evaluation_min, rollback_offline_count):
        return None, 'smart_updates_numeric_invalid'
    if not isinstance(raw.get('notify_only'), bool):
        return None, 'smart_updates_notify_invalid'

    return {
        'targets': clean_targets,
        'wait_days': wait_days,
        'backup_wait_min': backup_wait_min,
        'evaluation_min': evaluation_min,
        'rollback_offline_count': rollback_offline_count,
        'notify_only': bool(raw.get('notify_only')),
    }, ''


def _control_plane_smart_updates_current():
    settings = load_tech_settings()
    targets = [
        name for name, setting_key in _CONTROL_PLANE_SMART_UPDATE_TARGET_MAP
        if bool(settings.get(setting_key, DEFAULT_TECH_SETTINGS.get(setting_key, False)))
    ]
    return {
        'targets': targets,
        'wait_days': int(settings.get('update_wait_days', 3) or 3),
        'backup_wait_min': int(settings.get('update_backup_wait_min', 15) or 15),
        'evaluation_min': int(settings.get('update_eval_min', 20) or 20),
        'rollback_offline_count': int(settings.get('update_rollback_offline_count', 2) or 2),
        'notify_only': bool(settings.get('update_notify_only', False)),
    }


def _control_plane_smart_updates_equal(left, right):
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    left_clean, left_error = _control_plane_smart_updates_values(left, require_targets=False)
    right_clean, right_error = _control_plane_smart_updates_values(right, require_targets=False)
    return not left_error and not right_error and left_clean == right_clean


def _control_plane_smart_updates_settings(values):
    enabled_targets = set((values or {}).get('targets') or [])
    return {
        'update_core': 'core' in enabled_targets,
        'update_os': 'os' in enabled_targets,
        'update_addons': 'addons' in enabled_targets,
        'update_wait_days': int(values.get('wait_days', 3)),
        'update_backup_wait_min': int(values.get('backup_wait_min', 15)),
        'update_eval_min': int(values.get('evaluation_min', 20)),
        'update_rollback_offline_count': int(values.get('rollback_offline_count', 2)),
        'update_notify_only': bool(values.get('notify_only', False)),
    }



def _control_plane_vacation_policy_values(source):
    required = {'start', 'end', 'cover_open_time', 'cover_close_time'}
    if not isinstance(source, dict) or set(source.keys()) != required:
        return None, 'vacation_policy_payload_invalid'
    values = {}
    for key in ('start', 'end', 'cover_open_time', 'cover_close_time'):
        value = str(source.get(key, '') or '').strip()
        if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', value):
            return None, 'vacation_policy_time_invalid'
        values[key] = value
    return values, None


def _control_plane_vacation_policy_current():
    settings = load_tech_settings()
    return {
        'start': str(settings.get('vacation_start', '20:00') or '20:00')[:5],
        'end': str(settings.get('vacation_end', '23:59') or '23:59')[:5],
        'cover_open_time': str(settings.get('cover_open_time', '08:00') or '08:00')[:5],
        'cover_close_time': str(settings.get('cover_close_time', '20:00') or '20:00')[:5],
    }


def _control_plane_vacation_policy_equal(left, right):
    left_clean, left_error = _control_plane_vacation_policy_values(left)
    right_clean, right_error = _control_plane_vacation_policy_values(right)
    return not left_error and not right_error and left_clean == right_clean


def _control_plane_vacation_policy_settings(values):
    return {
        'vacation_start': str(values.get('start', '20:00')),
        'vacation_end': str(values.get('end', '23:59')),
        'cover_open_time': str(values.get('cover_open_time', '08:00')),
        'cover_close_time': str(values.get('cover_close_time', '20:00')),
    }


def _control_plane_vacation_selection_counts(settings=None):
    settings = settings or load_tech_settings()
    counts = {
        'lights': len(settings.get('vacation_lights') or []),
        'covers': len(settings.get('vacation_covers') or []),
        'audio': len(settings.get('vacation_audio') or []),
    }
    counts['total'] = counts['lights'] + counts['covers'] + counts['audio']
    return counts


def _control_plane_vacation_helper_state():
    try:
        states = get_ha_states_for_ui()
    except Exception:
        return {'available': False, 'present': False, 'active': False}
    for item in states or []:
        if not isinstance(item, dict):
            continue
        if str(item.get('entity_id', '') or '') == 'input_boolean.smart_pro_vacation':
            return {
                'available': True,
                'present': True,
                'active': str(item.get('state', '') or '').strip().lower() == 'on',
            }
    return {'available': True, 'present': False, 'active': False}


def _external_url_tunnel_supervisor_apply(payload):
    if str(payload.get('family','') or '') != 'managed_external_url_private_tunnel': return None, 'external_url_family_invalid'
    peer=_external_access_normalize_peer_address(payload.get('peer_address'))
    if not peer: return None, 'external_url_peer_invalid'
    endpoint=str(payload.get('gateway_endpoint','') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}', endpoint): return None, 'external_url_gateway_endpoint_invalid'
    gkey=str(payload.get('gateway_public_key','') or '').strip()
    try:
        if len(base64.b64decode(gkey.encode('ascii'),validate=True)) != 32: return None, 'external_url_gateway_key_invalid'
    except Exception: return None, 'external_url_gateway_key_invalid'
    expected_sha=str(payload.get('expected_tunnel_public_key_sha256','') or '').strip().lower()
    enrollment=_external_access_tunnel_enrollment_snapshot()
    if not enrollment.get('valid') or str(enrollment.get('public_key_sha256','')) != expected_sha: return None, 'external_url_tunnel_identity_mismatch'
    addons,err=_supervisor_api_json('/addons','GET')
    if err: return None, 'external_url_supervisor_addons_unavailable'
    if isinstance(addons,dict):
        items=addons.get('addons') if isinstance(addons.get('addons'),list) else []
    elif isinstance(addons,list):
        items=addons
    else:
        return None, 'external_url_supervisor_addons_unavailable'
    slug=''
    for item in items:
        if not isinstance(item,dict): continue
        candidate=str(item.get('slug','') or '')
        name=str(item.get('name','') or '')
        if candidate.endswith('smart_pro_tunnel') or name == 'Smart Pro Tunnel': slug=candidate; break
    if not slug: return None, 'external_url_tunnel_addon_not_found'
    info,err=_supervisor_api_json(f'/addons/{slug}/info','GET')
    if err or not isinstance(info,dict): return None, 'external_url_tunnel_info_unavailable'
    version=str(info.get('version','') or '')
    if not version or tuple(int(x) for x in re.findall(r'\d+',version)[:3]) < (0,1,6): return None, 'external_url_tunnel_version_too_old'
    core,err=_supervisor_api_json('/core/info','GET')
    if err or not isinstance(core,dict): return None, 'external_url_core_info_unavailable'
    core_host=str(core.get('ip_address','') or '').strip()
    try:
        core_ip=ipaddress.ip_address(core_host)
    except ValueError:
        return None, 'external_url_core_target_invalid'
    if core_ip.version != 4 or not core_ip.is_private or core_ip.is_loopback or core_ip.is_multicast or core_ip.is_unspecified:
        return None, 'external_url_core_target_invalid'
    try:
        core_port=int(core.get('port',8123) or 8123)
    except (TypeError,ValueError):
        return None, 'external_url_core_target_invalid'
    if core_port < 1 or core_port > 65535: return None, 'external_url_core_target_invalid'
    core_ssl=bool(core.get('ssl',False))
    desired={'enabled':True,'gateway_endpoint':endpoint,'gateway_public_key':gkey,'peer_address':peer,'private_proxy_enabled':True,'home_assistant_target_host':str(core_ip),'home_assistant_target_port':core_port,'home_assistant_target_ssl':core_ssl}
    _,err=_supervisor_api_json(f'/addons/{slug}/options','POST',{'options':desired})
    if err: return None, 'external_url_tunnel_options_failed'
    action='restart' if str(info.get('state','') or '') == 'started' else 'start'
    _,err=_supervisor_api_json(f'/addons/{slug}/{action}','POST')
    if err: return None, 'external_url_tunnel_start_failed'
    return {'slug_hint':slug[-24:],'peer_address':peer,'gateway_endpoint_configured':True,'private_proxy_enabled':True,'home_assistant_target_source':'supervisor_core_info'}, ''

def _control_plane_execute_command(command):
    state = load_control_plane_state()
    if not isinstance(command, dict):
        return False
    command_id = str(command.get('command_id', '') or '').strip().lower()
    nonce = str(command.get('nonce', '') or '').strip().lower()
    key_id = str(command.get('key_id', '') or '').strip().lower()
    kind = str(command.get('kind', '') or '').strip()
    capability = str(command.get('capability', '') or '').strip()
    installation_id = str(command.get('installation_id', '') or '').strip()
    signature = str(command.get('signature', '') or '').strip().lower()
    issued_at = int(command.get('issued_at', 0) or 0)
    expires_at = int(command.get('expires_at', 0) or 0)
    now = int(time.time())

    # Idempotent replay handling: only the exact same command-id + nonce may
    # reuse the original acknowledgement. Reusing a command ID with a different
    # nonce is rejected and never executed.
    reject = None
    for item in state.get('seen') or []:
        if isinstance(item, dict) and str(item.get('command_id', '') or '') == command_id:
            if str(item.get('nonce', '') or '') == nonce:
                ack = item.get('ack') if isinstance(item.get('ack'), dict) else None
                if ack:
                    state['last_ack'] = ack
                    save_control_plane_state(state)
                    return True
            reject = ('command_id_reuse', 'Το command ID έχει ήδη χρησιμοποιηθεί με διαφορετικό nonce.')
            break

    if not re.fullmatch(r'[0-9a-f]{32}', command_id): reject = ('invalid_command_id', 'Μη έγκυρο command ID.')
    elif not re.fullmatch(r'[0-9a-f]{32}', nonce): reject = ('invalid_nonce', 'Μη έγκυρο nonce.')
    elif not re.fullmatch(r'[0-9a-f]{16}', key_id): reject = ('invalid_key_id', 'Μη έγκυρο key ID.')
    elif installation_id != paired_installation_id(): reject = ('installation_mismatch', 'Το command δεν ανήκει σε αυτή την εγκατάσταση.')
    elif key_id != str(state.get('key_id', '') or ''): reject = ('key_mismatch', 'Το command υπογράφηκε με διαφορετικό key.')
    elif (kind, capability) not in CONTROL_PLANE_ALLOWED_CAPABILITIES:
        reject = ('capability_denied', 'Η capability δεν επιτρέπεται από το ενεργό Control Plane authority manifest.')
    elif issued_at <= 0 or expires_at <= issued_at: reject = ('invalid_ttl', 'Μη έγκυρο command TTL.')
    elif expires_at - issued_at > CONTROL_PLANE_MAX_TTL_SECONDS: reject = ('ttl_too_long', 'Το command TTL υπερβαίνει το επιτρεπτό όριο.')
    elif issued_at > now + CONTROL_PLANE_CLOCK_SKEW_SECONDS: reject = ('issued_in_future', 'Το command έχει μελλοντικό timestamp.')
    elif now >= expires_at: reject = ('expired', 'Το command έχει λήξει.')
    elif any(isinstance(item, dict) and str(item.get('nonce', '') or '') == nonce for item in state.get('seen') or []): reject = ('nonce_replay', 'Το nonce έχει ήδη χρησιμοποιηθεί.')

    secret = b''
    if reject is None:
        try:
            secret = base64.b64decode(str(state.get('secret_b64', '') or '').encode('ascii'), validate=True)
        except Exception:
            reject = ('key_unavailable', 'Δεν υπάρχει έγκυρο local signing key.')
    if reject is None and len(secret) != 32:
        reject = ('key_unavailable', 'Δεν υπάρχει έγκυρο local signing key.')
    if reject is None:
        expected = hmac.new(secret, _control_plane_canonical(_control_plane_unsigned_command(command)).encode('utf-8'), hashlib.sha256).hexdigest()
        if not re.fullmatch(r'[0-9a-f]{64}', signature) or not hmac.compare_digest(expected, signature):
            reject = ('signature_invalid', 'Η υπογραφή του command δεν επαληθεύτηκε.')

    if reject is not None:
        ack = _control_plane_ack(command, 'rejected' if reject[0] != 'expired' else 'expired', reject[0], reject[1])
        _control_plane_store_ack(state, command, ack)
        print(f'[CONTROL] Command rejected: {reject[0]}', flush=True)
        return True

    payload = command.get('payload') if isinstance(command.get('payload'), dict) else {}
    if kind == 'probe' and capability == 'control_plane_probe':
        if str(payload.get('probe', '') or '') != 'secure-channel-foundation':
            ack = _control_plane_ack(command, 'rejected', 'probe_payload_invalid', 'Μη έγκυρο probe payload.')
        else:
            ack = _control_plane_ack(command, 'applied', 'probe_ok', 'Το ασφαλές command channel επαληθεύτηκε χωρίς αλλαγή ρυθμίσεων.')
    elif kind == 'settings_update' and capability == 'guardian_settings_manage':
        if str(payload.get('family', '') or '') != 'guardian_core':
            ack = _control_plane_ack(command, 'rejected', 'guardian_family_invalid', 'Μη έγκυρη οικογένεια ρυθμίσεων Guardian.')
        else:
            desired, desired_error = _control_plane_guardian_values(payload.get('values'))
            expected, expected_error = _control_plane_guardian_values(payload.get('expected'))
            if desired_error:
                ack = _control_plane_ack(command, 'rejected', desired_error, 'Οι νέες ρυθμίσεις Guardian δεν πέρασαν validation.')
            elif expected_error:
                ack = _control_plane_ack(command, 'rejected', expected_error, 'Το expected Guardian baseline δεν πέρασε validation.')
            else:
                current = _control_plane_guardian_current()
                if not _control_plane_guardian_equal(current, expected):
                    ack = _control_plane_ack(command, 'rejected', 'guardian_state_conflict', 'Οι local ρυθμίσεις Guardian άλλαξαν μετά το preview. Δεν εφαρμόστηκε καμία αλλαγή.')
                elif _control_plane_guardian_equal(current, desired):
                    ack = _control_plane_ack(command, 'applied', 'guardian_settings_noop', 'Οι ρυθμίσεις Guardian ήταν ήδη ίδιες με την επιθυμητή κατάσταση.')
                else:
                    saved = save_tech_settings(desired, merge=True)
                    readback = {
                        'check_interval_min': round(float(saved.get('check_interval_min', 5.0) or 5.0), 2),
                        'alert_delay_min': round(float(saved.get('alert_delay_min', 15.0) or 15.0), 2),
                        'battery_limit': round(float(saved.get('battery_limit', 15.0) or 15.0), 2),
                    }
                    if not _control_plane_guardian_equal(readback, desired):
                        ack = _control_plane_ack(command, 'failed', 'guardian_readback_failed', 'Η αποθήκευση δεν επιβεβαιώθηκε από το local read-back.')
                    else:
                        _guardian_refresh_status(saved)
                        ack = _control_plane_ack(command, 'applied', 'guardian_settings_applied', 'Οι ελεγχόμενες ρυθμίσεις Guardian εφαρμόστηκαν και επιβεβαιώθηκαν τοπικά.')
    elif kind == 'settings_update' and capability == 'guardian_scope_manage':
        if str(payload.get('family', '') or '') != 'guardian_scope':
            ack = _control_plane_ack(command, 'rejected', 'guardian_scope_family_invalid', 'Μη έγκυρη οικογένεια Guardian Monitoring Scope.')
        else:
            desired, desired_error = _control_plane_guardian_scope_values(payload.get('values'), require_nonempty=True)
            expected, expected_error = _control_plane_guardian_scope_values(payload.get('expected'), require_nonempty=False)
            if desired_error:
                ack = _control_plane_ack(command, 'rejected', desired_error, 'Το νέο Guardian Monitoring Scope δεν πέρασε validation.')
            elif expected_error:
                ack = _control_plane_ack(command, 'rejected', expected_error, 'Το expected Guardian Monitoring Scope δεν πέρασε validation.')
            else:
                current = _control_plane_guardian_scope_current()
                if not _control_plane_guardian_scope_equal(current, expected):
                    ack = _control_plane_ack(command, 'rejected', 'guardian_scope_conflict', 'Το local Guardian Monitoring Scope άλλαξε μετά το preview. Δεν εφαρμόστηκε καμία αλλαγή.')
                elif _control_plane_guardian_scope_equal(current, desired):
                    ack = _control_plane_ack(command, 'applied', 'guardian_scope_noop', 'Το Guardian Monitoring Scope ήταν ήδη ίδιο με την επιθυμητή κατάσταση.')
                else:
                    saved = save_tech_settings(_control_plane_guardian_scope_settings(desired), merge=True)
                    readback = {
                        'domains': [
                            domain for domain, setting_key in _CONTROL_PLANE_GUARDIAN_SCOPE_MAP
                            if bool(saved.get(setting_key, DEFAULT_TECH_SETTINGS.get(setting_key, False)))
                        ]
                    }
                    if not _control_plane_guardian_scope_equal(readback, desired):
                        ack = _control_plane_ack(command, 'failed', 'guardian_scope_readback_failed', 'Η αλλαγή Monitoring Scope δεν επιβεβαιώθηκε από το local read-back.')
                    else:
                        _guardian_refresh_status(saved)
                        ack = _control_plane_ack(command, 'applied', 'guardian_scope_applied', 'Το Guardian Monitoring Scope εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
    elif kind == 'settings_update' and capability == 'guardian_master_manage':
        if str(payload.get('family', '') or '') != 'guardian_master':
            ack = _control_plane_ack(command, 'rejected', 'guardian_master_family_invalid', 'Μη έγκυρη οικογένεια Guardian master.')
        else:
            expected = payload.get('expected') if isinstance(payload.get('expected'), dict) else None
            desired = payload.get('values') if isinstance(payload.get('values'), dict) else None
            if expected is None or set(expected.keys()) != {'enabled'} or desired is None or set(desired.keys()) != {'enabled'}:
                ack = _control_plane_ack(command, 'rejected', 'guardian_master_payload_invalid', 'Μη έγκυρο Guardian master payload.')
            elif not isinstance(expected.get('enabled'), bool) or not isinstance(desired.get('enabled'), bool):
                ack = _control_plane_ack(command, 'rejected', 'guardian_master_value_invalid', 'Ο Guardian master απαιτεί boolean state.')
            else:
                saved_now = load_tech_settings()
                current_enabled = bool(saved_now.get('watchdog_enabled', True))
                desired_enabled = bool(desired.get('enabled'))
                if current_enabled != bool(expected.get('enabled')):
                    ack = _control_plane_ack(command, 'rejected', 'guardian_master_state_conflict', 'Ο local Guardian master άλλαξε μετά το preview. Δεν εφαρμόστηκε αλλαγή.')
                elif current_enabled == desired_enabled:
                    ack = _control_plane_ack(command, 'applied', 'guardian_master_noop', 'Ο Guardian master ήταν ήδη στην επιθυμητή κατάσταση.')
                else:
                    test_active, test_status = _control_plane_guardian_test_active()
                    runtime = _guardian_runtime_summary(saved_now)
                    if not desired_enabled and test_active:
                        ack = _control_plane_ack(command, 'rejected', 'guardian_master_test_active', 'Η απενεργοποίηση μπλοκαρίστηκε επειδή εκτελείται Safe Guardian Test.')
                    elif not desired_enabled and int(runtime.get('offline_count', 0) or 0) > 0:
                        ack = _control_plane_ack(command, 'rejected', 'guardian_master_active_incident', 'Η απενεργοποίηση μπλοκαρίστηκε επειδή υπάρχει πραγματικό offline Guardian incident.')
                    elif desired_enabled and not get_monitored_domains(saved_now):
                        ack = _control_plane_ack(command, 'rejected', 'guardian_master_scope_empty', 'Η ενεργοποίηση απαιτεί τουλάχιστον μία κατηγορία Monitoring Scope.')
                    else:
                        saved = save_tech_settings({'watchdog_enabled': desired_enabled}, merge=True)
                        readback = bool(saved.get('watchdog_enabled', True))
                        if readback != desired_enabled:
                            ack = _control_plane_ack(command, 'failed', 'guardian_master_readback_failed', 'Ο Guardian master δεν επιβεβαιώθηκε από το local read-back.')
                        else:
                            _guardian_refresh_status(saved, enabled=readback)
                            ack = _control_plane_ack(command, 'applied', 'guardian_master_applied', 'Ο Guardian master εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
                            ack['details'] = {
                                'enabled': readback,
                                'offline_incidents': int(runtime.get('offline_count', 0) or 0),
                                'safe_test_status': test_status[:32],
                            }
    elif kind == 'settings_update' and capability == 'guardian_safe_test_policy_manage':
        if str(payload.get('family', '') or '') != 'guardian_safe_test_policy':
            ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_policy_family_invalid', 'Μη έγκυρη οικογένεια Safe Guardian Test policy.')
        else:
            desired, desired_error = _control_plane_guardian_safe_test_policy_values(payload.get('values'))
            expected, expected_error = _control_plane_guardian_safe_test_policy_values(payload.get('expected'))
            if desired_error:
                ack = _control_plane_ack(command, 'rejected', desired_error, 'Η νέα Safe Guardian Test policy δεν πέρασε validation.')
            elif expected_error:
                ack = _control_plane_ack(command, 'rejected', expected_error, 'Η expected Safe Guardian Test policy δεν πέρασε validation.')
            else:
                current = _control_plane_guardian_safe_test_policy_current()
                if not _control_plane_guardian_safe_test_policy_equal(current, expected):
                    ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_policy_conflict', 'Η local Safe Guardian Test policy άλλαξε μετά το preview. Δεν εφαρμόστηκε αλλαγή.')
                elif _control_plane_guardian_safe_test_policy_equal(current, desired):
                    ack = _control_plane_ack(command, 'applied', 'guardian_safe_test_policy_noop', 'Η Safe Guardian Test policy ήταν ήδη ίδια με την επιθυμητή κατάσταση.')
                else:
                    test_active, _test_status = _control_plane_guardian_test_active()
                    saved_now = load_tech_settings()
                    if test_active:
                        ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_policy_test_active', 'Η policy δεν αλλάζει όσο εκτελείται Safe Guardian Test.')
                    elif bool(desired.get('send_email')) and not bool(str(saved_now.get('email_password', '') or '').strip()):
                        ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_policy_email_unavailable', 'Το test-email policy απαιτεί ήδη ρυθμισμένο local SMTP credential.')
                    else:
                        saved = save_tech_settings(_control_plane_guardian_safe_test_policy_settings(desired), merge=True)
                        readback = {
                            'delay_sec': int(saved.get('watchdog_test_delay_sec', 10) or 10),
                            'clear_sec': int(saved.get('watchdog_test_clear_sec', 30) or 30),
                            'send_email': bool(saved.get('watchdog_test_send_email', False)),
                        }
                        if not _control_plane_guardian_safe_test_policy_equal(readback, desired):
                            ack = _control_plane_ack(command, 'failed', 'guardian_safe_test_policy_readback_failed', 'Η Safe Guardian Test policy δεν επιβεβαιώθηκε από το local read-back.')
                        else:
                            ack = _control_plane_ack(command, 'applied', 'guardian_safe_test_policy_applied', 'Η Safe Guardian Test policy εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
    elif kind == 'settings_update' and capability == 'vacation_policy_manage':
        if str(payload.get('family', '') or '') != 'vacation_policy':
            ack = _control_plane_ack(command, 'rejected', 'vacation_policy_family_invalid', 'Μη έγκυρη οικογένεια Vacation Mode policy.')
        else:
            desired, desired_error = _control_plane_vacation_policy_values(payload.get('values'))
            expected, expected_error = _control_plane_vacation_policy_values(payload.get('expected'))
            if desired_error:
                ack = _control_plane_ack(command, 'rejected', desired_error, 'Η νέα Vacation Mode policy δεν πέρασε validation.')
            elif expected_error:
                ack = _control_plane_ack(command, 'rejected', expected_error, 'Το expected Vacation Mode baseline δεν πέρασε validation.')
            else:
                current = _control_plane_vacation_policy_current()
                if not _control_plane_vacation_policy_equal(current, expected):
                    ack = _control_plane_ack(command, 'rejected', 'vacation_policy_state_conflict', 'Η local Vacation Mode policy άλλαξε μετά το preview. Δεν εφαρμόστηκε καμία αλλαγή.')
                elif _control_plane_vacation_policy_equal(current, desired):
                    ack = _control_plane_ack(command, 'applied', 'vacation_policy_noop', 'Η Vacation Mode policy ήταν ήδη ίδια με την επιθυμητή κατάσταση.')
                else:
                    settings_now = load_tech_settings()
                    counts = _control_plane_vacation_selection_counts(settings_now)
                    if bool(settings_now.get('auto_vacation_enabled', True)) and counts['total'] > 0:
                        helper = _control_plane_vacation_helper_state()
                        if not helper['available']:
                            ack = _control_plane_ack(command, 'rejected', 'vacation_runtime_guard_unavailable', 'Δεν ήταν δυνατό να επαληθευτεί με ασφάλεια η runtime κατάσταση Vacation Mode.')
                        elif helper['active']:
                            ack = _control_plane_ack(command, 'rejected', 'vacation_helper_active', 'Η Vacation Mode policy δεν αλλάζει απομακρυσμένα ενώ η πραγματική Vacation εκτέλεση είναι ενεργή στο Home Assistant.')
                        else:
                            saved = save_tech_settings(_control_plane_vacation_policy_settings(desired), merge=True)
                            readback = {
                                'start': str(saved.get('vacation_start', '20:00') or '20:00')[:5],
                                'end': str(saved.get('vacation_end', '23:59') or '23:59')[:5],
                                'cover_open_time': str(saved.get('cover_open_time', '08:00') or '08:00')[:5],
                                'cover_close_time': str(saved.get('cover_close_time', '20:00') or '20:00')[:5],
                            }
                            if not _control_plane_vacation_policy_equal(readback, desired):
                                ack = _control_plane_ack(command, 'failed', 'vacation_policy_readback_failed', 'Η Vacation Mode policy δεν επιβεβαιώθηκε από το local read-back.')
                            else:
                                ack = _control_plane_ack(command, 'applied', 'vacation_policy_applied', 'Η Vacation Mode policy εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
                    else:
                        saved = save_tech_settings(_control_plane_vacation_policy_settings(desired), merge=True)
                        readback = {
                            'start': str(saved.get('vacation_start', '20:00') or '20:00')[:5],
                            'end': str(saved.get('vacation_end', '23:59') or '23:59')[:5],
                            'cover_open_time': str(saved.get('cover_open_time', '08:00') or '08:00')[:5],
                            'cover_close_time': str(saved.get('cover_close_time', '20:00') or '20:00')[:5],
                        }
                        if not _control_plane_vacation_policy_equal(readback, desired):
                            ack = _control_plane_ack(command, 'failed', 'vacation_policy_readback_failed', 'Η Vacation Mode policy δεν επιβεβαιώθηκε από το local read-back.')
                        else:
                            ack = _control_plane_ack(command, 'applied', 'vacation_policy_applied', 'Η Vacation Mode policy εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
    elif kind == 'settings_update' and capability == 'vacation_master_manage':
        if str(payload.get('family', '') or '') != 'vacation_master':
            ack = _control_plane_ack(command, 'rejected', 'vacation_master_family_invalid', 'Μη έγκυρη οικογένεια Vacation Mode master.')
        else:
            expected = payload.get('expected') if isinstance(payload.get('expected'), dict) else None
            desired = payload.get('values') if isinstance(payload.get('values'), dict) else None
            if expected is None or set(expected.keys()) != {'enabled'} or desired is None or set(desired.keys()) != {'enabled'}:
                ack = _control_plane_ack(command, 'rejected', 'vacation_master_payload_invalid', 'Μη έγκυρο Vacation Mode master payload.')
            elif not isinstance(expected.get('enabled'), bool) or not isinstance(desired.get('enabled'), bool):
                ack = _control_plane_ack(command, 'rejected', 'vacation_master_value_invalid', 'Το Vacation Mode master απαιτεί boolean state.')
            else:
                settings_now = load_tech_settings()
                current_enabled = bool(settings_now.get('auto_vacation_enabled', True))
                desired_enabled = bool(desired.get('enabled'))
                if current_enabled != bool(expected.get('enabled')):
                    ack = _control_plane_ack(command, 'rejected', 'vacation_master_state_conflict', 'Ο local Vacation Mode master άλλαξε μετά το preview. Δεν εφαρμόστηκε αλλαγή.')
                elif current_enabled == desired_enabled:
                    ack = _control_plane_ack(command, 'applied', 'vacation_master_noop', 'Ο Vacation Mode master ήταν ήδη στην επιθυμητή κατάσταση.')
                else:
                    counts = _control_plane_vacation_selection_counts(settings_now)
                    if desired_enabled and counts['total'] > 0:
                        helper = _control_plane_vacation_helper_state()
                        if not helper['available']:
                            ack = _control_plane_ack(command, 'rejected', 'vacation_runtime_guard_unavailable', 'Δεν ήταν δυνατό να επαληθευτεί με ασφάλεια η runtime κατάσταση Vacation Mode.')
                        elif not helper['present']:
                            ack = _control_plane_ack(command, 'rejected', 'vacation_helper_missing', 'Η remote ενεργοποίηση απαιτεί διαθέσιμο Home Assistant Vacation helper όταν υπάρχουν επιλεγμένες συσκευές.')
                        elif helper['active']:
                            ack = _control_plane_ack(command, 'rejected', 'vacation_helper_active', 'Η remote ενεργοποίηση μπλοκαρίστηκε επειδή η πραγματική Vacation εκτέλεση είναι ήδη ενεργή στο Home Assistant.')
                        else:
                            saved = save_tech_settings({'auto_vacation_enabled': True}, merge=True)
                            readback = bool(saved.get('auto_vacation_enabled', True))
                            if readback is not True:
                                ack = _control_plane_ack(command, 'failed', 'vacation_master_readback_failed', 'Ο Vacation Mode master δεν επιβεβαιώθηκε από το local read-back.')
                            else:
                                ack = _control_plane_ack(command, 'applied', 'vacation_master_applied', 'Ο Vacation Mode master εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
                                ack['details'] = {'enabled': True, 'selection_count': counts['total']}
                    else:
                        saved = save_tech_settings({'auto_vacation_enabled': desired_enabled}, merge=True)
                        readback = bool(saved.get('auto_vacation_enabled', True))
                        if readback != desired_enabled:
                            ack = _control_plane_ack(command, 'failed', 'vacation_master_readback_failed', 'Ο Vacation Mode master δεν επιβεβαιώθηκε από το local read-back.')
                        else:
                            ack = _control_plane_ack(command, 'applied', 'vacation_master_applied', 'Ο Vacation Mode master εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
                            ack['details'] = {'enabled': readback, 'selection_count': counts['total']}
    elif kind == 'settings_update' and capability == 'smart_updates_policy_manage':
        if str(payload.get('family', '') or '') != 'smart_updates_policy':
            ack = _control_plane_ack(command, 'rejected', 'smart_updates_family_invalid', 'Μη έγκυρη οικογένεια Smart Updates policy.')
        else:
            desired, desired_error = _control_plane_smart_updates_values(payload.get('values'), require_targets=True)
            expected, expected_error = _control_plane_smart_updates_values(payload.get('expected'), require_targets=False)
            if desired_error:
                ack = _control_plane_ack(command, 'rejected', desired_error, 'Η νέα Smart Updates policy δεν πέρασε validation.')
            elif expected_error:
                ack = _control_plane_ack(command, 'rejected', expected_error, 'Το expected Smart Updates baseline δεν πέρασε validation.')
            else:
                current = _control_plane_smart_updates_current()
                if not _control_plane_smart_updates_equal(current, expected):
                    ack = _control_plane_ack(command, 'rejected', 'smart_updates_state_conflict', 'Η local Smart Updates policy άλλαξε μετά το preview. Δεν εφαρμόστηκε καμία αλλαγή.')
                elif _control_plane_smart_updates_equal(current, desired):
                    ack = _control_plane_ack(command, 'applied', 'smart_updates_policy_noop', 'Η Smart Updates policy ήταν ήδη ίδια με την επιθυμητή κατάσταση.')
                else:
                    saved = save_tech_settings(_control_plane_smart_updates_settings(desired), merge=True)
                    readback = {
                        'targets': [
                            name for name, setting_key in _CONTROL_PLANE_SMART_UPDATE_TARGET_MAP
                            if bool(saved.get(setting_key, DEFAULT_TECH_SETTINGS.get(setting_key, False)))
                        ],
                        'wait_days': int(saved.get('update_wait_days', 3) or 3),
                        'backup_wait_min': int(saved.get('update_backup_wait_min', 15) or 15),
                        'evaluation_min': int(saved.get('update_eval_min', 20) or 20),
                        'rollback_offline_count': int(saved.get('update_rollback_offline_count', 2) or 2),
                        'notify_only': bool(saved.get('update_notify_only', False)),
                    }
                    if not _control_plane_smart_updates_equal(readback, desired):
                        ack = _control_plane_ack(command, 'failed', 'smart_updates_readback_failed', 'Η Smart Updates policy δεν επιβεβαιώθηκε από το local read-back.')
                    else:
                        ack = _control_plane_ack(command, 'applied', 'smart_updates_policy_applied', 'Η Smart Updates policy εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
    elif kind == 'settings_update' and capability == 'smart_updates_master_manage':
        if str(payload.get('family', '') or '') != 'smart_updates_master':
            ack = _control_plane_ack(command, 'rejected', 'smart_updates_master_family_invalid', 'Μη έγκυρη οικογένεια Smart Updates master.')
        else:
            expected = payload.get('expected') if isinstance(payload.get('expected'), dict) else None
            desired = payload.get('values') if isinstance(payload.get('values'), dict) else None
            if expected is None or set(expected.keys()) != {'enabled'} or desired is None or set(desired.keys()) != {'enabled'}:
                ack = _control_plane_ack(command, 'rejected', 'smart_updates_master_payload_invalid', 'Μη έγκυρο Smart Updates master payload.')
            elif not isinstance(expected.get('enabled'), bool) or not isinstance(desired.get('enabled'), bool):
                ack = _control_plane_ack(command, 'rejected', 'smart_updates_master_value_invalid', 'Το Smart Updates master απαιτεί boolean state.')
            else:
                saved_now = load_tech_settings()
                current_enabled = bool(saved_now.get('auto_update_enabled', False))
                if current_enabled != bool(expected.get('enabled')):
                    ack = _control_plane_ack(command, 'rejected', 'smart_updates_master_state_conflict', 'Ο local Smart Updates master άλλαξε μετά το preview. Δεν εφαρμόστηκε αλλαγή.')
                elif current_enabled == bool(desired.get('enabled')):
                    ack = _control_plane_ack(command, 'applied', 'smart_updates_master_noop', 'Ο Smart Updates master ήταν ήδη στην επιθυμητή κατάσταση.')
                elif bool(desired.get('enabled')) and not bool(saved_now.get('update_notify_only', False)):
                    ack = _control_plane_ack(command, 'rejected', 'smart_updates_master_requires_notify_only', 'Η remote ενεργοποίηση επιτρέπεται μόνο όταν το Notify-only είναι ήδη ενεργό.')
                else:
                    saved = save_tech_settings({'auto_update_enabled': bool(desired.get('enabled'))}, merge=True)
                    readback = bool(saved.get('auto_update_enabled', False))
                    if readback != bool(desired.get('enabled')):
                        ack = _control_plane_ack(command, 'failed', 'smart_updates_master_readback_failed', 'Ο Smart Updates master δεν επιβεβαιώθηκε από το local read-back.')
                    else:
                        ack = _control_plane_ack(command, 'applied', 'smart_updates_master_applied', 'Ο Smart Updates master εφαρμόστηκε και επιβεβαιώθηκε τοπικά.')
                        ack['details'] = {'enabled': readback, 'notify_only_guard': bool(saved.get('update_notify_only', False))}
    elif kind == 'action' and capability == 'smart_updates_safe_test_run':
        if set(payload.keys()) != {'family', 'action', 'scenario'} or str(payload.get('family', '') or '') != 'smart_updates_safe_test' or str(payload.get('action', '') or '') != 'run':
            ack = _control_plane_ack(command, 'rejected', 'smart_updates_safe_test_payload_invalid', 'Μη έγκυρο Safe Smart Updates Test payload.')
        else:
            scenario = str(payload.get('scenario', '') or '').strip()
            if scenario not in SMART_UPDATES_TEST_SCENARIOS:
                ack = _control_plane_ack(command, 'rejected', 'smart_updates_safe_test_scenario_invalid', 'Μη έγκυρο Safe Smart Updates Test scenario.')
            else:
                try:
                    result = run_smart_updates_safe_test({'scenario': scenario})
                    ack = _control_plane_ack(command, 'applied', 'smart_updates_safe_test_completed', 'Η ασφαλής προσομοίωση Smart Updates ολοκληρώθηκε χωρίς πραγματικές ενέργειες.')
                    ack['details'] = {
                        'scenario': str(result.get('scenario', '') or '')[:32],
                        'status': str(result.get('status', '') or '')[:32],
                        'real_actions_executed': bool(result.get('real_actions_executed', False)),
                    }
                except ValueError as error:
                    ack = _control_plane_ack(command, 'rejected', 'smart_updates_safe_test_rejected', str(error)[:180])
                except Exception:
                    ack = _control_plane_ack(command, 'failed', 'smart_updates_safe_test_failed', 'Η ασφαλής προσομοίωση Smart Updates απέτυχε.')
    elif kind == 'action' and capability == 'guardian_safe_test_start':
        if set(payload.keys()) != {'family', 'action'} or str(payload.get('family', '') or '') != 'guardian_safe_test' or str(payload.get('action', '') or '') != 'start':
            ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_payload_invalid', 'Μη έγκυρο Safe Guardian Test start payload.')
        else:
            try:
                status = start_watchdog_test({})
                ack = _control_plane_ack(command, 'applied', 'guardian_safe_test_started', 'Η ασφαλής δοκιμή Φρουρού ξεκίνησε με την υπάρχουσα local test policy.')
                ack['details'] = {
                    'status': str(status.get('status', '') or '')[:32],
                    'delay_seconds': int(status.get('delay_seconds', 0) or 0),
                    'clear_seconds': int(status.get('clear_seconds', 0) or 0),
                    'send_email': bool(status.get('send_email', False)),
                }
            except ValueError as error:
                ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_start_rejected', str(error)[:180])
            except Exception:
                ack = _control_plane_ack(command, 'failed', 'guardian_safe_test_start_failed', 'Η ασφαλής δοκιμή Φρουρού δεν μπόρεσε να ξεκινήσει.')
    elif kind == 'action' and capability == 'guardian_safe_test_cancel':
        if set(payload.keys()) != {'family', 'action'} or str(payload.get('family', '') or '') != 'guardian_safe_test' or str(payload.get('action', '') or '') != 'cancel':
            ack = _control_plane_ack(command, 'rejected', 'guardian_safe_test_cancel_payload_invalid', 'Μη έγκυρο Safe Guardian Test cancel payload.')
        else:
            status = cancel_watchdog_test()
            ack = _control_plane_ack(command, 'applied', 'guardian_safe_test_cancelled', 'Η ασφαλής δοκιμή Φρουρού καθαρίστηκε τοπικά.')
            ack['details'] = {'status': str(status.get('status', '') or '')[:32]}
    elif kind == 'action' and capability == 'guardian_email_test':
        if set(payload.keys()) != {'family', 'action'} or str(payload.get('family', '') or '') != 'guardian_notifications' or str(payload.get('action', '') or '') != 'email_test':
            ack = _control_plane_ack(command, 'rejected', 'guardian_email_test_payload_invalid', 'Μη έγκυρο technical email test payload.')
        else:
            tech_config = load_tech_settings()
            if not str(tech_config.get('email_password', '') or ''):
                ack = _control_plane_ack(command, 'rejected', 'guardian_email_not_configured', 'Δεν υπάρχει αποθηκευμένο technical alert email credential.')
            else:
                result = send_email_alert(
                    'Δοκιμή τεχνικών ειδοποιήσεων',
                    'Αυτό είναι δοκιμαστικό email από το Admin Portal μέσω του ασφαλούς Smart Pro System command channel. Η αποστολή SMTP λειτουργεί κανονικά.',
                    tech_config,
                )
                if result.get('success'):
                    ack = _control_plane_ack(command, 'applied', 'guardian_email_test_sent', 'Το δοκιμαστικό technical alert email στάλθηκε επιτυχώς.')
                else:
                    ack = _control_plane_ack(command, 'failed', 'guardian_email_test_failed', 'Η αποστολή του δοκιμαστικού technical alert email απέτυχε.')
    elif kind == 'action' and capability == 'external_url_tunnel_configure_start':
        result, error = _external_url_tunnel_supervisor_apply(payload)
        if error:
            ack = _control_plane_ack(command, 'failed', error, 'Η ελεγχόμενη ρύθμιση/εκκίνηση του Smart Pro Tunnel απέτυχε fail-closed.')
        else:
            ack = _control_plane_ack(command, 'applied', 'external_url_tunnel_runtime_applied', 'Το Smart Pro Tunnel ρυθμίστηκε και ξεκίνησε μέσω του ασφαλούς Control Plane.')
    else:
        ack = _control_plane_ack(command, 'rejected', 'capability_denied', 'Η capability δεν επιτρέπεται σε αυτό το milestone.')
    _control_plane_store_ack(state, command, ack)
    print(f"[CONTROL] Command {command_id} -> {ack['status']} / {ack['result_code']}", flush=True)
    return True


def _portal_maybe_process_control_plane(response):
    control = response.get('control_plane') if isinstance(response, dict) else None
    if not isinstance(control, dict) or str(control.get('contract', '') or '') != CONTROL_PLANE_CONTRACT_ID:
        return False
    changed = _control_plane_apply_provision(control.get('provision'))
    if isinstance(control.get('command'), dict):
        changed = _control_plane_execute_command(control.get('command')) or changed
    return changed


def _portal_heartbeat_payload(home_assistant_snapshot=None, diagnostic_check_ack=None):
    payload = {
        'addon_version': ADDON_VERSION,
        'device_name': 'Home Assistant',
        'guardian': guardian_status_snapshot(),
        'technician_center': technician_center_portal_snapshot(),
        'command_channel': command_channel_snapshot(),
        'managed_backup': managed_backup_agent_heartbeat_snapshot(),
        'external_access': external_access_agent_heartbeat_snapshot(),
        'home_assistant': home_assistant_snapshot if isinstance(home_assistant_snapshot, dict) else home_assistant_diagnostics_snapshot(),
    }
    if isinstance(diagnostic_check_ack, dict) and diagnostic_check_ack.get('request_id'):
        payload['diagnostic_check_ack'] = diagnostic_check_ack
    return payload


def _portal_maybe_run_fresh_diagnostic_check(response, token):
    """Honor one bounded Portal fresh-diagnostic request and acknowledge it.

    The request is transported only on the existing authenticated heartbeat.
    The forced collection is read-only and local to Home Assistant. The second
    heartbeat carries the fresh aggregate snapshot plus the matching request ID.
    """
    request = response.get('diagnostic_check') if isinstance(response, dict) else None
    if not isinstance(request, dict) or not request.get('requested'):
        return response
    request_id = str(request.get('request_id', '') or '').strip()
    contract = str(request.get('contract', '') or '').strip()
    requested_at = int(request.get('requested_at', 0) or 0)
    expires_at = int(request.get('expires_at', 0) or 0)
    now = int(time.time())
    if not request_id or contract != 'smart-pro-fresh-diagnostic-check-v1':
        return response
    if requested_at <= 0 or (expires_at > 0 and now > expires_at):
        return response

    fresh_ha = home_assistant_diagnostics_snapshot(force=True)
    collected_at = int(time.time())
    ack = {
        'request_id': request_id,
        'collected_at': collected_at,
        'home_assistant_collected_at': int(fresh_ha.get('collected_at', 0) or 0),
        'forced_home_assistant_refresh': True,
        'contract': 'smart-pro-fresh-diagnostic-check-v1',
    }
    return portal_api_request('heartbeat', _portal_heartbeat_payload(fresh_ha, ack), token=token)


def send_portal_heartbeat():
    connection = load_portal_connection()
    token = str(connection.get('installation_token', '')).strip()
    if not token:
        return False
    try:
        response = portal_api_request('heartbeat', _portal_heartbeat_payload(), token=token)
        response = _portal_maybe_run_fresh_diagnostic_check(response, token)
        managed_changed = _portal_maybe_process_managed_backup(response)
        external_portal_state = _portal_maybe_process_external_access(response)
        control_changed = _portal_maybe_process_control_plane(response)
        if managed_changed or control_changed:
            # One immediate acknowledgement heartbeat publishes Managed Backup
            # local-job results and Control Plane acknowledgements without waiting
            # for the next 30-second cycle. The second heartbeat never creates a
            # second local backup because Managed Backup job execution is idempotent.
            response = portal_api_request('heartbeat', _portal_heartbeat_payload(), token=token)
            _portal_maybe_process_managed_backup(response)
            refreshed_external_state = _portal_maybe_process_external_access(response)
            if isinstance(refreshed_external_state, dict):
                external_portal_state = refreshed_external_state
        connection['last_heartbeat'] = int(time.time())
        if isinstance(external_portal_state, dict):
            connection['external_access_portal'] = external_portal_state
        connection['last_error'] = ''
        if response.get('installation_id'):
            connection['installation_id'] = str(response['installation_id'])
        connection['open_request_count'] = int(response.get('open_request_count', connection.get('open_request_count', 0)) or 0)
        connection['manual_open_request_count'] = int(response.get('manual_open_request_count', connection.get('manual_open_request_count', connection.get('open_request_count', 0))) or 0)
        connection['automatic_alert_count'] = int(response.get('automatic_alert_count', connection.get('automatic_alert_count', 0)) or 0)
        connection['latest_request'] = response.get('latest_request')
        update_portal_subscription(connection, response, verified_at=connection['last_heartbeat'])
        save_portal_connection(connection)
        _schedule_smart_pro_tunnel_recovery(connection, external_portal_state)
        # Heartbeat also migrates old installs and clears stale local request state.
        settings_patch = {}
        if connection.get('installation_id'):
            settings_patch['installation_id'] = connection['installation_id']
            settings_patch['customer_name'] = connection['installation_id']
        if connection.get('manual_open_request_count', connection.get('open_request_count', 0)) == 0:
            settings_patch['pending_request_time'] = 0
        save_tech_settings(settings_patch)
        write_managed_policy_file()
        return True
    except PortalAPIError as error:
        connection['last_error'] = str(error)
        connection['last_error_code'] = error.code
        connection['last_error_at'] = int(time.time())
        save_portal_connection(connection)
        write_managed_policy_file()
        print(f'[PORTAL] Heartbeat error: {error}', flush=True)
        return False

def portal_heartbeat_loop():
    time.sleep(5)
    while True:
        connection = load_portal_connection()
        interval = int(connection.get('heartbeat_seconds', PORTAL_HEARTBEAT_DEFAULT) or PORTAL_HEARTBEAT_DEFAULT)
        if connection.get('installation_token'):
            send_portal_heartbeat()
        time.sleep(max(15, min(interval, 300)))

def read_json_body(handler, max_bytes=16384):
    try:
        length = int(handler.headers.get('Content-Length', '0'))
    except ValueError:
        length = 0
    if length <= 0 or length > max_bytes:
        raise ValueError('Μη έγκυρο μέγεθος αιτήματος.')
    return json.loads(handler.rfile.read(length).decode('utf-8'))

def send_json(handler, status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

DEFAULT_TECH_SETTINGS = {
    "customer_name": "",  # legacy compatibility: mirrors installation_id
    "installation_id": "",
    "active_plan": "smartcare",
    "sub_start": datetime.now().strftime('%Y-%m-%d'),
    "sub_months": 12,
    "remote_session": False,
    "req_history": [],
    "main_history": [],
    "pending_request_time": 0,
    
    # --- SMART UPDATES SETTINGS ---
    "auto_update_enabled": False,
    "update_core": True,
    "update_os": True,
    "update_addons": True,
    "update_wait_days": 3,
    "update_backup_wait_min": 15,
    "update_eval_min": 20,
    "update_rollback_offline_count": 2,
    "update_notify_only": False,
    "known_updates": {}, 
    "notified_updates": {},
    
    "email_password": "",
    "watchdog_enabled": True,
    "check_interval_min": 5.0,
    "alert_delay_min": 15.0,
    "domain_light": True,
    "domain_switch": True,
    "domain_binary_sensor": True,
    "domain_cover": True,
    "domain_climate": True,
    "domain_lock": True,
    "domain_camera": True,
    "domain_water_heater": True,
    "domain_sensor": False,
    "battery_limit": 15.0,

    # --- SAFE WATCHDOG TEST SETTINGS ---
    "watchdog_test_delay_sec": 10,
    "watchdog_test_clear_sec": 30,
    "watchdog_test_device_name": "Δοκιμαστική συσκευή Φρουρού",
    "watchdog_test_send_email": False,

    "auto_vacation_enabled": True,
    "vacation_start": "20:00",
    "vacation_end": "23:59",
    "cover_open_time": "08:00",
    "cover_close_time": "20:00",
    "vacation_lights": [],
    "vacation_covers": [],
    "vacation_audio": [],
    "subscription_active": True,
    "managed_remote_support_manual_pause": False,
    
    # --- MESHCENTRAL BANNER SETTINGS ---
    "mesh_banner_enabled": False,
    "mesh_server_ip": "support.smart-pro-system.com"
}

def paired_installation_id():
    """Return the canonical Installation ID supplied by the active Portal pairing."""
    connection = load_portal_connection()
    return str(connection.get('installation_id', '') or '').strip()


def _read_tech_settings_unlocked():
    if not os.path.exists(TECH_SETTINGS_FILE):
        return {}
    try:
        with open(TECH_SETTINGS_FILE, 'r', encoding='utf-8') as file:
            data = json.load(file)
        return data if isinstance(data, dict) else {}
    except Exception as error:
        print(f'[SETTINGS] Could not read technical settings: {error}', flush=True)
        return {}


def _write_tech_settings_unlocked(data):
    temp_path = TECH_SETTINGS_FILE + '.tmp'
    with open(temp_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False)
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, TECH_SETTINGS_FILE)
    os.chmod(TECH_SETTINGS_FILE, 0o600)


def _normalize_tech_settings(data):
    normalized = DEFAULT_TECH_SETTINGS.copy()
    if isinstance(data, dict):
        normalized.update(data)

    # The active Portal pairing is the single source of truth. Keep the old
    # customer_name key mirrored so older installations continue to work.
    canonical_id = paired_installation_id()
    legacy_id = str(
        normalized.get('installation_id')
        or normalized.get('customer_name')
        or ''
    ).strip()
    installation_id = canonical_id or legacy_id
    normalized['installation_id'] = installation_id
    normalized['customer_name'] = installation_id

    # Guardian server-side validation. UI validation is convenience only; the
    # backend is authoritative so malformed/imported settings cannot create
    # unsafe polling or alert behavior.
    normalized['check_interval_min'] = round(clamp_number(
        normalized.get('check_interval_min', 5.0), 5.0, 1.0, 60.0
    ), 2)
    normalized['alert_delay_min'] = round(clamp_number(
        normalized.get('alert_delay_min', 15.0), 15.0, 1.0, 1440.0
    ), 2)
    normalized['battery_limit'] = round(clamp_number(
        normalized.get('battery_limit', 15.0), 15.0, 1.0, 100.0
    ), 2)
    normalized['watchdog_test_delay_sec'] = int(round(clamp_number(
        normalized.get('watchdog_test_delay_sec', 10), 10, 3, 300
    )))
    normalized['watchdog_test_clear_sec'] = int(round(clamp_number(
        normalized.get('watchdog_test_clear_sec', 30), 30, 5, 600
    )))

    # Smart Updates policy validation. The master switch remains independent,
    # but malformed policy values are bounded before any background cycle can
    # consume them.
    normalized['update_wait_days'] = int(round(clamp_number(
        normalized.get('update_wait_days', 3), 3, 0, 365
    )))
    normalized['update_backup_wait_min'] = int(round(clamp_number(
        normalized.get('update_backup_wait_min', 15), 15, 1, 180
    )))
    normalized['update_eval_min'] = int(round(clamp_number(
        normalized.get('update_eval_min', 20), 20, 1, 240
    )))
    normalized['update_rollback_offline_count'] = int(round(clamp_number(
        normalized.get('update_rollback_offline_count', 2), 2, 1, 1000
    )))
    normalized['update_core'] = bool(normalized.get('update_core', True))
    normalized['update_os'] = bool(normalized.get('update_os', True))
    normalized['update_addons'] = bool(normalized.get('update_addons', True))
    normalized['update_notify_only'] = bool(normalized.get('update_notify_only', False))
    return normalized


def tech_settings_public(settings):
    """Return browser-safe settings; never return stored SMTP credentials."""
    data = dict(settings or {})
    configured = bool(str(data.pop('email_password', '') or ''))
    data['email_password_configured'] = configured
    return data


def _smart_updates_test_telemetry():
    result = smart_updates_test_public_status()
    raw_steps = result.get('steps') if isinstance(result.get('steps'), list) else []
    steps = []
    for item in raw_steps[:10]:
        if not isinstance(item, dict):
            continue
        steps.append({
            'key': str(item.get('key', '') or '')[:48],
            'label': str(item.get('label', '') or '')[:80],
            'status': str(item.get('status', '') or '')[:32],
            'detail': str(item.get('detail', '') or '')[:180],
        })
    return {
        'status': str(result.get('status', 'idle') or 'idle')[:32],
        'scenario': str(result.get('scenario', '') or '')[:32],
        'scenario_label': str(result.get('scenario_label', '') or '')[:80],
        'message': str(result.get('message', '') or '')[:180],
        'started_at': int(result.get('started_at', 0) or 0),
        'finished_at': int(result.get('finished_at', 0) or 0),
        'real_actions_executed': bool(result.get('real_actions_executed', False)),
        'steps': steps,
    }


def _control_plane_authority_material():
    """Canonical Generation-1 authority/security material used for freeze integrity."""
    capability_rows = [
        f'{kind}:{capability}'
        for kind, capability in sorted(CONTROL_PLANE_ALLOWED_CAPABILITIES)
    ]
    return {
        'capability_contract': CONTROL_PLANE_CAPABILITIES_CONTRACT_ID,
        'generation': 1,
        'scope_complete': True,
        'families': list(CONTROL_PLANE_FAMILIES),
        'capabilities': capability_rows,
        'local_only': list(CONTROL_PLANE_LOCAL_ONLY_BOUNDARIES),
        'command_contract': CONTROL_PLANE_CONTRACT_ID,
        'max_ttl_sec': CONTROL_PLANE_MAX_TTL_SECONDS,
        'clock_skew_sec': CONTROL_PLANE_CLOCK_SKEW_SECONDS,
        'security_guards': list(CONTROL_PLANE_SECURITY_GUARDS),
    }


def _control_plane_authority_digest():
    material = _control_plane_authority_material()
    return hashlib.sha256(_control_plane_canonical(material).encode('utf-8')).hexdigest()


def control_plane_capability_manifest():
    """Return the bounded, non-secret frozen Generation-1 authority manifest.

    The digest covers the exact executor allow-list, family/local-only boundaries
    and core command security envelope. It grants no authority by itself.
    """
    material = _control_plane_authority_material()
    return {
        'contract': CONTROL_PLANE_CAPABILITIES_CONTRACT_ID,
        'generation': 1,
        'scope_complete': True,
        'families': material['families'],
        'capabilities': material['capabilities'],
        'local_only': material['local_only'],
        'freeze_contract': CONTROL_PLANE_FREEZE_CONTRACT_ID,
        'freeze_id': CONTROL_PLANE_FREEZE_ID,
        'frozen': True,
        'authority_digest': _control_plane_authority_digest(),
        'command_contract': CONTROL_PLANE_CONTRACT_ID,
        'max_ttl_sec': CONTROL_PLANE_MAX_TTL_SECONDS,
        'clock_skew_sec': CONTROL_PLANE_CLOCK_SKEW_SECONDS,
        'security_guards': list(CONTROL_PLANE_SECURITY_GUARDS),
    }


def technician_center_portal_snapshot():
    """Return the strict read-only Technician Center mirror for the Portal.

    Contract v1 intentionally contains only configuration/status values that are
    useful to an authorized Smart Pro Admin. Secrets, raw Home Assistant entity
    IDs, local device names and writable commands are deliberately excluded.
    """
    settings = load_tech_settings()
    connection = load_portal_connection()
    subscription = portal_subscription_public(connection)
    guardian = guardian_status_snapshot()
    safe_test_runtime = watchdog_test_public_status()

    monitored_domains = []
    domain_map = (
        ('domain_light', 'light'),
        ('domain_switch', 'switch'),
        ('domain_binary_sensor', 'binary_sensor'),
        ('domain_cover', 'cover'),
        ('domain_climate', 'climate'),
        ('domain_lock', 'lock'),
        ('domain_camera', 'camera'),
        ('domain_water_heater', 'water_heater'),
        ('domain_sensor', 'sensor'),
    )
    for key, label in domain_map:
        if bool(settings.get(key, DEFAULT_TECH_SETTINGS.get(key, False))):
            monitored_domains.append(label)

    update_targets = []
    if bool(settings.get('update_core', True)):
        update_targets.append('core')
    if bool(settings.get('update_os', True)):
        update_targets.append('os')
    if bool(settings.get('update_addons', True)):
        update_targets.append('addons')

    return {
        'contract': TECHNICIAN_CENTER_CONTRACT_ID,
        'collected_at': int(time.time()),
        'read_only': True,
        'control_plane': control_plane_capability_manifest(),
        'general': {
            'portal_connected': bool(connection.get('installation_token')),
            'installation_id': paired_installation_id(),
            'subscription_available': bool(subscription.get('available')),
            'subscription_plan': str(subscription.get('plan', '') or '')[:48],
            'subscription_status': str(subscription.get('status', '') or '')[:48],
            'subscription_verification_state': str(subscription.get('verification_state', '') or '')[:48],
            'managed_remote_support_manual_pause': bool(settings.get('managed_remote_support_manual_pause', False)),
            'mesh_banner_enabled': bool(settings.get('mesh_banner_enabled', False)),
            'mesh_server_configured': bool(str(settings.get('mesh_server_ip', '') or '').strip()),
            'alert_email_configured': bool(str(settings.get('email_password', '') or '')),
            'local_fallback_available': True,
        },
        'guardian': {
            'enabled': bool(settings.get('watchdog_enabled', True)),
            'status': str(guardian.get('status', 'waiting') or 'waiting')[:32],
            'reason_code': str(guardian.get('reason_code', '') or '')[:64],
            'check_interval_min': float(settings.get('check_interval_min', 5.0) or 5.0),
            'alert_delay_min': float(settings.get('alert_delay_min', 15.0) or 15.0),
            'battery_limit': float(settings.get('battery_limit', 15.0) or 15.0),
            'monitored_domains': monitored_domains[:16],
            'safe_test_delay_sec': int(settings.get('watchdog_test_delay_sec', 10) or 10),
            'safe_test_clear_sec': int(settings.get('watchdog_test_clear_sec', 30) or 30),
            'safe_test_email': bool(settings.get('watchdog_test_send_email', False)),
            'safe_test_status': str(safe_test_runtime.get('status', 'idle') or 'idle')[:32],
            'safe_test_request_code': str(safe_test_runtime.get('request_code', '') or '')[:32],
            'safe_test_seconds_until_request': max(0, min(600, int(safe_test_runtime.get('seconds_until_request', 0) or 0))),
            'safe_test_seconds_until_clear': max(0, min(900, int(safe_test_runtime.get('seconds_until_clear', 0) or 0))),
            'safe_test_message': str(safe_test_runtime.get('message', '') or '')[:180],
        },
        'automations': {
            'smart_updates': {
                'enabled': bool(settings.get('auto_update_enabled', False)),
                'notify_only': bool(settings.get('update_notify_only', False)),
                'targets': update_targets,
                'wait_days': int(settings.get('update_wait_days', 3) or 3),
                'backup_wait_min': int(settings.get('update_backup_wait_min', 15) or 15),
                'evaluation_min': int(settings.get('update_eval_min', 20) or 20),
                'rollback_offline_count': int(settings.get('update_rollback_offline_count', 2) or 2),
                'safe_test': _smart_updates_test_telemetry(),
            },
            'vacation': {
                'enabled': bool(settings.get('auto_vacation_enabled', True)),
                'start': str(settings.get('vacation_start', '20:00') or '20:00')[:5],
                'end': str(settings.get('vacation_end', '23:59') or '23:59')[:5],
                'cover_open_time': str(settings.get('cover_open_time', '08:00') or '08:00')[:5],
                'cover_close_time': str(settings.get('cover_close_time', '20:00') or '20:00')[:5],
                'lights_count': min(10000, len(settings.get('vacation_lights') or [])),
                'covers_count': min(10000, len(settings.get('vacation_covers') or [])),
                'audio_count': min(10000, len(settings.get('vacation_audio') or [])),
            },
        },
    }


TECH_SETTINGS_PUBLIC_WRITE_KEYS = {'req_history', 'main_history', 'pending_request_time'}


def load_tech_settings():
    """Load, migrate and self-heal technical settings atomically."""
    with TECH_SETTINGS_LOCK:
        stored = _read_tech_settings_unlocked()
        normalized = _normalize_tech_settings(stored)
        if normalized != stored:
            _write_tech_settings_unlocked(normalized)
        return normalized.copy()


def save_tech_settings(data, merge=True):
    """Merge a settings patch safely and preserve fields omitted by the UI."""
    with TECH_SETTINGS_LOCK:
        current = _read_tech_settings_unlocked() if merge else {}
        combined = dict(current)
        if isinstance(data, dict):
            combined.update(data)
        normalized = _normalize_tech_settings(combined)
        _write_tech_settings_unlocked(normalized)
        return normalized.copy()

def get_monitored_domains(tech_config):
    domains = []
    if tech_config.get('domain_light', True): domains.append('light.')
    if tech_config.get('domain_switch', True): domains.append('switch.')
    if tech_config.get('domain_climate', True): domains.append('climate.')
    if tech_config.get('domain_cover', True): domains.append('cover.')
    if tech_config.get('domain_lock', True): domains.append('lock.')
    if tech_config.get('domain_camera', True): domains.append('camera.')
    if tech_config.get('domain_water_heater', True): domains.append('water_heater.')
    if tech_config.get('domain_binary_sensor', True): domains.append('binary_sensor.')
    if tech_config.get('domain_sensor', False): domains.append('sensor.')
    return tuple(domains)

def mesh_configuration_status(tech_config=None):
    tech_config = tech_config or load_tech_settings()
    options = load_addon_options()
    enabled = bool(tech_config.get('mesh_banner_enabled', False))
    server_host = str(
        tech_config.get('mesh_server_ip', 'support.smart-pro-system.com')
        or 'support.smart-pro-system.com'
    ).strip()
    if not server_host or server_host == '100.70.104.64':
        server_host = 'support.smart-pro-system.com'
    server_host = server_host.removeprefix('https://').removeprefix('http://')
    server_host = server_host.rstrip('/').split('/', 1)[0].split(':', 1)[0]
    installation_id = paired_installation_id() or str(
        tech_config.get('installation_id')
        or tech_config.get('customer_name')
        or ''
    ).strip()
    mesh_access_token = str(options.get('mesh_access_token', '') or '').strip()
    return {
        'enabled': enabled,
        'server_host': server_host,
        'installation_id': installation_id,
        'has_token': bool(mesh_access_token),
        'mesh_access_token': mesh_access_token,
        'configured': bool(enabled and server_host and installation_id and mesh_access_token),
    }


def integration_health_status():
    connection = load_portal_connection()
    tech_config = load_tech_settings()
    mesh = mesh_configuration_status(tech_config)
    installation_id = paired_installation_id()
    stored_id = str(tech_config.get('installation_id', '') or '').strip()
    portal_connected = bool(connection.get('installation_token'))
    portal_error = str(connection.get('last_error', '') or '').strip()
    return {
        'portal': {
            'configured': portal_connected,
            'healthy': bool(portal_connected and not portal_error),
            'message': portal_error or ('Συνδεδεμένο' if portal_connected else 'Δεν έχει γίνει pairing'),
        },
        'meshcentral': {
            'configured': mesh['configured'],
            'enabled': mesh['enabled'],
            'message': 'Ρυθμισμένο' if mesh['configured'] else 'Χρειάζεται έλεγχο ρυθμίσεων',
        },
        'email': {
            'configured': bool(str(tech_config.get('email_password', '') or '')),
            'address': ALERT_EMAIL,
            'message': 'Ρυθμισμένο' if str(tech_config.get('email_password', '') or '') else 'Δεν έχει καταχωριστεί κωδικός',
        },
        'installation': {
            'installation_id': installation_id or stored_id,
            'synced': bool(installation_id and stored_id == installation_id),
        },
    }


def is_valid_email_address(value):
    value = str(value or '').strip()
    return bool(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value))


def send_email_alert(subject, body, tech_config, reply_to=''):
    """Send an automated technical alert and return a user-safe result."""
    email_pass = str(tech_config.get('email_password', '') or '')
    if not email_pass:
        message = 'Δεν έχει ρυθμιστεί κωδικός για το email τεχνικών ειδοποιήσεων.'
        print(f'[EMAIL ERROR] {message}', flush=True)
        return {'success': False, 'message': message, 'code': 'missing_password'}

    connection = load_portal_connection()
    installation_id = str(connection.get('installation_id', '') or '').strip()
    installation_name = str(connection.get('installation_name', '') or '').strip()
    customer = str(connection.get('customer_name', '') or '').strip()
    if not customer:
        customer = str(tech_config.get('customer_name', '') or '').strip()

    subject_prefix = '[Smart Pro System]'
    if installation_id:
        subject_prefix += f' [{installation_id}]'
    final_subject = f'{subject_prefix} {str(subject or "Τεχνική ειδοποίηση").strip()}'

    context_lines = [
        'Smart Pro System — Τεχνική ειδοποίηση',
        f'Ώρα: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Smart Pro System: {ADDON_VERSION}',
    ]
    if installation_id:
        context_lines.append(f'Installation ID: {installation_id}')
    if installation_name:
        context_lines.append(f'Εγκατάσταση: {installation_name}')
    if customer:
        context_lines.append(f'Πελάτης: {customer}')
    context_lines.extend(['', str(body or '').strip()])
    final_body = '\n'.join(context_lines).strip() + '\n'

    msg = EmailMessage()
    msg.set_content(final_body)
    msg['Subject'] = final_subject
    msg['From'] = ALERT_EMAIL
    msg['To'] = ALERT_EMAIL
    if is_valid_email_address(reply_to):
        msg['Reply-To'] = str(reply_to).strip()

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context, timeout=15) as server:
            server.login(ALERT_EMAIL, email_pass)
            server.send_message(msg)
        return {
            'success': True,
            'message': f'Το email τεχνικής ειδοποίησης στάλθηκε επιτυχώς στο {ALERT_EMAIL}.',
            'code': 'sent',
        }
    except smtplib.SMTPAuthenticationError:
        message = 'Η σύνδεση στο email απέτυχε. Έλεγξε τον κωδικό του alert@smart-pro-system.gr.'
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
        message = 'Δεν ήταν δυνατή η σύνδεση με τον διακομιστή email.'
    except Exception as error:
        message = f'Αποτυχία αποστολής email: {clean_portal_error_message(error, "Άγνωστο σφάλμα email.")}'

    print(f'[EMAIL ERROR] {message}', flush=True)
    return {'success': False, 'message': message, 'code': 'send_failed'}

def _ha_api_credential_available(configured_token=''):
    """Return True when the add-on can authenticate to Home Assistant Core.

    Home Assistant OS/Supervised injects a container-scoped SUPERVISOR_TOKEN when
    ``homeassistant_api: true`` is enabled. A manually configured long-lived token
    remains only as a compatibility fallback for environments where the scoped
    credential is unavailable.
    """
    return bool(str(os.getenv('SUPERVISOR_TOKEN', '') or '').strip() or str(configured_token or '').strip())


def _ha_transport_profile(configured_token=''):
    """Return the safest available internal Home Assistant transport.

    Home Assistant 2026+ recommends the Supervisor Core proxy for app-to-Core
    communication. Smart Pro Tools prefers that path when the scoped
    SUPERVISOR_TOKEN is available and keeps the historical direct Core route only
    as a compatibility fallback for older installs. No token is logged or exposed.
    """
    configured_token = str(configured_token or '').strip()
    supervisor_token = str(os.getenv('SUPERVISOR_TOKEN', '') or '').strip()
    if supervisor_token:
        return {
            'mode': 'supervisor_proxy',
            'http_base': 'http://supervisor/core',
            'ws_host': 'supervisor',
            'ws_port': 80,
            'ws_path': '/core/websocket',
            'host_header': 'supervisor',
            'token': supervisor_token,
        }
    return {
        'mode': 'direct_core',
        'http_base': 'http://homeassistant:8123',
        'ws_host': 'homeassistant',
        'ws_port': 8123,
        'ws_path': '/api/websocket',
        'host_header': 'homeassistant:8123',
        'token': configured_token,
    }


def _ha_http_target(configured_token, path):
    profile = _ha_transport_profile(configured_token)
    normalized_path = '/' + str(path or '').lstrip('/')
    return profile['http_base'] + normalized_path, profile['token']


def _supervisor_api_json(path, method='GET', data=None, timeout=10):
    """Call one tightly-scoped Supervisor API endpoint directly.

    Home Assistant 2026 blocks add-on-originated ``supervisor/api`` messages on
    the Core WebSocket proxy. Smart Pro Tools therefore uses the supported
    direct Supervisor API with the container-scoped ``SUPERVISOR_TOKEN``.

    The helper intentionally allows only the exact read/write endpoints needed
    by Managed External URL private-tunnel orchestration and its aggregate
    Supervisor/add-on diagnostics. No token, raw options or unrelated Supervisor
    surface is exposed to the Portal or browser.
    """
    method = str(method or 'GET').upper()
    path = '/' + str(path or '').lstrip('/')
    slug_re = r'[a-z0-9_]{1,128}'
    allowed = False
    if method == 'GET' and path in ('/supervisor/info', '/addons', '/core/info', '/backups/info', '/store', '/store/addons'):
        allowed = True
    elif method == 'GET' and re.fullmatch(rf'/addons/{slug_re}/info', path):
        allowed = True
    elif method == 'POST' and re.fullmatch(rf'/addons/{slug_re}/(?:options|start|restart)', path):
        allowed = True
    elif method == 'POST' and re.fullmatch(rf'/store/addons/{slug_re}/install', path):
        allowed = True
    if not allowed:
        return None, 'endpoint_not_allowed'

    token = str(os.getenv('SUPERVISOR_TOKEN', '') or '').strip()
    if not token:
        return None, 'supervisor_token_missing'

    body = None
    if data is not None:
        try:
            body = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        except (TypeError, ValueError):
            return None, 'request_invalid'

    request = urllib.request.Request(
        'http://supervisor' + path,
        data=body,
        method=method,
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode('utf-8')
        payload = json.loads(raw or '{}')
    except urllib.error.HTTPError as error:
        code = int(getattr(error, 'code', 0) or 0)
        if code in (401, 403):
            return None, 'auth_rejected'
        if code == 404:
            return None, 'not_found'
        return None, f'http_{code}'
    except urllib.error.URLError:
        return None, 'unreachable'
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, 'invalid_response'
    except Exception:
        return None, 'request_failed'

    # Supervisor API responses are normally wrapped as
    # {"result":"ok","data":...}. Accept an already-unwrapped payload as
    # a compatibility guard for test fixtures/older Supervisor behavior.
    if isinstance(payload, dict) and 'result' in payload:
        if str(payload.get('result', '') or '').lower() != 'ok':
            return None, 'supervisor_error'
        payload = payload.get('data')
    return payload, ''


def _smart_pro_tunnel_recovery_default():
    return {
        'contract': SMART_PRO_TUNNEL_RECOVERY_CONTRACT_ID,
        'state': 'idle',
        'reason_code': 'not_evaluated',
        'last_attempt_at': 0,
        'last_success_at': 0,
        'store_slug_hint': '',
        'tunnel_version': '',
        'installation_id': '',
    }


def load_smart_pro_tunnel_recovery_state():
    with SMART_PRO_TUNNEL_RECOVERY_STATE_LOCK:
        state = _smart_pro_tunnel_recovery_default()
        if SMART_PRO_TUNNEL_RECOVERY_STATE_FILE.exists():
            try:
                stored = json.loads(SMART_PRO_TUNNEL_RECOVERY_STATE_FILE.read_text(encoding='utf-8'))
                if isinstance(stored, dict):
                    state.update(stored)
            except Exception:
                pass
        return state


def save_smart_pro_tunnel_recovery_state(state):
    with SMART_PRO_TUNNEL_RECOVERY_STATE_LOCK:
        safe = _smart_pro_tunnel_recovery_default()
        if isinstance(state, dict):
            safe.update(state)
        safe['contract'] = SMART_PRO_TUNNEL_RECOVERY_CONTRACT_ID
        safe['state'] = str(safe.get('state', 'idle') or 'idle')[:48]
        safe['reason_code'] = str(safe.get('reason_code', '') or '')[:64]
        safe['last_attempt_at'] = max(0, int(safe.get('last_attempt_at', 0) or 0))
        safe['last_success_at'] = max(0, int(safe.get('last_success_at', 0) or 0))
        safe['store_slug_hint'] = str(safe.get('store_slug_hint', '') or '')[-32:]
        safe['tunnel_version'] = str(safe.get('tunnel_version', '') or '')[:32]
        safe['installation_id'] = str(safe.get('installation_id', '') or '')[:32]
        SMART_PRO_TUNNEL_RECOVERY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SMART_PRO_TUNNEL_RECOVERY_STATE_FILE.with_suffix('.tmp')
        tmp.write_text(json.dumps(safe, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        os.chmod(tmp, 0o600)
        os.replace(tmp, SMART_PRO_TUNNEL_RECOVERY_STATE_FILE)
        os.chmod(SMART_PRO_TUNNEL_RECOVERY_STATE_FILE, 0o600)
        return safe


def smart_pro_tunnel_recovery_public_status():
    state = load_smart_pro_tunnel_recovery_state()
    return {
        'contract': SMART_PRO_TUNNEL_RECOVERY_CONTRACT_ID,
        'state': str(state.get('state', 'idle') or 'idle')[:48],
        'reason_code': str(state.get('reason_code', '') or '')[:64],
        'last_attempt_at': max(0, int(state.get('last_attempt_at', 0) or 0)),
        'last_success_at': max(0, int(state.get('last_success_at', 0) or 0)),
        'store_slug_hint': str(state.get('store_slug_hint', '') or '')[-32:],
        'tunnel_version': str(state.get('tunnel_version', '') or '')[:32],
    }


def _smart_pro_tunnel_version_tuple(value):
    numbers = [int(item) for item in re.findall(r'\d+', str(value or ''))[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _smart_pro_tunnel_installed_match():
    addons, error = _supervisor_api_json('/addons', 'GET')
    if error:
        return None, 'supervisor_addons_' + error
    if isinstance(addons, dict):
        items = addons.get('addons') if isinstance(addons.get('addons'), list) else []
    elif isinstance(addons, list):
        items = addons
    else:
        return None, 'supervisor_addons_invalid'
    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        slug = str(item.get('slug', '') or '').strip().lower()
        name = str(item.get('name', '') or '').strip()
        if name == 'Smart Pro Tunnel' and (slug == 'smart_pro_tunnel' or slug.endswith('_smart_pro_tunnel')):
            matches.append(item)
    if len(matches) > 1:
        return None, 'installed_match_ambiguous'
    return (matches[0] if matches else None), ''


def _smart_pro_tunnel_repository_source(value):
    source = str(value or '').strip().rstrip('/').lower()
    if source.endswith('.git'):
        source = source[:-4]
    return source


def _smart_pro_tunnel_store_match():
    # Supervisor store app records expose ``repository`` as the repository slug,
    # not the repository source URL. Read the combined store payload so the app
    # slug can be joined to the repository metadata and verified against the
    # official tokenless Smart Pro repository source before any install mutation.
    store, error = _supervisor_api_json('/store', 'GET', timeout=20)
    if error:
        return None, 'store_' + error
    if not isinstance(store, dict):
        return None, 'store_invalid'

    items = store.get('addons') if isinstance(store.get('addons'), list) else []
    repositories = store.get('repositories') if isinstance(store.get('repositories'), list) else []
    repository_sources = {}
    for repository_item in repositories:
        if not isinstance(repository_item, dict):
            continue
        repository_slug = str(repository_item.get('slug', '') or '').strip().lower()
        source = _smart_pro_tunnel_repository_source(repository_item.get('source'))
        if repository_slug and source:
            repository_sources[repository_slug] = source

    expected_repository = _smart_pro_tunnel_repository_source(SMART_PRO_TUNNEL_OFFICIAL_REPOSITORY_URL)
    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        slug = str(item.get('slug', '') or '').strip().lower()
        name = str(item.get('name', '') or '').strip()
        repository_slug = str(item.get('repository', '') or '').strip().lower()
        if name != 'Smart Pro Tunnel':
            continue
        if not (slug == 'smart_pro_tunnel' or slug.endswith('_smart_pro_tunnel')):
            continue
        if not repository_slug or repository_sources.get(repository_slug) != expected_repository:
            continue
        if _smart_pro_tunnel_version_tuple(item.get('version_latest') or item.get('version')) < SMART_PRO_TUNNEL_MIN_RECOVERY_VERSION:
            continue
        matches.append(item)
    if len(matches) != 1:
        return None, 'store_match_missing' if not matches else 'store_match_ambiguous'
    return matches[0], ''


def _smart_pro_tunnel_recovery_worker(installation_id):
    attempt_at = int(time.time())
    state = load_smart_pro_tunnel_recovery_state()
    state.update({
        'state': 'preflight',
        'reason_code': 'checking_installed_state',
        'last_attempt_at': attempt_at,
        'installation_id': str(installation_id or '')[:32],
    })
    save_smart_pro_tunnel_recovery_state(state)
    try:
        installed, error = _smart_pro_tunnel_installed_match()
        if error:
            raise RuntimeError(error)

        slug = ''
        version = ''
        raw_state = ''
        if isinstance(installed, dict):
            slug = str(installed.get('slug', '') or '').strip().lower()
            version = str(installed.get('version', '') or '').strip()
            raw_state = str(installed.get('state', '') or '').strip().lower()
            if _smart_pro_tunnel_version_tuple(version) < SMART_PRO_TUNNEL_MIN_RECOVERY_VERSION:
                raise RuntimeError('installed_version_too_old')
            state.update({
                'state': 'installed',
                'reason_code': 'official_tunnel_already_installed',
                'store_slug_hint': slug[-32:],
                'tunnel_version': version[:32],
            })
            save_smart_pro_tunnel_recovery_state(state)
        else:
            store_item, error = _smart_pro_tunnel_store_match()
            if error or not isinstance(store_item, dict):
                raise RuntimeError(error or 'store_match_missing')
            slug = str(store_item.get('slug', '') or '').strip().lower()
            version = str(store_item.get('version_latest') or store_item.get('version') or '').strip()
            state.update({
                'state': 'installing',
                'reason_code': 'official_store_install_started',
                'store_slug_hint': slug[-32:],
                'tunnel_version': version[:32],
            })
            save_smart_pro_tunnel_recovery_state(state)
            _, error = _supervisor_api_json(
                f'/store/addons/{slug}/install',
                'POST',
                {'background': False},
                timeout=180,
            )
            if error:
                raise RuntimeError('install_' + error)
            info, error = _supervisor_api_json(f'/addons/{slug}/info', 'GET', timeout=20)
            if error or not isinstance(info, dict):
                raise RuntimeError('post_install_info_' + (error or 'invalid'))
            if str(info.get('name', '') or '').strip() != 'Smart Pro Tunnel':
                raise RuntimeError('post_install_name_mismatch')
            version = str(info.get('version', '') or '').strip()
            if _smart_pro_tunnel_version_tuple(version) < SMART_PRO_TUNNEL_MIN_RECOVERY_VERSION:
                raise RuntimeError('post_install_version_too_old')
            raw_state = str(info.get('state', '') or '').strip().lower()
            state.update({
                'state': 'installed',
                'reason_code': 'official_store_install_complete',
                'tunnel_version': version[:32],
            })
            save_smart_pro_tunnel_recovery_state(state)

        if raw_state not in ('started', 'running'):
            state.update({'state': 'starting_identity', 'reason_code': 'initial_identity_start'})
            save_smart_pro_tunnel_recovery_state(state)
            _, error = _supervisor_api_json(f'/addons/{slug}/start', 'POST', timeout=45)
            if error:
                raise RuntimeError('start_' + error)

        # The Tunnel writes public-only enrollment material almost immediately on
        # startup. Observe only a fresh publication from this attempt; never read
        # or copy its private key.
        deadline = time.time() + 20
        enrollment_ready = False
        while time.time() < deadline:
            enrollment = _external_access_tunnel_enrollment_snapshot()
            if (
                enrollment.get('valid')
                and int(enrollment.get('observed_at', 0) or 0) >= attempt_at
                and _smart_pro_tunnel_version_tuple(enrollment.get('tunnel_version')) >= SMART_PRO_TUNNEL_MIN_RECOVERY_VERSION
            ):
                enrollment_ready = True
                version = str(enrollment.get('tunnel_version', version) or version)
                break
            time.sleep(1)

        state.update({
            'state': 'identity_ready' if enrollment_ready else 'identity_pending',
            'reason_code': 'public_enrollment_ready' if enrollment_ready else 'public_enrollment_pending',
            'last_success_at': int(time.time()),
            'tunnel_version': version[:32],
        })
        save_smart_pro_tunnel_recovery_state(state)
        smart_pro_tunnel_runtime_public_status._cache = None
        print(f'[RECOVERY] Smart Pro Tunnel companion recovery -> {state["state"]}', flush=True)
    except Exception as exc:
        reason = str(exc or 'recovery_failed')[:64]
        state = load_smart_pro_tunnel_recovery_state()
        state.update({
            'state': 'failed',
            'reason_code': reason,
            'last_attempt_at': attempt_at,
            'installation_id': str(installation_id or '')[:32],
        })
        save_smart_pro_tunnel_recovery_state(state)
        smart_pro_tunnel_runtime_public_status._cache = None
        print(f'[RECOVERY] Smart Pro Tunnel companion recovery failed: {reason}', flush=True)
    finally:
        SMART_PRO_TUNNEL_RECOVERY_WORKER_LOCK.release()


def _schedule_smart_pro_tunnel_recovery(connection, external_portal_state):
    if not isinstance(connection, dict) or not isinstance(external_portal_state, dict):
        return False
    installation_id = str(connection.get('installation_id', '') or '').strip()
    token_present = bool(str(connection.get('installation_token', '') or '').strip())
    if not installation_id or not token_present:
        return False
    if not bool(external_portal_state.get('eligible', False)):
        return False

    subscription = portal_subscription_public(connection)
    if not bool(subscription.get('verification_valid', False)):
        return False

    runtime = smart_pro_tunnel_runtime_public_status()
    state = load_smart_pro_tunnel_recovery_state()
    now = int(time.time())

    # Never take over an independently installed/stopped Tunnel. A stopped app is
    # eligible for automatic retry only when this recovery state proves that the
    # 3.0.8 recovery worker itself already installed/started that companion and a
    # previous recovery step failed before identity publication completed.
    if bool(runtime.get('installed', False)):
        recovery_owned = bool(str(state.get('store_slug_hint', '') or '').strip()) and str(state.get('state', '') or '') in {
            'installing', 'installed', 'starting_identity', 'identity_pending', 'failed'
        }
        if bool(runtime.get('running', False)) or not recovery_owned:
            return False

    if str(state.get('state', '') or '') == 'failed':
        last_attempt = int(state.get('last_attempt_at', 0) or 0)
        if last_attempt and now - last_attempt < SMART_PRO_TUNNEL_RECOVERY_BACKOFF_SECONDS:
            return False

    if not SMART_PRO_TUNNEL_RECOVERY_WORKER_LOCK.acquire(blocking=False):
        return False
    thread = threading.Thread(
        target=_smart_pro_tunnel_recovery_worker,
        args=(installation_id,),
        name='smart-pro-tunnel-recovery',
        daemon=True,
    )
    thread.start()
    return True


def notify_ha_client(token, title, message):
    try:
        data = json.dumps({"title": title, "message": message}).encode('utf-8')
        url, auth_token = _ha_http_target(token, '/api/services/persistent_notification/create')
        req = urllib.request.Request(url, data=data, headers={'Authorization': f'Bearer {auth_token}', 'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
    except: pass

def call_ha_service(token, domain, service, service_data=None, timeout=10):
    try:
        req_data = json.dumps(service_data or {}).encode('utf-8')
        url, auth_token = _ha_http_target(token, f'/api/services/{domain}/{service}')
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=timeout):
            pass
        return True
    except Exception as e:
        print(f"Error calling {domain}.{service}: {e}", flush=True)
        return False


def call_ha_service_with_response(token, domain, service, service_data=None, timeout=900):
    """Call a Home Assistant action that returns response data."""
    try:
        req_data = json.dumps(service_data or {}).encode('utf-8')
        url, auth_token = _ha_http_target(token, f'/api/services/{domain}/{service}?return_response')
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode('utf-8')
        payload = json.loads(raw or '{}')
        return {
            'success': True,
            'response': payload.get('service_response'),
            'payload': payload,
            'error': '',
        }
    except Exception as e:
        print(f"Error calling {domain}.{service} with response: {e}", flush=True)
        return {
            'success': False,
            'response': None,
            'payload': {},
            'error': str(e),
        }


def extract_backup_slug(value):
    """Extract a backup slug from Home Assistant service response data."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ('slug', 'backup'):
            slug = extract_backup_slug(value.get(key))
            if slug:
                return slug
        for nested in value.values():
            slug = extract_backup_slug(nested)
            if slug:
                return slug
    if isinstance(value, (list, tuple)):
        for nested in value:
            slug = extract_backup_slug(nested)
            if slug:
                return slug
    return ''

def get_ha_states(token):
    try:
        url, auth_token = _ha_http_target(token, '/api/states')
        req = urllib.request.Request(url, headers={'Authorization': f'Bearer {auth_token}', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except Exception:
        return []


def get_ha_states_for_ui():
    """Fetch Home Assistant states server-side so the HA token never reaches the browser."""
    options = load_addon_options()
    token = str(options.get('ha_token', '') or '').strip()
    url, auth_token = _ha_http_target(token, '/api/states')
    if not auth_token:
        raise RuntimeError('Δεν υπάρχει διαθέσιμο Home Assistant API credential.')

    request = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {auth_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'Το Home Assistant API απέρριψε το Token (HTTP {error.code}).') from error
    except urllib.error.URLError as error:
        raise RuntimeError(f'Αδυναμία επικοινωνίας με το Home Assistant API: {error.reason}') from error
    except Exception as error:
        raise RuntimeError(f'Σφάλμα ανάγνωσης στοιχείων Home Assistant: {error}') from error

    if not isinstance(payload, list):
        raise RuntimeError('Το Home Assistant API επέστρεψε μη αναμενόμενα δεδομένα.')
    return payload


def _ha_diagnostic_http_json(token, path, timeout=10):
    """Read one HA REST endpoint and return only a bounded result/reason code."""
    url, auth_token = _ha_http_target(token, path)
    request = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {auth_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode('utf-8')
        return json.loads(raw or 'null'), ''
    except urllib.error.HTTPError as error:
        if int(getattr(error, 'code', 0) or 0) in (401, 403):
            return None, 'auth_rejected'
        return None, f'http_{int(getattr(error, "code", 0) or 0)}'
    except urllib.error.URLError:
        return None, 'unreachable'
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, 'invalid_response'
    except Exception:
        return None, 'request_failed'



def _ha_diagnostic_http_text(token, path, timeout=10, max_bytes=HA_ERROR_LOG_MAX_BYTES):
    """Read a bounded plaintext HA endpoint for diagnostics."""
    url, auth_token = _ha_http_target(token, path)
    request = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {auth_token}',
            'Accept': 'text/plain',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(max(1024, int(max_bytes)) + 1)
        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]
        return raw.decode('utf-8', errors='replace'), '', truncated
    except urllib.error.HTTPError as error:
        if int(getattr(error, 'code', 0) or 0) in (401, 403):
            return '', 'auth_rejected', False
        return '', f'http_{int(getattr(error, "code", 0) or 0)}', False
    except urllib.error.URLError:
        return '', 'unreachable', False
    except Exception:
        return '', 'request_failed', False


_HA_LOG_ENTITY_RE = re.compile(
    r'\b(?:sensor|binary_sensor|switch|light|automation|script|climate|cover|camera|'
    r'device_tracker|media_player|lock|alarm_control_panel|update|button|number|select|'
    r'text|input_boolean|input_number|input_select|input_text|input_datetime|timer|scene|'
    r'group|calendar|todo|person|zone|weather|fan|vacuum|water_heater|humidifier|siren|'
    r'valve|lawn_mower|remote)\.[A-Za-z0-9_]+\b',
    re.IGNORECASE,
)


def _ha_sanitize_error_log_line(value):
    """Aggressively minimize one HA system-log line before it can leave the install.

    This is intentionally stricter than ordinary UI escaping. The selected system-log
    export must not expose user-created aliases, device/entity identifiers, local
    add-on hostnames/slugs or other installation-specific labels.
    """
    line = ''.join(ch if ch >= ' ' else ' ' for ch in str(value or '')).strip()
    if not line:
        return ''
    # Credentials / auth material.
    line = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]+', 'Bearer [REDACTED]', line)
    line = re.sub(
        r'(?i)\b(token|access_token|refresh_token|password|passwd|secret|api[_-]?key|authorization)\b'
        r'(\s*[:=]\s*)([^\s,;]+)',
        lambda m: f'{m.group(1)}{m.group(2)}[REDACTED]',
        line,
    )
    # Network and personal identifiers.
    line = re.sub(r'(?i)\b(?:https?|wss?)://[^\s\'"<>()]+', '[URL]', line)
    line = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]', line)
    line = re.sub(r'(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b', '[IP]', line)
    line = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[MAC]', line)
    line = re.sub(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[EMAIL]', line)
    line = re.sub(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b', '[UUID]', line)
    # Installation-specific Home Assistant identifiers / labels.
    line = _HA_LOG_ENTITY_RE.sub('[ENTITY]', line)
    line = re.sub(r'(?i)\bdevice_id\s*[:=]?\s*[\'"]?[A-Za-z0-9._:-]{6,}[\'"]?', 'device_id [DEVICE_ID]', line)
    line = re.sub(r'(?i)\bID\s+[A-Za-z0-9._:-]{6,}\b', 'ID [OPAQUE_ID]', line)
    line = re.sub(r'(?i)\[[0-9a-f]{3,}\.\.\.[0-9a-f]{3,}\]', '[DEVICE_HINT]', line)
    line = re.sub(r'(?i)(\balias\s+)[\'"][^\'"]{1,160}[\'"]', r"\1'[NAME]'", line)
    line = re.sub(r'(?i)(\bfor\s+)[A-Za-z0-9_.-]{2,120}(\s+@\s+\[IP\])', r'\1[DEVICE_NAME]\2', line)
    line = re.sub(r'(?i)(\[homeassistant\.components\.\[ENTITY\]\]\s+)[^:]{1,160}(:)', r'\1[NAME]\2', line)
    # Local add-on routes/hostnames and filesystem paths.
    line = re.sub(r'(?i)\b[0-9a-f]{8}-[a-z0-9_-]+\.local\.hass\.io\b', '[LOCAL_HOST]', line)
    line = re.sub(r'(?i)(?:/config|/ssl|/share|/addons|/auth)(?:/[^\s:\'"]+)+', '[LOCAL_PATH]', line)
    line = re.sub(r'(?i)\b[0-9a-f]{8}_[a-z0-9_-]+\b', '[ADDON_ID]', line)
    # Long opaque values are more likely identifiers/secrets than useful prose.
    line = re.sub(r'(?i)\b[0-9a-f]{24,}\b', '[OPAQUE_ID]', line)
    line = re.sub(r'\s+', ' ', line).strip()
    return line[:HA_ERROR_LOG_MAX_LINE_CHARS]


def _ha_error_log_snapshot(token):
    """Collect a bounded, sanitized Home Assistant system-log excerpt.

    Primary source is the official admin-only ``system_log/list`` WebSocket
    command. This works on Home Assistant OS/Supervised where Supervisor
    intentionally disables the duplicate ``home-assistant.log`` file and the
    legacy ``/api/error_log`` route may therefore be absent. Raw exception
    payloads, source paths and identifiers never leave this function.

    For non-Supervisor/Core-style installations, ``/api/error_log`` remains a
    compatibility fallback. Only aggressively redacted one-line summaries are
    returned to the Portal heartbeat.
    """
    result, ws_error = _ha_diagnostic_websocket_command(token, {'type': 'system_log/list'})
    if not ws_error and isinstance(result, list):
        selected = []
        for entry in result:
            if len(selected) >= HA_ERROR_LOG_MAX_LINES:
                break
            if not isinstance(entry, dict):
                continue
            level = _ha_sanitize_error_log_line(str(entry.get('level', '') or '').upper())[:16]
            logger_name = _ha_sanitize_error_log_line(entry.get('name', ''))[:96]
            messages = entry.get('message')
            if isinstance(messages, list):
                message = next((str(v) for v in reversed(messages) if str(v or '').strip()), '')
            else:
                message = str(messages or '')
            message = _ha_sanitize_error_log_line(message)
            try:
                count = max(1, min(1000000, int(entry.get('count', 1) or 1)))
            except (TypeError, ValueError):
                count = 1
            parts = []
            if level:
                parts.append(level)
            if logger_name:
                parts.append(f'[{logger_name}]')
            if message:
                parts.append(message)
            line = _ha_sanitize_error_log_line(' '.join(parts))
            if count > 1 and line:
                line = _ha_sanitize_error_log_line(f'{line} (x{count})')
            if line:
                selected.append(line)
        return {
            'error_log_available': True,
            'error_log_collection_status': 'ready',
            'error_log_observed_lines': min(100000, len(result)),
            'error_log_selected_count': min(HA_ERROR_LOG_MAX_LINES, len(selected)),
            'error_log_truncated': len(result) > HA_ERROR_LOG_MAX_LINES,
            'error_log_fingerprint': hashlib.sha256('\n'.join(selected).encode('utf-8')).hexdigest() if selected else '',
            'error_log_entries': selected,
        }

    # Compatibility fallback for Core/container installations where a log file
    # exists and Home Assistant registers /api/error_log.
    text, rest_error, truncated = _ha_diagnostic_http_text(token, '/api/error_log')
    if rest_error:
        return {
            'error_log_available': False,
            'error_log_collection_status': ws_error or rest_error or 'invalid_response',
            'error_log_observed_lines': 0,
            'error_log_selected_count': 0,
            'error_log_truncated': bool(truncated),
            'error_log_fingerprint': '',
            'error_log_entries': [],
        }
    lines = [line for line in str(text or '').splitlines() if str(line or '').strip()]
    selected = []
    for line in lines[-HA_ERROR_LOG_MAX_LINES:]:
        sanitized = _ha_sanitize_error_log_line(line)
        if sanitized:
            selected.append(sanitized)
    return {
        'error_log_available': True,
        'error_log_collection_status': 'ready',
        'error_log_observed_lines': min(100000, len(lines)),
        'error_log_selected_count': min(HA_ERROR_LOG_MAX_LINES, len(selected)),
        'error_log_truncated': bool(truncated),
        'error_log_fingerprint': hashlib.sha256('\n'.join(selected).encode('utf-8')).hexdigest() if selected else '',
        'error_log_entries': selected,
    }


def _ha_ws_read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError('websocket_closed')
        data.extend(chunk)
    return bytes(data)


def _ha_ws_send_frame(sock, payload, opcode=0x1):
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    payload = bytes(payload)
    first = 0x80 | (opcode & 0x0F)
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes([first, 0x80 | length])
    elif length <= 0xFFFF:
        header = bytes([first, 0x80 | 126]) + struct.pack('!H', length)
    else:
        header = bytes([first, 0x80 | 127]) + struct.pack('!Q', length)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    sock.sendall(header + mask + masked)


def _ha_ws_receive_json(sock):
    fragments = bytearray()
    current_opcode = None
    while True:
        head = _ha_ws_read_exact(sock, 2)
        first, second = head[0], head[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack('!H', _ha_ws_read_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack('!Q', _ha_ws_read_exact(sock, 8))[0]
        mask = _ha_ws_read_exact(sock, 4) if masked else b''
        payload = _ha_ws_read_exact(sock, length) if length else b''
        if masked:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        if opcode == 0x8:
            raise ConnectionError('websocket_closed')
        if opcode == 0x9:
            _ha_ws_send_frame(sock, payload, opcode=0xA)
            continue
        if opcode == 0xA:
            continue
        if opcode in (0x1, 0x2):
            fragments = bytearray(payload)
            current_opcode = opcode
        elif opcode == 0x0 and current_opcode is not None:
            fragments.extend(payload)
        else:
            continue
        if not fin:
            continue
        if current_opcode != 0x1:
            raise ValueError('unexpected_binary_frame')
        return json.loads(bytes(fragments).decode('utf-8'))


def _ha_diagnostic_websocket_command(token, command, timeout=8):
    """Execute one read-only Home Assistant websocket command.

    This small stdlib-only client exists solely for bounded diagnostics such as
    Repairs registry counts. The access token is used for authentication but is
    never returned, logged, or placed in the Portal heartbeat.
    """
    sock = None
    try:
        profile = _ha_transport_profile(token)
        auth_token = str(profile.get('token', '') or '').strip()
        if not auth_token:
            return None, 'auth_missing'
        sock = socket.create_connection((profile['ws_host'], int(profile['ws_port'])), timeout=timeout)
        sock.settimeout(timeout)
        websocket_key = base64.b64encode(os.urandom(16)).decode('ascii')
        request = (
            f"GET {profile['ws_path']} HTTP/1.1\r\n"
            f"Host: {profile['host_header']}\r\n"
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {websocket_key}\r\n'
            'Sec-WebSocket-Version: 13\r\n\r\n'
        )
        sock.sendall(request.encode('ascii'))
        response = bytearray()
        while b'\r\n\r\n' not in response and len(response) < 16384:
            chunk = sock.recv(1)
            if not chunk:
                break
            response.extend(chunk)
        if not bytes(response).startswith(b'HTTP/1.1 101'):
            return None, 'websocket_handshake_failed'

        auth_required = _ha_ws_receive_json(sock)
        if not isinstance(auth_required, dict) or auth_required.get('type') != 'auth_required':
            return None, 'websocket_auth_protocol'
        _ha_ws_send_frame(sock, json.dumps({'type': 'auth', 'access_token': auth_token}, separators=(',', ':')))
        auth_result = _ha_ws_receive_json(sock)
        if not isinstance(auth_result, dict):
            return None, 'websocket_auth_protocol'
        if auth_result.get('type') == 'auth_invalid':
            return None, 'auth_rejected'
        if auth_result.get('type') != 'auth_ok':
            return None, 'websocket_auth_protocol'

        message = {'id': 1}
        message.update(command if isinstance(command, dict) else {})
        _ha_ws_send_frame(sock, json.dumps(message, separators=(',', ':')))
        for _ in range(20):
            result = _ha_ws_receive_json(sock)
            if not isinstance(result, dict):
                continue
            if result.get('type') == 'result' and int(result.get('id', 0) or 0) == 1:
                if not result.get('success'):
                    return None, 'websocket_command_failed'
                return result.get('result'), ''
        return None, 'websocket_result_timeout'
    except socket.timeout:
        return None, 'websocket_timeout'
    except (ConnectionError, OSError):
        return None, 'websocket_unreachable'
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None, 'websocket_invalid_response'
    except Exception:
        return None, 'websocket_failed'
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _ha_repairs_aggregate(token):
    result, error = _ha_diagnostic_websocket_command(token, {'type': 'repairs/list_issues'})
    aggregate = {
        'repairs_available': False,
        'repairs_active': 0,
        'repairs_warning': 0,
        'repairs_error': 0,
        'repairs_critical': 0,
        'repairs_fixable': 0,
        'repairs_collection_status': error or 'invalid_response',
    }
    if error:
        return aggregate
    issues = result.get('issues') if isinstance(result, dict) else None
    if not isinstance(issues, list):
        return aggregate
    active = []
    for issue in issues:
        if not isinstance(issue, dict) or bool(issue.get('ignored')):
            continue
        active.append(issue)
    aggregate['repairs_available'] = True
    aggregate['repairs_active'] = min(10000, len(active))
    aggregate['repairs_warning'] = min(10000, sum(1 for issue in active if str(issue.get('severity', '') or '').lower() == 'warning'))
    aggregate['repairs_error'] = min(10000, sum(1 for issue in active if str(issue.get('severity', '') or '').lower() == 'error'))
    aggregate['repairs_critical'] = min(10000, sum(1 for issue in active if str(issue.get('severity', '') or '').lower() == 'critical'))
    aggregate['repairs_fixable'] = min(10000, sum(1 for issue in active if bool(issue.get('is_fixable'))))
    aggregate['repairs_collection_status'] = 'ready'
    return aggregate


def _ha_device_registry_aggregate(token, states):
    """Return aggregate device/entity-registry health without exporting identifiers.

    Registry IDs are used only in-memory to correlate entity state to a device.
    They are never returned to the Portal heartbeat.
    """
    devices_result, devices_error = _ha_diagnostic_websocket_command(token, {'type': 'config/device_registry/list'})
    entities_result, entities_error = _ha_diagnostic_websocket_command(token, {'type': 'config/entity_registry/list'})
    aggregate = {
        'device_registry_available': False,
        'devices_total': 0,
        'devices_disabled': 0,
        'devices_attention': 0,
        'devices_unavailable': 0,
        'devices_unknown': 0,
        'devices_low_battery': 0,
        'attention_entities_without_device': 0,
        'entity_registry_total': 0,
        'entity_registry_disabled': 0,
        'device_registry_collection_status': devices_error or 'invalid_response',
        'entity_registry_collection_status': entities_error or 'invalid_response',
    }
    if devices_error or not isinstance(devices_result, list):
        return aggregate
    aggregate['device_registry_available'] = True
    aggregate['devices_total'] = min(100000, len(devices_result))
    aggregate['devices_disabled'] = min(100000, sum(1 for device in devices_result if isinstance(device, dict) and bool(device.get('disabled_by'))))
    aggregate['device_registry_collection_status'] = 'ready'

    if entities_error or not isinstance(entities_result, list):
        return aggregate
    aggregate['entity_registry_total'] = min(200000, len(entities_result))
    aggregate['entity_registry_disabled'] = min(200000, sum(1 for entity in entities_result if isinstance(entity, dict) and bool(entity.get('disabled_by'))))
    aggregate['entity_registry_collection_status'] = 'ready'

    entity_to_device = {}
    for entry in entities_result:
        if not isinstance(entry, dict):
            continue
        entity_id = str(entry.get('entity_id', '') or '').strip()
        device_id = str(entry.get('device_id', '') or '').strip()
        if entity_id and device_id:
            entity_to_device[entity_id] = device_id

    unavailable_devices = set()
    unknown_devices = set()
    low_battery_devices = set()
    attention_without_device = 0
    for entity in states if isinstance(states, list) else []:
        if not isinstance(entity, dict):
            continue
        entity_id = str(entity.get('entity_id', '') or '').strip()
        state = str(entity.get('state', '') or '').strip().lower()
        attributes = entity.get('attributes') if isinstance(entity.get('attributes'), dict) else {}
        category = ''
        if state == 'unavailable':
            category = 'unavailable'
        elif state == 'unknown':
            category = 'unknown'
        elif str(attributes.get('device_class', '') or '').strip().lower() == 'battery':
            try:
                battery_value = float(state)
            except (TypeError, ValueError):
                battery_value = None
            if battery_value is not None and battery_value < HA_DIAGNOSTICS_BATTERY_THRESHOLD:
                category = 'low_battery'
        if not category:
            continue
        device_id = entity_to_device.get(entity_id, '')
        if not device_id:
            attention_without_device += 1
            continue
        if category == 'unavailable':
            unavailable_devices.add(device_id)
        elif category == 'unknown':
            unknown_devices.add(device_id)
        elif category == 'low_battery':
            low_battery_devices.add(device_id)

    attention_devices = unavailable_devices | unknown_devices | low_battery_devices
    aggregate['devices_attention'] = min(100000, len(attention_devices))
    aggregate['devices_unavailable'] = min(100000, len(unavailable_devices))
    aggregate['devices_unknown'] = min(100000, len(unknown_devices))
    aggregate['devices_low_battery'] = min(100000, len(low_battery_devices))
    aggregate['attention_entities_without_device'] = min(100000, attention_without_device)
    return aggregate


def _ha_integration_diagnostics_aggregate(token):
    """Return aggregate config-entry health without exporting entry identifiers.

    Home Assistant config-entry IDs, titles, unique IDs and user-defined names never
    leave the installation. Only bounded state counters are returned to Portal.
    """
    result, error = _ha_diagnostic_websocket_command(token, {'type': 'config_entries/get'})
    aggregate = {
        'integration_diagnostics_available': False,
        'integration_entries_total': 0,
        'integration_domains_total': 0,
        'integration_loaded_entries': 0,
        'integration_disabled_entries': 0,
        'integration_attention_entries': 0,
        'integration_setup_error_entries': 0,
        'integration_retry_entries': 0,
        'integration_migration_error_entries': 0,
        'integration_failed_unload_entries': 0,
        'integration_not_loaded_entries': 0,
        'integration_collection_status': error or 'invalid_response',
    }
    if error or not isinstance(result, list):
        return aggregate

    domains = set()
    counters = {
        'loaded': 0,
        'setup_error': 0,
        'setup_retry': 0,
        'migration_error': 0,
        'failed_unload': 0,
        'not_loaded': 0,
    }
    disabled = 0
    attention = 0
    attention_states = {'setup_error', 'setup_retry', 'migration_error', 'failed_unload'}

    for entry in result:
        if not isinstance(entry, dict):
            continue
        domain = str(entry.get('domain', '') or '').strip().lower()
        if domain and re.fullmatch(r'[a-z0-9_]{1,64}', domain):
            domains.add(domain)
        state = str(entry.get('state', '') or '').strip().lower()
        is_disabled = bool(entry.get('disabled_by'))
        if is_disabled:
            disabled += 1
        if state in counters:
            counters[state] += 1
        # Intentionally disabled entries are inventory context, not attention.
        if not is_disabled and state in attention_states:
            attention += 1

    aggregate.update({
        'integration_diagnostics_available': True,
        'integration_entries_total': min(10000, len(result)),
        'integration_domains_total': min(10000, len(domains)),
        'integration_loaded_entries': min(10000, counters['loaded']),
        'integration_disabled_entries': min(10000, disabled),
        'integration_attention_entries': min(10000, attention),
        'integration_setup_error_entries': min(10000, counters['setup_error']),
        'integration_retry_entries': min(10000, counters['setup_retry']),
        'integration_migration_error_entries': min(10000, counters['migration_error']),
        'integration_failed_unload_entries': min(10000, counters['failed_unload']),
        'integration_not_loaded_entries': min(10000, counters['not_loaded']),
        'integration_collection_status': 'ready',
    })
    return aggregate



def _ha_supervisor_addon_diagnostics_aggregate(token):
    """Read aggregate Supervisor/add-on health through direct Supervisor API.

    Home Assistant 2026 blocks the historical ``supervisor/api`` Core WebSocket
    proxy for add-on-originated traffic. This collector now uses the scoped
    ``SUPERVISOR_TOKEN`` direct API path enabled for Smart Pro Tools. Add-on
    names, slugs, repositories, URLs and options are still discarded locally.
    """
    aggregate = {
        'supervisor_diagnostics_available': False,
        'supervisor_version': '',
        'supervisor_healthy': False,
        'supervisor_supported': False,
        'supervisor_update_available': False,
        'addons_diagnostics_available': False,
        'addons_total': 0,
        'addons_running': 0,
        'addons_stopped': 0,
        'addons_error': 0,
        'addons_unknown': 0,
        'addons_update_available': 0,
        'addons_unavailable': 0,
        'addons_system_managed': 0,
        'supervisor_addons_collection_status': 'not_collected',
    }

    supervisor, supervisor_error = _supervisor_api_json('/supervisor/info', 'GET')
    addons_result, addons_error = _supervisor_api_json('/addons', 'GET')

    supervisor_ready = isinstance(supervisor, dict) and not supervisor_error
    if supervisor_ready:
        aggregate.update({
            'supervisor_diagnostics_available': True,
            'supervisor_version': str(supervisor.get('version', '') or '')[:64],
            'supervisor_healthy': bool(supervisor.get('healthy', False)),
            'supervisor_supported': bool(supervisor.get('supported', False)),
            'supervisor_update_available': bool(supervisor.get('update_available', False)),
        })

    addons = None
    if isinstance(addons_result, dict):
        addons = addons_result.get('addons')
    elif isinstance(addons_result, list):
        addons = addons_result
    addons_ready = isinstance(addons, list) and not addons_error
    if addons_ready:
        counters = {
            'running': 0,
            'stopped': 0,
            'error': 0,
            'unknown': 0,
            'update_available': 0,
            'unavailable': 0,
            'system_managed': 0,
        }
        valid_addons = 0
        for addon in addons:
            if not isinstance(addon, dict):
                continue
            valid_addons += 1
            state = str(addon.get('state', '') or '').strip().lower()
            if state in ('started', 'running'):
                counters['running'] += 1
            elif state == 'stopped':
                counters['stopped'] += 1
            elif state in ('error', 'failed'):
                counters['error'] += 1
            else:
                counters['unknown'] += 1
            if bool(addon.get('update_available', False)):
                counters['update_available'] += 1
            if addon.get('available') is False:
                counters['unavailable'] += 1
            if bool(addon.get('system_managed', False)):
                counters['system_managed'] += 1
        aggregate.update({
            'addons_diagnostics_available': True,
            'addons_total': min(10000, valid_addons),
            'addons_running': min(10000, counters['running']),
            'addons_stopped': min(10000, counters['stopped']),
            'addons_error': min(10000, counters['error']),
            'addons_unknown': min(10000, counters['unknown']),
            'addons_update_available': min(10000, counters['update_available']),
            'addons_unavailable': min(10000, counters['unavailable']),
            'addons_system_managed': min(10000, counters['system_managed']),
        })

    if supervisor_ready and addons_ready:
        status = 'ready'
    elif supervisor_ready:
        status = 'addons_' + (addons_error or 'invalid_response')
    elif addons_ready:
        status = 'supervisor_' + (supervisor_error or 'invalid_response')
    else:
        status = supervisor_error or addons_error or 'invalid_response'
    aggregate['supervisor_addons_collection_status'] = str(status)[:48]
    return aggregate

def _ha_backup_timestamp(value):
    """Parse Supervisor backup ISO timestamp to epoch seconds."""
    raw = str(value or '').strip()
    if not raw:
        return 0
    try:
        if raw.endswith('Z'):
            raw = raw[:-1] + '+00:00'
        parsed = datetime.fromisoformat(raw)
        return max(0, int(parsed.timestamp()))
    except (TypeError, ValueError, OverflowError):
        return 0


def _ha_backup_health_aggregate(token):
    """Read minimal Home Assistant backup-health facts via Supervisor proxy.

    The collector is intentionally inventory-only. Backup names, slugs,
    locations, sizes, passwords and content identifiers are discarded locally.
    It reports only counts plus the newest completed backup that actually
    contains Home Assistant configuration. Backup creation/restore remains a
    separate Smart Pro Tools automation project.
    """
    aggregate = {
        'backup_diagnostics_available': False,
        'backups_total': 0,
        'backups_homeassistant': 0,
        'backups_full': 0,
        'backups_partial': 0,
        'backups_protected': 0,
        'backup_days_until_stale': 0,
        'backup_latest_at': 0,
        'backup_latest_age_seconds': 0,
        'backup_latest_type': '',
        'backup_latest_protected': False,
        'backup_latest_stale': False,
        'backup_collection_status': 'not_collected',
    }
    result, error = _supervisor_api_json('/backups/info', 'GET')
    if error:
        aggregate['backup_collection_status'] = str(error)[:48]
        return aggregate
    if not isinstance(result, dict):
        aggregate['backup_collection_status'] = 'invalid_response'
        return aggregate
    backups = result.get('backups')
    if not isinstance(backups, list):
        aggregate['backup_collection_status'] = 'invalid_backups'
        return aggregate

    days_until_stale = max(0, min(3650, int(result.get('days_until_stale', 0) or 0)))
    total = 0
    with_ha = 0
    full = 0
    partial = 0
    protected = 0
    latest_at = 0
    latest_type = ''
    latest_protected = False
    for backup in backups:
        if not isinstance(backup, dict):
            continue
        total += 1
        backup_type = str(backup.get('type', '') or '').strip().lower()
        if backup_type == 'full':
            full += 1
        elif backup_type == 'partial':
            partial += 1
        if bool(backup.get('protected', False)):
            protected += 1
        content = backup.get('content') if isinstance(backup.get('content'), dict) else {}
        includes_ha = bool(content.get('homeassistant', False))
        if not includes_ha:
            continue
        with_ha += 1
        created_at = _ha_backup_timestamp(backup.get('date'))
        if created_at > latest_at:
            latest_at = created_at
            latest_type = backup_type if backup_type in ('full', 'partial') else 'unknown'
            latest_protected = bool(backup.get('protected', False))

    now = int(time.time())
    age_seconds = max(0, now - latest_at) if latest_at > 0 else 0
    stale = bool(latest_at > 0 and days_until_stale > 0 and age_seconds > days_until_stale * 86400)
    aggregate.update({
        'backup_diagnostics_available': True,
        'backups_total': min(10000, total),
        'backups_homeassistant': min(10000, with_ha),
        'backups_full': min(10000, full),
        'backups_partial': min(10000, partial),
        'backups_protected': min(10000, protected),
        'backup_days_until_stale': days_until_stale,
        'backup_latest_at': latest_at,
        'backup_latest_age_seconds': age_seconds,
        'backup_latest_type': latest_type,
        'backup_latest_protected': latest_protected,
        'backup_latest_stale': stale,
        'backup_collection_status': 'ready',
    })
    return aggregate


def _home_assistant_diagnostics_collect():
    """Collect a strict-whitelist HA runtime/entity-health snapshot.

    The collector intentionally does not export entity IDs, friendly names,
    areas, device identifiers, location data or credentials.
    Device-registry diagnostics are aggregate-only and use registry IDs solely
    in memory for correlation. A bounded /api/error_log excerpt is collected only
    after aggressive redaction; raw device logs remain a separate future milestone.
    """
    now = int(time.time())
    token = str(load_addon_options().get('ha_token', '') or '').strip()
    credential_available = _ha_api_credential_available(token)
    base = {
        'contract': HA_DIAGNOSTICS_CONTRACT_ID,
        'monitored': False,
        'configured': credential_available,
        'health_state': 'waiting',
        'reason_code': 'missing_token' if not credential_available else 'collecting',
        'collected_at': now,
        'home_assistant_version': '',
        'core_state': '',
        'safe_mode': False,
        'total_entities': 0,
        'unavailable_entities': 0,
        'unknown_entities': 0,
        'low_battery_entities': 0,
        'updates_pending': 0,
        'updates_detected': 0,
        'updates_skipped': 0,
        'repairs_available': False,
        'repairs_active': 0,
        'repairs_warning': 0,
        'repairs_error': 0,
        'repairs_critical': 0,
        'repairs_fixable': 0,
        'repairs_collection_status': 'not_collected',
        'device_registry_available': False,
        'devices_total': 0,
        'devices_disabled': 0,
        'devices_attention': 0,
        'devices_unavailable': 0,
        'devices_unknown': 0,
        'devices_low_battery': 0,
        'attention_entities_without_device': 0,
        'entity_registry_total': 0,
        'entity_registry_disabled': 0,
        'device_registry_collection_status': 'not_collected',
        'entity_registry_collection_status': 'not_collected',
        'integration_diagnostics_available': False,
        'integration_entries_total': 0,
        'integration_domains_total': 0,
        'integration_loaded_entries': 0,
        'integration_disabled_entries': 0,
        'integration_attention_entries': 0,
        'integration_setup_error_entries': 0,
        'integration_retry_entries': 0,
        'integration_migration_error_entries': 0,
        'integration_failed_unload_entries': 0,
        'integration_not_loaded_entries': 0,
        'integration_collection_status': 'not_collected',
        'supervisor_diagnostics_available': False,
        'supervisor_version': '',
        'supervisor_healthy': False,
        'supervisor_supported': False,
        'supervisor_update_available': False,
        'addons_diagnostics_available': False,
        'addons_total': 0,
        'addons_running': 0,
        'addons_stopped': 0,
        'addons_error': 0,
        'addons_unknown': 0,
        'addons_update_available': 0,
        'addons_unavailable': 0,
        'addons_system_managed': 0,
        'supervisor_addons_collection_status': 'not_collected',
        'backup_diagnostics_available': False,
        'backups_total': 0,
        'backups_homeassistant': 0,
        'backups_full': 0,
        'backups_partial': 0,
        'backups_protected': 0,
        'backup_days_until_stale': 0,
        'backup_latest_at': 0,
        'backup_latest_age_seconds': 0,
        'backup_latest_type': '',
        'backup_latest_protected': False,
        'backup_latest_stale': False,
        'backup_collection_status': 'not_collected',
        'error_log_available': False,
        'error_log_collection_status': 'not_collected',
        'error_log_observed_lines': 0,
        'error_log_selected_count': 0,
        'error_log_truncated': False,
        'error_log_fingerprint': '',
        'error_log_entries': [],
        'battery_threshold_percent': HA_DIAGNOSTICS_BATTERY_THRESHOLD,
    }

    access = subscription_service_access('backup_health')
    if not access.get('allowed'):
        base.update({
            'configured': credential_available,
            'health_state': 'waiting',
            'reason_code': 'service_access_inactive',
            'service_access_reason': str(access.get('reason_code', '') or '')[:64],
        })
        return base

    if not credential_available:
        return base

    config, config_error = _ha_diagnostic_http_json(token, '/api/config')
    if config_error:
        base.update({'health_state': 'error', 'reason_code': config_error})
        return base
    if not isinstance(config, dict):
        base.update({'health_state': 'error', 'reason_code': 'invalid_config'})
        return base

    states, states_error = _ha_diagnostic_http_json(token, '/api/states')
    if states_error:
        base.update({
            'monitored': True,
            'home_assistant_version': str(config.get('version', '') or '')[:64],
            'core_state': str(config.get('state', '') or '')[:32].upper(),
            'safe_mode': bool(config.get('safe_mode', False)),
            'health_state': 'error',
            'reason_code': states_error,
        })
        return base
    if not isinstance(states, list):
        base.update({'health_state': 'error', 'reason_code': 'invalid_states'})
        return base

    unavailable = 0
    unknown = 0
    low_battery = 0
    updates_detected = 0
    updates_pending = 0
    updates_skipped = 0
    for entity in states:
        if not isinstance(entity, dict):
            continue
        state = str(entity.get('state', '') or '').strip().lower()
        if state == 'unavailable':
            unavailable += 1
        elif state == 'unknown':
            unknown += 1

        entity_id = str(entity.get('entity_id', '') or '')
        attributes = entity.get('attributes') if isinstance(entity.get('attributes'), dict) else {}
        if entity_id.startswith('update.') and state == 'on':
            updates_detected += 1
            skipped_version = str(attributes.get('skipped_version', '') or '').strip()
            latest_version = str(attributes.get('latest_version', '') or '').strip()
            is_skipped = bool(skipped_version) and (not latest_version or skipped_version == latest_version)
            if is_skipped:
                updates_skipped += 1
            else:
                updates_pending += 1
        if str(attributes.get('device_class', '') or '').strip().lower() == 'battery':
            try:
                battery_value = float(state)
            except (TypeError, ValueError):
                battery_value = None
            if battery_value is not None and battery_value < HA_DIAGNOSTICS_BATTERY_THRESHOLD:
                low_battery += 1

    repairs = _ha_repairs_aggregate(token)
    devices = _ha_device_registry_aggregate(token, states)
    integrations = _ha_integration_diagnostics_aggregate(token)
    supervisor_addons = _ha_supervisor_addon_diagnostics_aggregate(token)
    backup_health = _ha_backup_health_aggregate(token)
    error_log = _ha_error_log_snapshot(token)

    core_state = str(config.get('state', '') or '').strip().upper()[:32]
    safe_mode = bool(config.get('safe_mode', False))
    health_state = 'healthy'
    reason_code = 'ok'
    if safe_mode or (core_state not in ('', 'RUNNING')):
        health_state = 'attention'
        reason_code = 'core_attention'
    elif unavailable > 0 or unknown > 0 or low_battery > 0:
        health_state = 'attention'
        reason_code = 'entity_attention'

    base.update({
        'monitored': True,
        'configured': True,
        'health_state': health_state,
        'reason_code': reason_code,
        'home_assistant_version': str(config.get('version', '') or '')[:64],
        'core_state': core_state,
        'safe_mode': safe_mode,
        'total_entities': min(100000, len(states)),
        'unavailable_entities': min(100000, unavailable),
        'unknown_entities': min(100000, unknown),
        'low_battery_entities': min(100000, low_battery),
        'updates_pending': min(100000, updates_pending),
        'updates_detected': min(100000, updates_detected),
        'updates_skipped': min(100000, updates_skipped),
        'repairs_available': bool(repairs.get('repairs_available')),
        'repairs_active': min(10000, int(repairs.get('repairs_active', 0) or 0)),
        'repairs_warning': min(10000, int(repairs.get('repairs_warning', 0) or 0)),
        'repairs_error': min(10000, int(repairs.get('repairs_error', 0) or 0)),
        'repairs_critical': min(10000, int(repairs.get('repairs_critical', 0) or 0)),
        'repairs_fixable': min(10000, int(repairs.get('repairs_fixable', 0) or 0)),
        'repairs_collection_status': str(repairs.get('repairs_collection_status', '') or '')[:48],
        'device_registry_available': bool(devices.get('device_registry_available')),
        'devices_total': min(100000, int(devices.get('devices_total', 0) or 0)),
        'devices_disabled': min(100000, int(devices.get('devices_disabled', 0) or 0)),
        'devices_attention': min(100000, int(devices.get('devices_attention', 0) or 0)),
        'devices_unavailable': min(100000, int(devices.get('devices_unavailable', 0) or 0)),
        'devices_unknown': min(100000, int(devices.get('devices_unknown', 0) or 0)),
        'devices_low_battery': min(100000, int(devices.get('devices_low_battery', 0) or 0)),
        'attention_entities_without_device': min(100000, int(devices.get('attention_entities_without_device', 0) or 0)),
        'entity_registry_total': min(200000, int(devices.get('entity_registry_total', 0) or 0)),
        'entity_registry_disabled': min(200000, int(devices.get('entity_registry_disabled', 0) or 0)),
        'device_registry_collection_status': str(devices.get('device_registry_collection_status', '') or '')[:48],
        'entity_registry_collection_status': str(devices.get('entity_registry_collection_status', '') or '')[:48],
        'integration_diagnostics_available': bool(integrations.get('integration_diagnostics_available')),
        'integration_entries_total': min(10000, int(integrations.get('integration_entries_total', 0) or 0)),
        'integration_domains_total': min(10000, int(integrations.get('integration_domains_total', 0) or 0)),
        'integration_loaded_entries': min(10000, int(integrations.get('integration_loaded_entries', 0) or 0)),
        'integration_disabled_entries': min(10000, int(integrations.get('integration_disabled_entries', 0) or 0)),
        'integration_attention_entries': min(10000, int(integrations.get('integration_attention_entries', 0) or 0)),
        'integration_setup_error_entries': min(10000, int(integrations.get('integration_setup_error_entries', 0) or 0)),
        'integration_retry_entries': min(10000, int(integrations.get('integration_retry_entries', 0) or 0)),
        'integration_migration_error_entries': min(10000, int(integrations.get('integration_migration_error_entries', 0) or 0)),
        'integration_failed_unload_entries': min(10000, int(integrations.get('integration_failed_unload_entries', 0) or 0)),
        'integration_not_loaded_entries': min(10000, int(integrations.get('integration_not_loaded_entries', 0) or 0)),
        'integration_collection_status': str(integrations.get('integration_collection_status', '') or '')[:48],
        'supervisor_diagnostics_available': bool(supervisor_addons.get('supervisor_diagnostics_available')),
        'supervisor_version': str(supervisor_addons.get('supervisor_version', '') or '')[:64],
        'supervisor_healthy': bool(supervisor_addons.get('supervisor_healthy')),
        'supervisor_supported': bool(supervisor_addons.get('supervisor_supported')),
        'supervisor_update_available': bool(supervisor_addons.get('supervisor_update_available')),
        'addons_diagnostics_available': bool(supervisor_addons.get('addons_diagnostics_available')),
        'addons_total': min(10000, int(supervisor_addons.get('addons_total', 0) or 0)),
        'addons_running': min(10000, int(supervisor_addons.get('addons_running', 0) or 0)),
        'addons_stopped': min(10000, int(supervisor_addons.get('addons_stopped', 0) or 0)),
        'addons_error': min(10000, int(supervisor_addons.get('addons_error', 0) or 0)),
        'addons_unknown': min(10000, int(supervisor_addons.get('addons_unknown', 0) or 0)),
        'addons_update_available': min(10000, int(supervisor_addons.get('addons_update_available', 0) or 0)),
        'addons_unavailable': min(10000, int(supervisor_addons.get('addons_unavailable', 0) or 0)),
        'addons_system_managed': min(10000, int(supervisor_addons.get('addons_system_managed', 0) or 0)),
        'supervisor_addons_collection_status': str(supervisor_addons.get('supervisor_addons_collection_status', '') or '')[:48],
        'backup_diagnostics_available': bool(backup_health.get('backup_diagnostics_available')),
        'backups_total': min(10000, int(backup_health.get('backups_total', 0) or 0)),
        'backups_homeassistant': min(10000, int(backup_health.get('backups_homeassistant', 0) or 0)),
        'backups_full': min(10000, int(backup_health.get('backups_full', 0) or 0)),
        'backups_partial': min(10000, int(backup_health.get('backups_partial', 0) or 0)),
        'backups_protected': min(10000, int(backup_health.get('backups_protected', 0) or 0)),
        'backup_days_until_stale': min(3650, int(backup_health.get('backup_days_until_stale', 0) or 0)),
        'backup_latest_at': max(0, int(backup_health.get('backup_latest_at', 0) or 0)),
        'backup_latest_age_seconds': max(0, int(backup_health.get('backup_latest_age_seconds', 0) or 0)),
        'backup_latest_type': str(backup_health.get('backup_latest_type', '') or '')[:16],
        'backup_latest_protected': bool(backup_health.get('backup_latest_protected')),
        'backup_latest_stale': bool(backup_health.get('backup_latest_stale')),
        'backup_collection_status': str(backup_health.get('backup_collection_status', '') or '')[:48],
        'error_log_available': bool(error_log.get('error_log_available')),
        'error_log_collection_status': str(error_log.get('error_log_collection_status', '') or '')[:48],
        'error_log_observed_lines': min(100000, int(error_log.get('error_log_observed_lines', 0) or 0)),
        'error_log_selected_count': min(HA_ERROR_LOG_MAX_LINES, int(error_log.get('error_log_selected_count', 0) or 0)),
        'error_log_truncated': bool(error_log.get('error_log_truncated')),
        'error_log_fingerprint': str(error_log.get('error_log_fingerprint', '') or '')[:64],
        'error_log_entries': [
            str(line or '')[:HA_ERROR_LOG_MAX_LINE_CHARS]
            for line in list(error_log.get('error_log_entries') or [])[:HA_ERROR_LOG_MAX_LINES]
            if str(line or '').strip()
        ],
    })
    return base


def home_assistant_diagnostics_snapshot(force=False):
    """Return a cached, JSON-safe HA diagnostics snapshot for Portal heartbeat."""
    now = int(time.time())
    with HA_DIAGNOSTICS_LOCK:
        collected_at = int(HA_DIAGNOSTICS_STATE.get('collected_at', 0) or 0)
        if not force and collected_at > 0 and now - collected_at < HA_DIAGNOSTICS_REFRESH_SECONDS:
            return dict(HA_DIAGNOSTICS_STATE)

    collected = _home_assistant_diagnostics_collect()
    with HA_DIAGNOSTICS_LOCK:
        HA_DIAGNOSTICS_STATE.clear()
        HA_DIAGNOSTICS_STATE.update(collected)
        return dict(HA_DIAGNOSTICS_STATE)


def clamp_number(value, default, minimum, maximum):
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = float(default)
    return max(float(minimum), min(number, float(maximum)))


def create_tech_session():
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + TECH_SESSION_TTL_SECONDS
    with TECH_SESSION_LOCK:
        now = int(time.time())
        expired = [key for key, expiry in TECH_SESSIONS.items() if expiry <= now]
        for key in expired:
            TECH_SESSIONS.pop(key, None)
        TECH_SESSIONS[token] = expires_at
    return token, expires_at


def tech_session_authorized(handler):
    authorization = str(handler.headers.get('Authorization', '')).strip()
    if not authorization.lower().startswith('bearer '):
        return False
    token = authorization.split(' ', 1)[1].strip()
    if not token:
        return False
    now = int(time.time())
    with TECH_SESSION_LOCK:
        expires_at = int(TECH_SESSIONS.get(token, 0) or 0)
        if expires_at <= now:
            TECH_SESSIONS.pop(token, None)
            return False
        TECH_SESSIONS[token] = now + TECH_SESSION_TTL_SECONDS
    return True


def watchdog_test_public_status():
    now = time.time()
    expired_entity_id = ''
    with WATCHDOG_TEST_LOCK:
        status = str(WATCHDOG_TEST_STATE.get('status', 'idle'))
        finished_at = float(WATCHDOG_TEST_STATE.get('finished_at', 0) or 0)
        if status in WATCHDOG_TERMINAL_STATUSES and finished_at and now - finished_at >= 10:
            expired_entity_id = str(WATCHDOG_TEST_STATE.get('entity_id', ''))
            WATCHDOG_TEST_STATE.clear()
            WATCHDOG_TEST_STATE.update({
                'status': 'idle',
                'message': 'Δεν εκτελείται δοκιμή.',
            })
        state = dict(WATCHDOG_TEST_STATE)
    if expired_entity_id:
        OFFLINE_DEVICES.pop(expired_entity_id, None)
    due_at = float(state.get('due_at', 0) or 0)
    clear_at = float(state.get('clear_at', 0) or 0)
    state['seconds_until_request'] = max(0, int(round(due_at - now))) if due_at else 0
    state['seconds_until_clear'] = max(0, int(round(clear_at - now))) if clear_at else 0
    return state


def set_watchdog_test_state(**updates):
    with WATCHDOG_TEST_LOCK:
        WATCHDOG_TEST_STATE.update(updates)
        return dict(WATCHDOG_TEST_STATE)


def acknowledge_watchdog_test_result():
    """Return terminal test state to idle after the UI has displayed it."""
    with WATCHDOG_TEST_LOCK:
        status = str(WATCHDOG_TEST_STATE.get('status', 'idle'))
        entity_id = str(WATCHDOG_TEST_STATE.get('entity_id', ''))
        if status not in WATCHDOG_TERMINAL_STATUSES:
            return dict(WATCHDOG_TEST_STATE)
        WATCHDOG_TEST_STATE.clear()
        WATCHDOG_TEST_STATE.update({
            'status': 'idle',
            'message': 'Δεν εκτελείται δοκιμή.',
        })
    if entity_id:
        OFFLINE_DEVICES.pop(entity_id, None)
    return watchdog_test_public_status()


def start_watchdog_test(test_options):
    tech_config = load_tech_settings()
    if not subscription_entitlement_allowed('guardian_monitoring', tech_config):
        raise ValueError('Η υπηρεσία Φρουρού δεν είναι ενεργή για αυτή την εγκατάσταση.')
    if not tech_config.get('watchdog_enabled', True):
        raise ValueError('Ενεργοποίησε πρώτα τον Φρουρό.')

    connection = load_portal_connection()
    if not str(connection.get('installation_token', '')).strip():
        raise ValueError('Η εγκατάσταση δεν είναι συνδεδεμένη με το Portal.')

    addon_options = load_addon_options()
    configured_token = str(addon_options.get('ha_token', '') or '').strip()
    if not _ha_api_credential_available(configured_token):
        raise ValueError('Δεν υπάρχει διαθέσιμο Home Assistant API credential.')

    delay_sec = int(round(clamp_number(
        test_options.get('delay_seconds', tech_config.get('watchdog_test_delay_sec', 10)),
        10, 3, 300,
    )))
    clear_sec = int(round(clamp_number(
        test_options.get('clear_seconds', tech_config.get('watchdog_test_clear_sec', 30)),
        30, 5, 600,
    )))
    device_name = re.sub(r'\s+', ' ', str(
        test_options.get('device_name', tech_config.get('watchdog_test_device_name', 'Δοκιμαστική συσκευή Φρουρού'))
    )).strip()[:80]
    if not device_name:
        device_name = 'Δοκιμαστική συσκευή Φρουρού'
    send_email = bool(test_options.get('send_email', tech_config.get('watchdog_test_send_email', False)))

    now = time.time()
    with WATCHDOG_TEST_LOCK:
        current_status = str(WATCHDOG_TEST_STATE.get('status', 'idle'))
        if current_status in ('scheduled', 'running', 'request_created'):
            raise ValueError('Υπάρχει ήδη ενεργή δοκιμή Φρουρού.')

        test_id = secrets.token_hex(8)
        entity_id = f'sensor.smart_pro_watchdog_test_{test_id}'
        WATCHDOG_TEST_STATE.clear()
        WATCHDOG_TEST_STATE.update({
            'status': 'scheduled',
            'message': 'Η ασφαλής προσομοίωση προγραμματίστηκε.',
            'test_id': test_id,
            'entity_id': entity_id,
            'device_name': device_name,
            'started_at': int(now),
            'due_at': int(now + delay_sec),
            'clear_at': int(now + delay_sec + clear_sec),
            'delay_seconds': delay_sec,
            'clear_seconds': clear_sec,
            'send_email': send_email,
            'request_code': '',
            'error': '',
        })

    tech_config['watchdog_test_delay_sec'] = delay_sec
    tech_config['watchdog_test_clear_sec'] = clear_sec
    tech_config['watchdog_test_device_name'] = device_name
    tech_config['watchdog_test_send_email'] = send_email
    save_tech_settings(tech_config)
    return watchdog_test_public_status()


def cancel_watchdog_test():
    """Stop only the virtual Watchdog test and clean it up immediately."""
    now = int(time.time())
    with WATCHDOG_TEST_LOCK:
        previous_status = str(WATCHDOG_TEST_STATE.get('status', 'idle'))
        entity_id = str(WATCHDOG_TEST_STATE.get('entity_id', ''))
        request_code = str(WATCHDOG_TEST_STATE.get('request_code', ''))

        if previous_status not in ('scheduled', 'running', 'request_created'):
            state = dict(WATCHDOG_TEST_STATE)
            state['action_message'] = 'Δεν υπάρχει ενεργή δοκιμή για ακύρωση.'
            return state

        request_already_created = previous_status == 'request_created'
        if request_already_created:
            message = (
                'Η προσομοίωση καθαρίστηκε και η εικονική οντότητα '
                'επανήλθε σε κανονική κατάσταση. Το δοκιμαστικό αίτημα '
                'παραμένει ενεργό στο Portal και ολοκληρώνεται χειροκίνητα.'
            )
        else:
            message = (
                'Η δοκιμή ακυρώθηκε πριν δημιουργηθεί αίτημα. '
                'Η εικονική οντότητα επανήλθε σε κανονική κατάσταση.'
            )

        WATCHDOG_TEST_STATE.update({
            'status': 'cancelled',
            'message': message,
            'clear_at': now,
            'cancelled_at': now,
            'finished_at': now,
            'cancelled_after_request': request_already_created,
            'action_message': message,
            'request_code': request_code,
        })

    # Do not wait for the Watchdog loop: remove the simulation immediately.
    if entity_id:
        OFFLINE_DEVICES.pop(entity_id, None)
    return watchdog_test_public_status()


def synchronize_watchdog_test(tech_config, now_dt, now_ts):
    with WATCHDOG_TEST_LOCK:
        state = dict(WATCHDOG_TEST_STATE)

    status = str(state.get('status', 'idle'))
    entity_id = str(state.get('entity_id', ''))
    if not entity_id:
        return

    if status == 'cancelled':
        OFFLINE_DEVICES.pop(entity_id, None)
        return

    if status in ('completed', 'failed', 'expired'):
        OFFLINE_DEVICES.pop(entity_id, None)
        return

    if not subscription_entitlement_allowed('guardian_monitoring', tech_config):
        OFFLINE_DEVICES.pop(entity_id, None)
        set_watchdog_test_state(status='failed', message='Η δοκιμή σταμάτησε επειδή η υπηρεσία Φρουρού δεν είναι ενεργή.', finished_at=int(now_ts))
        return

    if not tech_config.get('watchdog_enabled', True):
        OFFLINE_DEVICES.pop(entity_id, None)
        set_watchdog_test_state(status='failed', message='Η δοκιμή σταμάτησε επειδή απενεργοποιήθηκε ο Φρουρός.', finished_at=int(now_ts))
        return

    clear_at = float(state.get('clear_at', 0) or 0)
    if clear_at and now_ts >= clear_at:
        OFFLINE_DEVICES.pop(entity_id, None)
        if status == 'request_created':
            set_watchdog_test_state(status='completed', message='Η δοκιμή ολοκληρώθηκε. Η εικονική οντότητα επανήλθε σε κανονική κατάσταση.', finished_at=int(now_ts))
        else:
            set_watchdog_test_state(status='expired', message='Η δοκιμή έληξε χωρίς να δημιουργηθεί αίτημα.', finished_at=int(now_ts))
        return

    if status == 'scheduled' and entity_id not in OFFLINE_DEVICES:
        due_at = float(state.get('due_at', now_ts) or now_ts)
        OFFLINE_DEVICES[entity_id] = {
            'time_down': now_dt,
            'alerted': False,
            'simulated': True,
            'alert_after_seconds': max(0, due_at - now_ts),
            'test_id': state.get('test_id', ''),
            'friendly_name': state.get('device_name', 'Δοκιμαστική συσκευή Φρουρού'),
            'send_email': bool(state.get('send_email', False)),
        }
        set_watchdog_test_state(status='running', message='Η εικονική συσκευή τέθηκε εκτός σύνδεσης.')


def smart_updates_test_public_status():
    """Return a safe copy of the latest Smart Updates simulation result."""
    with SMART_UPDATES_TEST_LOCK:
        return json.loads(json.dumps(SMART_UPDATES_TEST_STATE, ensure_ascii=False))


def _smart_updates_test_step(key, label, status, detail):
    return {
        'key': str(key),
        'label': str(label),
        'status': str(status),
        'detail': str(detail),
    }


def run_smart_updates_safe_test(test_options):
    """Simulate the update decision tree without calling Home Assistant services."""
    tech_config = load_tech_settings()
    if not subscription_entitlement_allowed('update_guidance', tech_config):
        raise ValueError('Η υπηρεσία Smart Updates δεν είναι ενεργή για αυτή την εγκατάσταση.')
    if tech_config.get('auto_update_enabled', False):
        raise ValueError(
            'Κλείσε πρώτα τον κεντρικό διακόπτη Smart Updates & Rollback '
            'και αποθήκευσε τη ρύθμιση.'
        )

    scenario = str((test_options or {}).get('scenario', 'notify_only')).strip()
    if scenario not in SMART_UPDATES_TEST_SCENARIOS:
        raise ValueError('Μη έγκυρο σενάριο ασφαλούς δοκιμής.')

    wait_days = int(clamp_number(tech_config.get('update_wait_days', 3), 3, 0, 365))
    offline_limit = int(clamp_number(
        tech_config.get('update_rollback_offline_count', 2),
        2, 1, 1000,
    ))
    scenario_label = SMART_UPDATES_TEST_SCENARIOS[scenario]
    steps = [
        _smart_updates_test_step(
            'master_guard',
            'Κεντρικός διακόπτης',
            'passed',
            'Επιβεβαιώθηκε κλειστός. Η πραγματική ωριαία ροή παραμένει ανενεργή.',
        ),
        _smart_updates_test_step(
            'update_detected',
            'Εντοπισμός ενημέρωσης',
            'passed',
            'Δημιουργήθηκε μόνο εικονική διαθέσιμη ενημέρωση.',
        ),
        _smart_updates_test_step(
            'maturity',
            'Περίοδος ωρίμανσης',
            'passed',
            f'Προσομοιώθηκε ότι ολοκληρώθηκαν οι {wait_days} ημέρες αναμονής.',
        ),
    ]

    if scenario == 'notify_only':
        steps.extend([
            _smart_updates_test_step(
                'notification',
                'Ειδοποίηση',
                'passed',
                'Προσομοιώθηκε μία ειδοποίηση χωρίς επανάληψη.',
            ),
            _smart_updates_test_step(
                'backup',
                'Backup',
                'skipped',
                'Παραλείφθηκε σωστά λόγω λειτουργίας μόνο ειδοποίησης.',
            ),
            _smart_updates_test_step(
                'install',
                'Εγκατάσταση',
                'skipped',
                'Δεν εκτελέστηκε εγκατάσταση.',
            ),
            _smart_updates_test_step(
                'health_check',
                'Έλεγχος υγείας',
                'skipped',
                'Δεν απαιτείται, επειδή δεν έγινε εγκατάσταση.',
            ),
            _smart_updates_test_step(
                'rollback',
                'Rollback',
                'skipped',
                'Δεν απαιτείται.',
            ),
        ])
        final_status = 'passed'
        message = 'Η ροή μόνο ειδοποίησης ολοκληρώθηκε σωστά.'

    elif scenario == 'backup_failure':
        steps.extend([
            _smart_updates_test_step(
                'backup',
                'Backup',
                'simulated_failure',
                'Προσομοιώθηκε αποτυχία δημιουργίας επιβεβαιωμένου backup.',
            ),
            _smart_updates_test_step(
                'install',
                'Εγκατάσταση',
                'blocked',
                'Μπλοκαρίστηκε σωστά επειδή δεν υπάρχει ασφαλές backup.',
            ),
            _smart_updates_test_step(
                'health_check',
                'Έλεγχος υγείας',
                'skipped',
                'Δεν απαιτείται.',
            ),
            _smart_updates_test_step(
                'rollback',
                'Rollback',
                'skipped',
                'Δεν έγινε εγκατάσταση, άρα δεν απαιτείται rollback.',
            ),
        ])
        final_status = 'expected_stop'
        message = 'Η ροή σταμάτησε σωστά μετά την προσομοιωμένη αποτυχία backup.'

    elif scenario == 'update_failure':
        steps.extend([
            _smart_updates_test_step(
                'backup',
                'Backup',
                'passed',
                'Προσομοιώθηκε επιβεβαιωμένο backup με ασφαλές slug.',
            ),
            _smart_updates_test_step(
                'install',
                'Εγκατάσταση',
                'simulated_failure',
                'Προσομοιώθηκε απόρριψη της εντολής εγκατάστασης.',
            ),
            _smart_updates_test_step(
                'health_check',
                'Έλεγχος υγείας',
                'blocked',
                'Δεν εκτελέστηκε ψεύτικη αξιολόγηση επιτυχίας.',
            ),
            _smart_updates_test_step(
                'rollback',
                'Rollback',
                'skipped',
                'Δεν ξεκίνησε εγκατάσταση, άρα δεν στάλθηκε rollback.',
            ),
        ])
        final_status = 'expected_stop'
        message = 'Η ροή σταμάτησε σωστά μετά την προσομοιωμένη αποτυχία εγκατάστασης.'

    else:
        steps.extend([
            _smart_updates_test_step(
                'backup',
                'Backup',
                'passed',
                'Προσομοιώθηκε επιβεβαιωμένο backup με ασφαλές slug.',
            ),
            _smart_updates_test_step(
                'install',
                'Εγκατάσταση',
                'passed',
                'Προσομοιώθηκε αποδοχή της εντολής εγκατάστασης.',
            ),
        ])

        if scenario == 'success':
            steps.extend([
                _smart_updates_test_step(
                    'health_check',
                    'Έλεγχος υγείας',
                    'passed',
                    f'Προσομοιώθηκαν 0 νέες offline συσκευές (όριο: {offline_limit}).',
                ),
                _smart_updates_test_step(
                    'rollback',
                    'Rollback',
                    'skipped',
                    'Δεν απαιτείται.',
                ),
            ])
            final_status = 'passed'
            message = 'Η επιτυχής ροή ενημέρωσης ολοκληρώθηκε σωστά.'
        else:
            steps.append(
                _smart_updates_test_step(
                    'health_check',
                    'Έλεγχος υγείας',
                    'simulated_failure',
                    (
                        f'Προσομοιώθηκαν {offline_limit} νέες offline συσκευές '
                        f'(όριο: {offline_limit}).'
                    ),
                )
            )
            if scenario == 'rollback_success':
                steps.append(
                    _smart_updates_test_step(
                        'rollback',
                        'Rollback',
                        'passed',
                        'Προσομοιώθηκε αποδοχή επαναφοράς στο συγκεκριμένο backup slug.',
                    )
                )
                final_status = 'passed'
                message = 'Η ροή αποτυχίας και επιτυχούς rollback ολοκληρώθηκε σωστά.'
            else:
                steps.append(
                    _smart_updates_test_step(
                        'rollback',
                        'Rollback',
                        'critical',
                        'Προσομοιώθηκε απόρριψη rollback και ανάγκη άμεσου χειροκίνητου ελέγχου.',
                    )
                )
                final_status = 'critical'
                message = 'Η κρίσιμη διαδρομή αποτυχίας rollback εμφανίστηκε σωστά.'

    result = {
        'status': final_status,
        'message': message,
        'scenario': scenario,
        'scenario_label': scenario_label,
        'test_id': secrets.token_hex(8),
        'started_at': int(time.time()),
        'finished_at': int(time.time()),
        'steps': steps,
        'auto_update_enabled': False,
        'master_switch_unchanged': True,
        'real_actions_executed': False,
        'safety_message': (
            'Προσομοίωση μόνο: δεν κλήθηκαν υπηρεσίες backup, update ή restore '
            'και δεν άλλαξε καμία ρύθμιση.'
        ),
    }
    with SMART_UPDATES_TEST_LOCK:
        SMART_UPDATES_TEST_STATE.clear()
        SMART_UPDATES_TEST_STATE.update(result)

    print(
        f"[SMART UPDATES TEST] scenario={scenario} status={final_status} "
        "real_actions=0 master_switch_changed=0",
        flush=True,
    )
    return smart_updates_test_public_status()


# -------------------------------------------------------------------
# ΝΕΟΣ ΕΓΚΕΦΑΛΟΣ: SMART UPDATES & ROLLBACK
# -------------------------------------------------------------------
def smart_updates_loop():
    while True:
        time.sleep(3600) # Ελέγχει κάθε 1 ώρα
        try:
            tech_config = load_tech_settings()
            if not subscription_entitlement_allowed('update_guidance', tech_config) or not tech_config.get('auto_update_enabled', False):
                continue
                
            if not os.path.exists('/data/options.json'): continue
            with open('/data/options.json') as f: ha_config = json.load(f)
            token = ha_config.get('ha_token', '').strip()
            if not _ha_api_credential_available(token):
                continue

            states = get_ha_states(token)
            important_domains = get_monitored_domains(tech_config)
            known_updates = tech_config.get('known_updates', {})
            notified_updates = tech_config.get('notified_updates', {})
            if not isinstance(known_updates, dict):
                known_updates = {}
            if not isinstance(notified_updates, dict):
                notified_updates = {}
            wait_days = int(tech_config.get('update_wait_days', 3))
            
            now_ts = time.time()
            changes_made = False
            
            for st in states:
                eid = st.get('entity_id', '')
                state = st.get('state', '')
                if eid.startswith('update.'):
                    is_core = (
                        eid == 'update.home_assistant_core_update'
                        or 'home_assistant_core' in eid
                    )
                    is_os = (
                        eid in {
                            'update.home_assistant_operating_system_update',
                            'update.home_assistant_supervisor_update',
                        }
                        or 'home_assistant_operating_system' in eid
                        or 'home_assistant_supervisor' in eid
                    )
                    
                    allowed = False
                    if is_core and tech_config.get('update_core', True): allowed = True
                    elif is_os and tech_config.get('update_os', True): allowed = True
                    elif not is_core and not is_os and tech_config.get('update_addons', True): allowed = True
                    
                    if allowed and state == 'on':
                        if eid not in known_updates:
                            known_updates[eid] = now_ts
                            changes_made = True
                        else:
                            days_passed = (now_ts - known_updates[eid]) / 86400.0
                            if days_passed >= wait_days:
                                # Η ΕΝΗΜΕΡΩΣΗ ΩΡΙΜΑΣΕ - ΕΚΚΙΝΗΣΗ ΔΙΑΔΙΚΑΣΙΑΣ
                                friendly = st.get('attributes', {}).get('friendly_name', eid)
                                backup_wait = int(tech_config.get('update_backup_wait_min', 15))
                                eval_wait = int(tech_config.get('update_eval_min', 20))
                                limit = int(tech_config.get('update_rollback_offline_count', 2))
                                notify_only = tech_config.get('update_notify_only', False)

                                # Σε λειτουργία μόνο ειδοποίησης δεν επιτρέπεται καμία
                                # μεταβολή στο Home Assistant: ούτε backup ούτε update.
                                if notify_only:
                                    if eid not in notified_updates:
                                        send_email_alert(
                                            '🔔 Διαθέσιμη Ενημέρωση',
                                            (
                                                f"Η ενημέρωση '{friendly}' έχει ολοκληρώσει "
                                                f"την περίοδο αναμονής των {wait_days} ημερών.\n\n"
                                                "Η ρύθμιση «Μόνο ειδοποίηση» είναι ενεργή. "
                                                "Δεν λήφθηκε backup και δεν ξεκίνησε εγκατάσταση."
                                            ),
                                            tech_config,
                                        )
                                        notified_updates[eid] = now_ts
                                        changes_made = True
                                    continue

                                # Re-check the service contract immediately before the first
                                # Home Assistant mutation. This closes the window where a
                                # subscription could become inactive after the hourly scan began.
                                if not subscription_entitlement_allowed('update_guidance', tech_config):
                                    continue

                                send_email_alert('🔄 Έναρξη Αυτόματης Ενημέρωσης', f"Ξεκινάει διαδικασία για: {friendly}.\nΛήψη πλήρους backup (μέγιστη αναμονή {backup_wait} λεπτά)...", tech_config)
                                
                                # 1. Λήψη Backup και καταγραφή του ακριβούς slug.
                                backup_result = call_ha_service_with_response(
                                    token,
                                    'hassio',
                                    'backup_full',
                                    {"name": f"SmartPro_PreUpdate_{friendly}"},
                                    timeout=max(60, backup_wait * 60),
                                )
                                backup_slug = extract_backup_slug(backup_result.get('response'))
                                if not backup_result.get('success') or not backup_slug:
                                    known_updates[eid] = now_ts
                                    notified_updates.pop(eid, None)
                                    changes_made = True
                                    send_email_alert(
                                        '❌ Αποτυχία Backup πριν από Ενημέρωση',
                                        (
                                            f"Δεν ολοκληρώθηκε επιβεβαιωμένο backup για '{friendly}'.\n\n"
                                            "Η εγκατάσταση της ενημέρωσης δεν ξεκίνησε, επειδή "
                                            "δεν επιστράφηκε έγκυρο backup slug. "
                                            f"Η διαδικασία θα μπορεί να επανεκτιμηθεί μετά από {wait_days} ημέρες, "
                                            "εφόσον η ενημέρωση παραμένει διαθέσιμη."
                                        ),
                                        tech_config,
                                    )
                                    continue
                                
                                # 2. Καταγραφή Offline Συσκευών (Baseline)
                                current_states = get_ha_states(token)
                                offline_baseline = sum(1 for e in current_states if e.get('entity_id').startswith(important_domains) and e.get('state') in ['unavailable', 'unknown'])
                                
                                # 3. Εγκατάσταση Ενημέρωσης
                                if not subscription_entitlement_allowed('update_guidance', tech_config):
                                    send_email_alert(
                                        '⏸️ Η ενημέρωση σταμάτησε',
                                        'Η συνδρομητική υπηρεσία Smart Updates δεν είναι πλέον ενεργή. Το backup διατηρήθηκε, αλλά δεν ξεκίνησε εγκατάσταση.',
                                        tech_config,
                                    )
                                    continue
                                update_started = call_ha_service(
                                    token,
                                    'update',
                                    'install',
                                    {"entity_id": eid},
                                )
                                if not update_started:
                                    known_updates[eid] = now_ts
                                    notified_updates.pop(eid, None)
                                    changes_made = True
                                    send_email_alert(
                                        '❌ Αποτυχία Έναρξης Ενημέρωσης',
                                        (
                                            f"Το αίτημα backup για '{friendly}' είχε γίνει αποδεκτό, "
                                            "αλλά το Home Assistant δεν δέχτηκε την εντολή εγκατάστασης.\n\n"
                                            "Δεν έγινε αξιολόγηση επιτυχίας και δεν στάλθηκε εντολή rollback. "
                                            f"Η διαδικασία θα μπορεί να επανεκτιμηθεί μετά από {wait_days} ημέρες, "
                                            "εφόσον η ενημέρωση παραμένει διαθέσιμη."
                                        ),
                                        tech_config,
                                    )
                                    continue
                                time.sleep(eval_wait * 60)
                                
                                # 4. Αξιολόγηση Μετά το Update
                                post_states = get_ha_states(token)
                                offline_post = sum(1 for e in post_states if e.get('entity_id').startswith(important_domains) and e.get('state') in ['unavailable', 'unknown'])
                                
                                new_offline_count = offline_post - offline_baseline
                                
                                if new_offline_count < limit:
                                    msg = f"✅ Η ενημέρωση '{friendly}' ολοκληρώθηκε επιτυχώς.\nΔεν εντοπίστηκαν σοβαρά προβλήματα."
                                    if new_offline_count > 0: msg += f"\n\nΣημείωση: Υπάρχουν {new_offline_count} νέες offline συσκευές, αλλά είναι κάτω από το όριο (Όριο: {limit})."
                                    send_email_alert('✅ Επιτυχής Ενημέρωση', msg, tech_config)
                                    known_updates.pop(eid, None)
                                    notified_updates.pop(eid, None)
                                    changes_made = True
                                else:
                                    msg = f"🚨 ΑΠΟΤΥΧΙΑ ΕΝΗΜΕΡΩΣΗΣ: '{friendly}'\n\nΒρέθηκαν {new_offline_count} ΝΕΕΣ offline συσκευές (Όριο: {limit})."
                                    rollback_started = call_ha_service(
                                        token,
                                        'hassio',
                                        'restore_partial',
                                        {
                                            "slug": backup_slug,
                                            "homeassistant": True,
                                        },
                                        timeout=120,
                                    )
                                    if rollback_started:
                                        subject = '🚨 ΚΡΙΣΙΜΟ: Rollback Ενημέρωσης'
                                        msg += "\n\nΤο αίτημα rollback έγινε αποδεκτό. Το Home Assistant επανέρχεται στο πρόσφατο backup."
                                    else:
                                        subject = '🛑 ΚΡΙΣΙΜΟ: Αποτυχία Rollback'
                                        msg += (
                                            "\n\nΗ εντολή rollback δεν έγινε δεκτή από το Home Assistant. "
                                            "Απαιτείται άμεσος χειροκίνητος έλεγχος."
                                        )
                                    send_email_alert(subject, msg, tech_config)
                                    known_updates[eid] = now_ts
                                    notified_updates.pop(eid, None)
                                    changes_made = True
                                    
                    elif state == 'off':
                        if eid in known_updates:
                            del known_updates[eid]
                            changes_made = True
                        if eid in notified_updates:
                            del notified_updates[eid]
                            changes_made = True
            
            if changes_made:
                tech_config['known_updates'] = known_updates
                tech_config['notified_updates'] = notified_updates
                save_tech_settings(tech_config)
                
        except Exception as e: print(f"Update Loop Error: {e}")

# -------------------------------------------------------------------
# ΥΠΑΡΧΩΝ ΕΓΚΕΦΑΛΟΣ: ΦΡΟΥΡΟΣ & VACATION MODE
# -------------------------------------------------------------------
def _guardian_runtime_summary(tech_config, now_dt=None):
    now_dt = now_dt or datetime.now()
    alert_delay_sec = float(tech_config.get('alert_delay_min', 15.0) or 15.0) * 60.0
    real_items = [
        (entity_id, info) for entity_id, info in OFFLINE_DEVICES.items()
        if isinstance(info, dict) and not info.get('simulated')
    ]
    pending = 0
    alerted = 0
    retry_pending = 0
    for _, info in real_items:
        if info.get('alerted'):
            alerted += 1
            continue
        pending += 1
        time_down = info.get('time_down')
        if not isinstance(time_down, datetime):
            time_down = datetime.fromtimestamp(_guardian_epoch(time_down, int(time.time())))
        if (now_dt - time_down).total_seconds() >= alert_delay_sec:
            retry_pending += 1

    email_retry_pending = sum(
        1 for _, info in real_items
        if not info.get('email_sent') and (
            now_dt - (info.get('time_down') if isinstance(info.get('time_down'), datetime)
                      else datetime.fromtimestamp(_guardian_epoch(info.get('time_down'), int(time.time()))))
        ).total_seconds() >= alert_delay_sec
    )
    if retry_pending:
        reason = 'alert_delivery_retry'
    elif alerted:
        reason = 'active_alert'
    elif pending:
        reason = 'offline_grace'
    elif LOW_BATTERY_DEVICES:
        reason = 'low_battery'
    else:
        reason = 'healthy'
    return {
        'status': 'attention' if (real_items or LOW_BATTERY_DEVICES) else 'healthy',
        'reason_code': reason,
        'offline_count': len(real_items),
        'low_battery_count': len(LOW_BATTERY_DEVICES),
        'pending_offline_count': pending,
        'alerted_offline_count': alerted,
        'retry_pending_count': retry_pending,
        'active_alert': alerted > 0,
        'email_retry_pending_count': email_retry_pending,
    }


def _guardian_refresh_status(tech_config, now_dt=None, **extra):
    summary = _guardian_runtime_summary(tech_config, now_dt)
    summary.update(extra)
    summary['monitoring_scope_count'] = len(get_monitored_domains(tech_config))
    summary['email_configured'] = bool(str(tech_config.get('email_password', '') or ''))
    update_guardian_status(**summary)


def _guardian_email_body(entries, request_code='', portal_pending=False):
    refs = [guardian_safe_device_ref(entity_id) for entity_id, _ in entries]
    lines = [
        f'Ο Φρουρός εντόπισε {len(refs)} συσκευή/ές εκτός σύνδεσης μετά την περίοδο ανοχής.',
        '',
    ]
    lines.extend(f'- {ref}' for ref in refs)
    lines.extend(['', 'Κανάλι: Guardian / automatic alert'])
    if request_code:
        lines.append(f'Αίτημα Portal: {request_code}')
    elif portal_pending:
        lines.append('Αίτημα Portal: εκκρεμεί επανάληψη αποστολής')
    return '\n'.join(lines)


def _guardian_try_email(entries, tech_config, request_code='', portal_pending=False, force=False):
    now_ts = int(time.time())
    eligible = []
    for entity_id, info in entries:
        if info.get('email_sent'):
            continue
        last_attempt = _guardian_epoch(info.get('last_email_attempt_at'))
        if not force and last_attempt and now_ts - last_attempt < GUARDIAN_EMAIL_RETRY_SECONDS:
            continue
        info['last_email_attempt_at'] = now_ts
        eligible.append((entity_id, info))
    if not eligible:
        return None
    result = send_email_alert(
        '⚠️ Αυτόματη ειδοποίηση Φρουρού',
        _guardian_email_body(eligible, request_code=request_code, portal_pending=portal_pending),
        tech_config,
    )
    if result.get('success'):
        for _, info in eligible:
            info['email_sent'] = True
            info['email_sent_at'] = now_ts
        save_guardian_state({'last_email_sent_at': now_ts, 'last_email_error_at': 0})
        update_guardian_status(last_email_sent_at=now_ts, last_email_error_at=0)
    else:
        save_guardian_state({'last_email_error_at': now_ts})
        update_guardian_status(last_email_error_at=now_ts)
    return result


def _guardian_deliver_due_alerts(tech_config, now_dt):
    now_ts = int(time.time())
    alert_delay_sec = float(tech_config.get('alert_delay_min', 15.0) or 15.0) * 60.0
    due = []
    for entity_id, info in OFFLINE_DEVICES.items():
        if not isinstance(info, dict) or info.get('simulated') or info.get('alerted'):
            continue
        time_down = info.get('time_down')
        if not isinstance(time_down, datetime):
            time_down = datetime.fromtimestamp(_guardian_epoch(time_down, now_ts))
            info['time_down'] = time_down
        if (now_dt - time_down).total_seconds() < alert_delay_sec:
            continue
        last_attempt = _guardian_epoch(info.get('last_portal_attempt_at'))
        if last_attempt and now_ts - last_attempt < GUARDIAN_ALERT_RETRY_SECONDS:
            continue
        due.append((entity_id, info))

    if due:
        event_material = '|'.join(sorted(
            f"{entity_id}:{int(info['time_down'].timestamp())}"
            for entity_id, info in due
        ))
        event_key = 'offline-' + hashlib.sha256(event_material.encode('utf-8')).hexdigest()[:24]
        body = (
            f'Ο Φρουρός εντόπισε {len(due)} συσκευή/ές εκτός σύνδεσης μετά την περίοδο ανοχής.\n' +
            '\n'.join(f'- {guardian_safe_device_ref(entity_id)}' for entity_id, _ in due)
        )
        for _, info in due:
            info['last_portal_attempt_at'] = now_ts
            info['event_key'] = event_key
        save_guardian_state()

        request_code = ''
        portal_ok = False
        try:
            response = create_portal_request(
                'device_offline',
                body,
                source='automatic',
                severity='warning',
                event_key=event_key,
            )
            request_data = response.get('request') or {}
            request_code = str(request_data.get('code', '') or '').strip()
            for _, info in due:
                info['alerted'] = True
                info['request_code'] = request_code
                info['request_created_at'] = now_ts
            portal_ok = True
            save_guardian_state({
                'last_alert_at': now_ts,
                'last_alert_request_code': request_code,
            })
            update_guardian_status(last_alert_at=now_ts, last_alert_request_code=request_code)
            print(f'[GUARDIAN] Automatic Portal request acknowledged: {request_code or "created"}.', flush=True)
        except Exception as portal_error:
            print(f'[GUARDIAN] Automatic request pending retry: {portal_error}', flush=True)

        # Email is an independent delivery channel. Send it even when Portal is
        # temporarily unavailable, then keep the Portal request queued locally.
        _guardian_try_email(
            due,
            tech_config,
            request_code=request_code,
            portal_pending=not portal_ok,
            force=True,
        )
        save_guardian_state()

    # Retry email independently after a successful Portal request (or after a
    # prior SMTP outage) without creating duplicate Portal requests.
    email_pending = []
    for entity_id, info in OFFLINE_DEVICES.items():
        if not isinstance(info, dict) or info.get('simulated'):
            continue
        time_down = info.get('time_down')
        if not isinstance(time_down, datetime):
            time_down = datetime.fromtimestamp(_guardian_epoch(time_down, now_ts))
            info['time_down'] = time_down
        if (now_dt - time_down).total_seconds() >= alert_delay_sec and not info.get('email_sent'):
            email_pending.append((entity_id, info))
    if email_pending:
        request_code = next((str(info.get('request_code', '') or '') for _, info in email_pending if info.get('request_code')), '')
        _guardian_try_email(
            email_pending,
            tech_config,
            request_code=request_code,
            portal_pending=any(not info.get('alerted') for _, info in email_pending),
            force=False,
        )
        save_guardian_state()


def vacation_mode_loop():
    """Run Vacation Mode independently from Guardian enable/disable state."""
    vac_devices = {}
    last_check = 0.0
    while True:
        time.sleep(2)
        try:
            tech_config = load_tech_settings()
            if not tech_config.get('auto_vacation_enabled', True):
                if vac_devices:
                    vac_devices.clear()
                continue
            if not subscription_runtime_allowed(tech_config):
                continue
            options = load_addon_options()
            token = str(options.get('ha_token', '') or '').strip()
            if not _ha_api_credential_available(token):
                continue
            now_ts = time.time()
            check_interval_sec = float(tech_config.get('check_interval_min', 5.0) or 5.0) * 60.0
            if now_ts - last_check < check_interval_sec:
                continue
            last_check = now_ts
            try:
                states = get_ha_states_for_ui()
            except RuntimeError as error:
                print(f'[VACATION] Home Assistant read failed: {error}', flush=True)
                continue

            now_dt = datetime.now()
            vacation_helper_on = any(
                st.get('entity_id') == 'input_boolean.smart_pro_vacation' and st.get('state') == 'on'
                for st in states
            )
            now_time_str = now_dt.strftime('%H:%M')
            if not vacation_helper_on:
                if vac_devices:
                    vac_devices.clear()
                continue

            c_open = tech_config.get('cover_open_time', '08:00')
            c_close = tech_config.get('cover_close_time', '20:00')
            target_cover_state = 'open_cover' if (c_open <= now_time_str < c_close) else 'close_cover'
            for dev in tech_config.get('vacation_covers', []):
                dev_state = next((st.get('state') for st in states if st.get('entity_id') == dev), None)
                desired = 'open' if target_cover_state == 'open_cover' else 'closed'
                if dev_state != desired and dev_state not in ['unavailable', 'unknown', None]:
                    dev_info = vac_devices.get(dev, {'last_sent': None})
                    if dev_info.get('last_sent') != desired:
                        call_ha_service(token, 'cover', target_cover_state, {'entity_id': dev})
                        dev_info['last_sent'] = desired
                        vac_devices[dev] = dev_info

            v_start = tech_config.get('vacation_start', '20:00')
            v_end = tech_config.get('vacation_end', '23:59')
            in_window = (v_start <= now_time_str <= v_end)
            if v_start > v_end:
                in_window = (now_time_str >= v_start or now_time_str <= v_end)
            random_devices = tech_config.get('vacation_lights', []) + tech_config.get('vacation_audio', [])
            if in_window:
                for dev in random_devices:
                    dev_info = vac_devices.get(dev)
                    if not dev_info or 'next_toggle' not in dev_info:
                        vac_devices[dev] = {'state': 'off', 'next_toggle': now_ts + random.randint(0, 900)}
                    if now_ts >= vac_devices[dev]['next_toggle']:
                        new_state = 'on' if vac_devices[dev]['state'] == 'off' else 'off'
                        vac_devices[dev]['state'] = new_state
                        vac_devices[dev]['next_toggle'] = now_ts + random.randint(900, 2700)
                        domain = dev.split('.')[0]
                        call_ha_service(token, domain, f'turn_{new_state}', {'entity_id': dev})
            else:
                for dev in random_devices:
                    dev_info = vac_devices.get(dev)
                    if dev_info and dev_info.get('state') == 'on':
                        domain = dev.split('.')[0]
                        call_ha_service(token, domain, 'turn_off', {'entity_id': dev})
                        dev_info['state'] = 'off'
        except Exception as error:
            print(f'[VACATION] Loop error: {error}', flush=True)


def watchdog_loop():
    global last_api_check
    while True:
        time.sleep(2)
        try:
            tech_config = load_tech_settings()
            now_ts = time.time()
            now_dt = datetime.now()
            synchronize_watchdog_test(tech_config, now_dt, now_ts)

            watchdog_enabled = bool(tech_config.get('watchdog_enabled', True))
            if not watchdog_enabled:
                for entity_id in list(OFFLINE_DEVICES.keys()):
                    if not OFFLINE_DEVICES.get(entity_id, {}).get('simulated'):
                        OFFLINE_DEVICES.pop(entity_id, None)
                LOW_BATTERY_DEVICES.clear()
                save_guardian_state()
                update_guardian_status(
                    enabled=False,
                    status='disabled',
                    reason_code='disabled',
                    offline_count=0,
                    low_battery_count=0,
                    pending_offline_count=0,
                    alerted_offline_count=0,
                    retry_pending_count=0,
                    active_alert=False,
                    monitoring_scope_count=0,
                    email_configured=bool(str(tech_config.get('email_password', '') or '')),
                )
                continue

            guardian_access = subscription_service_access('guardian_monitoring', tech_config, now=now_ts)
            if not guardian_access.get('allowed'):
                for entity_id in list(OFFLINE_DEVICES.keys()):
                    if not OFFLINE_DEVICES.get(entity_id, {}).get('simulated'):
                        OFFLINE_DEVICES.pop(entity_id, None)
                LOW_BATTERY_DEVICES.clear()
                save_guardian_state()
                update_guardian_status(
                    enabled=False,
                    status='disabled',
                    reason_code='service_access_inactive',
                    offline_count=0,
                    low_battery_count=0,
                    pending_offline_count=0,
                    alerted_offline_count=0,
                    retry_pending_count=0,
                    active_alert=False,
                    monitoring_scope_count=0,
                    email_configured=bool(str(tech_config.get('email_password', '') or '')),
                )
                continue

            update_guardian_status(enabled=True)

            options = load_addon_options()
            token = str(options.get('ha_token', '') or '').strip()
            if not _ha_api_credential_available(token):
                update_guardian_status(status='waiting', reason_code='missing_ha_token')
                continue

            important_domains = get_monitored_domains(tech_config)
            update_guardian_status(
                monitoring_scope_count=len(important_domains),
                email_configured=bool(str(tech_config.get('email_password', '') or '')),
            )
            # An empty unavailable/unknown domain scope does not disable the
            # independent low-battery monitor. Keep collecting states so battery
            # attention remains available.
            check_interval_sec = float(tech_config.get('check_interval_min', 5.0) or 5.0) * 60.0
            battery_limit = float(tech_config.get('battery_limit', 15.0) or 15.0)

            if now_ts - last_api_check >= check_interval_sec:
                last_api_check = now_ts
                try:
                    states = get_ha_states_for_ui()
                except RuntimeError as error:
                    error_at = int(now_ts)
                    save_guardian_state({'last_error_at': error_at, 'last_error_code': 'ha_api_error'})
                    update_guardian_status(
                        status='error',
                        reason_code='ha_api_error',
                        last_error_at=error_at,
                    )
                    print(f'[GUARDIAN] Home Assistant read failed: {error}', flush=True)
                    continue

                current_offline = []
                current_low_batt = []
                for entity in states:
                    entity_id = str(entity.get('entity_id', '') or '')
                    state = str(entity.get('state', '') or '')
                    attrs = entity.get('attributes', {}) if isinstance(entity.get('attributes'), dict) else {}
                    if entity_id.startswith(important_domains) and state in ('unavailable', 'unknown'):
                        current_offline.append(entity_id)
                    if attrs.get('device_class') == 'battery':
                        try:
                            if float(state) < battery_limit:
                                current_low_batt.append(entity_id)
                        except (TypeError, ValueError):
                            pass

                recovered = []
                for entity_id in current_offline:
                    if entity_id not in OFFLINE_DEVICES:
                        OFFLINE_DEVICES[entity_id] = {
                            'time_down': now_dt,
                            'alerted': False,
                            'request_code': '',
                            'event_key': '',
                            'last_portal_attempt_at': 0,
                            'email_sent': False,
                            'last_email_attempt_at': 0,
                            'simulated': False,
                        }
                for entity_id in list(OFFLINE_DEVICES.keys()):
                    info = OFFLINE_DEVICES.get(entity_id, {})
                    if info.get('simulated'):
                        continue
                    if entity_id not in current_offline:
                        recovered.append(entity_id)
                        OFFLINE_DEVICES.pop(entity_id, None)

                for entity_id in current_low_batt:
                    if entity_id not in LOW_BATTERY_DEVICES:
                        LOW_BATTERY_DEVICES[entity_id] = {'alerted': True, 'detected_at': int(now_ts)}
                        friendly = next(
                            (st.get('attributes', {}).get('friendly_name', entity_id)
                             for st in states if st.get('entity_id') == entity_id),
                            entity_id,
                        )
                        notify_ha_client(token, 'Smart Pro System', f"Η μπαταρία στη συσκευή '{friendly}' είναι χαμηλή.")
                for entity_id in list(LOW_BATTERY_DEVICES.keys()):
                    if entity_id not in current_low_batt:
                        LOW_BATTERY_DEVICES.pop(entity_id, None)

                state_extra = {'last_successful_check_at': int(now_ts), 'last_error_at': 0, 'last_error_code': ''}
                if recovered:
                    state_extra.update({
                        'last_recovery_at': int(now_ts),
                        'last_recovery_count': len(recovered),
                    })
                    update_guardian_status(last_recovery_at=int(now_ts), last_recovery_count=len(recovered))
                save_guardian_state(state_extra)
                _guardian_refresh_status(
                    tech_config,
                    now_dt,
                    last_check_at=int(now_ts),
                    last_successful_check_at=int(now_ts),
                    last_error_at=0,
                )

            _guardian_deliver_due_alerts(tech_config, now_dt)

            # Safe virtual Guardian test remains isolated from persistent real-device state.
            simulated_alerts = []
            for entity_id, info in list(OFFLINE_DEVICES.items()):
                if not isinstance(info, dict) or not info.get('simulated') or info.get('alerted'):
                    continue
                delay_seconds = float(info.get('alert_after_seconds', 0) or 0)
                time_down = info.get('time_down')
                if isinstance(time_down, datetime) and (now_dt - time_down) > timedelta(seconds=delay_seconds):
                    simulated_alerts.append((entity_id, info))

            for entity_id, info in simulated_alerts:
                device_name = str(info.get('friendly_name', 'Δοκιμαστική συσκευή Φρουρού'))
                test_id = str(info.get('test_id', ''))
                body = (
                    'ΔΟΚΙΜΗ — Προσομοιωμένη βλάβη Φρουρού\n'
                    f'Εικονική συσκευή: {device_name}\n'
                    'Δεν επηρεάστηκε πραγματική συσκευή, υπηρεσία ή σύνδεση δικτύου.'
                )
                try:
                    response = create_portal_request(
                        'device_offline',
                        body,
                        source='automatic',
                        severity='warning',
                        event_key=f'watchdog-test-{test_id}',
                    )
                    request_data = response.get('request') or {}
                    info['alerted'] = True
                    set_watchdog_test_state(
                        status='request_created',
                        message='Δημιουργήθηκε δοκιμαστικό αίτημα στο Portal.',
                        request_code=str(request_data.get('code', '')),
                        request_created_at=int(time.time()),
                    )
                    print('[PORTAL] Watchdog test request created.', flush=True)
                    if info.get('send_email'):
                        email_result = send_email_alert(
                            '🧪 Δοκιμή Φρουρού Smart Pro System',
                            body,
                            tech_config,
                        )
                        set_watchdog_test_state(
                            email_sent=bool(email_result.get('success')),
                            email_message=str(email_result.get('message', '')),
                        )
                except Exception as portal_error:
                    set_watchdog_test_state(
                        status='failed',
                        message='Η προσομοίωση εκτελέστηκε, αλλά το αίτημα δεν δημιουργήθηκε.',
                        error=str(portal_error),
                        finished_at=int(time.time()),
                    )
                    print(f'[PORTAL] Watchdog test request failed: {portal_error}', flush=True)

            _guardian_refresh_status(tech_config, now_dt)
        except Exception as error:
            error_at = int(time.time())
            save_guardian_state({'last_error_at': error_at, 'last_error_code': 'guardian_loop_error'})
            update_guardian_status(status='error', reason_code='guardian_loop_error', last_error_at=error_at)
            print(f'[GUARDIAN] Loop error: {error}', flush=True)

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Home Assistant Ingress/browser can otherwise retain an old index.html and
        # therefore keep loading an older script.js cache key after an add-on update.
        # Disable caching only for the browser UI/static path; API responses already
        # have their own response semantics.
        request_path = urllib.parse.urlparse(self.path).path.lower()
        if '/api/' not in request_path and not request_path.endswith('/status'):
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
        super().end_headers()

    def do_GET(self):
        request_path = urllib.parse.urlparse(self.path).path

        if request_path.endswith('/api/smart_updates_test/state'):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            else:
                send_json(self, 200, {
                    'status': 'success',
                    'test': smart_updates_test_public_status(),
                })

        # Check the test state before the legacy /status suffix. Otherwise,
        # /api/watchdog_test/status is captured by the generic route.
        elif request_path.endswith(('/api/watchdog_test/state', '/api/watchdog_test/status')):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            else:
                send_json(self, 200, {'status': 'success', 'test': watchdog_test_public_status()})

        elif request_path.endswith('/status'):
            tech_config = load_tech_settings()
            response_data = {"watchdog_enabled": tech_config.get('watchdog_enabled', True), "domains": list(get_monitored_domains(tech_config)), "battery_limit": tech_config.get('battery_limit', 15.0)}
            self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers(); self.wfile.write(json.dumps(response_data).encode())
        
        # --- ΕΔΩ ΕΙΝΑΙ Ο ΝΕΟΣ ΜΥΣΤΙΚΟΣ ΚΑΤΑΣΚΟΠΟΣ ΓΙΑ ΤΟ MESHCENTRAL ---
        elif request_path.endswith('/api/mesh_status'):
            mesh = mesh_configuration_status()
            is_active = False

            if mesh['configured']:
                try:
                    encoded_installation_id = urllib.parse.quote(
                        mesh['installation_id'],
                        safe=''
                    )
                    req_url = (
                        f"https://{mesh['server_host']}:8443/status"
                        f"?id={encoded_installation_id}"
                    )
                    request = urllib.request.Request(
                        req_url,
                        headers={
                            'Authorization': f"Bearer {mesh['mesh_access_token']}",
                            'Accept': 'application/json',
                            'Cache-Control': 'no-cache',
                        },
                    )
                    with urllib.request.urlopen(request, timeout=5) as response:
                        data = json.loads(response.read().decode('utf-8'))
                        is_active = bool(data.get('active', False))
                except Exception as error:
                    print(f'Secure MeshCentral Bridge Error: {error}', flush=True)

            send_json(self, 200, {
                'active': is_active,
                'configured': mesh['configured'],
            })
        # -------------------------------------------------------------
        
        elif request_path.endswith('/api/integration_health'):
            send_json(self, 200, integration_health_status())

        elif request_path.endswith('/api/ha_states'):
            try:
                send_json(self, 200, {'status': 'ok', 'states': get_ha_states_for_ui()})
            except RuntimeError as error:
                send_json(self, 502, {'status': 'error', 'message': str(error)})

        elif urllib.parse.urlparse(self.path).path.endswith('/api/portal_status'):
            send_json(self, 200, portal_public_status())

        elif urllib.parse.urlparse(self.path).path.endswith('/api/portal_requests'):
            try:
                send_json(self, 200, fetch_portal_requests(20))
            except PortalAPIError as error:
                send_json(self, error.status or 502, {'status': 'error', 'code': error.code, 'message': str(error)})

        elif request_path.endswith('/api/tech_settings'):
            # Browser-facing settings are always sanitized. Stored SMTP
            # credentials never leave the add-on, even during a technician session.
            send_json(self, 200, tech_settings_public(load_tech_settings()))
        elif self.path.endswith('/api/entities'):
            try:
                states = get_ha_states_for_ui()
                valid_ents = []
                for st in states:
                    eid = st.get('entity_id', '')
                    if eid.startswith(('light.', 'switch.', 'cover.', 'media_player.')):
                        fname = st.get('attributes', {}).get('friendly_name', eid)
                        valid_ents.append({"id": eid, "name": fname})
                self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers(); self.wfile.write(json.dumps(valid_ents).encode())
            except Exception: self.send_response(500); self.end_headers()
        else: super().do_GET() 

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path.endswith('/api/portal_pair'):
            try:
                data = read_json_body(self)
                status = pair_portal(data.get('code', ''))
                send_json(self, 200, {'status': 'connected', 'connection': status})
            except PortalAPIError as error:
                send_json(self, error.status or 502, {'status': 'error', 'code': error.code, 'message': str(error)})
            except Exception as error:
                send_json(self, 400, {'status': 'error', 'code': 'invalid_request', 'message': str(error)})
        elif urllib.parse.urlparse(self.path).path.endswith('/api/portal_request'):
            try:
                data = read_json_body(self)
                if not subscription_entitlement_allowed('support_requests'):
                    send_json(self, 403, {
                        'status': 'error',
                        'code': 'support_service_inactive',
                        'message': 'Τα κανονικά αιτήματα συνδρομητικής υποστήριξης δεν είναι ενεργά για αυτή την εγκατάσταση.',
                    })
                    return
                response = create_portal_request(
                    data.get('category', 'general'),
                    data.get('message', ''),
                    source='smart_pro_tools',
                    severity=data.get('severity', 'normal'),
                )
                send_json(self, 201, response)
            except PortalAPIError as error:
                send_json(self, error.status or 502, {'status': 'error', 'code': error.code, 'message': str(error)})
            except Exception as error:
                send_json(self, 400, {'status': 'error', 'code': 'invalid_request', 'message': str(error)})
        elif urllib.parse.urlparse(self.path).path.endswith('/api/portal_disconnect'):
            clear_portal_connection()
            write_managed_policy_file()
            send_json(self, 200, {'status': 'disconnected'})
        elif self.path.endswith('/api/verify_pin'):
            try:
                data = read_json_body(self)
            except Exception:
                send_json(self, 400, {'status': 'error', 'message': 'Μη έγκυρο αίτημα.'})
                return
            if data.get('pin', '') == "7777":
                token, expires_at = create_tech_session()
                send_json(self, 200, {
                    'status': 'success',
                    'tech_session_token': token,
                    'expires_at': expires_at,
                })
            else:
                send_json(self, 200, {'status': 'error'})
        elif urllib.parse.urlparse(self.path).path.endswith('/api/smart_updates_test/run'):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            else:
                try:
                    data = read_json_body(self)
                    result = run_smart_updates_safe_test(data)
                    send_json(self, 200, {'status': 'success', 'test': result})
                except ValueError as error:
                    send_json(self, 409, {'status': 'error', 'message': str(error)})
                except Exception as error:
                    send_json(self, 500, {
                        'status': 'error',
                        'message': f'Αποτυχία ασφαλούς δοκιμής Smart Updates: {error}',
                    })
        elif urllib.parse.urlparse(self.path).path.endswith('/api/watchdog_test/start'):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            else:
                try:
                    data = read_json_body(self)
                    status = start_watchdog_test(data)
                    send_json(self, 202, {'status': 'success', 'test': status})
                except ValueError as error:
                    send_json(self, 409, {'status': 'error', 'message': str(error)})
                except Exception as error:
                    send_json(self, 500, {'status': 'error', 'message': f'Αποτυχία έναρξης δοκιμής: {error}'})
        elif urllib.parse.urlparse(self.path).path.endswith('/api/watchdog_test/cancel'):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            else:
                send_json(self, 200, {'status': 'success', 'test': cancel_watchdog_test()})
        elif urllib.parse.urlparse(self.path).path.endswith('/api/watchdog_test/ack'):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            else:
                send_json(self, 200, {'status': 'success', 'test': acknowledge_watchdog_test_result()})
        elif urllib.parse.urlparse(self.path).path.endswith('/api/test_alert_email'):
            if not tech_session_authorized(self):
                send_json(self, 401, {'status': 'error', 'message': 'Η τεχνική συνεδρία έληξε.'})
            elif not subscription_entitlement_allowed('guardian_monitoring'):
                send_json(self, 403, {
                    'status': 'error',
                    'code': 'guardian_service_inactive',
                    'message': 'Η υπηρεσία Φρουρού δεν είναι ενεργή για αυτή την εγκατάσταση.',
                })
            else:
                try:
                    data = read_json_body(self)
                    tech_config = load_tech_settings()
                    supplied_password = str(data.get('email_password', '') or '')
                    if supplied_password:
                        tech_config['email_password'] = supplied_password
                    result = send_email_alert(
                        'Δοκιμή τεχνικών ειδοποιήσεων',
                        'Αυτό είναι δοκιμαστικό email από τον κλειδωμένο πίνακα τεχνικού. '
                        'Η αποστολή SMTP λειτουργεί κανονικά.',
                        tech_config,
                    )
                    send_json(self, 200 if result.get('success') else 502, result)
                except Exception as error:
                    send_json(self, 500, {
                        'success': False,
                        'message': f'Η δοκιμή email απέτυχε: {clean_portal_error_message(error)}',
                    })
        elif self.path.endswith('/api/set_subscription_status'):
            content_length = int(self.headers['Content-Length']); data = json.loads(self.rfile.read(content_length))
            tech_config = load_tech_settings(); tech_config['subscription_active'] = data.get('active', True); save_tech_settings(tech_config)
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"success"}')
        elif urllib.parse.urlparse(self.path).path.endswith('/api/tech_settings'):
            try:
                data = read_json_body(self)
                if not isinstance(data, dict):
                    raise ValueError('Μη έγκυρα δεδομένα ρυθμίσεων.')
                authorized = tech_session_authorized(self)
                if not authorized:
                    unexpected = set(data.keys()) - TECH_SETTINGS_PUBLIC_WRITE_KEYS
                    if unexpected:
                        send_json(self, 401, {
                            'status': 'error',
                            'message': 'Απαιτείται ενεργή τεχνική συνεδρία για αυτές τις ρυθμίσεις.',
                        })
                        return
                # A blank password means "keep the existing secret". The browser
                # never receives the stored password and therefore cannot echo it.
                if 'email_password' in data and not str(data.get('email_password', '') or '').strip():
                    data.pop('email_password', None)
                saved = save_tech_settings(data, merge=True)
                send_json(self, 200, {'status': 'success', 'settings': tech_settings_public(saved)})
            except Exception as error:
                send_json(self, 400, {'status': 'error', 'message': f'Αποτυχία αποθήκευσης ρυθμίσεων: {error}'})
        elif self.path.endswith('/send_email'):
            content_length = int(self.headers['Content-Length']); data = json.loads(self.rfile.read(content_length))
            issues = str(data.get('issues', '')).strip()
            if not subscription_entitlement_allowed('support_requests'):
                send_json(self, 403, {
                    'status': 'error',
                    'code': 'support_service_inactive',
                    'message': 'Τα κανονικά αιτήματα συνδρομητικής υποστήριξης δεν είναι ενεργά για αυτή την εγκατάσταση.',
                })
                return
            try:
                response = create_portal_request('general', issues, source='smart_pro_tools', severity='normal')
                send_json(self, 201, response)
            except Exception:
                tech_config = load_tech_settings()
                send_email_alert('Χειροκίνητο Αίτημα - Smart Pro System', f"Νέο αίτημα υποστήριξης.\n\nΠρόβλημα: {issues}", tech_config)
                send_json(self, 200, {'status': 'email_fallback'})
        else: self.send_response(404); self.end_headers()

if __name__ == "__main__":
    # Migrate/self-heal settings and restore Guardian incident state before
    # background loops start. Real Guardian state survives add-on restarts.
    load_tech_settings()
    restore_guardian_runtime_state()
    write_managed_policy_file()
    write_managed_network_file()
    threading.Thread(target=watchdog_loop, daemon=True).start()
    threading.Thread(target=vacation_mode_loop, daemon=True).start()
    threading.Thread(target=smart_updates_loop, daemon=True).start()
    threading.Thread(target=portal_heartbeat_loop, daemon=True).start()
    threading.Thread(target=managed_policy_refresh_loop, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("", PORT), MyHandler) as httpd:
        httpd.serve_forever()
