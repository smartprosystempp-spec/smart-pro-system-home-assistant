"""Smart Pro customer-admin enrollment, explicitly user-approved, paired and fail-closed.

This service is mounted ONLY into the existing Smart Pro System Supervisor Ingress.
Never start a second listener. This is a controlled staging pilot (3.0.30), NOT a
production-wide permission escalation. Portal tokens and credentials stay server side.
"""
from __future__ import annotations
import base64
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus

from ha_readback import AdminReadbackError, read_ha_admin_users
from core_session_qa import SupervisorCoreSession, RoundTripError, _inventory

CONTRACT = 'smart-pro-ha-admin-credential-handoff-v1'
ADMIN_GROUP = 'system-admin'
ACCOUNT_NAME = 'Smart Pro Managed Admin — PILOT'
ACCOUNT_USERNAME = 'smartpro_managed_admin_pilot'
LOCAL_ONLY = True  # no remote login until access-policy readiness is separately reviewed
TEST_ONLY = True
INGRESS_PEER = ipaddress.ip_address('172.30.32.2')
USER_ID_PATTERN = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
INSTALLATION_ID = re.compile(r'ID-[0-9]{1,12}\Z')
TOKEN_PATTERN = re.compile(r'[a-fA-F0-9]{64}\Z')
HEX32 = re.compile(r'[a-f0-9]{32}\Z')
HEX64 = re.compile(r'[a-f0-9]{64}\Z')
MARKER = Path('/data/sp_customer_admin_handoff_pilot.json')
APPROVAL_TTL = 180
_lock = threading.RLock()
_approvals: dict[str, tuple[str, str, float]] = {}
_attempted: set[str] = set()

class AccessError(RuntimeError):
    """Only constant safe status codes."""

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        raise AccessError('portal_redirect_rejected')

_OPENER = urllib.request.build_opener(_NoRedirect()).open


def _header_values(headers, key):
    return [v for k,v in headers.items() if str(k).lower() == key]


def admin_identity(handler, *, user_reader=read_ha_admin_users, token_supplier=None):
    """Require Supervisor-owned Ingress identity, fresh HA Core readback; fail closed."""
    try:
        if ipaddress.ip_address(handler.client_address[0]) != INGRESS_PEER:
            raise AccessError('untrusted_ingress')
    except ValueError:
        raise AccessError('untrusted_ingress') from None
    ids = _header_values(handler.headers, 'x-remote-user-id')
    groups = _header_values(handler.headers, 'x-remote-user-groups')
    if len(ids)!=1 or len(groups)!=1 or not isinstance(ids[0],str) or not USER_ID_PATTERN.fullmatch(ids[0]):
        raise AccessError('admin_identity_unavailable')
    if not isinstance(groups[0],str) or len(groups[0])>1024 or not re.fullmatch(r'[A-Za-z0-9_,-]+',groups[0]) or ADMIN_GROUP not in groups[0].split(','):
        raise AccessError('ha_admin_required')
    token = os.getenv('SUPERVISOR_TOKEN','') if token_supplier is None else token_supplier()
    try: users = user_reader(supervisor_token=token)
    except Exception: raise AccessError('core_admin_verification_unavailable') from None
    matches = [u for u in users if u.get('id') == ids[0]]
    if len(matches)!=1 or matches[0].get('is_active') is not True or ADMIN_GROUP not in matches[0].get('group_ids', []):
        raise AccessError('ha_admin_required')
    return ids[0]


def strict_origin(headers):
    origins,hosts,actions = [_header_values(headers,k) for k in ('origin','host','x-smart-pro-admin-action')]
    if len(origins)!=1 or len(hosts)!=1 or len(actions)!=1 or actions[0]!='v1': return False
    host,origin=hosts[0],origins[0]
    if not isinstance(host,str) or not host or any(c in host for c in '\r\n \t/') or not isinstance(origin,str):return False
    sites=_header_values(headers,'sec-fetch-site')
    if len(sites)>1 or (sites and sites[0]!='same-origin'):return False
    try: parsed=urllib.parse.urlsplit(origin)
    except ValueError:return False
    return (parsed.scheme in ('https','http') and parsed.netloc==host and not parsed.username and not parsed.password
            and not parsed.path and not parsed.query and not parsed.fragment and origin==parsed.scheme+'://'+host)


def _account_state(users):
    # Avoid touching other accounts, including the previous QA LOGIN LAB.
    matches=[u for u in users if isinstance(u.get('name'),str) and u['name'].startswith(ACCOUNT_NAME)]
    usernames=[u for u in users if u.get('username')==ACCOUNT_USERNAME]
    if not matches and not usernames:return 'absent',None
    if len(matches)!=1 or len(usernames)>1:return 'review_required',None
    u=matches[0]
    if u.get('name')!=ACCOUNT_NAME or not isinstance(u.get('id'),str) or not 16<=len(u['id'])<=128 or u.get('is_owner') is not False or u.get('system_generated') is not False or u.get('is_active') is not True or u.get('local_only') is not LOCAL_ONLY or u.get('group_ids') != [ADMIN_GROUP]:return 'review_required',None
    if not usernames and u.get('username') is None and u.get('credentials')==[]:return 'incomplete',u
    if len(usernames)==1 and usernames[0].get('id')==u['id'] and u.get('username')==ACCOUNT_USERNAME and u.get('credentials')==[{'type':'homeassistant'}]:return 'login_ready',u
    return 'review_required',None


def read_account(token):
    with SupervisorCoreSession(token) as core:
        return _account_state(_inventory(core.command('config/auth/list')))


def paired_settings(connection, options):
    if not isinstance(connection,dict) or not isinstance(options,dict):raise AccessError('portal_unpaired')
    installation=connection.get('installation_id')
    token=connection.get('installation_token')
    if not isinstance(installation,str) or not INSTALLATION_ID.fullmatch(installation) or not isinstance(token,str) or not TOKEN_PATTERN.fullmatch(token):raise AccessError('portal_unpaired')
    url=options.get('portal_url','')
    if not isinstance(url,str):raise AccessError('portal_invalid_url')
    parsed=urllib.parse.urlsplit(url.rstrip('/'))
    if parsed.scheme!='https' or parsed.hostname not in ('smart-pro-system.gr','www.smart-pro-system.gr') or parsed.username or parsed.password or parsed.port not in (None,443) or parsed.path not in ('','/') or parsed.query or parsed.fragment:raise AccessError('portal_invalid_url')
    basic_user=options.get('portal_basic_username',''); basic_password=options.get('portal_basic_password','')
    if not isinstance(basic_user,str) or not isinstance(basic_password,str):raise AccessError('portal_invalid_options')
    return (url.rstrip('/'),installation,token,basic_user,basic_password)


def portal_post(settings, endpoint, data, opener=_OPENER):
    url,installation,token,basic_user,basic_password=settings
    path='/wp-json/smart-pro/v1/ha-credential-handoff-real/'+endpoint
    dest=url+path
    hdr={'Content-Type':'application/json','Accept':'application/json','X-Smart-Pro-Token':token}
    if basic_user:hdr['Authorization']='Basic '+base64.b64encode((basic_user+':'+basic_password).encode()).decode('ascii')
    req=urllib.request.Request(dest,headers=hdr,method='POST',data=json.dumps(data,separators=(',',':')).encode('utf-8'))
    try:
        with opener(req,timeout=12) as response:
            if response.geturl()!=dest or getattr(response,'status',200)!=200:raise AccessError('portal_http_unavailable')
            raw=response.read(4097)
            if len(raw)>4096:raise AccessError('portal_invalid_reply')
        decoded=json.loads(raw.decode('utf-8','strict'))
        if not isinstance(decoded,dict) or decoded.get('contract')!=CONTRACT:raise AccessError('portal_invalid_reply')
        return decoded
    except (urllib.error.URLError,urllib.error.HTTPError,TimeoutError,OSError,ValueError,UnicodeError):
        raise AccessError('portal_unavailable_no_user_write') from None


def prepare_delivery(settings, post=portal_post, *, now=None):
    _,installation,_,_,_=settings
    result=post(settings,'auto-arm',{'contract':CONTRACT,'installation_id':installation})
    if result.get('status')!='queued' or result.get('installation_id')!=installation:raise AccessError('portal_not_ready_no_user_write')
    expiry=result.get('expires_at'); request_id=result.get('request_id');challenge=result.get('challenge');pkey=result.get('public_key')
    now=int(time.time()) if now is None else int(now)
    if type(expiry) is not int or expiry<=now+10 or expiry>now+900 or not isinstance(request_id,str) or not HEX32.fullmatch(request_id) or not isinstance(challenge,str) or not HEX64.fullmatch(challenge) or not isinstance(pkey,str) or len(pkey)>64:raise AccessError('portal_invalid_preflight_no_user_write')
    try: decoded=base64.b64decode(pkey,validate=True)
    except (ValueError,TypeError):raise AccessError('portal_invalid_preflight_no_user_write') from None
    if len(decoded)!=32:raise AccessError('portal_invalid_preflight_no_user_write')
    return dict(installation_id=installation,request_id=request_id,challenge=challenge,expires_at=expiry,public_key=decoded)


def _issue(identity, action):
    with _lock:
        now=time.monotonic()
        for k,v in tuple(_approvals.items()):
            if v[2]<=now or v[0]==identity: _approvals.pop(k,None)
        key=secrets.token_urlsafe(32)
        _approvals[key]=(identity,action,now+APPROVAL_TTL)
        return key


def _consume(identity,action,code):
    with _lock:
        value=_approvals.pop(code,None)
        return bool(value and value[0]==identity and value[1]==action and value[2]>=time.monotonic())


def _marker_read():
    try:
        data=json.loads(MARKER.read_text(encoding='utf-8'))
        return data if isinstance(data,dict) else {}
    except (ValueError,OSError,UnicodeError):return {}


def _marker_write(inst, uid):
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    tmp=MARKER.with_suffix('.tmp')
    tmp.write_text(json.dumps({'installation_id':inst,'user_id':uid,'state':'delivered','timestamp':int(time.time())}),encoding='utf-8')
    os.chmod(tmp,0o600); tmp.replace(MARKER); os.chmod(MARKER,0o600)


def _make_account(token,password_factory=lambda:secrets.token_urlsafe(36)):
    with SupervisorCoreSession(token) as core:
        before=_inventory(core.command('config/auth/list'))
        if _account_state(before)[0]!='absent':raise AccessError('account_already_exists_or_review')
        password=password_factory()
        if not isinstance(password,str) or not 40<=len(password)<=128 or not password.isascii() or not password.isprintable():raise AccessError('random_password_invalid')
        res=core.command('config/auth/create',name=ACCOUNT_NAME,group_ids=[ADMIN_GROUP],local_only=LOCAL_ONLY)
        uid=res.get('user',{}).get('id') if isinstance(res,dict) else None
        if not isinstance(uid,str) or not 16<=len(uid)<=128:raise AccessError('created_identity_uncertain')
        mid=_inventory(core.command('config/auth/list'))
        mid_state,mid_user=_account_state(mid)
        if mid_state!='incomplete' or mid_user['id']!=uid:raise AccessError('created_identity_uncertain')
        core.command('config/auth_provider/homeassistant/create',user_id=uid,username=ACCOUNT_USERNAME,password=password)
        end=_inventory(core.command('config/auth/list'))
        end_state,end_user=_account_state(end)
        if end_state!='login_ready' or end_user['id']!=uid:raise AccessError('credential_attach_uncertain')
        return {'username':ACCOUNT_USERNAME,'password':password,'id':uid}


def create_and_deliver(connection,options, *, prepare=prepare_delivery, post=portal_post, create=_make_account, seal_fn=None, prepared=None):
    if prepared is None:
        settings=paired_settings(connection,options)
        info=prepare(settings)  # always before any HA user mutation
    else:
        settings,info=prepared
    if seal_fn is None:
        try:
            from nacl.public import PublicKey, SealedBox
        except ImportError:raise AccessError('crypto_unavailable_no_user_write') from None
        def seal_fn(public_key,plain):return SealedBox(PublicKey(public_key)).encrypt(plain)
    try:
        proof=seal_fn(info['public_key'],b'crypto-precheck')
        if not isinstance(proof,bytes) or len(proof)<48:raise ValueError('invalid seal')
    except Exception:raise AccessError('crypto_unavailable_no_user_write') from None
    token=os.getenv('SUPERVISOR_TOKEN','')
    if len(token)<16:raise AccessError('core_unavailable_no_user_write')
    # After this point NO automatic retry: an HA admin may have been created.
    account=create(token)
    try:
        plain=json.dumps({'contract':CONTRACT,'installation_id':info['installation_id'],
             'request_id':info['request_id'],'username':account['username'],
             'password':account['password']},separators=(',',':')).encode('utf-8')
        encrypted=seal_fn(info['public_key'],plain)
        envelope={'contract':CONTRACT,'installation_id':info['installation_id'],
             'request_id':info['request_id'],'challenge':info['challenge'],
             'sent_at':int(time.time()),'ciphertext':base64.b64encode(encrypted).decode('ascii')}
        answer=post(settings,'deliver',envelope)
        if answer.get('status')!='received':raise AccessError('handoff_uncertain_manual_review')
        _marker_write(info['installation_id'],account['id'])
        return 'enrolled_pending_portal_receipt'
    except Exception:
        raise AccessError('handoff_uncertain_manual_review') from None
    finally:
        account.clear()
        if 'plain' in locals():del plain


def revoke_account(connection):
    token=os.getenv('SUPERVISOR_TOKEN','')
    if len(token)<16:raise AccessError('core_unavailable')
    with SupervisorCoreSession(token) as core:
        before=_inventory(core.command('config/auth/list'))
        state,u=_account_state(before)
        if state=='absent':return 'already_absent'
        if state not in ('login_ready','incomplete') or not u:raise AccessError('revoke_review_required')
        core.command('config/auth/delete',user_id=u['id'])
        after=_inventory(core.command('config/auth/list'))
        if _account_state(after)[0]!='absent' or any(x.get('id')==u['id'] for x in after):raise AccessError('revoke_uncertain_review_required')
    try:MARKER.unlink(missing_ok=True)
    except OSError:pass
    return 'revoked_verified'


def _respond(handler,code,payload):
    body=json.dumps(payload,separators=(',',':')).encode('utf-8')
    handler.send_response(code)
    for k,v in (('Content-Type','application/json; charset=utf-8'),('Cache-Control','no-store,private,max-age=0'),('Pragma','no-cache'),('X-Content-Type-Options','nosniff'),('Content-Length',str(len(body)))):handler.send_header(k,v)
    handler.end_headers();handler.wfile.write(body)


def status(handler,connection):
    try:
        identity=admin_identity(handler)
        settings=paired_settings(connection,_read_options())
        token=os.getenv('SUPERVISOR_TOKEN','')
        state,u=read_account(token)
        marker=_marker_read()
        if state=='login_ready':
            if marker.get('user_id')!=u['id'] or marker.get('installation_id')!=settings[1]:state='undelivered_revoke_only'
            else:state='active'
        operation='revoke' if state in ('active','incomplete','undelivered_revoke_only') else 'activate'
        permission = state not in ('review_required',)
        proof=_issue(identity,operation) if permission else ''
        _respond(handler,200,{'status':state,'paired':True,'operation':operation if permission else 'none','consent_token':proof,'version':'3.0.30-pilot'})
    except AccessError as e:
        _respond(handler,403,{'status':str(e),'paired':False,'operation':'none','consent_token':''})
    except Exception:_respond(handler,503,{'status':'status_unavailable','paired':False,'operation':'none','consent_token':''})


def _read_options():
    try:
        data=json.loads(Path('/data/options.json').read_text(encoding='utf-8'))
        return data if isinstance(data,dict) else {}
    except (OSError,ValueError):return {}


def action(handler,connection):
    try:
        identity=admin_identity(handler)
        if not strict_origin(handler.headers):raise AccessError('origin_denied_no_write')
        if _header_values(handler.headers,'content-type')!=['application/json']:raise AccessError('invalid_type_no_write')
        n=int(handler.headers.get('Content-Length','0'))
        if not 1<=n<=384:raise AccessError('invalid_size_no_write')
        data=json.loads(handler.rfile.read(n).decode('utf-8'))
        if not isinstance(data,dict) or set(data)!= {'operation','consent_token','confirmation'}:raise AccessError('invalid_request_no_write')
        operation=data['operation'];proof=data['consent_token'];confirmation=data['confirmation']
        if operation not in ('activate','revoke') or not isinstance(proof,str) or len(proof)>100 or not isinstance(confirmation,str):raise AccessError('invalid_request_no_write')
        expected='ΕΓΚΡΙΝΩ' if operation=='activate' else 'ΑΝΑΚΛΗΣΗ'
        if confirmation!=expected or not _consume(identity,operation,proof):raise AccessError('approval_denied_no_write')
        if operation=='activate':
            state,_=read_account(os.getenv('SUPERVISOR_TOKEN',''))
            if state!='absent':raise AccessError('account_exists_manual_review')
            opts=_read_options()
            settings=paired_settings(connection,opts)
            prepared=(settings,prepare_delivery(settings))
            # Paired Portal readiness must succeed before consuming the single write attempt.
            with _lock:
                if operation in _attempted:raise AccessError('already_attempted_manual_review')
                _attempted.add(operation)
            result=create_and_deliver(connection,opts,prepared=prepared)
        else:
            with _lock:
                if operation in _attempted:raise AccessError('already_attempted_manual_review')
                _attempted.add(operation)
            result=revoke_account(connection)
        _respond(handler,200,{'code':result})
    except AccessError as exc:
        _respond(handler,409,{'code':str(exc)})
    except (OSError,ValueError,KeyError,RoundTripError):
        _respond(handler,503,{'code':'action_uncertain_manual_review'})
    except Exception:_respond(handler,503,{'code':'action_uncertain_manual_review'})
