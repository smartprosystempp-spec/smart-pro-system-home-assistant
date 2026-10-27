"""Smart Pro Managed Backup: technician-gated full GET to private quarantine.

No Supervisor restore/import, shell execution, filesystem export, or data-plane write.
The only effect after an explicit signed recovery grant is a bounded HTTPS GET to
an object-specific OVH S3 URL and a private, hash-verified local archive.
"""
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
import shutil
import ssl
import threading
import time
from urllib.parse import parse_qs, quote, urlsplit
from datetime import datetime, timezone

_LOCK = threading.Lock()
_ROOT = Path('/data/managed_backup_recovery')
_META = _ROOT / 'result.json'
_HOST = 's3.eu-south-mil.io.cloud.ovh.net'
_BUCKET = 'smartpro-managed-backup-primary-mil'
_MAX_BYTES = 2 * 1024 ** 3
_FLOOR_BYTES = 512 * 1024 ** 2
_EXPECTED_FIELDS = frozenset({
    'contract','action','request_id','installation_id','node_id','point_id',
    'provider_id','bucket','object_key','object_version_id','object_sha256',
    'object_size','url','nonce','issued_at','expires_at','download_authorized',
    'restore_authorized','delete_authorized','replication_authorized','signature',
})


def _load():
    try:
        v = json.loads(_META.read_text(encoding='utf-8'))
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(v):
    _ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(_ROOT, 0o700)
    temp = _ROOT / 'result.tmp'
    with open(temp, 'w', encoding='utf-8') as out:
        os.chmod(temp, 0o600)
        json.dump(v, out, sort_keys=True, separators=(',', ':'))
    os.replace(temp, _META)
    os.chmod(_META, 0o600)


def public_result():
    with _LOCK:
        v = _load()
    state = v.get('state')
    if state not in ('running','verified','failed'):
        return None
    # Never retain a VERIFIED badge when the quarantined artifact is missing.
    if state == 'verified':
        archive = _ROOT / (str(v.get('request_id') or '') + '.tar')
        try:
            info = archive.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != int(v.get('bytes_received') or 0):
                raise OSError('quarantine mismatch')
        except OSError:
            v.update(state='failed',reason='verified_archive_unavailable',sha256='')
    return {k:v.get(k) for k in ('contract','request_id','point_id','node_id',
        'state','reason','bytes_received','sha256','finished_at')}


def _safe_url(url, object_key, issued_at, expires_at):
    try:
        u = urlsplit(url)
        if u.scheme != 'https' or u.hostname != _HOST or u.port not in (None,443) or u.username or u.password or u.fragment:
            return None
        expected_path = '/' + _BUCKET + '/' + '/'.join(quote(p,safe='') for p in object_key.split('/'))
        if u.path != expected_path or not u.query:
            return None
        query = parse_qs(u.query, keep_blank_values=True, strict_parsing=True)
        required = ('X-Amz-Algorithm','X-Amz-Credential','X-Amz-Date','X-Amz-Expires','X-Amz-SignedHeaders','X-Amz-Signature')
        if any(len(query.get(k,[])) != 1 for k in required):
            return None
        if query['X-Amz-Algorithm'][0] != 'AWS4-HMAC-SHA256' or query['X-Amz-SignedHeaders'][0] != 'host':
            return None
        issued = int(datetime.strptime(query['X-Amz-Date'][0],'%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp())
        expires = int(query['X-Amz-Expires'][0]); now = int(time.time())
        if expires < 30 or expires > 120 or issued < issued_at-5 or issued+expires > expires_at+5 or now > issued+expires:
            return None
        return u.path + '?' + u.query
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def _validate(job, ctx):
    if not isinstance(job,dict) or set(job)!=_EXPECTED_FIELDS:
        return None
    if job.get('contract') != 'smart-pro-managed-backup-recovery-download-v1' or job.get('action') != 'verify_primary_recovery_download':
        return None
    if any(job.get(k) is not False for k in ('restore_authorized','delete_authorized','replication_authorized')) or job.get('download_authorized') is not True:
        return None
    if job.get('installation_id') != ctx.get('installation_id') or job.get('node_id') != ctx.get('node_id'):
        return None
    if job.get('provider_id') != 'ovh_s3_primary_mil_v1' or job.get('bucket') != _BUCKET:
        return None
    rid = str(job.get('request_id') or '')
    if not re.fullmatch(r'mbr_[0-9a-f]{32}', rid) or not re.fullmatch(r'mbrp_[a-f0-9]{32}',str(job.get('point_id') or '')):
        return None
    if not re.fullmatch(r'[a-f0-9]{32}',str(job.get('nonce') or '')) or not re.fullmatch(r'[a-f0-9]{64}',str(job.get('object_sha256') or '')):
        return None
    if not re.fullmatch(r'managed-backup-presigned/[0-9a-f]{24}/mbj_[a-f0-9]{32}\.tar',str(job.get('object_key') or '')):
        return None
    if len(str(job.get('object_version_id') or '')) > 128 or not re.fullmatch(r'[A-Za-z0-9._~-]{0,128}',str(job.get('object_version_id') or '')):
        return None
    try:
        size=int(job['object_size']); issued=int(job['issued_at']); expires=int(job['expires_at'])
    except (ValueError,TypeError,KeyError):
        return None
    now=int(time.time())
    if not 0<size<=_MAX_BYTES or not 0<issued<=now+30 or now>expires or not 0<expires-issued<=120:
        return None
    target=_safe_url(str(job.get('url') or ''),str(job['object_key']),issued,expires)
    if target is None:
        return None
    secret=ctx.get('secret',b'')
    if not isinstance(secret,bytes) or len(secret)!=32:
        return None
    unsigned={k:v for k,v in job.items() if k!='signature'}
    message=json.dumps(unsigned,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    signature=hmac.new(secret,message,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature,str(job.get('signature') or '')):
        return None
    return {'id':rid,'point_id':job['point_id'],'node_id':job['node_id'],
            'expected_sha':job['object_sha256'],'size':size,'version':job['object_version_id'],'target':target}


def _worker(plan):
    result={'contract':'smart-pro-managed-backup-recovery-result-v1',
            'request_id':plan['id'],'point_id':plan['point_id'],'node_id':plan['node_id'],
            'state':'failed','reason':'download_failed','bytes_received':0,'sha256':'','finished_at':0}
    targetfile = _ROOT / (plan['id'] + '.tar')
    partial = _ROOT / (plan['id'] + '.part')
    conn=None
    try:
        _ROOT.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(_ROOT,0o700)
        free=shutil.disk_usage(_ROOT).free
        if free < plan['size'] + _FLOOR_BYTES:
            raise ValueError('insufficient_quarantine_space')
        if partial.exists() or targetfile.exists():
            raise ValueError('recovery_destination_exists')
        conn=http.client.HTTPSConnection(_HOST,443,timeout=90,context=ssl.create_default_context())
        conn.request('GET',plan['target'],headers={'Accept-Encoding':'identity','Connection':'close'})
        response=conn.getresponse()
        if response.status != 200:
            raise ValueError('provider_get_status_invalid')
        length=response.getheader('Content-Length','')
        if not str(length).isdigit() or int(length)!=plan['size'] or response.getheader('Content-Encoding','').lower() not in ('','identity'):
            raise ValueError('provider_get_header_mismatch')
        expected_version=plan['version']
        if expected_version and response.getheader('x-amz-version-id','') != expected_version:
            raise ValueError('object_version_changed')
        digest=hashlib.sha256(); total=0
        with open(partial,'xb') as out:
            os.chmod(partial,0o600)
            while True:
                chunk=response.read(min(1024*1024,plan['size']-total+1))
                if not chunk:break
                total+=len(chunk)
                if total>plan['size']:
                    raise ValueError('download_size_limit')
                digest.update(chunk);out.write(chunk)
            out.flush();os.fsync(out.fileno())
        if total!=plan['size'] or not hmac.compare_digest(digest.hexdigest(),plan['expected_sha']):
            raise ValueError('recovery_content_hash_mismatch')
        os.replace(partial,targetfile)
        os.chmod(targetfile,0o600)
        result.update(state='verified',reason='full_sha256_verified',bytes_received=total,sha256=digest.hexdigest())
    except ValueError as error:
        result['reason']=str(error)[:64]
    except Exception:
        result['reason']='recovery_transport_failed'
    finally:
        if conn:conn.close()
        try:partial.unlink(missing_ok=True)
        except OSError:pass
        result['finished_at']=int(time.time())
        with _LOCK:
            _save(result)


def maybe_start(job, ctx):
    plan=_validate(job,ctx)
    if not plan:return False
    with _LOCK:
        current=_load()
        if current.get('request_id')==plan['id']:
            return False  # All states, including failures, are single-shot
        if current.get('state')=='running':
            return False
        # Do not accumulate multiple verified recovery archives in this pilot.
        if _ROOT.exists() and any(_ROOT.glob('mbr_*.tar')):
            return False
        _save({'contract':'smart-pro-managed-backup-recovery-result-v1',
              'request_id':plan['id'],'point_id':plan['point_id'],'node_id':plan['node_id'],
              'state':'running','reason':'quarantine_download_started','bytes_received':0,
              'sha256':'','finished_at':0})
    thread=threading.Thread(target=_worker,args=(plan,),name='managed-backup-recovery',daemon=True)
    thread.start()
    return True
