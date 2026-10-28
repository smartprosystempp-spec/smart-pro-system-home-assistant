"""Explicit technician-staging of an already SHA-256 verified backup into Supervisor.

This module may call only Supervisor GET /backups, POST /backups/new/upload,
and GET /backups/<slug>/info. It NEVER invokes Supervisor restore or delete.
Only a valid Portal-signed, exact installation/node/point grant starts the job.
"""
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tarfile
import threading
import time
from urllib.parse import quote

import recovery_verifier

_LOCK = threading.Lock()
_ROOT = Path('/data/managed_backup_recovery')
_META = _ROOT / 'supervisor_stage_result.json'
_FIELDS = frozenset({
    'contract','action','request_id','installation_id','node_id','point_id',
    'recovery_request_id','object_sha256','object_size','case_id','nonce',
    'issued_at','expires_at','supervisor_upload_authorized','restore_authorized',
    'delete_authorized','export_authorized','signature',
})


def _read_state():
    try:
        result=json.loads(_META.read_text('utf-8'))
        return result if isinstance(result,dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(record):
    _ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(_ROOT,0o700)
    tmp=_ROOT/'supervisor_stage_result.tmp'
    with open(tmp,'w',encoding='utf-8') as out:
        os.chmod(tmp,0o600)
        json.dump(record,out,sort_keys=True,separators=(',',':'))
        out.flush();os.fsync(out.fileno())
    os.replace(tmp,_META)
    os.chmod(_META,0o600)


def public_result():
    with _LOCK:
        rec=_read_state()
    if rec.get('state') not in ('running','imported','failed'):return None
    return {k:rec.get(k) for k in ('contract','request_id','recovery_request_id','point_id','node_id',
                                    'state','reason','slug_hint','finished_at','quarantine_cleanup')}




def quarantine_record_diagnostics_readonly():
    """Bounded metadata-only diagnosis. No archive scans, file reads, hashes or mutations."""
    def metadata_status(path):
        try:
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
                return 'unsafe_metadata'
            try:
                value=json.loads(path.read_text(encoding='utf-8'))
            except (ValueError, UnicodeError):
                return 'invalid_json'
            if not isinstance(value,dict):
                return 'invalid_json'
            return 'valid_json' if re.fullmatch(r'mbr_[a-f0-9]{32}',str(value.get('recovery_request_id' if path == _META else 'request_id') or '')) else 'missing_request_binding'
        except FileNotFoundError:
            return 'absent'
        except OSError:
            return 'inspection_failed'
    return {
        'recovery_record':metadata_status(recovery_verifier._META),
        'stage_record':metadata_status(_META),
        'sha256_rechecked':False,'supervisor_live_rechecked':False,
        'delete_authorized':False,
    }



def quarantine_orphan_survey_readonly():
    """Strictly bounded, direct-child metadata survey for an unbound old archive.

    No file contents, cloud calls, Supervisor calls, filenames or raw identifiers
    in telemetry. A candidate-name SHA-256 is NOT an archive content hash.
    This survey never authorizes rebinding, cleanup, import or restore.
    """
    result = {
        'contract': 'smart-pro-quarantine-orphan-survey-v1',
        'state': 'inspection_failed', 'archive_count': 0, 'partial_count': 0,
        'candidate_bytes': 0, 'candidate_request_sha256': '',
        'sha256_rechecked': False, 'supervisor_live_rechecked': False,
        'delete_authorized': False,
    }
    try:
        directory = _ROOT.lstat()
        if not stat.S_ISDIR(directory.st_mode):
            result['state'] = 'unsafe_directory'
            return result
    except FileNotFoundError:
        result['state'] = 'directory_absent'
        return result
    except OSError:
        return result
    archives = []
    partials = 0
    seen = 0
    try:
        with os.scandir(_ROOT) as entries:
            for entry in entries:
                seen += 1
                if seen > 128:
                    result['state'] = 'directory_limit_exceeded'
                    return result
                name = entry.name
                if re.fullmatch(r'mbr_[a-f0-9]{32}\.part', name):
                    partials += 1
                elif re.fullmatch(r'mbr_[a-f0-9]{32}\.tar', name):
                    archives.append((name, entry))
    except OSError:
        return result
    result['archive_count'] = min(len(archives), 2)
    result['partial_count'] = min(partials, 2)
    if not archives:
        result['state'] = 'no_archive_candidate' if not partials else 'partials_only'
        return result
    if len(archives) != 1 or partials:
        result['state'] = 'ambiguous_candidates'
        return result
    name, entry = archives[0]
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return result
    if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and 0 < info.st_size <= 2 * 1024**3):
        result['state'] = 'unsafe_candidate'
        return result
    result['state'] = 'single_candidate_unbound'
    result['candidate_bytes'] = int(info.st_size)
    result['candidate_request_sha256'] = hashlib.sha256(name[:-4].encode('ascii')).hexdigest()
    return result

def quarantine_inventory_readonly():
    """Bounded local lstat only. Never hashes, opens, restores or deletes a file.

    Historical supervisor-stage success is informational, NOT live Supervisor
    verification and NOT deletion authorization.
    """
    with _LOCK:
        stage = _read_state()
    held = recovery_verifier.public_result()
    if not isinstance(held, dict) or not re.fullmatch(r'mbr_[a-f0-9]{32}', str(held.get('request_id') or '')):
        return {'contract':'smart-pro-recovery-quarantine-inventory-v1', 'state':'no_bound_record', 'observed_at':int(time.time()), 'delete_authorized':False, 'record_diagnostic':quarantine_record_diagnostics_readonly(), 'directory_diagnostic':quarantine_orphan_survey_readonly()}
    request_id = held['request_id']
    path = _ROOT / (request_id + '.tar')
    state='absent'
    try:
        info = path.lstat()
        expected = int(held.get('bytes_received') or 0)
        if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            0 < expected <= 2*1024**3 and info.st_size == expected):
            state='present_size_match_unhashed'
        else:
            state='file_mismatch'
    except FileNotFoundError:
        state='absent'
    except (OSError, ValueError, TypeError):
        state='inspection_failed'
    stage_match = (stage.get('recovery_request_id') == request_id and
                   stage.get('point_id') == held.get('point_id') and
                   stage.get('node_id') == held.get('node_id'))
    result = {
        'contract':'smart-pro-recovery-quarantine-inventory-v1',
        'request_id':request_id,
        'point_id':str(held.get('point_id') or ''),
        'node_id':str(held.get('node_id') or ''),
        'state':state,
        'supervisor_stage_historical': 'imported' if stage_match and stage.get('state') == 'imported' else 'unconfirmed',
        'observed_at':int(time.time()),
        'sha256_rechecked':False,
        'supervisor_live_rechecked':False,
        'delete_authorized':False,
    }
    # 3.0.25: metadata-only post-import directory confirmation. This NEVER
    # scans file contents, deletes anything or alters Supervisor/backup state.
    # Emitted only for the same bound record and an absent exact archive.
    if state == 'absent' and stage_match and stage.get('state') == 'imported' and stage.get('quarantine_cleanup') == 'deleted':
        result['directory_diagnostic'] = quarantine_orphan_survey_readonly()
    return result


def _validated_archive(path, expected_size, expected_hash):
    """No extraction, links, or metadata disclosure; re-hash the exact archive."""
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size!=expected_size or info.st_nlink!=1:
        raise ValueError('quarantine_file_invalid')
    digest=hashlib.sha256()
    with open(path,'rb') as file:
        while chunk:=file.read(1024*1024):digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(),expected_hash):
        raise ValueError('quarantine_sha256_mismatch')
    metadata=None
    members=0
    # Supervisor backs up as a plain *outer* tar with ./backup.json metadata.
    with tarfile.open(path,mode='r:') as archive:
        for member in archive:
            members+=1
            if members>2048:raise ValueError('archive_member_limit')
            name=member.name.removeprefix('./')
            if name.startswith('/') or '..' in Path(name).parts or not (member.isfile() or member.isdir()):
                raise ValueError('archive_unsafe_member')
            if name in ('backup.json','snapshot.json'):
                if metadata is not None or not member.isfile() or member.size>131072:
                    raise ValueError('archive_metadata_invalid')
                f=archive.extractfile(member)
                if f is None:raise ValueError('archive_metadata_invalid')
                metadata=json.loads(f.read(131073))
    if not isinstance(metadata,dict):raise ValueError('archive_metadata_missing')
    slug=str(metadata.get('slug') or '')
    kind=str(metadata.get('type') or '')
    if not re.fullmatch('[A-Za-z0-9_-]{6,64}',slug) or kind not in ('full','partial'):
        raise ValueError('archive_metadata_invalid')
    return slug


def _validate(job,ctx):
    if not isinstance(job,dict) or set(job)!=_FIELDS:return None
    if job.get('contract')!='smart-pro-managed-backup-supervisor-stage-v1' or job.get('action')!='stage_verified_archive_only':return None
    if job.get('supervisor_upload_authorized') is not True or any(job.get(k) is not False for k in ('restore_authorized','delete_authorized','export_authorized')):return None
    if job.get('installation_id')!=ctx.get('installation_id') or job.get('node_id')!=ctx.get('node_id'):return None
    if not re.fullmatch('mbst_[a-f0-9]{32}',str(job.get('request_id') or '')):return None
    if not re.fullmatch('mbr_[a-f0-9]{32}',str(job.get('recovery_request_id') or '')):return None
    if not re.fullmatch('mbrp_[a-f0-9]{32}',str(job.get('point_id') or '')):return None
    if not re.fullmatch('mbhr_[a-f0-9]{32}',str(job.get('case_id') or '')):return None
    if not re.fullmatch('[a-f0-9]{32}',str(job.get('nonce') or '')) or not re.fullmatch('[a-f0-9]{64}',str(job.get('object_sha256') or '')):return None
    try: size=int(job['object_size']);issued=int(job['issued_at']);expires=int(job['expires_at'])
    except (TypeError,ValueError,KeyError):return None
    now=int(time.time())
    if not 0<size<=2*1024**3 or not 0<issued<=now+30 or now>expires or not 0<expires-issued<=120:return None
    secret=ctx.get('secret',b'')
    if not isinstance(secret,bytes) or len(secret)!=32:return None
    canonical=json.dumps({k:v for k,v in job.items() if k!='signature'},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    if not hmac.compare_digest(hmac.new(secret,canonical,hashlib.sha256).hexdigest(),str(job.get('signature') or '')):return None
    held=recovery_verifier.public_result()
    if not held or held.get('state')!='verified' or held.get('reason')!='full_sha256_verified':return None
    if any(str(job[k])!=str(held.get(v,'')) for k,v in [('recovery_request_id','request_id'),('point_id','point_id'),('node_id','node_id'),('object_sha256','sha256')]):return None
    if size!=int(held.get('bytes_received') or 0):return None
    return {'request_id':job['request_id'],'recovery_request_id':job['recovery_request_id'],
            'point_id':job['point_id'],'node_id':job['node_id'],'size':size,'sha':job['object_sha256']}


def _call_supervisor(method, route, token, archive=None):
    conn=http.client.HTTPConnection('supervisor',80,timeout=180)
    try:
        headers={'Authorization':'Bearer '+token,'Accept':'application/json','Connection':'close'}
        if archive is None:
            conn.request(method,route,headers=headers)
        else:
            boundary='smartpro'+secrets.token_hex(12)
            prefix=('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="backup.tar"\r\n'
                    'Content-Type: application/x-tar\r\n\r\n').encode()
            suffix=('\r\n--'+boundary+'--\r\n').encode()
            headers['Content-Type']='multipart/form-data; boundary='+boundary
            headers['Content-Length']=str(len(prefix)+archive.stat().st_size+len(suffix))
            conn.putrequest(method,route);[conn.putheader(k,v) for k,v in headers.items()];conn.endheaders()
            conn.send(prefix)
            with open(archive,'rb') as file:
                while chunk:=file.read(1024*1024):conn.send(chunk)
            conn.send(suffix)
        response=conn.getresponse(); data=response.read(1024*1024+1)
        if response.status!=200 or len(data)>1024*1024:raise ValueError('supervisor_api_rejected')
        result=json.loads(data)
        if not isinstance(result,dict) or result.get('result')!='ok':raise ValueError('supervisor_api_rejected')
        return result.get('data',{})
    finally:conn.close()



def _cleanup_imported_quarantine(archive, plan, original):
    """Remove only the exact downloaded archive after verified Supervisor read-back.

    Never walk directories, remove backup inventory, follow links, or delete a
    changed/replaced file. A failure leaves the archive for technician review.
    """
    if not re.fullmatch(r'mbr_[a-f0-9]{32}', str(plan.get('recovery_request_id') or '')):
        return 'retained'
    if archive.parent != _ROOT or archive.name != plan['recovery_request_id'] + '.tar':
        return 'retained'
    try:
        current = archive.lstat()
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or
                current.st_size != plan['size'] or current.st_dev != original.st_dev or
                current.st_ino != original.st_ino):
            return 'retained'
        archive.unlink()
        return 'deleted'
    except OSError:
        return 'retained'


def _worker(plan):
    result={'contract':'smart-pro-managed-backup-supervisor-stage-result-v1','request_id':plan['request_id'],
            'recovery_request_id':plan['recovery_request_id'],'point_id':plan['point_id'],
            'node_id':plan['node_id'],'state':'failed','reason':'staging_failed','slug_hint':'','finished_at':0,'quarantine_cleanup':'not_attempted'}
    try:
        token=str(os.getenv('SUPERVISOR_TOKEN') or '').strip()
        if not token:raise ValueError('supervisor_token_missing')
        archive=_ROOT/(plan['recovery_request_id']+'.tar')
        slug=_validated_archive(archive,plan['size'],plan['sha'])
        original=archive.lstat()
        # Explicit fail-closed collision check. Never replace a Supervisor backup.
        collection=_call_supervisor('GET','/backups',token)
        if not isinstance(collection,dict) or not isinstance(collection.get('backups'),list):raise ValueError('supervisor_listing_invalid')
        if any(isinstance(item,dict) and item.get('slug')==slug for item in collection['backups']):raise ValueError('supervisor_slug_already_present')
        result_body=_call_supervisor('POST','/backups/new/upload',token,archive)
        if not isinstance(result_body,dict) or result_body.get('slug')!=slug:raise ValueError('supervisor_import_unconfirmed')
        details=_call_supervisor('GET','/backups/'+quote(slug,safe='')+'/info',token)
        if not isinstance(details,dict) or details.get('slug')!=slug:raise ValueError('supervisor_import_readback_failed')
        result.update(state='imported',reason='supervisor_backup_listed',slug_hint=slug[-12:])
        result['quarantine_cleanup']=_cleanup_imported_quarantine(archive,plan,original)
    except (OSError,ValueError,tarfile.TarError,RuntimeError) as err:
        # No raw response bodies, file paths, tokens, backup metadata or URLs in result.
        code=str(err) if isinstance(err,ValueError) else ''
        allowed={'supervisor_slug_already_present','supervisor_token_missing',
                 'quarantine_file_invalid','quarantine_sha256_mismatch',
                 'archive_unsafe_member','archive_metadata_missing','archive_metadata_invalid',
                 'archive_member_limit','supervisor_api_rejected','supervisor_import_unconfirmed',
                 'supervisor_import_readback_failed','supervisor_listing_invalid'}
        result['reason']=code if code in allowed else 'supervisor_stage_failed'
    except Exception:
        result['reason']='supervisor_stage_failed'
    finally:
        result['finished_at']=int(time.time())
        with _LOCK:_save_state(result)


def maybe_start(job,ctx):
    plan=_validate(job,ctx)
    if not plan:return False
    with _LOCK:
        last=_read_state()
        if last.get('request_id')==plan['request_id'] or last.get('state') in ('running','imported'):return False
        _save_state({'contract':'smart-pro-managed-backup-supervisor-stage-result-v1','request_id':plan['request_id'],
                     'recovery_request_id':plan['recovery_request_id'],'point_id':plan['point_id'],
                     'node_id':plan['node_id'],'state':'running','reason':'stage_started','slug_hint':'','finished_at':0,'quarantine_cleanup':'not_attempted'})
    threading.Thread(target=_worker,args=(plan,),name='managed-backup-supervisor-stage',daemon=True).start()
    return True
