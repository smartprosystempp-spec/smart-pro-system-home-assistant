"""Offline regression: exact Supervisor slug metadata is bound to collision/import result only.

No live Supervisor, backup download, or filesystem mutation outside temp directory.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'smart-pro-system'))
import recovery_stage as rs

SLUG='SmartPro_Managed_bace535e'
PLAN={'request_id': 'mbst_'+'a'*32, 'recovery_request_id':'mbr_'+'b'*32,
      'point_id':'mbrp_'+'c'*32, 'node_id':'d'*64, 'size':10, 'sha':'e'*64}

class SlugEvidence(unittest.TestCase):
    def _run(self, supervisor):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root / (PLAN['recovery_request_id']+'.tar')).write_bytes(b'1234567890')
            with patch.object(rs, '_ROOT', root), patch.object(rs,'_META',root/'result.json'), \
                 patch.object(rs,'_validated_archive',return_value=SLUG), \
                 patch.object(rs,'_call_supervisor',side_effect=supervisor), \
                 patch.object(rs.os,'getenv',return_value='local-only-test-token'):
                rs._worker(PLAN)
                result=rs.public_result()
                return result, (root / (PLAN['recovery_request_id']+'.tar')).exists()

    def test_slug_collision_reporting_does_not_delete_or_upload(self):
        calls=[]
        def supervisor(method,route,token,archive=None):
            calls.append((method,route))
            return {'backups':[{'slug':SLUG}]} if route=='/backups' else {'slug':SLUG}
        result, archive_exists=self._run(supervisor)
        self.assertEqual(result['state'],'failed')
        self.assertEqual(result['reason'],'supervisor_slug_already_present')
        self.assertEqual(result['supervisor_slug'],SLUG)
        self.assertEqual(result['slug_hint'],SLUG[-12:])
        self.assertEqual(result['quarantine_cleanup'],'not_attempted')
        self.assertTrue(archive_exists)
        self.assertEqual(calls,[('GET','/backups'),('GET','/backups/'+SLUG+'/info')])
        self.assertEqual(result['collision_evidence'],'info_confirmed')
        self.assertGreater(result['collision_checked_at'],0)

    def test_missing_info_keeps_listing_only_and_blocks_upload(self):
        calls=[]
        def supervisor(method,route,token,archive=None):
            calls.append((method,route))
            if route=='/backups':return {'backups':[{'slug':SLUG}]}
            raise ValueError('supervisor_api_rejected')
        result, exists=self._run(supervisor)
        self.assertEqual(result['state'],'failed')
        self.assertEqual(result['reason'],'supervisor_slug_already_present')
        self.assertEqual(result['collision_evidence'],'listing_only')
        self.assertTrue(exists)
        self.assertEqual(len(calls),2)

    def test_success_readback_reports_exact_imported_slug(self):
        calls=[]
        def supervisor(method,route,token,archive=None):
            calls.append((method,route))
            if route=='/backups':return {'backups':[]}
            return {'slug':SLUG}
        result, archive_exists=self._run(supervisor)
        self.assertEqual(result['state'],'imported')
        self.assertEqual(result['reason'],'supervisor_backup_listed')
        self.assertEqual(result['supervisor_slug'],SLUG)
        self.assertEqual(result['quarantine_cleanup'],'deleted')
        self.assertFalse(archive_exists)
        self.assertEqual(len(calls),3)

    def test_failed_supervisor_list_does_not_claim_collision_slug(self):
        def supervisor(method,route,token,archive=None):
            raise ValueError('supervisor_api_rejected')
        result, archive_exists=self._run(supervisor)
        self.assertEqual(result['state'],'failed')
        self.assertEqual(result['reason'],'supervisor_api_rejected')
        self.assertEqual(result['supervisor_slug'],'')
        self.assertTrue(archive_exists)

if __name__=='__main__':unittest.main()
