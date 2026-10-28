"""Offline, read-only survey safety checks: no HA/OVH/Supervisor access."""
import importlib.util
from pathlib import Path
import tempfile
import hashlib
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'smart-pro-system' / 'recovery_stage.py'

# Match the add-on Python path for the existing imported recovery_verifier module.
import sys
sys.path.insert(0, str(MODULE.parent))
spec=importlib.util.spec_from_file_location('recovery_stage_survey_test', MODULE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class QuarantineSurveyTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name) / 'quarantine'
        self.old_root=mod._ROOT
        mod._ROOT=self.root
    def tearDown(self):
        mod._ROOT=self.old_root
        self.temp.cleanup()
    def survey(self):
        result=mod.quarantine_orphan_survey_readonly()
        self.assertFalse(result['delete_authorized'])
        self.assertFalse(result['sha256_rechecked'])
        self.assertFalse(result['supervisor_live_rechecked'])
        self.assertNotIn('path',result)
        self.assertNotIn('filename',result)
        return result
    def make_archive(self, suffix='a'*32, data=b'test'):
        self.root.mkdir(exist_ok=True)
        p=self.root/('mbr_'+suffix+'.tar')
        p.write_bytes(data)
        return p
    def test_directory_absent(self):
        self.assertEqual(self.survey()['state'],'directory_absent')
    def test_empty_directory(self):
        self.root.mkdir()
        self.assertEqual(self.survey()['state'],'no_archive_candidate')
    def test_single_candidate_metadata_only(self):
        p=self.make_archive()
        v=self.survey()
        self.assertEqual(v['state'],'single_candidate_unbound')
        self.assertEqual(v['candidate_bytes'],4)
        self.assertEqual(v['archive_count'],1)
        self.assertEqual(v['candidate_request_sha256'],hashlib.sha256(('mbr_'+'a'*32).encode()).hexdigest())
        self.assertTrue(p.exists())
        self.assertEqual(p.read_bytes(),b'test')
    def test_multiple_candidates_fail_closed(self):
        self.make_archive('a'*32);self.make_archive('b'*32)
        self.assertEqual(self.survey()['state'],'ambiguous_candidates')
    def test_partial_and_archive_are_ambiguous(self):
        self.make_archive()
        (self.root/('mbr_'+'b'*32+'.part')).write_bytes(b'part')
        self.assertEqual(self.survey()['state'],'ambiguous_candidates')
    def test_partial_only(self):
        self.root.mkdir()
        (self.root/('mbr_'+'a'*32+'.part')).write_bytes(b'x')
        self.assertEqual(self.survey()['state'],'partials_only')
    def test_symlink_candidate_blocked(self):
        self.root.mkdir()
        (self.root/('mbr_'+'a'*32+'.tar')).symlink_to('/etc/hosts')
        self.assertEqual(self.survey()['state'],'unsafe_candidate')
    def test_hardlink_candidate_blocked(self):
        p=self.make_archive();p2=self.root/'other';p2.hardlink_to(p)
        self.assertEqual(self.survey()['state'],'unsafe_candidate')
    def test_symlink_directory_blocked(self):
        self.root.symlink_to(Path(self.temp.name))
        self.assertEqual(self.survey()['state'],'unsafe_directory')
    def test_many_entries_bounded(self):
        self.root.mkdir()
        for k in range(129): (self.root / f'unknown-{k}').touch()
        self.assertEqual(self.survey()['state'],'directory_limit_exceeded')
    def test_ignores_other_files_not_archive(self):
        self.root.mkdir()
        (self.root/'supervisor_stage_result.json').write_text('x')
        (self.root/'foo.tar').write_text('x')
        self.assertEqual(self.survey()['state'],'no_archive_candidate')

if __name__=='__main__': unittest.main()
