import importlib.util,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]/'smart-pro-system'
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('recovery_stage_post_import_test',ROOT/'recovery_stage.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class PostImportSurveyTest(unittest.TestCase):
    def test_bound_imported_cleanup_deleted_receives_survey(self):
        held={'request_id':'mbr_'+'a'*32,'point_id':'mbrp_'+'b'*32,'node_id':'node1'}
        rec={'recovery_request_id':held['request_id'],'point_id':held['point_id'],'node_id':'node1','state':'imported','quarantine_cleanup':'deleted'}
        with patch.object(mod,'_read_state',return_value=rec),patch.object(mod.recovery_verifier,'public_result',return_value=held),patch.object(mod,'_ROOT',Path('/no_such_dir_for_post_import_test')):
            v=mod.quarantine_inventory_readonly()
        self.assertEqual(v['state'],'absent')
        self.assertEqual(v['directory_diagnostic']['state'],'directory_absent')
        self.assertFalse(v['delete_authorized'])
    def test_unmatched_stage_never_receives_survey(self):
        held={'request_id':'mbr_'+'a'*32,'point_id':'mbrp_'+'b'*32,'node_id':'node1'}
        rec={'recovery_request_id':'mbr_'+'c'*32,'point_id':held['point_id'],'node_id':'node1','state':'imported','quarantine_cleanup':'deleted'}
        with patch.object(mod,'_read_state',return_value=rec),patch.object(mod.recovery_verifier,'public_result',return_value=held),patch.object(mod,'_ROOT',Path('/no_such_dir_for_post_import_test')):
            v=mod.quarantine_inventory_readonly()
        self.assertNotIn('directory_diagnostic',v)
    def test_no_cleanup_success_never_receives_survey(self):
        held={'request_id':'mbr_'+'a'*32,'point_id':'mbrp_'+'b'*32,'node_id':'node1'}
        rec={'recovery_request_id':held['request_id'],'point_id':held['point_id'],'node_id':'node1','state':'imported','quarantine_cleanup':'retained'}
        with patch.object(mod,'_read_state',return_value=rec),patch.object(mod.recovery_verifier,'public_result',return_value=held),patch.object(mod,'_ROOT',Path('/no_such_dir_for_post_import_test')):
            v=mod.quarantine_inventory_readonly()
        self.assertNotIn('directory_diagnostic',v)
if __name__=='__main__':unittest.main()
