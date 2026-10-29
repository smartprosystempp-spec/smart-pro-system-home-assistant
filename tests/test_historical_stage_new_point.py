"""Offline check: a prior imported point does not block a different, already-validated grant."""
import sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'smart-pro-system'))
import recovery_stage as rs
class NoopThread:
    def __init__(self,*a,**kw):pass
    def start(self):pass
class HistoricalStageTests(unittest.TestCase):
    def setUp(self):
        self.old={'state':'imported','request_id':'mbst_'+'a'*32,
                  'point_id':'mbrp_'+'a'*32,'recovery_request_id':'mbr_'+'a'*32}
        self.new={'request_id':'mbst_'+'b'*32,'point_id':'mbrp_'+'b'*32,'recovery_request_id':'mbr_'+'b'*32,
                  'node_id':'n','size':1024,'sha':'f'*64}
    def run_case(self,last,plan):
        saved=[]
        with patch.object(rs,'_validate',return_value=plan),patch.object(rs,'_read_state',return_value=last),\
             patch.object(rs,'_save_state',side_effect=lambda v:saved.append(v)),patch.object(rs.threading,'Thread',NoopThread):
            result=rs.maybe_start({}, {})
        return result,saved
    def test_distinct_signed_and_verified_point_can_start(self):
        result,saved=self.run_case(self.old,self.new)
        self.assertTrue(result)
        self.assertEqual(saved[0]['point_id'],self.new['point_id'])
    def test_same_old_point_blocked(self):
        req={**self.new,'point_id':self.old['point_id']}
        result,saved=self.run_case(self.old,req)
        self.assertFalse(result);self.assertEqual(saved,[])
    def test_same_archive_request_blocked(self):
        req={**self.new,'recovery_request_id':self.old['recovery_request_id']}
        result,saved=self.run_case(self.old,req)
        self.assertFalse(result);self.assertEqual(saved,[])
    def test_imported_same_stage_request_blocked(self):
        req={**self.new,'request_id':self.old['request_id']}
        result,saved=self.run_case(self.old,req)
        self.assertFalse(result);self.assertEqual(saved,[])
    def test_running_request_blocked(self):
        result,saved=self.run_case({**self.old,'state':'running'},self.new)
        self.assertFalse(result);self.assertEqual(saved,[])
    def test_unvalidated_request_denied(self):
        result,saved=self.run_case(self.old,None)
        self.assertFalse(result);self.assertEqual(saved,[])
if __name__=='__main__':unittest.main()
