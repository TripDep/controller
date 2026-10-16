"""Real hashed Controller audit fixture; never an asset-quality or MG0 PASS."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from real_work_intake import canonical, sha as source_sha
from c07_process_r178 import inspect, ProcessBindingError, RULE_ID, RULE_TEXT

MASTER=b'canonical master independent fixture'
ASSET='TEST'
STEP='S001'
ID='e'*64

class Cases(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.master=root/'MASTER.md';self.master.write_bytes(MASTER)
        self.audit=root/'audit.jsonl'
        self.dependency=b'immutable upstream source bytes\n'
        self.dep_hash=hashlib.sha256(self.dependency).hexdigest()
        self.work={'master_sha256':hashlib.sha256(MASTER).hexdigest(),
                   'attempt_id':'a'*64,'operation_sha256':'b'*64,
                   'work_dependencies':{ID:self.dep_hash}}
        self.plan={'dependency_files':{ID:'src/source.blend'},'phase':'P0'}
        self.inv={'schema':'gg-effective-family-inventory-v1','rule_count':763,
                  'canonical_master_sha256':self.work['master_sha256'],
                  'rules':{RULE_ID:{'family':'AAA-200','catalog_number':178,
                      'catalog_section':'R','catalog_phase':'P0',
                      'requirement':RULE_TEXT,
                      'requirement_sha256':hashlib.sha256(RULE_TEXT.encode()).hexdigest()}}}
        self.events=[]
        plan=self.push('SUPERVISOR_PLAN_ENROLLED',plan=self.plan)
        reserve=self.push('SUPERVISOR_OPERATION_RESERVED',
                           work=self.work,operation_sha256=self.work['operation_sha256'],
                           plan_record_hash=plan['record_hash'])
        self.push('SUPERVISOR_OPERATION_OPENED',
                  reservation_hash=reserve['record_hash'],step=STEP)
        self.state={'last_audit_hash':self.events[-1]['record_hash'],
                    'active_step':{'step':STEP}}
        self.c=Mock(master=self.master)
        self.c.audit_path.return_value=self.audit
        self.c.asset_state.return_value=self.state

    def push(self,event,**kv):
        item={'asset':ASSET,'event':event,'prev_hash':self.events[-1]['record_hash']
              if self.events else 'GENESIS',**kv}
        item['record_hash']=source_sha(canonical(item))
        self.events.append(item)
        self.audit.write_bytes(b'\n'.join(canonical(x) for x in self.events)+b'\n')
        return item

    def execute(self):
        return inspect(self.c,ASSET,STEP,self.work,self.plan,self.inv,
                       lambda path:self.dependency if path=='src/source.blend' else None)

    def test_valid_current_controller_state_and_dependencies_have_scoped_pass(self):
        o=self.execute()
        self.assertEqual(o['current_operation_process_observation'],'PASS')
        self.assertEqual(o['dependency_bytes_checked'],1)
        self.assertTrue(all(o['criteria'].values()))
        self.assertEqual(o['positive_3d_rule_semantic_passes'],0)
        self.assertEqual(o['individual_mg0_passes'],0)
        self.assertFalse(o['advancement_authorized'])

    def test_dependency_bytes_changed_is_real_rule_failure(self):
        self.dependency=b'new unregistered source'
        r=self.execute()
        self.assertEqual(r['current_operation_process_observation'],'FAIL')
        self.assertIn('immutable_dependency_bytes_match_registration',r['failed_criteria'])

    def test_state_tail_mismatch_is_failure_not_promotion(self):
        self.state['last_audit_hash']='0'*64
        r=self.execute()
        self.assertEqual(r['current_operation_process_observation'],'FAIL')
        self.assertIn('chain_state_at_current_tail',r['failed_criteria'])

    def test_current_active_step_mismatch_does_not_pass(self):
        self.state['active_step']={'step':'WRONG'}
        self.assertEqual(self.execute()['current_operation_process_observation'],'FAIL')

    def test_plan_forgery_is_stopped(self):
        self.plan['dependency_files'][ID]='different-path.blend'
        with self.assertRaisesRegex(ProcessBindingError,'ENROLLED_PLAN_NOT_AUTHENTICATED'):
            self.execute()

    def test_audit_tamper_is_stopped(self):
        content=self.audit.read_bytes()
        self.audit.write_bytes(content.replace(b'SUPERVISOR_OPERATION_OPENED',b'FAKE_OPEN_OPERATION'))
        with self.assertRaises(Exception):self.execute()

if __name__=='__main__':unittest.main()
