"""C07 R120: source-specific scoped positive evidence. Never a global PASS."""
import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import c07_process_positive_batch as x

HEX='a'*64

def rawjson(v):return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()

def scope(inv,plan):
    ids=sorted(inv['rules'])
    return {'due':ids,'by_rule':{i:{'disposition':'DUE'} for i in ids},'rule_count':763}

class Fake:
    def __init__(self, root):
        self.root=root
        self.master=root/'master.md'
        self.master.write_bytes(b'CERTIFIED MASTER source text')
        self.out=root/'audit.jsonl'
        self.rows=[]
        self.current={}
        self.asset=None
    def append(self,event,**kwargs):
        row={'asset':self.asset,'event':event,'prev_hash':self.rows[-1]['record_hash'] if self.rows else 'GENESIS',**kwargs}
        row['record_hash']=x.sha(rawjson(row))
        self.rows.append(row)
        self.out.write_bytes(b'\n'.join(rawjson(v) for v in self.rows)+b'\n')
        self.current['last_audit_hash']=row['record_hash']
        return row
    def audit_path(self,asset):return self.out
    def asset_state(self,asset):return self.current

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.c=Fake(root)
        self.c.asset='GARDEN'
        self.master=x.sha(self.c.master.read_bytes())
        ids=['110_ERROR_REGISTRY','A']+['AAA-200-'+chr(65+(i-1)//10)+'-'+str(i).zfill(3) for i in range(1,199)]
        ids+=['Q-%03d'%i for i in range(1,564)]
        self.inv={'schema':'gg-effective-family-inventory-v1','rule_count':763,
           'canonical_master_sha256':self.master,
           'families':{'AAA-200':ids[2:200],'OTHER':[ids[0],ids[1]]+ids[200:]},
           'rules':{rid:{'family':'AAA-200' if rid.startswith('AAA-') else 'OTHER',
                      'requirement':'Source obligation '+rid,
                      'requirement_sha256':x.sha(('Source obligation '+rid).encode()),
                      'source_sha256':'b'*64} for rid in ids}}
        self.c.current={'active_step':{'step':'S001'},'scope':'Garden','artifacts':[]}
        d=root/'needed.json';d.write_bytes(b'IMMUTABLE proof dependency')
        self.key='c'*64
        self.plan={'master_sha256':self.master,'dependency_files':{self.key:'needed.json'},
                   'operation':{'category':'MUTATION'}}
        self.work={'master_sha256':self.master,'attempt_id':'d'*64,
                   'operation_sha256':'e'*64,'work_item_sha256':x.sha(rawjson('GARDEN')), 
                   'work_dependencies':{self.key:x.sha(d.read_bytes())}}
        self.c.append('WORK_INIT')
        self.plan_row=self.c.append('SUPERVISOR_PLAN_ENROLLED',plan=self.plan)
        self.res=self.c.append('SUPERVISOR_OPERATION_RESERVED',work=self.work,
                               plan_record_hash=self.plan_row['record_hash'])
        self.c.append('SUPERVISOR_OPERATION_OPENED',step='S001',
                      reservation_hash=self.res['record_hash'])
        self.c.append('STEP_OPEN',step='S001')
        self.src=root/'output.blend';self.src.write_bytes(b'fake test model source 012345')
        self.glb=root/'output.glb';self.glb.write_bytes(b'fake test model export 012345')
        for path,role in ((self.src,'EDITABLE_SOURCE'),(self.glb,'GLB_EXPORT')):
            info={'path':str(path),'role':role,'sha256':x.sha(path.read_bytes()),
                  'size_bytes':path.stat().st_size,'step':'S001'}
            self.c.current['artifacts'].append(info)
            self.c.append('ARTIFACT_RECORDED',step='S001',result='PASS',evidence_operation=info)
        proof=[{'source':'SYNTHETIC_WINDING_OBSERVATION','individual_mg0_passes':0}]
        self.c.append('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE',attempt_id=self.work['attempt_id'],
                      operation_sha256=self.work['operation_sha256'],native_reports=proof,
                      native_reports_sha256=x.sha(json.dumps(proof,sort_keys=True,separators=(',',':')).encode()),
                      advancement_authorized=False)
        self.patches=[patch('c07_operation_scope.inspect',side_effect=scope)]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])
    def go(self):
        return x.inspect(self.inv,self.plan,self.c,'GARDEN','S001',self.work,
                         source_loader=lambda path:Path(path).read_bytes())
    def test_one_batch_observes_thirteen_real_machine_source_predicates(self):
        r=self.go()
        self.assertEqual(r['rule_specific_machine_predicates'],13)
        self.assertEqual(r['rule_specific_scoped_observed'],13)
        self.assertEqual(r['actual_artifact_bytes_verified'],2)
        self.assertEqual(r['actual_dependency_bytes_verified'],1)
        self.assertEqual(r['complete_work_rule_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        self.assertEqual(r['results']['AAA-200-R-172']['scoped_positive_observation'],'OBSERVED_SCOPE_PASS')
        self.assertTrue(all(row['complete_rule_semantics']=='UNKNOWN'
                           and row['work_pass'] is False for row in r['results'].values()))
    def test_missing_native_check_is_unknown_not_pass(self):
        self.c.rows.pop()
        self.c.out.write_bytes(b'\n'.join(rawjson(y) for y in self.c.rows)+b'\n')
        self.c.current['last_audit_hash']=self.c.rows[-1]['record_hash']
        r=self.go()
        self.assertEqual(r['results']['AAA-200-R-175']['scoped_positive_observation'],'UNKNOWN_OR_SCOPE_FAIL')
        self.assertEqual(r['complete_work_rule_passes'],0)
    def test_source_export_separation_is_not_approved_without_two_files(self):
        self.c.current['artifacts'].pop()
        # A mismatched registered item is an authenticity failure, not an UNKNOWN.
        with self.assertRaisesRegex(x.EvidenceBlocked,'REGISTERED_FILE_MISSING'):
            self.go()
    def test_changed_export_bytes_never_satisfy_preservation(self):
        self.glb.write_bytes(b'some incompatible new fake bytes')
        r=self.go()
        self.assertEqual(r['results']['AAA-200-R-177']['scoped_positive_observation'],'UNKNOWN_OR_SCOPE_FAIL')
        self.assertEqual(r['actual_artifact_bytes_verified'],1)
        self.assertFalse(r['results']['AAA-200-R-177']['work_pass'])
    def test_changed_actual_dependency_blocks_scoped_positive(self):
        (self.c.root/'needed.json').write_bytes(b'mutated dependency')
        r=self.go()
        self.assertEqual(r['results']['AAA-200-B-016']['scoped_positive_observation'],'UNKNOWN_OR_SCOPE_FAIL')
        self.assertEqual(r['results']['AAA-200-R-178']['scoped_positive_observation'],'UNKNOWN_OR_SCOPE_FAIL')
    def test_master_or_audit_tampering_denied(self):
        self.c.master.write_bytes(b'MASTER changed')
        with self.assertRaisesRegex(x.EvidenceBlocked,'MASTER_ACTUAL_CONTENT_CHANGED'):
            self.go()
        self.c.master.write_bytes(b'CERTIFIED MASTER source text')
        self.c.rows[1]['plan']['operation']['category']='EXPORT'
        self.c.out.write_bytes(b'\n'.join(rawjson(y) for y in self.c.rows)+b'\n')
        with self.assertRaisesRegex(ValueError,'INTAKE_AUDIT_RECORD|R120_'):
            self.go()
    def test_state_tail_divergence_blocks(self):
        self.c.current['last_audit_hash']='0'*64
        with self.assertRaisesRegex(x.EvidenceBlocked,'WORK_STATE_AUDIT_DIVERGED'):
            self.go()
    def test_requirement_tampering_blocks_specific_id(self):
        self.inv['rules']['AAA-200-R-180']['requirement']='changed'
        with self.assertRaisesRegex(x.EvidenceBlocked,'CANONICAL_RULE_SOURCE_DRIFT'):
            self.go()

if __name__=='__main__':unittest.main()
