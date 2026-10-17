"""Adversarial, entirely synthetic Controller fixtures; NOT actual asset PASS."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile
from c07_positive_native_process import inspect, RULES, NativeEvidenceBlocked
import c07_positive_native_process as target

def canonical(row):
 return json.dumps(row,sort_keys=True,ensure_ascii=False,
                   separators=(",", ":"),allow_nan=False).encode("utf-8")

def audit_check(raw,asset):
 rows=[];prior="GENESIS"
 for line in raw.splitlines():
  row=json.loads(line)
  if row.get('asset')!=asset or row.get('prev_hash')!=prior:
   raise ValueError('INTAKE_AUDIT_CHAIN')
  h=row.get('record_hash')
  if h!=sha(canonical({k:v for k,v in row.items() if k!='record_hash'})):
   raise ValueError('INTAKE_AUDIT_RECORD')
  rows.append(row);prior=h
 if not rows:raise ValueError('INTAKE_EMPTY_AUDIT')
 return rows,prior
# Simulate the same original-chain validation as production, using actual
# byte-for-byte canonical JSON; never stub a PASS or a fixed hash.


def sha(raw):return hashlib.sha256(raw).hexdigest()

class FakeController:
 def __init__(self,root,state):
  self.root=root
  self.master=root/'MASTER.md'
  self._state=state
 def audit_path(self,asset):return self.root/(asset+'.jsonl')
 def asset_state(self,asset):return self._state

class Tests(unittest.TestCase):
 def setUp(self):
  self.patch_audit=patch.object(target, "audit_check", audit_check)
  self.patch_audit.start()
  self.addCleanup(self.patch_audit.stop)
  self.tmp=tempfile.TemporaryDirectory(prefix='gg-r123-unit-')
  self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name)
  self.master=b'original canonical master bytes'
  (self.root/'MASTER.md').write_bytes(self.master)
  self.asset='TEST'
  self.step='UNIT-STEP-3'
  self.work={'master_sha256':sha(self.master),'attempt_id':'a'*64,
             'operation_sha256':'b'*64,'work_dependencies':{'d'*64:sha(b'dependency-original')}}
  self.plan={'master_sha256':sha(self.master), 'dependency_files':{'d'*64:'dependency.txt'},
             'operation':{'category':'GENERATION'}}
  (self.root/'dependency.txt').write_bytes(b'dependency-original')
  self.inv={'schema':'gg-effective-family-inventory-v1','rule_count':763,
            'canonical_master_sha256':sha(self.master),
            'source_digests':{'aaa_catalog':'c'*64},'rules':{}}
  for rid,(n,requirement,criteria) in RULES.items():
   self.inv['rules'][rid]={'family':'AAA-200','catalog_number':n,
      'catalog_section':'R','catalog_phase':'P0','requirement':requirement,
      'requirement_sha256':sha(requirement.encode()),'source_sha256':'c'*64}
  self.items={}
  self.add_item('SOURCE_EDITABLE','scene.blend',b'BLENDER-synthetic-fixture')
  self.add_item('NATIVE_EXPORT','scene.glb',b'glTF-synthetic-fixture')
  self.add_item('DELIVERY_PACKAGE','scene.zip',self.make_zip())
  self.rebuild()
 def add_item(self,role,name,content):
  path=self.root/name
  path.write_bytes(content)
  self.items[role]={'path':str(path),'role':role,'sha256':sha(content),
                    'size_bytes':len(content),'step':self.step,'recorded_at':'fixture-only'}
 def make_zip(self,*,wrong_attempt=False,wrong_sha=False,with_manifest=True,
              traversal=False,wrong_export=False):
  manifest={'schema':'gg-c07-delivery-source-export-binding-v1',
     'asset':'TEST','attempt_id':('e'*64 if wrong_attempt else self.work['attempt_id']),
     'source_sha256':self.items['SOURCE_EDITABLE']['sha256'],
     'export_sha256':('f'*64 if wrong_sha else self.items['NATIVE_EXPORT']['sha256']),
     'export_member':'scene.glb'}
  b=io.BytesIO()
  with ZipFile(b,'w') as z:
   z.writestr('scene.glb',b'altered' if wrong_export else
              (self.root/'scene.glb').read_bytes())
   if with_manifest:z.writestr('C07_DELIVERY_MANIFEST.json',json.dumps(manifest))
   if traversal:z.writestr('../escape',b'e')
  return b.getvalue()
 def rebuild(self,*,bad_order=False,mutate_plan=False):
  state={'active_step':{'step':self.step},'scope':{'asset':self.asset},
         'artifacts':list(self.items.values())}
  controller=FakeController(self.root,state)
  records=[]
  def append(event,**extra):
   prior=records[-1]['record_hash'] if records else 'GENESIS'
   row={'asset':self.asset,'event':event,'prev_hash':prior,**extra}
   row['record_hash']=sha(canonical(row))
   records.append(row)
   return row
  p=append('SUPERVISOR_PLAN_ENROLLED',plan=(dict(self.plan, master_sha256='d'*64) if mutate_plan else self.plan))
  r=append('SUPERVISOR_OPERATION_RESERVED',plan_record_hash=p['record_hash'],
           operation_sha256=self.work['operation_sha256'],work=self.work)
  if not bad_order:append('STEP_OPEN',step=self.step)
  append('SUPERVISOR_OPERATION_OPENED',step=self.step,reservation_hash=r['record_hash'])
  for item in self.items.values():append('ARTIFACT_RECORDED',step=self.step,result='PASS',evidence_operation=item)
  if bad_order:append('STEP_OPEN',step=self.step)
  controller.audit_path(self.asset).write_bytes(b''.join(canonical(row)+b'\n' for row in records))
  state['last_audit_hash']=records[-1]['record_hash']
  self.controller=controller
  self.records=records
 def run_check(self):
  return inspect(self.inv,self.plan,self.controller,self.asset,self.step,self.work,
                 source_loader=lambda p:Path(p).read_bytes())
 def test_genuine_positive_semantics_for_both_exact_literal_rules(self):
  report=self.run_check()
  self.assertEqual(report['machine_semantic_observed_count'],2)
  self.assertEqual(report['source_specific_positive_engines_evaluated'],2)
  self.assertEqual(report['individual_mg0_passes'],0)
  self.assertFalse(report['advancement_authorized'])
  for rid,row in report['rules'].items():
   self.assertEqual(row['semantic_result'],'SEMANTIC_OBSERVED')
   self.assertEqual(row['individual_mg0'],'UNKNOWN')
   self.assertEqual(len(row['criteria']),len(RULES[rid][2]))
 def test_missing_delivery_is_unknown_not_pass(self):
  del self.items['DELIVERY_PACKAGE'];self.rebuild()
  r=self.run_check()
  self.assertEqual(r['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
  self.assertEqual(r['rules']['AAA-200-R-178']['semantic_result'],'SEMANTIC_OBSERVED')
 def test_missing_native_export_is_unknown(self):
  del self.items['NATIVE_EXPORT'];self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_missing_source_is_unknown(self):
  del self.items['SOURCE_EDITABLE'];self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_zip_with_wrong_attempt_is_unknown(self):
  self.add_item('DELIVERY_PACKAGE','scene.zip',self.make_zip(wrong_attempt=True));self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_zip_with_wrong_sha_is_unknown(self):
  self.add_item('DELIVERY_PACKAGE','scene.zip',self.make_zip(wrong_sha=True));self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_zip_with_different_glb_is_unknown(self):
  self.add_item('DELIVERY_PACKAGE','scene.zip',self.make_zip(wrong_export=True));self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_zip_without_manifest_is_unknown(self):
  self.add_item('DELIVERY_PACKAGE','scene.zip',self.make_zip(with_manifest=False));self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_path_traversal_in_zip_is_unknown(self):
  self.add_item('DELIVERY_PACKAGE','scene.zip',self.make_zip(traversal=True));self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_changed_registered_file_is_rejected(self):
  (self.root/'scene.glb').write_bytes(b'NEW_BYTES')
  with self.assertRaisesRegex(NativeEvidenceBlocked,'ARTIFACT_BYTES_CHANGED'):
   self.run_check()
 def test_changed_dependency_is_unknown(self):
  (self.root/'dependency.txt').write_bytes(b'other')
  r=self.run_check()
  self.assertEqual(r['rules']['AAA-200-R-178']['semantic_result'],'UNKNOWN')
 def test_changed_master_blocked(self):
  (self.root/'MASTER.md').write_bytes(b'other')
  with self.assertRaisesRegex(NativeEvidenceBlocked,'ORIGINAL_MASTER'):
   self.run_check()
 def test_changed_rule_text_is_blocked(self):
  self.inv['rules']['AAA-200-R-178']['requirement']='foo'
  with self.assertRaisesRegex(NativeEvidenceBlocked,'LITERAL_RULE'):
   self.run_check()
 def test_changed_rule_source_is_blocked(self):
  self.inv['source_digests']['aaa_catalog']='x'*64
  with self.assertRaisesRegex(NativeEvidenceBlocked,'LITERAL_RULE'):
   self.run_check()
 def test_changed_attempt_is_blocked(self):
  self.work=copy.deepcopy(self.work)
  self.work['attempt_id']='f'*64
  with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
   self.run_check()
 def test_changed_plan_is_blocked(self):
  self.rebuild(mutate_plan=True)
  with self.assertRaisesRegex(NativeEvidenceBlocked,'ENROLLED_PLAN'):
   self.run_check()
 def test_broken_audit_chain_is_blocked(self):
  p=self.controller.audit_path(self.asset)
  p.write_bytes(p.read_bytes().replace(b'ARTIFACT_RECORDED',b'ARTIFACT_FAKE___'))
  with self.assertRaisesRegex(ValueError,'INTAKE_AUDIT_RECORD'):
   self.run_check()
 def test_invalid_role_extension_is_blocked(self):
  info=self.items.pop('SOURCE_EDITABLE')
  info['role']='NATIVE_EXPORT'
  self.items['SURPRISE']=info
  self.rebuild()
  with self.assertRaisesRegex(NativeEvidenceBlocked,'ROLE_EXTENSION_CONTRADICTION'):
   self.run_check()
 def test_double_role_is_unknown(self):
  self.add_item('NATIVE_EXPORT_2','second.glb',b'OTHER')
  self.items['NATIVE_EXPORT_2']['role']='NATIVE_EXPORT'
  self.rebuild()
  self.assertEqual(self.run_check()['rules']['AAA-200-R-172']['semantic_result'],'UNKNOWN')
 def test_state_tail_drift_is_blocked(self):
  self.controller._state['last_audit_hash']='0'*64
  with self.assertRaisesRegex(NativeEvidenceBlocked,'AUDIT_STATE_DIVERGED'):
   self.run_check()
 def test_current_step_drift_is_blocked(self):
  self.controller._state['active_step']['step']='wrong'
  with self.assertRaisesRegex(NativeEvidenceBlocked,'AUDIT_STATE_DIVERGED'):
   self.run_check()
 def test_missing_scope_is_unknown_for_R178(self):
  self.controller._state['scope']={}
  self.assertEqual(self.run_check()['rules']['AAA-200-R-178']['semantic_result'],'UNKNOWN')
 def test_missing_step_open_is_unknown_for_R178(self):
  # Build valid hash chain but make STEP_OPEN unrelated.
  self.rebuild(bad_order=True)
  # A STEP_OPEN after the supervisor operation is not a valid source
  # for demonstrating the earlier state of the operation.
  self.assertEqual(self.run_check()['rules']['AAA-200-R-178']['semantic_result'],'UNKNOWN')

if __name__=='__main__':unittest.main()