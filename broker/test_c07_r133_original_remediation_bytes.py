"""R133: adversarial original-byte proof tests for all 110 remediation rules.

These are entirely synthetic Controller audit fixtures, not owner QA or MG0.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import c07_remediation_original_bytes as r133
import c07_behavior110_remediation as r130
from test_c07_behavior110_remediation import Tests as Base

def sha(raw):return hashlib.sha256(raw).hexdigest()

class RealWitnessBytes(unittest.TestCase):
    def setUp(self):
        self.f=Base('test_all_110_source_bound_rules_read_on_one_real_hash_chain')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def finding(self,rid='BEHAVIOR-055'):
        return self.f.finding(rule=rid)

    def add_witness(self,origin,phase,rid='BEHAVIOR-055',override=None):
        path='proofs/'+rid+'_'+phase+'.json'
        predecessor=self.f.rows[-1]['record_hash']
        doc={'schema':r133.WITNESS,'rule_id':rid,
             'attempt_id':self.f.attempt,'operation_sha256':self.f.op,
             'step':self.f.step,'trigger_record_hash':origin['record_hash'],
             'phase':phase,'predecessor_record_sha256':predecessor}
        if override:doc.update(override)
        raw=json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(raw)
        row=self.f.add(phase,step=self.f.step,rule_id=rid,
            attempt_id=self.f.attempt,result='PASS',
            trigger_record_hash=origin['record_hash'],
            evidence_operation={'schema':r133.POINTER,
                 'relative_path':path,'sha256':sha(raw)})
        return p,row

    def verdict(self):
        source=self.f.report()
        return r133.inspect(source,self.f.raw(),self.f.rows[-1]['record_hash'],
                            self.f.asset,self.f.step,self.f.work,self.root)

    def test_110_exact_no_findings_remain_unknown_not_pass(self):
        x=self.verdict()
        self.assertEqual(x['source_rules_examined'],110)
        self.assertEqual(x['result'],'UNKNOWN')
        self.assertEqual(x['four_distinct_original_byte_witness_chains'],0)
        self.assertEqual(x['individual_mg0_PASS'],0)
        self.assertEqual(x['full_semantic_PASS'],0)
        self.assertFalse(x['advancement_authorized'])

    def test_four_text_only_green_claims_fail_real_byte_readback(self):
        finding=self.finding()
        for phase in r130.STEPS:
            self.f.add(phase,step=self.f.step,rule_id='BEHAVIOR-055',
                attempt_id=self.f.attempt,result='PASS',
                trigger_record_hash=finding['record_hash'],
                evidence_operation='I certify everything was fixed')
        x=self.verdict()
        self.assertEqual(x['four_distinct_original_byte_witness_chains'],0)
        self.assertIn('BEHAVIOR-055',x['failed_rule_ids'])
        self.assertEqual(x['result'],'FAIL')

    def test_four_real_distinct_sha_verified_byte_files_but_mg0_still_unknown(self):
        finding=self.finding()
        for phase in r130.STEPS:self.add_witness(finding,phase)
        x=self.verdict()
        self.assertEqual(x['four_distinct_original_byte_witness_chains'],1)
        self.assertEqual(x['verified_original_file_paths'],4)
        self.assertEqual(x['failed_rule_ids'],[])
        self.assertTrue(x['rules']['BEHAVIOR-055']['all_original_finding_bytes_witnessed'])
        self.assertEqual(x['rules']['BEHAVIOR-055']['owner_authenticity'],'UNKNOWN')
        self.assertEqual(x['rules']['BEHAVIOR-055']['semantic_result'],'UNKNOWN')
        self.assertEqual(x['full_semantic_PASS'],0)
        self.assertEqual(x['individual_mg0_PASS'],0)

    def test_modified_original_after_controller_registration_is_rejected(self):
        finding=self.finding();files=[]
        for phase in r130.STEPS:files.append(self.add_witness(finding,phase)[0])
        files[2].write_text('post-audit tampering')
        self.assertIn('BEHAVIOR-055',self.verdict()['failed_rule_ids'])

    def test_forged_source_rule_attempt_and_operation_all_fail(self):
        for override in ({'rule_id':'BEHAVIOR-056'},
                         {'attempt_id':'d'*64},
                         {'operation_sha256':'e'*64},
                         {'trigger_record_hash':'f'*64},
                         {'step':'DIFFERENT'}):
            with self.subTest(override=override):
                # One fresh fixture per trial to isolate the chronological record.
                f=Base('test_all_110_source_bound_rules_read_on_one_real_hash_chain')
                f.setUp();old=self.f;self.f=f
                try:
                    finding=self.finding()
                    for i,phase in enumerate(r130.STEPS):
                        self.add_witness(finding,phase,override=override if i==1 else None)
                    self.assertIn('BEHAVIOR-055',self.verdict()['failed_rule_ids'])
                finally:
                    self.f=old;f.doCleanups()

    def test_symlink_to_same_valid_bytes_is_rejected(self):
        finding=self.finding();files=[]
        for phase in r130.STEPS:files.append(self.add_witness(finding,phase)[0])
        moved=files[0].with_suffix('.backup')
        files[0].rename(moved)
        files[0].symlink_to(moved)
        self.assertIn('BEHAVIOR-055',self.verdict()['failed_rule_ids'])

    def test_all_110_original_source_bytes_bound_separately(self):
        for rid in r133.IDS:
            finding=self.finding(rid)
            for phase in r130.STEPS:self.add_witness(finding,phase,rid)
        x=self.verdict()
        self.assertEqual(x['source_rules_examined'],110)
        self.assertEqual(x['actual_failure_observations_checked'],110)
        self.assertEqual(x['four_distinct_original_byte_witness_chains'],110)
        self.assertEqual(x['verified_original_file_paths'],440)
        self.assertEqual(x['failed_rule_ids'],[])
        self.assertEqual(x['full_semantic_PASS'],0)
        self.assertEqual(x['individual_mg0_PASS'],0)
        self.assertFalse(x['advancement_authorized'])

    def test_original_report_other_attempt_fails_closed(self):
        x=self.f.report();x['attempt_id']='a'*64
        with self.assertRaisesRegex(r133.OriginalEvidenceBlocked,'R133_EXACT_ORIGINAL'):
            r133.inspect(x,self.f.raw(),self.f.rows[-1]['record_hash'],
                         self.f.asset,self.f.step,self.f.work,self.root)

    def test_missing_source_file_is_never_a_valid_remediation(self):
        finding=self.finding()
        files=[self.add_witness(finding,p)[0] for p in r130.STEPS]
        files[3].unlink()
        self.assertEqual(self.verdict()['result'],'FAIL')

    def test_no_matching_genuine_controller_root_rejected(self):
        x=self.f.report()
        with self.assertRaisesRegex(r133.OriginalEvidenceBlocked,'ROOT_UNAVAILABLE'):
            r133.inspect(x,self.f.raw(),self.f.rows[-1]['record_hash'],
                         self.f.asset,self.f.step,self.f.work,self.root/'MISSING')

if __name__=='__main__':unittest.main()
