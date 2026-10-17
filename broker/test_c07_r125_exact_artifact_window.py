"""R125 regression: old R123/R124 silently used same-step artefacts outside active operation.

All tests use synthetic hash-chained audit records, never asset-approval PASS.
"""
import copy
from pathlib import Path
import unittest
from c07_positive_native_process import NativeEvidenceBlocked
import test_c07_positive_native_process as old
import c07_positive_native_process as native
import c07_r124_positive_process as r124


class ArtifactProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.f = old.Tests('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        for n, text in r124.TEXT.items():
            self.f.inv['rules'][f'AAA-200-R-{n:03}'] = {
                'family':'AAA-200', 'catalog_number':n,
                'catalog_section':'R', 'catalog_phase':'P0',
                'requirement':text, 'requirement_sha256':old.sha(text.encode()),
                'source_sha256':'c'*64}

    def write_chain(self):
        prior='GENESIS'
        for record in self.f.records:
            record['prev_hash']=prior
            record.pop('record_hash', None)
            record['record_hash']=old.sha(old.canonical(record))
            prior=record['record_hash']
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b''.join(old.canonical(row)+b'\n' for row in self.f.records))
        self.f.controller._state['last_audit_hash']=prior

    def both_engines(self):
        a=self.f.run_check()
        b=r124.inspect(self.f.inv,self.f.plan,self.f.controller,self.f.asset,
                        self.f.step,self.f.work,
                        source_loader=lambda p:Path(p).read_bytes())
        return a,b

    def blocks_both(self, why):
        with self.assertRaisesRegex(NativeEvidenceBlocked,why):
            self.f.run_check()
        with self.assertRaisesRegex(NativeEvidenceBlocked,why):
            r124.inspect(self.f.inv,self.f.plan,self.f.controller,self.f.asset,
                         self.f.step,self.f.work,
                         source_loader=lambda p:Path(p).read_bytes())

    def test_normal_current_window_is_accepted_not_work_pass(self):
        a,b=self.both_engines()
        self.assertEqual(a['individual_mg0_passes'],0)
        self.assertEqual(b['full_current_attempt_rule_passes'],0)
        self.assertFalse(a['advancement_authorized'])
        self.assertFalse(b['advancement_authorized'])

    def test_artefact_recorded_before_operation_open_is_rejected(self):
        a=self.f.records
        index=next(i for i,x in enumerate(a) if x['event']=='ARTIFACT_RECORDED')
        entry=a.pop(index)
        opened=next(i for i,x in enumerate(a) if x['event']=='SUPERVISOR_OPERATION_OPENED')
        a.insert(opened,entry)
        self.write_chain()
        self.blocks_both('R125_ARTIFACT_OUTSIDE_CURRENT_OPERATION_WINDOW')

    def test_artefact_recorded_after_step_close_is_rejected(self):
        a=self.f.records
        index=next(i for i,x in enumerate(a) if x['event']=='ARTIFACT_RECORDED')
        a.insert(index,{'asset':self.f.asset,'event':'STEP_CLOSE','step':self.f.step})
        self.write_chain()
        self.blocks_both('R125_ARTIFACT_OUTSIDE_CURRENT_OPERATION_WINDOW')

    def test_unrecorded_extra_state_artefact_is_rejected(self):
        entry=copy.deepcopy(self.f.items['SOURCE_EDITABLE'])
        entry['path']=str(self.f.root/'phantom.blend')
        self.f.controller._state['artifacts'].append(entry)
        self.blocks_both('R125_STATE_ARTIFACT_AUDIT_SET_DIVERGED')

    def test_duplicate_state_row_is_rejected(self):
        self.f.controller._state['artifacts'].append(
            copy.deepcopy(self.f.items['NATIVE_EXPORT']))
        self.blocks_both('R125_STATE_ARTIFACT_AUDIT_SET_DIVERGED')

    def test_failed_recorded_artefact_is_not_silently_skipped(self):
        row=next(x for x in self.f.records if x['event']=='ARTIFACT_RECORDED')
        row['result']='FAIL'
        self.write_chain()
        self.blocks_both('R125_ARTIFACT_OUTSIDE_CURRENT_OPERATION_WINDOW')

    def test_old_step_close_before_new_open_is_not_a_valid_same_step_reuse(self):
        a=self.f.records
        index=next(i for i,x in enumerate(a) if x['event']=='SUPERVISOR_OPERATION_OPENED')
        a.insert(index,{'asset':self.f.asset,'event':'STEP_CLOSE','step':self.f.step})
        self.write_chain()
        self.blocks_both('R125_ARTIFACT_HISTORIC_CLOSED_STEP_REUSED')

    def test_other_step_unrelated_artefact_does_not_contaminate(self):
        a=self.f.records
        i=next(i for i,x in enumerate(a) if x['event']=='ARTIFACT_RECORDED')
        a.insert(i, {'asset':self.f.asset,'event':'ARTIFACT_RECORDED',
                     'step':'ANOTHER_STEP','result':'FAIL',
                     'evidence_operation':{'path':'fake'}})
        self.write_chain()
        x,y=self.both_engines()
        self.assertEqual(x['machine_semantic_observed_count'],2)
        self.assertEqual(y['full_current_attempt_rule_passes'],0)

if __name__=='__main__':unittest.main()