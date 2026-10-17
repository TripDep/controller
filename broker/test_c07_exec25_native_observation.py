"""R129: 25 canonical EXEC rules; tests use hash-chained synthetic records only."""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch
import c07_exec25_native_observation as r129
import test_c07_positive_native_process as fixture
from c07_positive_native_process import NativeEvidenceBlocked

def sh(b):return hashlib.sha256(b).hexdigest()

class Exec25Test(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        sections=[]
        for i in range(1,26):
            sections.append('## EXEC-%03d — Unit canonical title\\n**VERIFIED_FILE.** Unit scope %d.'%(i,i))
        text='\\n\\n'.join(sections)+'\\n\\n# 13. Current Pavilion / Golden Ting state\\n'
        # Python literal backslash escapes are converted to linebreaks here.
        text=text.replace('\\n','\n')
        self.f.master=text.encode()
        (self.f.root/'MASTER.md').write_bytes(self.f.master)
        digest=sh(self.f.master)
        self.f.work['master_sha256']=digest
        self.f.plan['master_sha256']=digest
        self.f.plan['operation']['action']='Original synthetic test-only operation'
        self.f.inv['canonical_master_sha256']=digest
        for i in range(1,26):
            rid='EXEC-%03d'%i
            raw=sections[i-1].replace('\\n','\n')
            self.f.inv['rules'][rid]={
                'family':'EXECUTION','source':'master',
                'source_sha256':digest,'requirement':raw,
                'requirement_sha256':sh(raw.encode())}
        p=patch.object(r129,'operation_scope',return_value={
            'due':list(r129.IDS)})
        p.start()
        self.addCleanup(p.stop)
        self.rebuild()

    def rebuild(self):
        self.f.rebuild()
        ev=next(v for v in self.f.records
                if v['event']=='SUPERVISOR_OPERATION_OPENED')
        ev['operation_sha256']=self.f.work['operation_sha256']
        self.rehash()

    def rehash(self):
        last='GENESIS'
        for item in self.f.records:
            item['prev_hash']=last
            item.pop('record_hash',None)
            item['record_hash']=sh(fixture.canonical(item))
            last=item['record_hash']
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b''.join(fixture.canonical(v)+b'\n' for v in self.f.records))
        self.f.controller._state['last_audit_hash']=last

    def run_check(self):
        return r129.inspect(self.f.inv,self.f.plan,self.f.controller,
            self.f.asset,self.f.step,self.f.work,
            source_loader=lambda p:Path(p).read_bytes())

    def test_all_25_named_source_specific_observations_no_fake_pass(self):
        x=self.run_check()
        self.assertEqual(x['source_rule_count'],25)
        self.assertEqual(set(x['rules']),set(r129.IDS))
        self.assertGreater(x['machine_predicates_observed'],0)
        self.assertEqual(x['registered_artifact_bytes_verified'],3)
        self.assertEqual(x['dependency_bytes_verified'],1)
        self.assertEqual(x['full_rule_passes'],0)
        self.assertEqual(x['individual_mg0_passes'],0)
        self.assertFalse(x['advancement_authorized'])
        all_keys=[]
        for rid in r129.IDS:
            row=x['rules'][rid]
            all_keys += list(row['scoped_machine_predicates'])
            with self.subTest(rid=rid):
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertEqual(len(row['scoped_machine_predicates']),2)
                self.assertTrue(row['missing_independent_semantics'])
                self.assertFalse(row['full_rule_pass'])
                self.assertFalse(row['advancement_authorized'])
        self.assertEqual(len(all_keys),len(set(all_keys)))

    def test_each_of_25_literal_clauses_tampered_fails_closed(self):
        for rid in r129.IDS:
            original=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='substituted'
            with self.subTest(rule=rid):
                with self.assertRaisesRegex(r129.UnverifiedSource,'R129_RULE_SOURCE_CHANGED'):
                    self.run_check()
            self.f.inv['rules'][rid]['requirement']=original

    def test_each_of_25_source_hash_changed_fails_closed(self):
        for rid in r129.IDS:
            real=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='0'*64
            with self.subTest(rule=rid):
                with self.assertRaisesRegex(r129.UnverifiedSource,'R129_RULE_SOURCE_CHANGED'):
                    self.run_check()
            self.f.inv['rules'][rid]['source_sha256']=real

    def test_original_dependency_content_mutation_is_not_ignored(self):
        (self.f.root/'dependency.txt').write_text('altered')
        with self.assertRaisesRegex(r129.UnverifiedSource,'ORIGINAL_BYTES_CHANGED'):
            self.run_check()

    def test_real_registered_export_removed_is_not_assumed(self):
        del self.f.items['NATIVE_EXPORT']
        self.rebuild()
        x=self.run_check()
        self.assertFalse(x['rules']['EXEC-019']['scoped_machine_predicates'][
            'actual_native_export_recorded'])
        self.assertEqual(x['full_rule_passes'],0)

    def test_master_drift_is_rejected(self):
        (self.f.root/'MASTER.md').write_bytes(b'other')
        with self.assertRaisesRegex(r129.UnverifiedSource,'MASTER_BYTES_CHANGED'):
            self.run_check()

    def test_hash_chained_cross_operation_opening_is_rejected(self):
        row=next(v for v in self.f.records
                 if v['event']=='SUPERVISOR_OPERATION_OPENED')
        row['operation_sha256']='c'*64
        self.rehash()
        with self.assertRaisesRegex(r129.UnverifiedSource,'OTHER_OPERATION_REPLAY'):
            self.run_check()

    def test_cross_attempt_reservation_is_rejected(self):
        self.f.work['attempt_id']='e'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.run_check()

    def test_preclose_already_closed_cannot_be_reinterpreted(self):
        self.f.records.append({
            'asset':self.f.asset,'event':'STEP_CLOSE',
            'step':self.f.step,'result':'PASS'})
        self.rehash()
        with self.assertRaisesRegex(r129.UnverifiedSource,'ALREADY_CLOSED_STEP'):
            self.run_check()

    def test_no_registered_source_means_no_real_artifact_qa(self):
        self.f.items.clear()
        self.rebuild()
        report=self.run_check()
        self.assertFalse(report['rules']['EXEC-005']['scoped_machine_predicates'][
            'registered_output_bytes_independently_read'])
        self.assertEqual(report['full_rule_passes'],0)

    def test_no_unknown_owner_or_visual_review_auto_pass(self):
        d=self.run_check()['rules']
        for n in (5,14,15,16,19,20,22,23,25):
            row=d['EXEC-%03d'%n]
            self.assertTrue(row['missing_independent_semantics'])
            self.assertEqual(row['owner_approval'],'UNKNOWN')
            self.assertEqual(row['native_git_reviewer'],'UNKNOWN')

if __name__=='__main__':unittest.main()
