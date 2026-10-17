"""R138: all 25 original EXEC rules exercised individually with source bytes."""
import unittest
from pathlib import Path
from c07_exec25_domain_machine_probes import inspect, ProofError
from test_c07_exec25_native_observation import Exec25Test as Fixture
from c07_exec25_native_observation import UnverifiedSource, IDS
from c07_positive_native_process import NativeEvidenceBlocked

class TestExec25NativeDomain(unittest.TestCase):
    def setUp(self):
        self.f=Fixture('test_all_25_named_source_specific_observations_no_fake_pass')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def run_actual(self):
        f=self.f.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
             source_loader=lambda p:Path(p).read_bytes())

    def test_all_25_distinct_oracles_exercised_from_original_source(self):
        report=self.run_actual()
        self.assertEqual(report['source_rule_count'],25)
        self.assertEqual(report['domain_probes'],50)
        self.assertEqual(len(report['rules']),25)
        self.assertEqual(set(report['rules']),set(IDS))
        self.assertEqual(report['full_native_semantics_passes'],0)
        self.assertEqual(report['individual_mg0_passes'],0)
        self.assertFalse(report['advancement_authorized'])
        uniq=[]
        for rule in IDS:
            with self.subTest(rule=rule):
                v=report['rules'][rule]
                self.assertEqual(v['whole_source_requirement'],'UNKNOWN')
                self.assertEqual(v['individual_mg0'],'UNKNOWN')
                self.assertEqual(v['owner_approval'],'UNKNOWN')
                self.assertEqual(len(v['additional_domain_machine_criteria']),2)
                self.assertTrue(all(type(a) is bool for a in
                    v['additional_domain_machine_criteria'].values()))
                uniq+=list(v['additional_domain_machine_criteria'])
        self.assertEqual(len(uniq),50)
        self.assertEqual(len(set(uniq)),50)

    def test_every_original_exec_source_clause_tampering_blocks(self):
        for rid in IDS:
            original=self.f.f.inv['rules'][rid]['requirement']
            self.f.f.inv['rules'][rid]['requirement']='FAKE APPROVAL'
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(UnverifiedSource,'R129_RULE_SOURCE_CHANGED'):
                    self.run_actual()
            self.f.f.inv['rules'][rid]['requirement']=original

    def test_dependency_bytes_tampering_blocks(self):
        (self.f.f.root/'dependency.txt').write_bytes(b'altered')
        with self.assertRaisesRegex(UnverifiedSource,'DEPENDENCY_ORIGINAL_BYTES_CHANGED'):
            self.run_actual()

    def test_original_export_bytes_tampering_blocks(self):
        (self.f.f.root/'scene.glb').write_bytes(b'altered')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'ARTIFACT_BYTES_CHANGED'):
            self.run_actual()

    def test_original_audit_chain_tampering_blocks(self):
        p=self.f.f.controller.audit_path(self.f.f.asset)
        p.write_bytes(p.read_bytes().replace(
            b'ARTIFACT_RECORDED',b'ARTIFACT_FALSIFIED'))
        with self.assertRaises(ValueError):
            self.run_actual()

    def test_missing_native_binary_never_turns_into_positive(self):
        del self.f.f.items['NATIVE_EXPORT']
        self.f.rebuild()
        report=self.run_actual()
        self.assertFalse(report['rules']['EXEC-005'][
            'additional_domain_machine_criteria'][
            'actual_export_has_nondegenerate_geometry'])
        self.assertFalse(report['rules']['EXEC-021'][
            'additional_domain_machine_criteria'][
            'native_export_actual_bytes_accessible'])
        self.assertEqual(report['full_native_semantics_passes'],0)

    def test_self_reported_fresh_eyes_never_grants_artist_or_mg0(self):
        self.f.f.records.append({'asset':self.f.f.asset,'event':
            'FRESH_EYES_REVIEW','step':self.f.f.step})
        self.f.rehash()
        report=self.run_actual()
        self.assertTrue(report['rules']['EXEC-016'][
            'additional_domain_machine_criteria'][
            'fresh_eye_original_audit_event_present'])
        self.assertEqual(report['rules']['EXEC-016']['whole_source_requirement'],'UNKNOWN')
        self.assertEqual(report['rules']['EXEC-016']['individual_mg0'],'UNKNOWN')

    def test_cross_attempt_replay_blocks(self):
        self.f.f.work['attempt_id']='e'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.run_actual()

if __name__=='__main__':unittest.main()
