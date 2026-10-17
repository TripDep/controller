"""Adversarial synthetic fixtures, never proof of production PASS."""
import copy
import hashlib
import json
import struct
import unittest
from pathlib import Path
import test_c07_positive_native_process as old
import c07_r124_positive_process as sut


def test_glb():
    positions=struct.pack('<9f',0,0,0,1,0,0,0,1,0)
    document={'asset':{'version':'2.0'},
              'buffers':[{'byteLength':len(positions)}],
              'bufferViews':[{'buffer':0,'byteOffset':0,'byteLength':len(positions)}],
              'meshes':[{'primitives':[{'attributes':{'POSITION':0},'mode':4}]}],
              'accessors':[{'bufferView':0,'byteOffset':0,'count':3,
                            'type':'VEC3','componentType':5126}]}
    raw=json.dumps(document,separators=(',',':')).encode()
    raw+=b' ' * (-len(raw)%4)
    size=12+8+len(raw)+8+len(positions)
    return (struct.pack('<4sII',b'glTF',2,size)+
            struct.pack('<I4s',len(raw),b'JSON')+raw+
            struct.pack('<I4s',len(positions),b'BIN\x00')+positions)


class Tests(unittest.TestCase):
    def setUp(self):
        # Reuse R123's exact original-controller-chain construction, not a stub
        # that always returns PASS. The original asset fixture is SYNTHETIC.
        self.f=old.Tests('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        for n,text in sut.TEXT.items():
            rid=f'AAA-200-R-{n:03}'
            self.f.inv['rules'][rid]={'family':'AAA-200','catalog_number':n,
                  'catalog_section':'R','catalog_phase':'P0','requirement':text,
                  'requirement_sha256':old.sha(text.encode()),'source_sha256':'c'*64}

    def observe(self):
        return sut.inspect(self.f.inv,self.f.plan,self.f.controller,self.f.asset,
                           self.f.step,self.f.work,
                           source_loader=lambda name:Path(name).read_bytes())

    def add_audit(self,event,**fields):
        prior=self.f.records[-1]['record_hash']
        row={'asset':self.f.asset,'prev_hash':prior,'event':event,**fields}
        row['record_hash']=old.sha(old.canonical(row))
        self.f.records.append(row)
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b''.join(old.canonical(r)+b'\n' for r in self.f.records))
        self.f.controller._state['last_audit_hash']=row['record_hash']

    def make_glb(self):
        self.f.add_item('NATIVE_EXPORT','scene.glb',test_glb())
        self.f.rebuild()

    def test_eight_literal_rules_exact_criteria(self):
        r=self.observe()
        self.assertEqual(r['source_rules_evaluated'],8)
        self.assertEqual(set(r['rules']),{f'AAA-200-R-{i:03}' for i in sut.TEXT})
        self.assertEqual(r['full_native_semantic_certifications_new'],0)
        self.assertEqual(r['full_current_attempt_rule_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        self.assertGreater(r['observed_scoped_predicates'],1)
        for row in r['rules'].values():
            self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
            self.assertEqual(row['individual_mg0'],'UNKNOWN')
            self.assertFalse(row['advancement_authorized'])

    def test_171_coherent_real_bytes_scoped_true(self):
        r=self.observe()['rules']['AAA-200-R-171']
        self.assertEqual(r['machine_scope'],'OBSERVED_SCOPE_PASS')
        self.assertEqual(r['full_rule_semantics'],'UNKNOWN')

    def test_171_source_name_mismatch(self):
        self.f.items['SOURCE_EDITABLE']['path']=str(self.f.root/'different.blend')
        (self.f.root/'different.blend').write_bytes(b'BLENDER-synthetic-fixture')
        self.f.rebuild()
        r=self.observe()['rules']['AAA-200-R-171']
        self.assertFalse(r['machine_checks']['source_export_name_stems_coherent'])

    def test_171_missing_export(self):
        self.f.items.pop('NATIVE_EXPORT');self.f.rebuild()
        r=self.observe()['rules']['AAA-200-R-171']
        self.assertEqual(r['machine_scope'],'PARTIAL_OR_UNKNOWN')

    def test_173_does_not_claim_git_asset_control(self):
        r=self.observe()['rules']['AAA-200-R-173']
        self.assertTrue(r['machine_checks']['current_attempt_in_append_only_audit'])
        self.assertFalse(r['machine_checks']['original_asset_version_control_verified'])

    def test_174_does_not_forge_owner_acceptance(self):
        self.f.add_item('BASELINE_SNAPSHOT','baseline.blend',b'CANONICAL_ASSET')
        self.f.add_item('CURRENT_SOURCE_COPY','recovery.blend',b'CANONICAL_ASSET')
        self.f.rebuild()
        r=self.observe()['rules']['AAA-200-R-174']
        self.assertTrue(r['machine_checks']['two_distinct_registered_protected_files_byte_identical'])
        self.assertFalse(r['machine_checks']['original_approval_source_authenticated'])
        self.assertEqual(r['full_rule_semantics'],'UNKNOWN')

    def test_174_modified_copy(self):
        self.f.add_item('BASELINE_SNAPSHOT','baseline.blend',b'ASSET')
        self.f.add_item('CURRENT_SOURCE_COPY','recovery.blend',b'CHANGED')
        self.f.rebuild()
        self.assertFalse(self.observe()['rules']['AAA-200-R-174']['machine_checks'][
           'two_distinct_registered_protected_files_byte_identical'])

    def test_175_recorded_repeated_native_check_observed_not_assumed_beneficial(self):
        checks=[{'readback':'synthetic-observation', 'no_claim':'semantic-pass'}]
        d=old.sha(json.dumps(checks,sort_keys=True,separators=(',',':')).encode())
        for _ in range(2):
            self.add_audit('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE',
                           attempt_id=self.f.work['attempt_id'],
                           operation_sha256=self.f.work['operation_sha256'],
                           native_reports=checks,native_reports_sha256=d,
                           advancement_authorized=False)
        r=self.observe()['rules']['AAA-200-R-175']
        self.assertTrue(r['machine_checks']['repeated_distinct_source_bound_machine_checks_observed'])
        self.assertFalse(r['machine_checks']['real_benefit_measured_not_assumed'])

    def test_175_digest_fake_is_not_native_check(self):
        self.add_audit('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE',
                       attempt_id=self.f.work['attempt_id'],
                       operation_sha256=self.f.work['operation_sha256'],
                       native_reports=[{'fake':True}],native_reports_sha256='f'*64,
                       advancement_authorized=False)
        self.assertFalse(self.observe()['rules']['AAA-200-R-175']['machine_checks'][
            'machine_checks_on_current_attempt'])

    def test_176_real_glb_geometry_parsed(self):
        self.make_glb()
        r=self.observe()['rules']['AAA-200-R-176']
        self.assertTrue(r['machine_checks']['nonempty_export_bytes_independently_parsed'])
        self.assertFalse(r['machine_checks']['required_geometry_outcome_independently_verified'])
        self.assertEqual(r['full_rule_semantics'],'UNKNOWN')

    def test_176_extension_only_does_not_pass(self):
        self.assertFalse(self.observe()['rules']['AAA-200-R-176']['machine_checks'][
            'nonempty_export_bytes_independently_parsed'])

    def test_176_json_only_mesh_without_binary_rejected(self):
        b=bytearray(test_glb())
        b[-36:]=b'\x00'*36
        self.assertFalse(sut._glb_mesh(bytes(b)))

    def test_176_nonfinite_vertices_rejected(self):
        b=bytearray(test_glb())
        b[-36:]=struct.pack('<9f',float('nan'),0,0,1,0,0,0,1,0)
        self.assertFalse(sut._glb_mesh(bytes(b)))

    def test_176_wrong_glb_declared_size(self):
        b=bytearray(test_glb());b[8:12]=struct.pack('<I',999999)
        self.assertFalse(sut._glb_mesh(bytes(b)))

    def test_176_bad_glb_accessor(self):
        raw=b'glTF'+b'\x02\x00\x00\x00'+b'\x14\x00\x00\x00'+b'\x00'*8
        self.assertFalse(sut._glb_mesh(raw))

    def test_177_equal_backup_bytes_not_approval(self):
        self.f.add_item('BASELINE_SNAPSHOT','old.blend',b'ORIGINAL')
        self.f.add_item('CURRENT_SOURCE_COPY','copy.blend',b'ORIGINAL')
        self.f.rebuild()
        r=self.observe()['rules']['AAA-200-R-177']
        self.assertTrue(r['machine_checks']['prior_protected_bytes_equal_current_copy'])
        self.assertFalse(r['machine_checks']['no_unobserved_overwrite_proven'])

    def test_179_unique_transaction_not_checkpoint_approval(self):
        r=self.observe()['rules']['AAA-200-R-179']
        self.assertTrue(r['machine_checks']['one_unique_reservation_and_open'])
        self.assertFalse(r['machine_checks']['original_prior_checkpoint_sha_verified'])

    def test_180_new_binary_only_partial_delta(self):
        self.make_glb()
        r=self.observe()['rules']['AAA-200-R-180']
        self.assertTrue(r['machine_checks']['new_non_document_binary_output_present'])
        self.assertFalse(r['machine_checks']['measured_quality_or_completion_delta_verified'])

    def test_mutated_artifact_fails_hard(self):
        (self.f.root/'scene.glb').write_bytes(b'mutated')
        with self.assertRaisesRegex(sut.EvidenceBlocked,'ARTIFACT_BYTES_CHANGED'):
            self.observe()

    def test_mutated_master_fails_hard(self):
        (self.f.root/'MASTER.md').write_bytes(b'mutated')
        with self.assertRaisesRegex(sut.EvidenceBlocked,'MASTER_STATE_OR_AUDIT_DRIFT'):
            self.observe()

    def test_cross_attempt_fails_hard(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='e'*64
        with self.assertRaisesRegex(sut.EvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.observe()

    def test_changed_canonical_requirement_fails_hard(self):
        self.f.inv['rules']['AAA-200-R-177']['requirement']='anything'
        with self.assertRaisesRegex(sut.EvidenceBlocked,'SOURCE_CLAUSE_DRIFT'):
            self.observe()

    def test_changed_canonical_sha_fails_hard(self):
        self.f.inv['rules']['AAA-200-R-171']['source_sha256']='f'*64
        with self.assertRaisesRegex(sut.EvidenceBlocked,'SOURCE_CLAUSE_DRIFT'):
            self.observe()

    def test_broken_original_audit_fails_hard(self):
        p=self.f.controller.audit_path(self.f.asset)
        p.write_bytes(p.read_bytes().replace(b'ARTIFACT_RECORDED',b'ARTIFACT_REPLACED'))
        with self.assertRaisesRegex(ValueError,'INTAKE_AUDIT_RECORD'):
            self.observe()

    def test_all_eight_rules_not_mg0_pass_even_with_glb_and_snapshots(self):
        self.make_glb()
        self.f.add_item('BASELINE_SNAPSHOT','approved-old.blend',b'A')
        self.f.add_item('CURRENT_SOURCE_COPY','approved-copy.blend',b'A')
        self.f.rebuild()
        r=self.observe()
        self.assertTrue(all(x['individual_mg0']=='UNKNOWN' for x in r['rules'].values()))
        self.assertTrue(all(x['advancement_authorized'] is False for x in r['rules'].values()))
        self.assertEqual(r['full_native_semantic_certifications_new'],0)

if __name__=='__main__':unittest.main()