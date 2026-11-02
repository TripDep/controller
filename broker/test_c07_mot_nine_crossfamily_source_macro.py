"""C07 M/O/T nine-rule source macro: actual recomputation, adversarial drift.

All nine user literals keep full semantic, MG0 and user acceptance UNKNOWN.
Tests exercise SHA-pinned original bytes, variant-mesh/lighting and budgets,
Blender/ZIP source linkage, plus false owner/gameplay declarations.
"""
import copy
import json
import unittest

from test_c07_p4_material_macro_full_review import P4MaterialMacroTests,POLICY
from test_c07_p345_remaining_original_review import RemainingP345Tests
from test_c07_p8_delivery_macro_full_review import DeliveryFamilyFiveOriginalTests
from test_c07_p345_forty_native_evidence import encoded
from test_c07_p4_texture_semantics import png,solid
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import QUAD,NORMALS
from c07_mot_nine_crossfamily_source_macro import inspect,IDS,CRITERIA
from c07_native_source_rule_replayers import build_packet,FULL_LITERAL_REVIEWED

class NineMOTCrossFamilyTests(unittest.TestCase):
    def context(self,rid):
        family=rid.split('-')[2]
        if family=='M':
            t=P4MaterialMacroTests(
                'test_all_seven_literal_rules_are_distinct_and_source_bound')
            self.addCleanup(t.doCleanups)
            test,ctx=t.context()
            t.source_test=test
        elif family=='O':
            t=RemainingP345Tests(
                'test_positive_source_benefits_measured_not_promoted_to_full')
            self.addCleanup(t.doCleanups)
            test,ctx=t.context()
            t.source_test=test
        else:
            t=DeliveryFamilyFiveOriginalTests(
                'test_five_source_literal_oracles_and_no_false_operational_pass')
            t.setUp()
            self.addCleanup(t.doCleanups)
            ctx=t.context()
        return t,ctx

    def row(self,ctx,rid):
        observed=inspect(ctx,rid)
        self.assertEqual(observed['rule_id'],rid)
        self.assertEqual(set(observed['checks']),set(CRITERIA[int(rid[-3:])]))
        self.assertTrue(all(type(v) is bool for v in observed['checks'].values()))
        self.assertIs(list(observed['checks'].values())[-1],False)
        self.assertEqual(observed['full_rule_semantics'],'UNKNOWN')
        self.assertEqual(observed['individual_mg0'],'UNKNOWN')
        self.assertFalse(observed['advancement_authorized'])
        packet=build_packet(ctx,rid)
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertNotIn(rid,FULL_LITERAL_REVIEWED)
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        return observed

    def test_whole_nine_original_source_rules_attached_to_consumer(self):
        self.assertEqual(len(IDS),9)
        self.assertEqual(len({x for cs in CRITERIA.values() for x in cs}),27)
        for rid in IDS:
            with self.subTest(rule=rid):
                t,ctx=self.context(rid)
                row=self.row(ctx,rid)
                self.assertTrue(row['original_audit_sha256'])
                self.assertFalse(row['advancement_authorized'])

    def test_actual_p4_three_lighting_buffers_and_pre_d_physics(self):
        rid='AAA-200-M-122'
        t,ctx=self.context(rid)
        row=self.row(ctx,rid)
        self.assertTrue(row['evidence_complete'])
        self.assertTrue(all(list(row['checks'].values())[:2]))
        # Even three convincing PNGs do NOT prove real renderer execution.
        policy=copy.deepcopy(POLICY)
        policy['light_response']['min_direct_neutral_delta']=240
        t.source_test.add('P4_MATERIAL_CONFORMANCE',
                          'p4_material_conformance.json',encoded(policy))
        t.source_test.sync()
        ctx['controller']=t.source_test.f.controller
        self.assertFalse(self.row(ctx,rid)['checks'][CRITERIA[122][1]])

    def test_p4_rgb_response_rejects_byte_identical_synthetic_views(self):
        rid='AAA-200-M-130'
        t,ctx=self.context(rid)
        # No changes to original sources without fresh audit.
        self.assertTrue(self.row(ctx,rid)['checks'][CRITERIA[130][1]])
        t.source_test.add('P4_VIEW_DIRECT','p4_view_direct.png',
                          png(solid(90)))
        t.source_test.sync()
        ctx['controller']=t.source_test.f.controller
        self.assertFalse(self.row(ctx,rid)['checks'][CRITERIA[130][1]])

    def test_original_lod_requires_complete_near_far_evidence(self):
        rid='AAA-200-O-145'
        _,ctx=self.context(rid)
        row=self.row(ctx,rid)
        self.assertTrue(row['evidence_complete'])
        self.assertTrue(row['checks'][CRITERIA[145][0]])
        self.assertFalse(row['checks'][CRITERIA[145][2]])

    def test_p95_source_budget_is_independent_of_producer_label(self):
        rid='AAA-200-O-150'
        _,ctx=self.context(rid)
        row=self.row(ctx,rid)
        self.assertTrue(row['evidence_complete'])
        self.assertTrue(row['checks'][CRITERIA[150][0]])
        self.assertTrue(row['checks'][CRITERIA[150][1]])
        self.assertFalse(row['checks'][CRITERIA[150][2]])

    def test_runtime_source_samples_over_budget_cannot_be_p95_pass(self):
        rid='AAA-200-O-150'
        t,ctx=self.context(rid)
        t.source_test.add('P5_RUNTIME_CAPTURE','runtime_capture.json',
                          encoded({'frame_ms_samples':[50]*20}))
        t.source_test.sync()
        ctx['controller']=t.source_test.f.controller
        self.assertTrue(self.row(ctx,rid)['checks'][CRITERIA[150][0]])
        self.assertFalse(self.row(ctx,rid)['checks'][CRITERIA[150][1]])

    def test_guide_with_five_m_claim_cannot_earn_useful_documentation(self):
        rid='AAA-200-T-195'
        t,ctx=self.context(rid)
        t.fixture.docs['P8_MAINTENANCE_GUIDE']['fivem_verified']=True
        t.refresh()
        self.assertFalse(self.row(t.context(),rid)['checks'][CRITERIA[195][1]])

    def test_all_four_delivery_preflights_preserve_owner_gate(self):
        for n in (191,193,195,200):
            rid='AAA-200-T-%03d'%n
            with self.subTest(rule=n):
                _,ctx=self.context(rid)
                row=self.row(ctx,rid)
                self.assertEqual(row['real_blender_fivem_or_owner_provenance'],
                                 'UNVERIFIED')
                if n in (191,193,195):
                    self.assertTrue(row['evidence_complete'])
                    self.assertTrue(all(list(row['checks'].values())[:2]),row)
                else:
                    self.assertFalse(list(row['checks'].values())[-1])

    def test_missing_original_material_sha_is_no_full_pass(self):
        t,ctx=self.context('AAA-200-M-129')
        ctx['plan']['p345_evidence_contract'][
            'original_artifact_sha256'].pop('P4_MATERIAL_CONFORMANCE')
        with self.assertRaises(ValueError):
            inspect(ctx,'AAA-200-M-129')

    def test_tampered_zip_bytes_rejected_before_source_attestation(self):
        t,ctx=self.context('AAA-200-T-193')
        (t.f.root/'delivery.zip').write_bytes(b'not a zip')
        with self.assertRaises(ValueError):
            inspect(ctx,'AAA-200-T-193')

    def test_current_original_attempt_forgery_rejected(self):
        _,ctx=self.context('AAA-200-O-150')
        ctx['work']=dict(ctx['work'],attempt_id='0'*64)
        with self.assertRaises(ValueError):
            inspect(ctx,'AAA-200-O-150')

if __name__=='__main__':
    unittest.main()
