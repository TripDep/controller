"""Macro C07 P3/P4/P5: all forty literal oracles, three stage cutoffs.

No fixture can certify MG0, FiveM, user approval or source provenance of a
renderer. Verify full source set, exact due phases, contamination and UNKNOWNs.
"""
import unittest
from unittest.mock import patch

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p345_forty_native_evidence import P345Forty
from c07_p345_forty_native_evidence import TEXT, IDS
from c07_p345_macro_execution import run, require_source_execution, MacroExecutionBlocked
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED)

class MacroFortyOriginalTests(unittest.TestCase):
    def context(self, phase):
        test,ctx=NativeOriginalReplayerTests.context(
            self, P345Forty, 'test_p4_30_due_and_p5_40_due')
        test.f.work['phase']=test.f.plan['phase']=phase
        test.sync()
        ctx['controller']=test.f.controller
        return test,ctx

    def test_visited_40_with_blocked_originals_cannot_be_certified(self):
        _,ctx=self.context('P5')
        result=run(ctx)
        # Isolate the BLOCKED gate from the independent missing-pin gate:
        # every other rule carries a verified fixture pin, not a real claim.
        for rid,row in result['rows'].items():
            row['machine_result']='UNKNOWN'
            row['blocked_reason']=None
            row['source_checks']={c:(i==0) for i,c in
                                  enumerate(NATIVE_RULES[rid][1])}
        blocked_id=IDS[0]
        result['rows'][blocked_id]['machine_result']='BLOCKED'
        result['rows'][blocked_id]['blocked_reason']='original absent'
        result['result_counts']={'PASS':0,'FAIL':0,'UNKNOWN':39,
                                 'BLOCKED':1,'NOT_DUE':0}
        with self.assertRaisesRegex(MacroExecutionBlocked,
                                    'C07_P345_CERTIFICATE_SOURCE_REPLAY_BLOCKED'):
            require_source_execution(result, source_context=ctx)

    def test_all_40_unknown_unpinned_cannot_receive_execution_certificate(self):
        _,ctx=self.context('P5')
        result=run(ctx)
        for rid,row in result['rows'].items():
            row['machine_result']='UNKNOWN'
            row['blocked_reason']=None
            row['source_checks']={c:False for c in NATIVE_RULES[rid][1]}
        result['result_counts']={'PASS':0,'FAIL':0,'UNKNOWN':40,
                                 'BLOCKED':0,'NOT_DUE':0}
        with self.assertRaisesRegex(
                MacroExecutionBlocked,'C07_P345_CERTIFICATE_PRE_D_PIN_NOT_VERIFIED'):
            require_source_execution(result, source_context=ctx)

    def test_file_io_error_is_blocked_not_silent_pass(self):
        _,ctx=self.context('P5')
        with patch('c07_p345_macro_execution.build_packet',
                   side_effect=FileNotFoundError('registered original absent')):
            result=run(ctx)
        self.assertEqual(result['result_counts']['BLOCKED'],40)
        self.assertEqual(result['result_counts']['PASS'],0)
        with self.assertRaisesRegex(MacroExecutionBlocked,
                                    'C07_P345_CERTIFICATE_SOURCE_REPLAY_BLOCKED'):
            require_source_execution(result, source_context=ctx)

    def test_certification_of_only_complete_source_replay_never_promotes_mg0(self):
        _,ctx=self.context('P5')
        result=run(ctx)
        # The following is an isolated gate fixture, not asset source evidence.
        for rid,row in result['rows'].items():
            row['machine_result']='UNKNOWN'
            row['blocked_reason']=None
            row['source_checks']={c:(i==0) for i,c in
                                  enumerate(NATIVE_RULES[rid][1])}
        result['result_counts']={'PASS':0,'FAIL':0,'UNKNOWN':40,
                                 'BLOCKED':0,'NOT_DUE':0}
        # A forged report used to be accepted here. The gate must now
        # independently re-run all forty original-source replayers and reject
        # the caller's invented pin checks even when shape and counts match.
        with self.assertRaisesRegex(
                MacroExecutionBlocked,
                'C07_P345_CERTIFICATE_ORIGINAL_REPLAY_MISMATCH'):
            require_source_execution(result,source_context=ctx)
        # Only in an isolated mocked gate test may source replay be simulated:
        # its certificate must still grant no full literal, MG0 or FiveM PASS.
        with patch('c07_p345_macro_execution.run',return_value=result):
            certificate=require_source_execution(result,source_context=ctx)
        self.assertTrue(certificate['source_execution_verified'])
        self.assertFalse(certificate['full_semantics_verified'])
        self.assertFalse(certificate['independent_mg0_verified'])
        self.assertFalse(certificate['fivem_verified'])
        self.assertFalse(certificate['advancement_authorized'])

    def test_forged_report_without_trusted_context_is_rejected(self):
        _,ctx=self.context('P5')
        result=run(ctx)
        with self.assertRaisesRegex(
                MacroExecutionBlocked,
                'C07_P345_CERTIFICATE_SOURCE_REPLAY_BLOCKED'):
            require_source_execution(result,source_context=ctx)
        # The certificate cannot be minted by merely supplying a report:
        # explicitly require a consuming-side source context.
        with self.assertRaises(TypeError):
            require_source_execution(result)

    def test_all_40_original_literals_replayed_in_one_source_operation(self):
        _,ctx=self.context('P5')
        result=run(ctx)
        self.assertEqual(result['canonical_rule_count'],40)
        self.assertEqual(result['due_count'],40)
        self.assertEqual(result['visited_due_count'],40)
        self.assertEqual(len(result['rows']),40)
        self.assertEqual(set(result['rows']),set(IDS))
        self.assertEqual(set(result['result_counts']),
                         {'PASS','FAIL','UNKNOWN','BLOCKED','NOT_DUE'})
        self.assertEqual(result['result_counts']['NOT_DUE'],0)
        self.assertGreaterEqual(sum(
            bool(row['source_checks']) for row in result['rows'].values()),25)
        self.assertEqual(result['reviewed_literal_implementation_count'],
                         len(set(IDS)&set(FULL_LITERAL_REVIEWED)))
        self.assertEqual(result['candidate_count'],
                         40-result['reviewed_literal_implementation_count'])
        self.assertFalse(result['full_semantic_coverage'])
        self.assertFalse(result['advancement_authorized'])
        self.assertFalse(result['individual_mg0_independently_approved'])
        self.assertFalse(result['fivem_runtime_approved'])
        for rid,row in result['rows'].items():
            with self.subTest(rule=rid):
                self.assertEqual(row['canonical_literal'],
                                 TEXT[str(int(rid[-3:]))][0])
                self.assertEqual(row['phase'],
                                 TEXT[str(int(rid[-3:]))][1])
                if row['source_checks']:
                    self.assertEqual(set(row['source_checks']),
                                     set(NATIVE_RULES[rid][1]))
                if rid not in FULL_LITERAL_REVIEWED:
                    self.assertNotEqual(row['machine_result'],'PASS')
                if row['machine_result']=='PASS':
                    self.assertTrue(row['evidence_proven'])
                    self.assertIn(rid,FULL_LITERAL_REVIEWED)

    def test_P3_P4_P5_phase_scoping_never_claims_future_rules(self):
        for phase,count in (('P3',10),('P4',30),('P5',40)):
            with self.subTest(phase=phase):
                _,ctx=self.context(phase)
                result=run(ctx)
                self.assertEqual(result['due_count'],count)
                self.assertEqual(result['visited_due_count'],count)
                self.assertEqual(result['result_counts']['NOT_DUE'],
                                 40-count)
                self.assertFalse(result['advancement_authorized'])
                for rid in IDS[count:]:
                    self.assertEqual(result['rows'][rid]['machine_result'],
                                     'NOT_DUE')
                    self.assertEqual(result['rows'][rid]['mg0'],'NOT_DUE')

    def test_canonical_requirement_change_blocks_entire_macro(self):
        _,ctx=self.context('P5')
        rid='AAA-200-N-135'
        ctx['inventory']['rules'][rid]['requirement']='producer forged text'
        with self.assertRaisesRegex(
                MacroExecutionBlocked,
                'C07_P345_MACRO_LITERAL_OR_IMPLEMENTATION_DRIFT'):
            run(ctx)

    def test_wrong_attempt_phase_blocks_without_reporting_any_pass(self):
        _,ctx=self.context('P5')
        ctx['work']['phase']='P3'
        with self.assertRaisesRegex(
                MacroExecutionBlocked,'C07_P345_MACRO_763_PHASE'):
            run(ctx)

    def test_corrupt_original_is_not_a_positive_or_authorized(self):
        test,ctx=self.context('P5')
        (test.f.root/'scene.glb').write_bytes(b'forged original bytes')
        result=run(ctx)
        self.assertEqual(result['canonical_rule_count'],40)
        self.assertFalse(result['advancement_authorized'])
        self.assertEqual(result['result_counts']['PASS'],0)
        self.assertGreater(result['result_counts']['BLOCKED'],0)

    def test_no_unenrolled_source_candidate_can_be_positive(self):
        _,ctx=self.context('P5')
        result=run(ctx)
        for rid in IDS:
            if rid not in FULL_LITERAL_REVIEWED:
                with self.subTest(rule=rid):
                    item=result['rows'][rid]
                    self.assertIn(item['machine_result'],
                                  ('UNKNOWN','BLOCKED','FAIL'))
                    self.assertEqual(item['source_scope'],
                                     'ORIGINAL_SCOPED_CANDIDATE')
                    self.assertFalse(item['evidence_proven'])

if __name__=='__main__':
    unittest.main()
