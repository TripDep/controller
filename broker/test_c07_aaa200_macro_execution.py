"""C07 source-byte whole-200 macro orchestration negative/positive fixtures.

No source mocked in this file is an operational asset, MG0, FiveM or owner PASS.
"""
import unittest
from unittest.mock import patch

import supervisor_judgment as judgment
import c07_aaa200_macro_execution as macro
from c07_native_source_rule_replayers import NATIVE_RULES, VALIDATORS
from test_c07_aaa200_macro_families import inventory


def context(phase='P8'):
    work={
        'phase':phase, 'work_item_sha256':'1'*64,
        'attempt_id':'2'*64, 'operation_sha256':'3'*64,
        'attempt_number':1,'previous_attempt_id':None,
        'master_sha256':'4'*64, 'work_dependencies':{'5'*64:'6'*64},
    }
    return {
        'inventory':inventory(), 'plan':{'phase':phase},
        'controller':object(), 'asset':'GARDEN','step':'STEP001',
        'work':work,'source_loader':lambda _:b'fixture-only',
    }


def replay_unknown(source, rid, *, expected=None):
    return {
        'schema':'gg-semantic-rule-v1',
        'scope':judgment.SEMANTIC_SCOPE,
        'validator_id':VALIDATORS[rid],
        'binding':expected,
        'rule':{
            'result':'UNKNOWN',
            'checks':{key:False for key in NATIVE_RULES[rid][1]},
            'proof_digest':'a'*64,
        },
        'mg0':{
            'binding':expected, 'triggered':None, 'result':'UNKNOWN',
            'checks':{'canonical_triggers_checked':False},
            'proof_digest':'b'*64,
        },
    }


class CompletePhaseMacroExecutionTests(unittest.TestCase):
    def test_exact_200_original_roles_and_three_digit_family_ids(self):
        with patch.object(macro,'build_packet',side_effect=replay_unknown):
            result=macro.inspect(context())
        self.assertEqual(result['canonical_rule_count'],200)
        self.assertEqual(result['family_count'],20)
        self.assertEqual(result['macro_count'],9)
        self.assertEqual(len(result['rows']),200)
        self.assertEqual(result['source_replays_attempted'],
                         result['native_code_reviewed'])
        self.assertEqual(result['source_replays_completed'],
                         result['native_code_reviewed'])
        self.assertEqual(result['source_replays_attempted']+
                         result['native_code_missing'],200)
        self.assertTrue(all(m['source_result']=='UNKNOWN'
                            for m in result['macros']))
        self.assertTrue(all(v['full_semantic_asset_verdict']=='UNKNOWN'
                            for v in result['rows'].values()))
        self.assertFalse(result['advancement_authorized'])
        self.assertFalse(result['c07_finished'])

    def test_early_phase_does_not_execute_future_originals(self):
        with patch.object(macro,'build_packet',side_effect=replay_unknown):
            result=macro.inspect(context('P3'))
        self.assertLess(result['source_replays_attempted'],
                        result['native_code_reviewed'])
        self.assertEqual(result['rows']['AAA-200-T-197']['source_result'],
                         'NOT_DUE')
        self.assertEqual(result['rows']['AAA-200-L-111']['source_result'],
                         'UNKNOWN')
        self.assertFalse(result['advancement_authorized'])

    def test_missing_originals_block_code_reviewed_and_do_not_forge_pass(self):
        with patch.object(macro,'build_packet',
                          side_effect=FileNotFoundError('source original absent')):
            result=macro.inspect(context())
        self.assertEqual(result['source_replays_completed'],0)
        self.assertEqual(result['source_replays_attempted'],
                         result['native_code_reviewed'])
        self.assertEqual(result['rows']['AAA-200-E-041']['source_result'],
                         'BLOCKED')
        self.assertEqual(result['rows']['AAA-200-A-001']['source_result'],
                         'UNKNOWN')
        self.assertEqual(result['independent_mg0'],'UNVERIFIED')
        self.assertFalse(result['advancement_authorized'])

    def test_forged_source_pass_with_failed_checks_is_blocked(self):
        def forged(source,rid,*,expected=None):
            packet=replay_unknown(source,rid,expected=expected)
            packet['rule']['result']='PASS'
            return packet
        with patch.object(macro,'build_packet',side_effect=forged):
            with self.assertRaisesRegex(macro.WholeMacroBlocked,
                                        'C07_AAA200_MACRO_REPLAYER_FALSE_POSITIVE'):
                macro.inspect(context())

    def test_wrong_mg0_binding_or_schema_is_blocked(self):
        def forged(source,rid,*,expected=None):
            packet=replay_unknown(source,rid,expected=expected)
            packet['mg0']['binding']={'forged':True}
            return packet
        with patch.object(macro,'build_packet',side_effect=forged):
            with self.assertRaisesRegex(ValueError,'JUDGMENT_MG0_BINDING'):
                macro.inspect(context())

    def test_real_negative_predicate_stays_fail_not_unknown_or_pass(self):
        def contradicted(source,rid,*,expected=None):
            packet=replay_unknown(source,rid,expected=expected)
            if rid=='AAA-200-E-041':
                packet['rule']['result']='FAIL'
            return packet
        with patch.object(macro,'build_packet',side_effect=contradicted):
            result=macro.inspect(context())
        self.assertEqual(result['rows']['AAA-200-E-041']['source_result'],
                         'FAIL')
        self.assertEqual(result['macros'][1]['source_result'],'FAIL')
        self.assertFalse(result['advancement_authorized'])


if __name__=='__main__':
    unittest.main()
