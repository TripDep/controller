"""C07 entire 100-rule macro family enforcement, adversarial source gates.

Synthetic registry tests do not prove an original asset, MG0, owner or FiveM.
"""
import copy
import unittest
from unittest.mock import patch

import c07_cohort_completion_gate as gate


class WholeFamilyMacroTests(unittest.TestCase):
    def test_frozen_100_partition_has_three_entire_macro_groups(self):
        result = gate.macro_snapshot()
        self.assertEqual(result['macro_count'], 3)
        self.assertEqual(result['family_count'], 10)
        self.assertEqual([g['rule_count'] for g in result['macros']],
                         [30, 40, 30])
        self.assertEqual([g['family_count'] for g in result['macros']],
                         [3, 4, 3])
        self.assertEqual(sum(g['code_reviewed'] for g in result['macros']),
                         result['code_reviewed'])
        self.assertEqual(sum(g['code_missing'] for g in result['macros']),
                         result['code_missing'])
        self.assertEqual(result['code_reviewed'] + result['code_missing'], 100)
        self.assertFalse(result['advancement_authorized'])
        self.assertFalse(result['c07_finished'])
        self.assertEqual(result['independent_mg0'], 'UNVERIFIED')

    def test_each_family_is_ten_exact_canonical_ids_not_ten_micro_tests(self):
        result = gate.macro_snapshot()
        family_letters = ''.join(
            fam['family'] for group in result['macros']
            for fam in group['families'])
        self.assertEqual(family_letters, 'DEFLMNOPQS')
        for group in result['macros']:
            for family in group['families']:
                self.assertEqual(family['rule_count'], 10)
                self.assertEqual(family['code_reviewed'] + family['missing'], 10)
                self.assertEqual(family['code_family_ready'],
                                 family['missing'] == 0 and not
                                 family['inconsistent_ids'])
                self.assertEqual(family['operational_mg0'], 'UNVERIFIED')

    def test_forged_all100_and_authorization_cannot_pass_recount(self):
        original = gate.snapshot()
        forged = copy.deepcopy(original)
        forged['code_100_ready'] = True
        forged['code_reviewed_count'] = 100
        forged['code_missing_count'] = 0
        forged['code_missing_ids'] = []
        forged['registry_inconsistent_ids'] = []
        forged['c07_finished'] = True
        with self.assertRaisesRegex(gate.CohortIncomplete,
                                    'C07_100_SEMANTIC_REPLAYERS_NOT_COMPLETED'):
            gate.require_code100(forged)

    def test_forged_completed_family_macro_is_rejected_by_fresh_recount(self):
        original = gate.macro_snapshot()
        fabricated = copy.deepcopy(original)
        fabricated['macros'][0]['code_macro_ready'] = True
        fabricated['code_all_macros_ready'] = True
        with self.assertRaisesRegex(gate.CohortIncomplete,
                                    'C07_MACRO_SOURCE_CODE_RECOUNT_MISMATCH'):
            gate.require_macro_code_ready(
                gate.MACRO_GROUPS[0][0], fabricated)
        with self.assertRaisesRegex(gate.CohortIncomplete,
                                    'C07_MACRO_WHOLE_FAMILIES_INCOMPLETE'):
            gate.require_macro_code_ready(gate.MACRO_GROUPS[0][0], original)

    def test_family_cannot_silently_replace_a_missing_canonical_rule(self):
        original = gate.MACRO_GROUPS
        mutated = list(original)
        name, members = mutated[0]
        tampered = list(members)
        tampered[-1] = 'AAA-200-G-061'
        mutated[0] = (name, tuple(tampered))
        with patch.object(gate, 'MACRO_GROUPS', tuple(mutated)):
            with self.assertRaisesRegex(gate.CohortIncomplete,
                                        'C07_MACRO_FAMILY_'):
                gate.macro_snapshot()

    def test_complete_code_fixture_can_never_grant_real_completion(self):
        # Isolated code gate unit proof only, not original source readback.
        fake = gate.snapshot()
        fake['code_100_ready'] = True
        fake['code_reviewed_count'] = 100
        fake['code_missing_count'] = 0
        fake['code_missing_ids'] = []
        fake['registry_inconsistent_ids'] = []
        with patch.object(gate, 'snapshot', return_value=fake):
            self.assertTrue(gate.require_code100(fake))
            with self.assertRaisesRegex(gate.CohortIncomplete,
                                        'C07_MG0_OWNER_FIVEM_PROOF_NOT_VERIFIED'):
                gate.refuse_full_completion(fake)


if __name__ == '__main__':
    unittest.main()
