"""C07 P1 E/F macro: TEN original semantics per entire canonical family.

Reviewed source-code eligibility is distinct from asset correctness, MG0,
owner decisions and FiveM. No micro observer can fill a missing literal.
"""
import unittest
from unittest.mock import patch
import c07_cohort_completion_gate as cohort
from c07_native_source_rule_replayers import REVIEWED_RULES


class FullOriginalP1FamilySemantics(unittest.TestCase):
    def test_e041_e050_ten_distinct_reviewed_native_consumers(self):
        result=cohort.macro_snapshot()
        p1=result['macros'][0]
        family=next(f for f in p1['families'] if f['family']=='E')
        self.assertEqual(family['rule_count'],10)
        self.assertEqual(family['code_reviewed'],10)
        self.assertEqual(family['missing_ids'],[])
        self.assertEqual(family['inconsistent_ids'],[])
        self.assertTrue(family['code_family_ready'])
        expected={'AAA-200-E-'+str(n).zfill(3)
                  for n in range(41,51)}
        self.assertTrue(expected.issubset(set(REVIEWED_RULES)))
        self.assertEqual(family['operational_mg0'],'UNVERIFIED')
        self.assertFalse(p1['code_macro_ready'])  # D remains incomplete
        self.assertFalse(result['c07_finished'])

    def test_f_family_is_whole_ten_rule_original_code_review(self):
        result=cohort.macro_snapshot()
        fam=next(f for f in result['macros'][0]['families']
                 if f['family']=='F')
        self.assertEqual(fam['rule_count'],10)
        self.assertEqual(fam['code_reviewed'],10)
        self.assertEqual(fam['missing_ids'],[])
        self.assertTrue(fam['code_family_ready'])
        self.assertEqual(fam['operational_mg0'],'UNVERIFIED')

    def test_forged_nine_rule_e_family_cannot_be_complete(self):
        rules=dict(REVIEWED_RULES)
        rules.pop('AAA-200-E-046')
        with patch.object(cohort,'NATIVE_RULES',rules):
            result=cohort.macro_snapshot()
        fam=result['macros'][0]['families'][1]
        self.assertEqual(fam['family'],'E')
        self.assertEqual(fam['missing_ids'],['AAA-200-E-046'])
        self.assertFalse(fam['code_family_ready'])

    def test_e_completion_is_code_only_never_asset_or_full_c07_pass(self):
        result=cohort.macro_snapshot()
        self.assertEqual(result['cohort_count'],100)
        self.assertEqual(result['independent_mg0'],'UNVERIFIED')
        self.assertFalse(result['code_all_macros_ready'])
        self.assertFalse(result['advancement_authorized'])
        self.assertFalse(result['c07_finished'])


if __name__=='__main__':
    unittest.main()
