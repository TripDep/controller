"""Whole canonical AAA-200 A-T family macro gates (synthetic tests only)."""
import copy
import hashlib
import unittest
from unittest.mock import patch

import c07_cohort_completion_gate as gate


PHASE_LETTERS = (
    ('P0', 'ABC'), ('P1','DEF'), ('P2','GHIJ'), ('P3','KL'),
    ('P4','MN'), ('P5','O'), ('P6','P'), ('P7','QR'), ('P8','ST'),
)


def inventory():
    phases = {letter:phase for phase,letters in PHASE_LETTERS
              for letter in letters}
    rows = {}
    for index,letter in enumerate('ABCDEFGHIJKLMNOPQRST'):
        for n in range(index*10+1, index*10+11):
            rid='AAA-200-'+letter+'-'+str(n).zfill(3)
            literal='synthetic original requirement '+str(n)
            rows[rid]={
                'family':'AAA-200','catalog_number':n,
                'catalog_phase':phases[letter],
                'requirement':literal,
                'requirement_sha256':hashlib.sha256(literal.encode()).hexdigest(),
                'source_sha256':gate.AAA_CATALOG_SHA,
            }
    for i in range(563):
        rows['OTHER-'+str(i).zfill(3)] = {}
    return {
        'schema':'gg-effective-family-inventory-v1',
        'rule_count':763,'rules':rows,
        'source_digests':{'aaa_catalog':gate.AAA_CATALOG_SHA},
    }


class EntireAAA200FamilyMacroTests(unittest.TestCase):
    def test_all_twenty_families_grouped_into_nine_phase_macros(self):
        result=gate.catalog200_macro_snapshot(inventory())
        self.assertEqual(result['canonical_rule_count'],200)
        self.assertEqual(result['family_count'],20)
        self.assertEqual(result['phase_macro_count'],9)
        self.assertEqual(''.join(
            f['family'] for m in result['macros'] for f in m['families']),
            'ABCDEFGHIJKLMNOPQRST')
        self.assertEqual(
            [m['rule_count'] for m in result['macros']],
            [30,30,40,20,20,10,10,20,20])
        self.assertEqual(
            sum(f['canonical_rule_count'] for m in result['macros']
                for f in m['families']),200)
        self.assertEqual(result['native_code_reviewed']+
                         result['missing_native_code'],200)
        self.assertFalse(result['advancement_authorized'])
        self.assertFalse(result['c07_finished'])
        self.assertEqual(result['independent_mg0'],'UNVERIFIED')

    def test_reviewed_scope_is_not_mistaken_for_operational_pass(self):
        result=gate.catalog200_macro_snapshot(inventory())
        for macro in result['macros']:
            self.assertEqual(macro['operational_mg0'],'UNVERIFIED')
            self.assertFalse(macro['advancement_authorized'])
            for fam in macro['families']:
                self.assertEqual(fam['canonical_rule_count'],10)
                self.assertEqual(fam['reviewed_native_code']+
                                 fam['missing_native_code'],10)
                self.assertEqual(fam['full_semantic_asset_verdict'],'UNKNOWN')
                self.assertEqual(fam['independent_mg0'],'UNVERIFIED')
        # A-008/A-009 may be enrolled for documentary R173 review.
        # That enrollment cannot count as native full-literal coverage.
        self.assertEqual(result['macros'][0]['families'][0][
                         'reviewed_native_code'],0)
        self.assertEqual(result['macros'][0]['families'][0][
                         'registry_inconsistencies'],[])

    def test_tampered_original_sha_or_requirement_is_rejected(self):
        for key,value in (('requirement_sha256','0'*64),
                          ('source_sha256','0'*64),
                          ('catalog_number',42)):
            inv=inventory()
            inv['rules']['AAA-200-E-041'][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(
                    gate.CohortIncomplete,'C07_AAA200_ORIGINAL_LITERAL'):
                gate.catalog200_macro_snapshot(inv)

    def test_family_cannot_split_phase_or_omit_one_original(self):
        inv=inventory()
        inv['rules']['AAA-200-M-130']['catalog_phase']='P5'
        with self.assertRaisesRegex(
                gate.CohortIncomplete,'C07_AAA200_FAMILY_SPLIT_ACROSS_PHASES'):
            gate.catalog200_macro_snapshot(inv)
        inv=inventory()
        inv['rules'].pop('AAA-200-D-031')
        inv['rules']['OTHER-NEW']={}
        with self.assertRaisesRegex(
                gate.CohortIncomplete,'C07_AAA200_ORIGINAL_LITERAL'):
            gate.catalog200_macro_snapshot(inv)

    def test_inconsistent_native_dispatch_does_not_complete_any_family(self):
        rid='AAA-200-E-041'
        bad=copy.deepcopy(gate.NATIVE_RULES)
        domain,criteria=bad[rid]
        bad[rid]=(domain,('new_fake_criterion',)+criteria)
        with patch.object(gate,'NATIVE_RULES',bad):
            result=gate.catalog200_macro_snapshot(inventory())
        family=result['macros'][1]['families'][1]
        self.assertEqual(family['family'],'E')
        self.assertIn(rid,family['registry_inconsistencies'])
        self.assertIn(rid,family['missing_ids'])
        self.assertFalse(family['whole_family_code_ready'])

    def test_unverified_inventory_cannot_masquerade_as_canonical_763(self):
        inv=inventory()
        inv['source_digests']['aaa_catalog']='0'*64
        with self.assertRaisesRegex(
                gate.CohortIncomplete,'C07_AAA200_CANONICAL_763'):
            gate.catalog200_macro_snapshot(inv)


if __name__ == '__main__':
    unittest.main()
