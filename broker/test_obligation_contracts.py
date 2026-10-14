"""Source-grounded obligation ledger tests; no synthetic work PASS."""
import copy
import unittest
import obligation_contracts as o

def mock_inventory():
    ids=['AAA-200-A-008','AAA-200-B-012','AAA-200-B-018','MASTER_A']
    rules={rid:{'family':'AAA-200' if rid.startswith('AAA') else 'MASTER_CHAIN',
                'requirement':'Riconoscere la differenza tra un fatto verificato e una supposizione.'
                if rid=='AAA-200-A-008' else 'Controllare il terreno e la walkability.',
                'source_sha256':'a'*64,'requirement_sha256':'b'*64,
                **({'catalog_phase':'P0','asset_type':'all'} if rid.startswith('AAA') else {})}
           for rid in ids}
    return {'schema':'gg-effective-family-inventory-v1',
            'canonical_master_sha256':o.CURRENT_MASTER,
            'families':{'AAA-200':ids[:3],'MASTER_CHAIN':ids[3:]},
            'rules':rules,'source_digests':{'master':o.CURRENT_MASTER},
            'rule_count':4,'family_count':2}

class Tests(unittest.TestCase):
    def test_all_ids_preserved_without_work_promotion(self):
        d=o.build(mock_inventory())
        self.assertEqual(d['registered_rule_ids'],4)
        self.assertEqual(d['registered_families'],2)
        self.assertEqual(d['reviewed_documentary_predicate_implementations'],3)
        self.assertEqual(d['missing_semantic_verifier_implementations'],1)
        self.assertFalse(d['advancement_authorized'])
        self.assertEqual(set(d['rules']),set(mock_inventory()['rules']))
        self.assertTrue(all(r['individual_mg0_result']=='UNKNOWN' and
                            not r['current_phase_authorized']
                            for r in d['rules'].values()))
    def test_omitted_id_is_blocked(self):
        inv=mock_inventory()
        inv['families']['AAA-200'].pop()
        with self.assertRaisesRegex(o.Blocked,'OMITTED_OR_DUPLICATE_ID'):
            o.build(inv)
    def test_duplicate_id_is_blocked(self):
        inv=mock_inventory()
        inv['families']['AAA-200'].append('AAA-200-B-012')
        with self.assertRaisesRegex(o.Blocked,'OMITTED_OR_DUPLICATE_ID'):
            o.build(inv)
    def test_master_mismatch_blocks(self):
        inv=mock_inventory()
        inv['canonical_master_sha256']='0'*64
        with self.assertRaisesRegex(o.Blocked,'MASTER_DRIFT'):o.build(inv)
    def test_missing_rule_source_digest_blocks(self):
        inv=mock_inventory();inv['rules']['MASTER_A']['source_sha256']=''
        with self.assertRaisesRegex(o.Blocked,'SOURCE_ID_INVALID'):
            o.build(inv)
    def test_work_risks_generate_specific_modalities(self):
        r=o.build(mock_inventory())['rules']['MASTER_A']
        self.assertIn('GEOMETRY_OR_WORLD_COORDINATE_MEASUREMENT',
                      r['required_individual_evidence_modalities'])
        self.assertIn('SOURCE_SPECIFIC_VERIFIER_IMPLEMENTATION',r['unresolved'])
    def test_current_phase_never_inferred_from_catalog_earliest_phase(self):
        d=o.build(mock_inventory())
        r=d['rules']['AAA-200-A-008']
        self.assertEqual(r['earliest_catalog_phase'],'P0')
        self.assertEqual(r['current_work_applicability'],
                         'UNRESOLVED_NO_TRUSTED_CONTROLLER_WORK_RECORD')

if __name__=='__main__':unittest.main()
