"""Adversarial 300-question tests. Fixtures do not certify actual 3D work."""
import hashlib
import sys
import types
import unittest
from unittest.mock import patch
import c07_questions_300 as gate

def sha(v): return hashlib.sha256(v).hexdigest()

def sample():
    header=(
        '# GOLDEN GARDEN SOURCE\n'
        '## How 300+ works\n'
        'There are 300 base questions, non-mechanical and context-sensitive.\n'
        'Questions 280–285 force dynamic discovery.\n'
        '## Canonical 300 base questions\n\n'
    )
    bank=''.join(f'{n}. What must be checked in question {n}?\n'
                 for n in range(1,301))
    usage=(
        '\n## Bank usage integrity\n'
        'Do not claim all questions passed without evidence.\n'
        'A new material question also requires investigation.\n'
        'Any important answer that lacks evidence remains UNKNOWN.\n'
        '\n# 13. Current Pavilion / Golden Ting state\n'
    )
    master=(header+bank+usage).encode()
    ids=['Q-%03d' % n for n in range(1,301)]
    extras={f'OTHER-{i}': [f'OTHER-{i}-{j}' for j in range(1 if i<18 else 445)]
            for i in range(19)}
    groups={'QUESTIONS_300':ids,**extras}
    rows={}
    for n,rid in enumerate(ids,1):
        q=f'What must be checked in question {n}?'
        rows[rid]={
            'family':'QUESTIONS_300','source':'master',
            'source_path':gate.SOURCE_PATH,'source_sha256':sha(master),
            'requirement':q,'requirement_sha256':sha(q.encode()),
            'required_mg0':True}
    rows.update({rid:{'family':family}
                 for family,items in extras.items() for rid in items})
    inventory={
        'schema':'gg-effective-family-inventory-v1',
        'source_digests':{'master':sha(master)},
        'canonical_master_sha256':sha(master),
        'families':groups,'rules':rows,'rule_count':763,'family_count':20}
    plan={'master_sha256':sha(master),'mode':'DIAGNOSTIC_ONLY',
          'phase':'P0','asset_type':'terrain',
          'profiles':['TERRAIN_PATH_PROFILE'],'enrolled':{}}
    return inventory,plan,master

COVERAGE=types.ModuleType('family_coverage')
COVERAGE.expected_result=lambda *args:'PASS'
APPROVED=types.ModuleType('approved_validators')
APPROVED.REVIEWED={}
INTAKE=types.ModuleType('real_work_intake')
INTAKE.audit_check=lambda data,asset:([], 'f'*64)
MG0=types.ModuleType('c07_mg0_individual')
MG0.inspect=lambda *args:{'individual_rule_mg0':'UNKNOWN'}

class Tests(unittest.TestCase):
    def setUp(self):
        self.inv,self.plan,self.master=sample()
        p=patch.dict(sys.modules,{'family_coverage':COVERAGE,
                                  'approved_validators':APPROVED,
                                  'real_work_intake':INTAKE,
                                  'c07_mg0_individual':MG0})
        p.start();self.addCleanup(p.stop)
    def inspect(self):
        return gate.inspect(self.inv,self.plan,master_raw=self.master)
    def test_300_exact_questions_and_no_work_pass(self):
        r=self.inspect()
        self.assertEqual(r['base_questions'],300)
        self.assertEqual(len(r['questions']),300)
        self.assertEqual(len(r['missing_due_semantic_validators']),300)
        self.assertEqual(r['answers_independently_verified'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        self.assertEqual(r['canonical_questions_source_integrity_pass'],300)
    def test_dynamic_280_to_285_and_plus_are_not_deleted(self):
        r=self.inspect()
        self.assertEqual(r['required_dynamic_discovery_questions'],
                         [f'Q-{i:03}' for i in range(280,286)])
        self.assertTrue(all(r['questions'][q]['dynamic_question_discovery_required']
                            for q in r['required_dynamic_discovery_questions']))
        self.assertIn('UNRESOLVED',r['additional_material_questions'])
    def test_operational_without_verifiers_blocks(self):
        self.plan['mode']='OPERATIONAL'
        with self.assertRaisesRegex(gate.Blocked,'C07_300_MISSING_SEMANTIC_QUESTION_VALIDATORS:300'):
            gate.require_operational_scope(self.inv,self.plan,master_raw=self.master)
    def test_omitted_question_blocks(self):
        self.inv['families']['QUESTIONS_300'].pop()
        with self.assertRaisesRegex(gate.Blocked,'C07_300_CANONICAL_INVENTORY_MEMBERSHIP'):
            self.inspect()
    def test_duplicate_question_blocks(self):
        self.inv['families']['QUESTIONS_300'][0]='Q-002'
        with self.assertRaisesRegex(gate.Blocked,'C07_300_CANONICAL_INVENTORY_MEMBERSHIP'):
            self.inspect()
    def test_modified_question_hash_blocks(self):
        self.inv['rules']['Q-087']['requirement']+=' manipulated'
        with self.assertRaisesRegex(gate.Blocked,'C07_300_SOURCE_QUESTION_DRIFT'):
            self.inspect()
    def test_modified_master_bytes_blocks(self):
        with self.assertRaisesRegex(gate.Blocked,'C07_300_LIVE_MASTER_DRIFT'):
            gate.inspect(self.inv,self.plan,master_raw=self.master+b'!')
    def test_private_master_question_text_mismatch_blocks(self):
        rid='Q-004'
        changed='An invented question?'
        self.inv['rules'][rid]['requirement']=changed
        self.inv['rules'][rid]['requirement_sha256']=sha(changed.encode())
        with self.assertRaisesRegex(gate.Blocked,'C07_300_MASTER_QUESTION_TEXT_MISMATCH'):
            self.inspect()
    def test_lost_dynamic_source_section_blocks(self):
        altered=self.master.replace(b'Questions 280',b'Questions 270')
        with self.assertRaisesRegex(gate.Blocked,'C07_300_CONTEXT_DYNAMIC_SOURCE_NOT_FOUND'):
            gate.extract_bank(altered)
    def test_nonsequential_bank_blocks(self):
        altered=self.master.replace(b'280. What',b'279. What')
        with self.assertRaisesRegex(gate.Blocked,'C07_300_QUESTION_COUNT_ORDER_DUPLICATE'):
            gate.extract_bank(altered)
    def test_lost_bank_usage_integrity_blocks(self):
        altered=self.master.replace(b'A new material question',b'Ignore additional questions')
        with self.assertRaisesRegex(gate.Blocked,'C07_300_BANK_USAGE_FAIL_CLOSED_SOURCE'):
            gate.extract_bank(altered)
    def test_attempt_partial_context_blocks(self):
        with self.assertRaisesRegex(gate.Blocked,'C07_300_INCOMPLETE_TRUSTED_ATTEMPT'):
            gate.inspect(self.inv,self.plan,master_raw=self.master,
                         audit_raw=b'fixture')
    def test_claimed_mg0_pass_blocked(self):
        old=MG0.inspect;MG0.inspect=lambda *args:{'individual_rule_mg0':'PASS'}
        self.addCleanup(setattr,MG0,'inspect',old)
        with self.assertRaisesRegex(gate.Blocked,'C07_300_MG0_FALSE_PASS'):
            gate.inspect(self.inv,self.plan,master_raw=self.master,
                         audit_raw=b'audit',asset='TEST',attempt_id='a'*64)
    def test_observed_fail_is_preserved(self):
        old=INTAKE.audit_check
        INTAKE.audit_check=lambda raw,asset:(
            [{'event':'QUALITY_FINDING','result':'FAIL','record_hash':'a'*64,
              'rule_id':'Q-280','attempt_id':'b'*64}], 'c'*64)
        self.addCleanup(setattr,INTAKE,'audit_check',old)
        r=gate.inspect(self.inv,self.plan,master_raw=self.master,
                       audit_raw=b'audit',asset='TEST',attempt_id='b'*64)
        self.assertEqual(r['observed_question_failure_ids'],['Q-280'])
        self.assertFalse(r['advancement_authorized'])
    def test_stale_other_attempt_cannot_be_current_evidence(self):
        old=INTAKE.audit_check
        INTAKE.audit_check=lambda raw,asset:(
            [{'event':'QUALITY_FINDING','result':'FAIL','record_hash':'a'*64,
              'rule_id':'Q-280','attempt_id':'b'*64}], 'c'*64)
        self.addCleanup(setattr,INTAKE,'audit_check',old)
        r=gate.inspect(self.inv,self.plan,master_raw=self.master,
                       audit_raw=b'audit',asset='TEST',attempt_id='d'*64)
        self.assertEqual(r['observed_question_failure_ids'],[])
        self.assertEqual(r['answers_independently_verified'],0)
    def test_validated_registry_entry_alone_not_an_answer(self):
        rid='Q-001'
        reviewed={rid:('reviewed-validator',('criterion',))}
        self.plan['enrolled'][rid]={'validator_id':'reviewed-validator'}
        r=gate.inspect(self.inv,self.plan,master_raw=self.master,reviewed=reviewed)
        self.assertEqual(len(r['missing_due_semantic_validators']),299)
        self.assertEqual(r['questions'][rid]['semantic_verdict'],'UNKNOWN')
        self.assertEqual(r['answers_independently_verified'],0)

if __name__=='__main__':unittest.main()
