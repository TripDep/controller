import unittest
import hashlib
import approved_validators as v

def sha(x):return hashlib.sha256(x.encode()).hexdigest()
def fixture():
    rid='AAA-200-A-008'
    name='Riconoscere la differenza tra un fatto verificato e una supposizione.'
    spec={'validator_id':v.R173_VALIDATOR,'criteria':list(v.R173_CRITERIA[rid]),
          'requirement_sha256':sha(name),
          'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40},'source_ref':'c'*40}
    return rid,spec,{'rules':{rid:{'requirement_sha256':sha(name)}}}

class Tests(unittest.TestCase):
    def test_reviewed_subset_still_not_work_authorization(self):
        rid,spec,inventory=fixture()
        result=v.validate({rid:spec},inventory)
        self.assertEqual(result['reviewed_enrolled_count'],1)
        self.assertFalse(result['work_authorized'])
        self.assertFalse(result['complete_763_rule_coverage'])
    def test_unreviewed_id_stays_unavailable(self):
        rid,spec,inventory=fixture()
        inventory['rules']['AAA-200-A-010']={'requirement_sha256':spec['requirement_sha256']}
        with self.assertRaisesRegex(v.InvalidEnrollment,'VALIDATOR_NOT_IMPLEMENTED_FOR_RULE'):
            v.validate({'AAA-200-A-010':spec},inventory)
    def test_unreviewed_implementation_is_not_enrolled(self):
        rid,spec,inventory=fixture();spec['validator_id']='unreviewed'
        with self.assertRaisesRegex(v.InvalidEnrollment,'VALIDATOR_ID_NOT_REVIEWED'):
            v.validate({rid:spec},inventory)
    def test_omitted_semantic_criterion_is_rejected(self):
        rid,spec,inventory=fixture();spec['criteria'].pop()
        with self.assertRaisesRegex(v.InvalidEnrollment,'VALIDATOR_REQUIRED_SEMANTIC_CRITERIA'):
            v.validate({rid:spec},inventory)
    def test_stale_requirement_is_rejected(self):
        rid,spec,inventory=fixture();spec['requirement_sha256']='0'*64
        with self.assertRaisesRegex(v.InvalidEnrollment,'VALIDATOR_CANONICAL_REQUIREMENT_CHANGED'):
            v.validate({rid:spec},inventory)
    def test_mutable_source_is_rejected(self):
        rid,spec,inventory=fixture();spec['source_ref']='main'
        with self.assertRaisesRegex(v.InvalidEnrollment,'VALIDATOR_R173_EVIDENCE_IMMUTABLE_REF'):
            v.validate({rid:spec},inventory)
    def test_issuer_is_required(self):
        rid,spec,inventory=fixture();spec['issuer']={}
        with self.assertRaisesRegex(v.InvalidEnrollment,'VALIDATOR_GIT_ORIGIN_MISSING'):
            v.validate({rid:spec},inventory)
if __name__=='__main__':unittest.main()
