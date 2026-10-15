"""Synthetic negative tests: AAA-200 catalog integrity is not asset approval."""
import hashlib, json, sys, types, unittest
from unittest.mock import patch
import c07_aaa200 as gate

def sha(b): return hashlib.sha256(b).hexdigest()

def fixture():
    rows=[]
    for n in range(1,201):
        section=gate.SECTIONS[(n-1)//10]
        rows.append({'id':n,'section':section,'section_title':'Section '+section,
                     'requirement':'Requirement '+str(n),'phase':'P0' if n<=40 else 'P1',
                     'asset_type':'all'})
    raw=json.dumps({'schema':'GG_AAA200_CATALOG_V1','phase_order':list(gate.PHASES),
                    'asset_types':list(gate.ASSET_TYPES),'catalog':rows},ensure_ascii=False).encode()
    ids=['AAA-200-'+r['section']+'-'+str(r['id']).zfill(3) for r in rows]
    inventory={'schema':'gg-effective-family-inventory-v1',
       'canonical_master_sha256':sha(b'master'),
       'source_digests':{'aaa_catalog':sha(raw)},
       'families':{'AAA-200':ids,'OTHER':[f'OTHER-{i:03}' for i in range(563)]},
       'rules':{},'rule_count':763,'family_count':20}
    for rid,row in zip(ids,rows):
        inventory['rules'][rid]={
            'family':'AAA-200','source':'aaa_catalog',
            'source_path':gate.SOURCE_PATH,'source_sha256':sha(raw),
            'requirement':row['requirement'],
            'requirement_sha256':sha(row['requirement'].encode()),
            'required_mg0':True,'catalog_number':row['id'],
            'catalog_section':row['section'],'catalog_phase':row['phase'],
            'asset_type':row['asset_type']}
    inventory['rules'].update({rid:{'family':'OTHER'} for rid in inventory['families']['OTHER']})
    plan={'master_sha256':sha(b'master'),'phase':'P0',
          'asset_type':'terrain','profiles':['TERRAIN_PATH_PROFILE'],
          'mode':'DIAGNOSTIC_ONLY','enrolled':{}}
    return inventory,plan,raw

COVERAGE=types.ModuleType('family_coverage')
COVERAGE.expected_result=lambda row,*args: 'PASS' if row['catalog_phase']=='P0' else 'FUTURE_PHASE'
APPROVED=types.ModuleType('approved_validators')
APPROVED.REVIEWED={}
INTAKE=types.ModuleType('real_work_intake')
INTAKE.audit_check=lambda raw,asset: ([], 'd'*64)
MG0=types.ModuleType('c07_mg0_individual')
MG0.inspect=lambda *args: {'individual_rule_mg0':'UNKNOWN'}

class Tests(unittest.TestCase):
    def setUp(self):
        self.inventory,self.plan,self.raw=fixture()
        p=patch.dict(sys.modules,{'family_coverage':COVERAGE,
                    'approved_validators':APPROVED,'real_work_intake':INTAKE,
                    'c07_mg0_individual':MG0})
        p.start();self.addCleanup(p.stop)
    def review(self): return gate.inspect(self.inventory,self.plan,catalog_raw=self.raw)
    def test_every_rule_and_scope(self):
        r=self.review()
        self.assertEqual(r['catalog_rules_verified'],200)
        self.assertEqual(len(r['entries']),200)
        self.assertEqual(len(r['section_counts']),20)
        self.assertEqual(r['due'],40)
        self.assertEqual(len(r['missing_due_semantic_validators']),40)
        self.assertFalse(r['advancement_authorized'])
        self.assertEqual(r['native_semantic_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertEqual(r['asset_quality_approvals'],0)
    def test_operational_unreviewed_fails(self):
        self.plan['mode']='OPERATIONAL'
        with self.assertRaisesRegex(gate.Blocked,'AAA200_MISSING_DUE_SEMANTIC_VALIDATORS:40'):
            gate.require_operational_scope(self.inventory,self.plan,catalog_raw=self.raw)
    def test_missing_id_fails(self):
        self.inventory['families']['AAA-200'].pop()
        with self.assertRaisesRegex(gate.Blocked,'AAA200_FULL_FAMILY_MEMBERSHIP'):
            self.review()
    def test_duplicate_id_fails(self):
        self.inventory['families']['AAA-200'][0]=self.inventory['families']['AAA-200'][1]
        with self.assertRaisesRegex(gate.Blocked,'AAA200_FULL_FAMILY_MEMBERSHIP'):
            self.review()
    def test_source_change_fails(self):
        with self.assertRaisesRegex(gate.Blocked,'AAA200_CATALOG_HASH_DRIFT'):
            gate.inspect(self.inventory,self.plan,catalog_raw=self.raw+b'x')
    def test_rule_mismatch_fails(self):
        self.inventory['rules']['AAA-200-A-001']['requirement']+='bogus'
        with self.assertRaisesRegex(gate.Blocked,'AAA200_RULE_SOURCE_DRIFT'):
            self.review()
    def test_wrong_phase_mapping_fails(self):
        self.inventory['rules']['AAA-200-A-001']['catalog_phase']='P8'
        with self.assertRaisesRegex(gate.Blocked,'AAA200_PRIVATE_CATALOG_DRIFT'):
            self.review()
    def test_wrong_asset_mapping_fails(self):
        self.inventory['rules']['AAA-200-A-001']['asset_type']='architecture'
        with self.assertRaisesRegex(gate.Blocked,'AAA200_PRIVATE_CATALOG_DRIFT'):
            self.review()
    def test_catalog_duplicate_number_fails(self):
        d=json.loads(self.raw);d['catalog'][1]['id']=1
        with self.assertRaisesRegex(gate.Blocked,'AAA200_CANONICAL_SEQUENCE'):
            gate.parse_catalog(json.dumps(d).encode())
    def test_catalog_duplicate_object_key_fails(self):
        with self.assertRaisesRegex(gate.Blocked,'AAA200_DUPLICATE_JSON_KEY'):
            gate.parse_catalog(b'{"schema":"a","schema":"b"}')
    def test_current_master_drift_fails(self):
        self.plan['master_sha256']='f'*64
        with self.assertRaisesRegex(gate.Blocked,'AAA200_TRUSTED_PLAN'):
            self.review()
    def test_partial_audit_context_fails(self):
        with self.assertRaisesRegex(gate.Blocked,'AAA200_ATTEMPT_AUDIT_BINDING_REQUIRED'):
            gate.inspect(self.inventory,self.plan,catalog_raw=self.raw,audit_raw=b'audit')
    def test_mg0_cannot_forge_pass(self):
        old=MG0.inspect;MG0.inspect=lambda *args:{'individual_rule_mg0':'PASS'}
        self.addCleanup(setattr,MG0,'inspect',old)
        with self.assertRaisesRegex(gate.Blocked,'AAA200_MG0_FALSE_PASS'):
            gate.inspect(self.inventory,self.plan,catalog_raw=self.raw,
                         master_raw=b'master',audit_raw=b'audit',
                         asset='TEST',attempt_id='a'*64)
    def test_observed_fail_and_mg0_fail_cannot_advance(self):
        old=MG0.inspect; old_audit=INTAKE.audit_check
        MG0.inspect=lambda *args:{'individual_rule_mg0':'FAIL' if args[4]=='AAA-200-A-001' else 'UNKNOWN'}
        INTAKE.audit_check=lambda raw,asset: ([{'rule_id':'AAA-200-A-001',
           'attempt_id':'a'*64,'event':'QUALITY_FINDING','result':'FAIL',
           'record_hash':'c'*64}], 'd'*64)
        self.addCleanup(setattr,MG0,'inspect',old)
        self.addCleanup(setattr,INTAKE,'audit_check',old_audit)
        r=gate.inspect(self.inventory,self.plan,catalog_raw=self.raw,
                       master_raw=b'master',audit_raw=b'audit',
                       asset='TEST',attempt_id='a'*64)
        self.assertEqual(r['observed_native_fail_rules'],['AAA-200-A-001'])
        self.assertEqual(r['observed_uncorrected_mg0_fail_rules'],['AAA-200-A-001'])
        self.assertFalse(r['advancement_authorized'])
    def test_stale_fail_different_attempt_not_current(self):
        old=INTAKE.audit_check
        INTAKE.audit_check=lambda raw,asset: ([{'rule_id':'AAA-200-A-001',
           'attempt_id':'b'*64,'result':'FAIL','record_hash':'c'*64}], 'd'*64)
        self.addCleanup(setattr,INTAKE,'audit_check',old)
        r=gate.inspect(self.inventory,self.plan,catalog_raw=self.raw,
                       master_raw=b'master',audit_raw=b'audit',
                       asset='TEST',attempt_id='a'*64)
        self.assertFalse(r['observed_native_fail_rules'])
        self.assertEqual(r['native_semantic_passes'],0)
    def test_reviewed_is_not_a_pass(self):
        reviewed={'AAA-200-A-001':('fixture',('criterion',))}
        self.plan['enrolled']['AAA-200-A-001']={'validator_id':'fixture'}
        r=gate.inspect(self.inventory,self.plan,catalog_raw=self.raw,reviewed=reviewed)
        self.assertEqual(len(r['missing_due_semantic_validators']),39)
        self.assertEqual(r['entries']['AAA-200-A-001']['semantic_result'],'UNKNOWN')
        self.assertFalse(r['advancement_authorized'])

if __name__=='__main__': unittest.main()
