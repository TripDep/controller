import copy,hashlib,json,unittest
from pathlib import Path
from unittest.mock import patch
import supervisor_judgment as j
import family_coverage as f
from test_rule_evidence import API,binding as old_binding
from test_supervisor_context import receipt,seal

def inventory():
    return {'canonical_master_sha256':'a'*64,'family_count':2,'rule_count':2,'families':{'EXECUTION':['EXEC-003'],'ASSET_PROFILE_READINESS':['PROFILE_FOLIAGE']},'rules':{'EXEC-003':{'family':'EXECUTION','source_sha256':'a'*64,'requirement_sha256':'b'*64},'PROFILE_FOLIAGE':{'family':'ASSET_PROFILE_READINESS','source_sha256':'a'*64,'requirement_sha256':'c'*64,'profile':'FOLIAGE_PROFILE'}}}
def work():
    return {'work_item_sha256':'a'*64,'attempt_id':'b'*64,'operation_sha256':'e'*64,'attempt_number':1,'previous_attempt_id':None,'phase':'P8','asset_type':'vegetation','profiles':['FOLIAGE_PROFILE'],'master_sha256':'a'*64,'work_dependencies':{'c'*64:'d'*64},'asset_specific_extensions_verified':True,'guardian_required':False,'mode':'DIAGNOSTIC_ONLY','closure_requested':False}
def contexts():return {'rescue':receipt(),'guardian':receipt('guardian')}
class FixtureBackend:
    synthetic=True
    def __init__(self,verdict='PASS'):self.verdict=verdict;self.rows={}
    def rule(self,r,expected,offer):return self.rows.get(r,{'result':self.verdict,'mg0':'PASS','semantic_scope':j.SEMANTIC_SCOPE,'proof_digest':'e'*64})
def judge(backend=None,w=None,inv=None,**kw):return j.judge(inv or inventory(),w or work(),{},backend or FixtureBackend(),current_contexts=kw.pop('current_contexts',contexts()),**kw)
class Tests(unittest.TestCase):
    def test_fixture_ready_never_authorizes(self):
        d=judge();self.assertTrue(d['phase_ready']);self.assertFalse(d['advancement_authorized']);self.assertEqual(d['counts']['PASS'],2)
    def test_fail_stops(self):self.assertEqual(judge(FixtureBackend('FAIL'))['action'],'STOP_CORRECT_RESUBMIT')
    def test_unknown_stops(self):self.assertFalse(judge(FixtureBackend('UNKNOWN'))['phase_ready'])
    def test_no_enrolled_validators_unknown(self):
        d=judge(j.NativeRuleBackend(API(),{}));self.assertEqual(d['counts']['UNKNOWN'],2);self.assertFalse(d['advancement_authorized'])
    def test_hash_linkage_not_semantic_pass(self):
        b=FixtureBackend();b.rows['EXEC-003']={'result':'PASS','mg0':'BINDING_CHECKED_NOT_MG0_PASS','semantic_scope':'GOVERNANCE_EVIDENCE_LINKAGE_TEST_ONLY','proof_digest':'e'*64}
        with self.assertRaisesRegex(j.Blocked,'NOT_A_SEMANTIC_MG0_PASS'):judge(b)
    def test_missing_family_source_inventory(self):
        i=inventory();i['families'].pop('EXECUTION')
        with self.assertRaisesRegex(j.Blocked,'INVENTORY_INCOMPLETE'):judge(inv=i)
    def test_duplicate_rule_inventory(self):
        i=inventory();i['families']['EXECUTION'].append('PROFILE_FOLIAGE')
        with self.assertRaises(j.Blocked):judge(inv=i)
    def test_unknown_offer_rule(self):
        with self.assertRaisesRegex(j.Blocked,'UNKNOWN_RULE_IDS'):j.judge(inventory(),work(),{'FAKE':{}},FixtureBackend(),current_contexts=contexts())
    def test_current_dependency_changed(self):
        c=contexts();c['rescue']['dependencies']['c'*64]='0'*64;seal(c['rescue']);self.assertEqual(judge(current_contexts=c)['action'],'STOP_CONTEXT_RECHECK')
    def test_unrelated_context_change_does_not_restart(self):
        old=contexts();c=copy.deepcopy(old);c['rescue']['observed_at']='2020-10-13T19:00:00+00:00';c['rescue']['dependencies']['e'*64]='0'*64;seal(c['rescue']);self.assertTrue(judge(current_contexts=c,previous_contexts=old)['phase_ready'])
    def test_guardian_required_unverified(self):
        w=work();w['guardian_required']=True;self.assertFalse(judge(w=w)['phase_ready'])
    def test_asset_extensions_not_verified(self):
        w=work();w['asset_specific_extensions_verified']=False;self.assertFalse(judge(w=w)['phase_ready'])
    def test_correction_needs_real_prior_failure(self):
        w=work();w['attempt_number']=2;w['previous_attempt_id']='f'*64;self.assertFalse(judge(w=w)['phase_ready'])
        prior={'work_item_sha256':w['work_item_sha256'],'attempt_id':w['previous_attempt_id'],'attempt_number':1,'action':'STOP_CORRECT_RESUBMIT'};self.assertTrue(judge(w=w,previous_decision=prior)['phase_ready'])
    def test_future_phase_not_closure(self):
        i=inventory();i['rules']['EXEC-003'].update(catalog_phase='P8',asset_type='all');w=work();w['phase']='P0';d=judge(w=w,inv=i);self.assertEqual(d['counts']['FUTURE_PHASE'],1);self.assertFalse(d['closure_ready'])
        w['closure_requested']=True;self.assertFalse(judge(w=w,inv=i)['phase_ready'])
    def test_na_remains_visible(self):
        i=inventory();i['rules']['EXEC-003'].update(catalog_phase='P0',asset_type='architecture');d=judge(inv=i);self.assertEqual(d['rule_count'],2);self.assertEqual(d['counts']['N_A'],1)
    def test_native_consumer_denies_fixture_backend(self):
        with self.assertRaisesRegex(j.Blocked,'TRUSTED_BACKEND_REQUIRED'):j.consume_native(API(),{}, {},inventory(),work(),{},FixtureBackend(),contexts(),'e'*64,set())
    def test_stop_cannot_be_consumed(self):
        d=judge(FixtureBackend('UNKNOWN'))
        with self.assertRaisesRegex(j.Blocked,'ADVANCEMENT_DENIED'):j._consume_checked(d,d,work(),'e'*64,set())
    def test_operation_replay(self):
        with self.assertRaisesRegex(j.Blocked,'OPERATION_REPLAY'):j._consume_checked({}, {},work(),'e'*64,{'e'*64})
    def test_wrong_operation(self):
        with self.assertRaisesRegex(j.Blocked,'WRONG_OPERATION'):j._consume_checked({}, {},work(),'f'*64,set())
    def test_enrolled_native_rule_backend(self):
        a=API();b=j.binding(work(),inventory()['rules']['EXEC-003'],'EXEC-003');p={'schema':'gg-semantic-rule-v1','scope':j.SEMANTIC_SCOPE,'validator_id':'unit','binding':b,'rule':{'result':'PASS','checks':{'clause':True},'proof_digest':'e'*64},'mg0':{'binding':copy.deepcopy(b),'triggered':False,'result':'PASS','checks':{'canonical_triggers_checked':True},'proof_digest':'f'*64}}
        a.jobs['jobs'][0]['steps'][0]['name']=j.SEMANTIC_STEP
        a.job_logs=lambda _: '2020-10-13T18:00:00Z '+j.PREFIX+json.dumps(p)
        spec={'validator_id':'unit','criteria':['clause'],'requirement_sha256':b['requirement_sha256'],'issuer':a.issuer}
        r=j.NativeRuleBackend(a,{'EXEC-003':spec}).rule('EXEC-003',b,{'native_origin':a.origin,'expected_packet_sha256':j.digest(p)});self.assertEqual(r['result'],'PASS')
        p['mg0']['binding']['rule_id']='other';r=j.NativeRuleBackend(a,{'EXEC-003':spec}).rule('EXEC-003',b,{'native_origin':a.origin,'expected_packet_sha256':j.digest(p)});self.assertEqual(r['result'],'UNKNOWN')
    def test_semantic_criteria_and_mg0(self):
        b=j.binding(work(),inventory()['rules']['EXEC-003'],'EXEC-003');p={'schema':'gg-semantic-rule-v1','scope':j.SEMANTIC_SCOPE,'validator_id':'unit','binding':b,'rule':{'result':'PASS','checks':{'clause':True},'proof_digest':'e'*64},'mg0':{'binding':copy.deepcopy(b),'triggered':False,'result':'PASS','checks':{'canonical_triggers_checked':True},'proof_digest':'f'*64}}
        spec={'validator_id':'unit','criteria':['clause']};self.assertEqual(j.semantic_packet(p,b,spec)['result'],'PASS');p['rule']['checks']['clause']=False;self.assertEqual(j.semantic_packet(p,b,spec)['result'],'FAIL')
    def test_triggered_mg0_requires_process_correction(self):
        b=j.binding(work(),inventory()['rules']['EXEC-003'],'EXEC-003');p={'schema':'gg-semantic-rule-v1','scope':j.SEMANTIC_SCOPE,'validator_id':'unit','binding':b,'rule':{'result':'PASS','checks':{'clause':True},'proof_digest':'e'*64},'mg0':{'binding':b,'triggered':True,'result':'PASS','checks':{'canonical_triggers_checked':True},'proof_digest':'f'*64}}
        with self.assertRaisesRegex(j.Blocked,'MG0_REQUIRED_CHECKS'):j.semantic_packet(p,b,{'validator_id':'unit','criteria':['clause']})
    def test_future_and_nonapplicable_retained_without_premature_semantic_mg0(self):
        i=inventory()
        i['rules']['EXEC-003'].update(catalog_phase='P8',asset_type='all')
        w=work();w['phase']='P0'
        class Backend(FixtureBackend):
            def __init__(self):super().__init__('PASS');self.called=[]
            def rule(self,r,expected,offer):self.called.append(r);return super().rule(r,expected,offer)
        b=Backend();d=judge(backend=b,w=w,inv=i)
        self.assertEqual(b.called,['PROFILE_FOLIAGE'])
        self.assertEqual(d['counts']['FUTURE_PHASE'],1)
        self.assertEqual(d['counts']['PASS'],1)
        entry=d['families']['EXECUTION']['EXEC-003']
        self.assertEqual(entry['result'],'FUTURE_PHASE')
        self.assertEqual(entry['mg0'],'NOT_DUE_NO_CURRENT_RULE_PASS')
        self.assertEqual(entry['applicability_basis']['canonical_phase'],'P8')
        self.assertEqual(entry['applicability_basis']['binding']['requirement_sha256'],'b'*64)
        self.assertTrue(d['phase_ready'])
        self.assertFalse(d['advancement_authorized']) # Fixture cannot authorize.

    def test_na_rule_kept_and_missing_applicable_evidence_still_blocks(self):
        i=inventory()
        i['rules']['EXEC-003'].update(catalog_phase='P0',asset_type='architecture')
        d=judge(j.NativeRuleBackend(API(),{}),inv=i)
        self.assertEqual(d['counts']['N_A'],1)
        self.assertEqual(d['counts']['UNKNOWN'],1)
        self.assertEqual(d['families']['EXECUTION']['EXEC-003']['mg0'],'NOT_DUE_NO_CURRENT_RULE_PASS')
        self.assertEqual(d['families']['ASSET_PROFILE_READINESS']['PROFILE_FOLIAGE']['result'],'UNKNOWN')
        self.assertFalse(d['advancement_authorized'])

    def test_no_current_applicable_semantic_pass_never_advances(self):
        i=inventory()
        i['rules']['EXEC-003'].update(catalog_phase='P8',asset_type='all')
        i['rules']['PROFILE_FOLIAGE'].update(catalog_phase='P8',asset_type='all')
        w=work();w['phase']='P0'
        d=judge(backend=FixtureBackend(),w=w,inv=i)
        self.assertEqual(d['counts']['FUTURE_PHASE'],2)
        self.assertEqual(d['counts']['PASS'],0)
        self.assertIn('NO_APPLICABLE_RULE_SEMANTIC_PASS',d['blockers'])
        self.assertFalse(d['phase_ready'])

    def test_synthetic_full_inventory_all_ids_retained(self):
        from test_family_coverage import synthetic_sources
        raw=synthetic_sources()
        with patch.object(f,'AUX_PINS',{k:f.sha(raw[k]) for k in f.AUX_PINS}):inv=f.build_inventory(raw,f.sha(raw['master']))
        w=work();w['master_sha256']=inv['canonical_master_sha256'];c=contexts()
        for role in c:c[role]['master']['sha256']=w['master_sha256'];seal(c[role])
        d=j.judge(inv,w,{},j.NativeRuleBackend(API(),{}),current_contexts=c);self.assertEqual(d['rule_count'],inv['rule_count']);self.assertEqual(sum(d['counts'].values()),inv['rule_count']);self.assertEqual(d['counts']['PASS'],0);self.assertGreater(d['counts']['UNKNOWN'],0);self.assertFalse(d['advancement_authorized'])
if __name__=='__main__':unittest.main()
