import base64,copy,hashlib,json,unittest
from unittest.mock import patch
import rule_evidence as e

REPO='TripDep/SERVE-PER-FARTI-LAVORARE-';PUBLIC='b'*40
SOURCE=('  ref: '+PUBLIC+'\n').encode();BLOB=hashlib.sha1(b'blob '+str(len(SOURCE)).encode()+b'\0'+SOURCE).hexdigest()
def binding():
    b={k:'a'*64 for k in ('work_item_sha256','attempt_id','master_sha256','source_sha256','requirement_sha256','rescue_observation_id','guardian_observation_id')}
    b.update(attempt_number=1,previous_attempt_id=None,phase='VERIFY',family='EXECUTION',rule_id='EXEC-003',work_dependencies={'c'*64:'d'*64},context_scope=e.SCOPE);return b
def packet():
    b=binding();obs=[{'scope':'SYNTHETIC_UNIT_FIXTURE'}];mg={'scope':'SYNTHETIC_UNIT_FIXTURE'}
    return {'schema':'gg-bound-rule-evidence-v1','scope':e.SCOPE,'binding':b,'evidence':{'kind':'NATIVE_CONTEXT_TRANSPORT_TEST','result':'LINKAGE_CHECKED_ONLY','content_sha256':e.digest(obs),'observations':obs,'native_origin':{'run_id':10}},'mg0':{'binding':copy.deepcopy(b),'kind':'INDIVIDUAL_PROCESS_PROOF_BINDING','result':'BINDING_CHECKED_NOT_MG0_PASS','trigger_assessment':mg,'content_sha256':e.digest(mg)},'advancement_authorized':False}
class API:
    repository=REPO
    def __init__(self):
        self.origin={'run_id':10,'job_id':20,'run_attempt':1,'head_sha':'a'*40};self.issuer={'workflow_blob':BLOB,'public_sha':PUBLIC};self.payload=packet();self.duplicate=False;self.changed=False;self.reads=0
        self.run={'id':10,'run_attempt':1,'head_sha':'a'*40,'head_branch':'main','status':'completed','conclusion':'success','event':'workflow_run','path':e.WORKFLOW,'workflow_id':e.WORKFLOW_ID,'repository':{'full_name':REPO},'head_repository':{'full_name':REPO}}
        self.jobs={'total_count':1,'jobs':[{'id':20,'run_id':10,'head_sha':'a'*40,'name':'automatic-review','status':'completed','conclusion':'success','steps':[{'name':e.EMIT_STEP,'status':'completed','conclusion':'success'}]}]}
    def call(self,method,path):
        assert method=='GET'
        if path=='/actions/runs/10':
            self.reads+=1;r=copy.deepcopy(self.run)
            if self.changed and self.reads>1:r['run_attempt']=2
            return r
        if path.endswith('/jobs?per_page=100'):return self.jobs
        if path.startswith('/contents/'):
            return {'type':'file','path':e.WORKFLOW,'encoding':'base64','content':base64.b64encode(SOURCE).decode(),'sha':BLOB}
        raise AssertionError(path)
    def job_logs(self,_):
        l='2020-10-13T18:00:00Z '+e.PREFIX+json.dumps(self.payload)
        return l+'\n'+l if self.duplicate else l
class Tests(unittest.TestCase):
    def verify(self,a):return e.verify(a,a.origin,a.issuer,binding())
    def test_native_content_and_binding(self):
        r=self.verify(API());self.assertTrue(r['native_content_retrieved']);self.assertFalse(r['advancement_authorized']);self.assertFalse(r['mg0_execution_pass'])
    def test_self_reported_pass_rejected(self):
        a=API();a.payload['result']='PASS'
        with self.assertRaisesRegex(e.Blocked,'PACKET_SCHEMA'):self.verify(a)
    def test_all_attempt_context_fields_bound(self):
        for field,value in [('work_item_sha256','b'*64),('attempt_id','b'*64),('phase','P2'),('rule_id','AAA-001'),('family','AAA-200'),('source_sha256','b'*64),('requirement_sha256','b'*64),('master_sha256','b'*64),('rescue_observation_id','b'*64),('guardian_observation_id','b'*64),('work_dependencies',{'c'*64:'f'*64})]:
            a=API();a.payload['binding'][field]=value
            with self.assertRaisesRegex(e.Blocked,'ATTEMPT_OR_CONTEXT_MISMATCH'):self.verify(a)
    def test_missing_rule_evidence(self):
        a=API();a.payload.pop('evidence')
        with self.assertRaises(e.Blocked):self.verify(a)
    def test_missing_mg0(self):
        a=API();a.payload.pop('mg0')
        with self.assertRaises(e.Blocked):self.verify(a)
    def test_mg0_other_rule(self):
        a=API();a.payload['mg0']['binding']['rule_id']='MG0'
        with self.assertRaisesRegex(e.Blocked,'MG0_BINDING'):self.verify(a)
    def test_mg0_pass_injection(self):
        a=API();a.payload['mg0']['result']='PASS'
        with self.assertRaisesRegex(e.Blocked,'MG0_BINDING'):self.verify(a)
    def test_proof_contents_tampered(self):
        a=API();a.payload['evidence']['observations'][0]['scope']='changed'
        with self.assertRaisesRegex(e.Blocked,'CONTENT_DIGEST'):self.verify(a)
    def test_mg0_contents_tampered(self):
        a=API();a.payload['mg0']['trigger_assessment']['scope']='changed'
        with self.assertRaisesRegex(e.Blocked,'MG0_CONTENT'):self.verify(a)
    def test_duplicate_result(self):
        a=API();a.duplicate=True
        with self.assertRaisesRegex(e.Blocked,'RESULT_NOT_UNIQUE'):self.verify(a)
    def test_wrong_run_attempt_or_head(self):
        for field,value in [('run_attempt',2),('head_sha','f'*40),('head_branch','feature'),('event','pull_request'),('conclusion','failure')]:
            a=API();a.run[field]=value
            with self.assertRaises(e.Blocked):self.verify(a)
    def test_cross_repository(self):
        a=API();a.run['head_repository']['full_name']='other/private'
        with self.assertRaisesRegex(e.Blocked,'CROSS_REPO'):self.verify(a)
    def test_wrong_job(self):
        a=API();a.jobs['jobs'][0]['id']=21
        with self.assertRaises(e.Blocked):self.verify(a)
    def test_pending_step(self):
        a=API();a.jobs['jobs'][0]['steps'][0]['conclusion']='skipped'
        with self.assertRaisesRegex(e.Blocked,'EVIDENCE_STEP'):self.verify(a)
    def test_unenrolled_workflow(self):
        a=API();a.issuer['workflow_blob']='f'*40
        with self.assertRaisesRegex(e.Blocked,'UNENROLLED_ISSUER'):self.verify(a)
    def test_source_pin_changed(self):
        a=API();a.issuer['public_sha']='f'*40
        with self.assertRaisesRegex(e.Blocked,'PUBLIC_PIN'):self.verify(a)
    def test_rerun_during_read(self):
        a=API();a.changed=True
        with self.assertRaisesRegex(e.Blocked,'RUN_CHANGED'):self.verify(a)
    def test_job_page_missing(self):
        a=API();a.jobs['total_count']=2
        with self.assertRaisesRegex(e.Blocked,'JOB_PAGE'):self.verify(a)
    def test_bool_native_id(self):
        a=API();a.origin['run_id']=True
        with self.assertRaisesRegex(e.Blocked,'NATIVE_ID'):self.verify(a)
    def test_correction_chain_required(self):
        b=binding();b['attempt_number']=2
        with self.assertRaisesRegex(e.Blocked,'CORRECTION_CHAIN'):e.binding(b)
        b['previous_attempt_id']='f'*64;e.binding(b)
    def test_empty_dependencies_not_waiver(self):
        b=binding();b['work_dependencies']={}
        with self.assertRaisesRegex(e.Blocked,'DEPENDENCY_BINDINGS'):e.binding(b)
    def test_asset_scope_not_enrolled(self):
        b=binding();b['context_scope']='ASSET_PASS'
        with self.assertRaisesRegex(e.Blocked,'SCOPE_NOT_ENROLLED'):e.binding(b)
    def test_no_hash_only_input(self):
        with self.assertRaises(e.Blocked):e.validate_packet({'sha256':'a'*64},binding())
if __name__=='__main__':unittest.main()
