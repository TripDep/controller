import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
from urllib.error import HTTPError
import git_judgment_origin as origin

REPO='Example/private'
WORKFLOW=b'  ref: '+b'c'*40+b'\n  run: tool --public-sha '+b'c'*40+b'\n  run: tool --public-sha '+b'c'*40+b'\n'
BLOB=hashlib.sha1(b'blob '+str(len(WORKFLOW)).encode()+b'\0'+WORKFLOW).hexdigest()

class API:
    repository=REPO
    def __init__(self):
        self.expected={'run_id':10,'job_id':20,'run_attempt':1,'workflow_head_sha':'a'*40,
                      'public_sha':'c'*40,'pr_number':24,'head_sha':'b'*40,'base_sha':'a'*40,'master_sha256':'d'*64}
        self.run={'id':10,'run_attempt':1,'head_sha':'a'*40,'head_branch':'main','status':'completed',
                  'conclusion':'success','event':'workflow_run','path':origin.WORKFLOW,'workflow_id':origin.WORKFLOW_ID,
                  'repository':{'full_name':REPO},'head_repository':{'full_name':REPO}}
        self.jobs={'total_count':1,'jobs':[{'id':20,'run_id':10,'head_sha':'a'*40,'name':'automatic-review',
            'status':'completed','conclusion':'success','steps':[{'name':'Check actual PR sources, checks and completed workflow provenance','status':'completed','conclusion':'success'}]}]}
        self.file={'type':'file','path':origin.WORKFLOW,'encoding':'base64','sha':BLOB,'content':base64.b64encode(WORKFLOW).decode()}
        self.pr={'number':24,'head':{'sha':'b'*40,'repo':{'full_name':REPO}},'base':{'sha':'a'*40,'repo':{'full_name':REPO}}}
        self.result={'status':'ROUTINE_PRECHECK_PASS_ONLY','pr_number':24,'pr_head_sha':'b'*40,'master_sha256':'d'*64,
            'public_controller_sha':origin.ACTION_PIN,'authority_mode':'PINNED_LIBRARY_SNAPSHOT',
            'merge_authorized':False,'broker_enabled':False,'library_live_read':False,'private_write_isolation_verified':False}
        self.changed_run=False;self.reads=0;self.extra_result=False;self.unstamped=False
    def call(self,method,route):
        assert method=='GET'
        if route=='/actions/runs/10':
            self.reads+=1;r=copy.deepcopy(self.run)
            if self.changed_run and self.reads>1:r['run_attempt']=2
            return r
        if route.endswith('/jobs?per_page=100'):return self.jobs
        if route.startswith('/contents/'):return self.file
        if route=='/pulls/24':return self.pr
        raise AssertionError(route)
    def job_logs(self,_id):
        line=('' if self.unstamped else '2026-10-13T14:00:00Z ')+json.dumps(self.result)
        return line+'\n'+line if self.extra_result else line

class OriginTests(unittest.TestCase):
    def setUp(self):
        self.repo=patch.object(origin,'PRIVATE_REPO_SHA',hashlib.sha256(REPO.encode()).hexdigest());self.repo.start();self.addCleanup(self.repo.stop)
        self.pins=patch.object(origin,'TRUSTED_ISSUERS',{BLOB:'c'*40});self.pins.start();self.addCleanup(self.pins.stop)
    def verify(self,api):return origin.verify_git_origin(api,api.expected)
    def test_authenticated_origin_keeps_work_gate_closed(self):
        r=self.verify(API());self.assertEqual(r['status'],'AUTHENTIC_GITHUB_PR_PRECHECK');self.assertFalse(r['advancement_authorized']);self.assertFalse(r['all_families_verified'])
    def test_self_submitted_pass_is_not_a_request(self):
        a=API();a.expected['result']='PASS'
        with self.assertRaises(origin.Blocked):self.verify(a)
    def test_wrong_run_workflow_event_or_attempt_is_denied(self):
        for field,value in [('id',11),('path','other.yml'),('event','pull_request'),('run_attempt',2),('conclusion','failure'),('head_sha','f'*40),('head_branch','feature')]:
            a=API();a.run[field]=value
            with self.assertRaises(origin.Blocked):self.verify(a)
    def test_cross_repository_run_is_denied(self):
        a=API();a.run['head_repository']['full_name']='Other/private'
        with self.assertRaises(origin.Blocked):self.verify(a)
    def test_wrong_or_pending_job_is_denied(self):
        for field,value in [('id',21),('run_id',11),('head_sha','f'*40),('status','in_progress'),('conclusion','failure')]:
            a=API();a.jobs['jobs'][0][field]=value
            with self.assertRaises(origin.Blocked):self.verify(a)
    def test_duplicate_or_incomplete_jobs_are_denied(self):
        a=API();a.jobs['total_count']=2
        with self.assertRaises(origin.Blocked):self.verify(a)
        a=API();a.jobs['jobs']*=2;a.jobs['total_count']=2
        with self.assertRaises(origin.Blocked):self.verify(a)
    def test_validator_step_required(self):
        a=API();a.jobs['jobs'][0]['steps']=[]
        with self.assertRaises(origin.Blocked):self.verify(a)
    def test_unenrolled_or_tampered_source_is_denied(self):
        a=API();a.file['sha']='f'*40
        with self.assertRaises(ValueError):self.verify(a)
        with patch.object(origin,'TRUSTED_ISSUERS',{}):
            with self.assertRaises(origin.Blocked):self.verify(API())
    def test_result_binding_and_false_scope_are_enforced(self):
        for field,value in [('pr_number',25),('pr_head_sha','f'*40),('master_sha256','f'*64),('merge_authorized',True),('library_live_read',True),('public_controller_sha','f'*40)]:
            a=API();a.result[field]=value
            with self.assertRaises(origin.Blocked):self.verify(a)
    def test_duplicate_or_unstamped_result_is_denied(self):
        for key in ('extra_result','unstamped'):
            a=API();setattr(a,key,True)
            with self.assertRaises(origin.Blocked):self.verify(a)
    def test_moved_pr_head_or_base_is_denied(self):
        for key in ('head','base'):
            a=API();a.pr[key]['sha']='f'*40
            with self.assertRaises(origin.Blocked):self.verify(a)
    def test_rerun_during_read_is_denied(self):
        a=API();a.changed_run=True
        with self.assertRaises(origin.Blocked):self.verify(a)
    def test_boolean_id_is_denied(self):
        a=API();a.expected['run_id']=True
        with self.assertRaises(origin.Blocked):self.verify(a)
    def test_pr_origin_can_never_authorize_work(self):
        with self.assertRaisesRegex(origin.Blocked,'PER_RULE_JUDGMENT'):origin.require_work_advancement(self.verify(API()))
    def test_log_storage_never_receives_bearer(self):
        response=MagicMock();response.read.return_value=b'log';response.__enter__.return_value=response
        redirect=HTTPError('https://api.github.com/x',302,'Found',{'Location':'https://productionresultssa1.blob.core.windows.net/log?sig=example'},None)
        with patch.object(origin.request,'build_opener') as factory:
            factory.return_value.open.side_effect=[redirect,response]
            self.assertEqual(origin.OriginAPI('x'*40,REPO).job_logs(20),'log')
            calls=factory.return_value.open.call_args_list
            self.assertTrue(calls[0].args[0].has_header('Authorization'))
            self.assertFalse(calls[1].args[0].has_header('Authorization'))
    def test_untrusted_log_redirect_host_is_denied(self):
        for url in ('http://productionresultssa1.blob.core.windows.net/log','https://evil.example/log','https://x@productionresultssa1.blob.core.windows.net/log'):
            redirect=HTTPError('https://api.github.com/x',302,'Found',{'Location':url},None)
            with patch.object(origin.request,'build_opener') as f:
                f.return_value.open.side_effect=redirect
                with self.assertRaises(origin.Blocked):origin.OriginAPI('x'*40,REPO).job_logs(20)
                self.assertEqual(f.return_value.open.call_count,1)
    def test_log_overflow_and_encoding_are_denied(self):
        for raw in (b'x'*(4*1024*1024+1),b'\xff'):
            response=MagicMock();response.read.return_value=raw;response.__enter__.return_value=response
            with patch.object(origin.request,'build_opener') as f:
                f.return_value.open.return_value=response
                with self.assertRaises(origin.Blocked):origin.OriginAPI('x'*40,REPO).job_logs(20)
    def test_second_redirect_is_denied(self):
        first=HTTPError('https://api.github.com/x',302,'Found',{'Location':'https://productionresultssa1.blob.core.windows.net/log'},None)
        second=HTTPError('https://productionresultssa1.blob.core.windows.net/log',302,'Found',{'Location':'https://evil.example'},None)
        with patch.object(origin.request,'build_opener') as f:
            f.return_value.open.side_effect=[first,second]
            with self.assertRaises(origin.Blocked):origin.OriginAPI('x'*40,REPO).job_logs(20)

if __name__=='__main__':unittest.main()
