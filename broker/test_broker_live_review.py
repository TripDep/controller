import base64
import copy
import hashlib
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
import broker_live_review as live

def file_record(raw=b'hello',path='source'):
    return {'type':'file','path':path,'encoding':'base64','content':base64.b64encode(raw).decode(),
            'sha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def event():
    return {'workflow_run':{'name':'Golden Garden mandatory phase guard','path':live.WORKFLOW,
        'status':'completed','conclusion':'success','repository':{'full_name':'Org/Repo'},
        'head_repository':{'full_name':'Org/Repo'},'event':'pull_request','pull_requests':[{'number':19}]}}

class LiveReviewTests(unittest.TestCase):
    def test_large_json_is_not_truncated(self):
        import json
        payload={'content':'x'*800000}
        response=MagicMock();response.read.return_value=json.dumps(payload).encode()
        response.__enter__.return_value=response
        with patch.object(live.request,'build_opener') as opener:
            opener.return_value.open.return_value=response
            self.assertEqual(live.ReadOnlyAPI('x'*40,'Org/Repo').call('GET','/contents/master'),payload)
            response.read.assert_called_once_with(live.MAX_RESPONSE+1)
    def test_response_overflow_is_denied(self):
        response=MagicMock();response.read.return_value=b'x'*(live.MAX_RESPONSE+1)
        response.__enter__.return_value=response
        with patch.object(live.request,'build_opener') as opener:
            opener.return_value.open.return_value=response
            with self.assertRaisesRegex(live.auto.Blocked,'RESPONSE_TOO_LARGE'):
                live.ReadOnlyAPI('x'*40,'Org/Repo').call('GET','/contents/master')
    def test_redirects_are_denied(self):
        with self.assertRaisesRegex(live.auto.Blocked,'REDIRECT_FORBIDDEN'):
            live.NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_writes_never_reach_network(self):
        api=live.ReadOnlyAPI('x'*40,'Org/Repo')
        with patch.object(live.base.GitHubAPI,'call') as network:
            for method in ('POST','PUT','PATCH','DELETE'):
                with self.assertRaisesRegex(live.auto.Blocked,'WRITE_FORBIDDEN'):api.call(method,'/pulls/19')
            network.assert_not_called()
    def test_merge_never_reaches_network(self):
        with self.assertRaisesRegex(live.auto.Blocked,'MERGE_FORBIDDEN'):live.ReadOnlyAPI('x'*40,'Org/Repo').merge(19,'a'*40)
    def test_untrusted_routes_rejected(self):
        api=live.ReadOnlyAPI('x'*40,'Org/Repo')
        for route in ('https://evil.test','/x/../y','/x\nAuthorization: fake'):
            with self.assertRaises(live.auto.Blocked):api.call('GET',route)
    def test_source_bytes_and_blob_verified(self):
        self.assertEqual(live.decode_file(file_record(),'source'),b'hello')
    def test_tampered_blob_rejected(self):
        value=file_record();value['sha']='a'*40
        with self.assertRaisesRegex(live.auto.Blocked,'BLOB_MISMATCH'):live.decode_file(value,'source')
    def test_wrong_source_record_rejected(self):
        for field,value in [('path','other'),('type','symlink'),('encoding','utf8')]:
            row=file_record();row[field]=value
            with self.assertRaises(live.auto.Blocked):live.decode_file(row,'source')
    def test_bad_base64_rejected(self):
        value=file_record();value['content']='!!!'
        with self.assertRaises(live.auto.Blocked):live.decode_file(value,'source')
    def test_unique_immutable_workflow_pin(self):
        raw=b'      - name: Controller\n        uses: TripDep/controller@'+b'a'*40+b'\n'
        self.assertEqual(live.workflow_pin(raw),'a'*40)
        with self.assertRaises(live.auto.Blocked):live.workflow_pin(raw+raw)
        with self.assertRaises(live.auto.Blocked):live.workflow_pin(b'uses: TripDep/controller@main')
    def test_real_upstream_identity_required(self):
        self.assertEqual(live.event_pr_numbers(event(),'Org/Repo'),[19])
        for field,value in [('path','untrusted.yml'),('conclusion','failure'),('status','in_progress')]:
            e=event();e['workflow_run'][field]=value
            with self.assertRaises(live.auto.Blocked):live.event_pr_numbers(e,'Org/Repo')
    def test_cross_repo_upstream_rejected(self):
        e=event();e['workflow_run']['head_repository']['full_name']='Other/Repo'
        with self.assertRaises(live.auto.Blocked):live.event_pr_numbers(e,'Org/Repo')
    def test_ambiguous_or_boolean_pr_rejected(self):
        for rows in ([],[{'number':True}],[{'number':19},{'number':20}]):
            e=event();e['workflow_run']['pull_requests']=rows
            with self.assertRaises(live.auto.Blocked):live.event_pr_numbers(e,'Org/Repo')
    def test_push_is_no_authorization(self):
        e=event();e['workflow_run']['event']='push'
        self.assertEqual(live.event_pr_numbers(e,'Org/Repo'),[])

if __name__=='__main__':unittest.main()
