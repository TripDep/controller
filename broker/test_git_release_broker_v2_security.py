"""Proof that the integrated broker refuses spoofed green checks and workflow changes."""
from datetime import datetime,timezone,timedelta
from pathlib import Path
from unittest.mock import patch
import copy
import hashlib
import unittest

import git_release_broker_v2 as broker
import test_git_release_broker_v2 as base_tests
TEST_REPO = base_tests.TEST_REPO
from test_workflow_provenance_gate import FakeAPI, HEAD, ID, NAMES, check, job, RUN, REPO

class IntegratedSecurityTests(unittest.TestCase):
    def setUp(self):
        sample=base_tests.SyntheticBrokerTests(methodName='test_valid_synthetic_snapshot')
        sample.setUp()
        self.t=sample
        self.api=FakeAPI()
        self.api.run['head_repository']['full_name']=TEST_REPO
        self.api.run['head_sha']=sample.head
        self.api.jobs['jobs']=[job(i,n) for i,n in zip(ID,NAMES)]
        self.api.jobs['total_count']=3
        for j in self.api.jobs['jobs']:
            j['check_run_url']=f'https://api.github.com/repos/{TEST_REPO}/check-runs/{j["id"]}'
            j['html_url']=f'https://github.com/{TEST_REPO}/actions/runs/{RUN}/job/{j["id"]}'
        self.api.run['pull_requests']=[{'number':sample.auth['pr_number']}]
        self.pr=copy.deepcopy(sample.pr)
        self.pr['changed_files']=1
        self.checks={'total_count':3,'check_runs':[check(i,n) for i,n in zip(ID,NAMES)]}
        for c in self.checks['check_runs']:
            c['details_url']=f'https://github.com/{TEST_REPO}/actions/runs/{RUN}/job/{c["id"]}'
        self.api.merge_calls=[]
        self.api.snapshot=lambda n,h:(self.pr,sample.branch,sample.files,self.checks)
        def fake_call(method, path):
            if method!='GET':raise AssertionError('Non-read-only unexpected')
            self.api.calls.append((method,path))
            if path==f'/actions/runs/{RUN}':return copy.deepcopy(self.api.run)
            if path==f'/actions/runs/{RUN}/jobs?per_page=100':return copy.deepcopy(self.api.jobs)
            raise AssertionError('Wrong API path: '+path)
        self.api.call=fake_call
        self.api.merge=lambda n,h:self.api.merge_calls.append((n,h)) or {'merged':True,'sha':'f'*40}

    def verify_merge(self):
        with patch.object(broker,'verify_owner_signature',return_value=True):
            return broker.approve_and_merge(self.t.policy,self.t.auth,b'fake','synthetic-public.pem',self.api)

    def test_valid_3_jobs_and_workflow_merge_mock_only(self):
        self.assertEqual(self.verify_merge()['status'],'MERGED')
        self.assertEqual(self.api.merge_calls,[(19,'a'*40)])

    def test_fake_named_job_does_not_merge(self):
        self.api.run['path']='.github/workflows/fake-green.yml'
        with self.assertRaisesRegex(broker.Blocked,'TRUSTED_ACTIONS_PROVENANCE_FAILED'):
            self.verify_merge()
        self.assertEqual(self.api.merge_calls,[])

    def test_workflow_mutation_blocks(self):
        self.t.files[:]=[{'filename':'.github/workflows/gg-phase-guard.yml'}]
        with self.assertRaisesRegex(broker.Blocked,'WORKFLOW_OR_GITHUB_POLICY_MUTATION_FORBIDDEN'):
            self.verify_merge()
        self.assertEqual(self.api.merge_calls,[])

    def test_workflow_renamed_blocks(self):
        self.t.files[:]=[{'filename':'governance/safe.py','previous_filename':'.github/workflows/gg-phase-guard.yml'}]
        with self.assertRaisesRegex(broker.Blocked,'WORKFLOW_OR_GITHUB_POLICY_MUTATION_FORBIDDEN'):
            self.verify_merge()
        self.assertEqual(self.api.merge_calls,[])

    def test_legitimate_job_provenance_but_wrong_pr_blocks(self):
        self.api.run['pull_requests']=[{'number':20}]
        with self.assertRaisesRegex(broker.Blocked,'WORKFLOW_RUN_PR_MISMATCH'):
            self.verify_merge()
        self.assertEqual(self.api.merge_calls,[])

    def test_alternative_green_check_from_other_run_blocks(self):
        self.checks['check_runs'][2]['details_url']=f'https://github.com/{TEST_REPO}/actions/runs/{RUN+1}/job/{ID[2]}'
        with self.assertRaisesRegex(broker.Blocked,'CHECKS_FROM_MULTIPLE_RUNS'):
            self.verify_merge()
        self.assertEqual(self.api.merge_calls,[])

if __name__=='__main__':unittest.main(verbosity=2)
