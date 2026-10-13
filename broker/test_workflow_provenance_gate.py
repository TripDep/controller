"""Synthetic-only workflow provenance checks; no token, network, credentials, or merge."""
import copy
import unittest
from workflow_provenance_gate import (Blocked, checked_same_trusted_run,
                                     prohibit_workflow_mutations, parse_check_job_url)

REPO = 'ExampleOrg/synthetic-private'
HEAD = 'a' * 40
RUN = 123456789
ID = (987650001,987650002,987650003)
NAMES = ('guard-tests','phase-guard','public-controller')


def check(i,name):
    return {'id':i,'name':name,'head_sha':HEAD,'status':'completed','conclusion':'success',
            'app':{'slug':'github-actions'},
            'details_url':f'https://github.com/{REPO}/actions/runs/{RUN}/job/{i}'}


def job(i,name):
    return {'id':i,'run_id':RUN,'name':name,'status':'completed','conclusion':'success',
            'check_run_url':f'https://api.github.com/repos/{REPO}/check-runs/{i}',
            'html_url':f'https://github.com/{REPO}/actions/runs/{RUN}/job/{i}'}


class FakeAPI:
    def __init__(self):
        self.calls=[]
        self.run={'id':RUN,'path':'.github/workflows/gg-phase-guard.yml',
                  'event':'pull_request','head_sha':HEAD,'status':'completed',
                  'conclusion':'success','head_repository':{'full_name':REPO},
                  'pull_requests':[{'number':19}]}
        self.jobs={'total_count':3,'jobs':[job(i,n) for i,n in zip(ID,NAMES)]}

    def call(self, method, path):
        self.calls.append((method,path))
        if method != 'GET':
            raise AssertionError('MUTATION_FORBIDDEN_IN_TEST')
        if path == f'/actions/runs/{RUN}': return copy.deepcopy(self.run)
        if path == f'/actions/runs/{RUN}/jobs?per_page=100': return copy.deepcopy(self.jobs)
        raise AssertionError('Unexpected URL '+path)


class WorkflowProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.api=FakeAPI()
        self.checks={'total_count':3,'check_runs':[check(i,n) for i,n in zip(ID,NAMES)]}

    def check_ok(self):
        return checked_same_trusted_run(self.api,REPO,HEAD,19,self.checks)

    def blocked(self, code):
        with self.assertRaisesRegex(Blocked,code): self.check_ok()

    def test_good_complete_provenance(self):
        self.assertTrue(self.check_ok())
        self.assertEqual(self.api.calls,[('GET',f'/actions/runs/{RUN}'),('GET',f'/actions/runs/{RUN}/jobs?per_page=100')])
    def test_fake_pass_from_different_run(self):
        self.checks['check_runs'][0]['details_url']=f'https://github.com/{REPO}/actions/runs/99/job/{ID[0]}'
        self.blocked('CHECKS_FROM_MULTIPLE_RUNS')
    def test_check_name_spoofed_different_job(self):
        self.api.jobs['jobs'][0]['name']='fake-status'
        self.blocked('WORKFLOW_JOB_NOT_TRUSTED')
    def test_wrong_workflow_path(self):
        self.api.run['path']='.github/workflows/attacker.yml'
        self.blocked('WORKFLOW_RUN_NOT_TRUSTED')
    def test_untrusted_fork_repository(self):
        self.api.run['head_repository']['full_name']='bad/fork'
        self.blocked('WORKFLOW_RUN_NOT_TRUSTED')
    def test_untrusted_push_event(self):
        self.api.run['event']='push'
        self.blocked('WORKFLOW_RUN_NOT_TRUSTED')
    def test_rerun_on_different_head(self):
        self.api.run['head_sha']='f'*40
        self.blocked('WORKFLOW_RUN_NOT_TRUSTED')
    def test_wrong_pr_number(self):
        self.api.run['pull_requests']=[{'number':99}]
        self.blocked('WORKFLOW_RUN_PR_MISMATCH')
    def test_job_id_mismatch(self):
        self.checks['check_runs'][0]['id']=198
        self.blocked('JOB_CHECK_RUN_ID_MISMATCH')
    def test_duplicate_check_blocked(self):
        self.checks['check_runs'].append(copy.deepcopy(self.checks['check_runs'][0]));self.checks['total_count']=4
        self.blocked('CHECK_MISSING_OR_DUPLICATE')
    def test_partial_check_page_blocked(self):
        self.checks['total_count']=4
        self.blocked('PROVENANCE_PAGINATION_INCOMPLETE')
    def test_partial_jobs_page_blocked(self):
        self.api.jobs['total_count']=4
        self.blocked('PROVENANCE_PAGINATION_INCOMPLETE')
    def test_failed_job_blocked_despite_status_green(self):
        self.api.jobs['jobs'][1]['conclusion']='failure'
        self.blocked('WORKFLOW_JOB_NOT_TRUSTED')
    def test_job_wrong_parent_run(self):
        self.api.jobs['jobs'][1]['run_id']=RUN+1
        self.blocked('WORKFLOW_JOB_NOT_TRUSTED')
    def test_job_different_details_url(self):
        self.api.jobs['jobs'][2]['html_url']='https://github.com/ExampleOrg/other/actions/runs/123/job/5'
        self.blocked('WORKFLOW_JOB_DETAILS_MISMATCH')
    def test_run_not_finished(self):
        self.api.run['status']='in_progress'
        self.blocked('WORKFLOW_RUN_NOT_TRUSTED')
    def test_malicious_url_rejected(self):
        for url in [f'https://evil.com/{REPO}/actions/runs/1/job/2',
                    f'https://github.com.evil.com/{REPO}/actions/runs/1/job/2',
                    f'https://github.com/{REPO}/actions/runs/1/job/2?x=1',
                    f'https://github.com/{REPO}/actions/runs/1/job/2#x',
                    f'http://github.com/{REPO}/actions/runs/1/job/2']:
            with self.subTest(url=url),self.assertRaises(Blocked):parse_check_job_url(url,REPO)
    def test_prohibit_github_workflow_changes(self):
        for name in ['.github/workflows/gg-phase-guard.yml','.github/CODEOWNERS','.github/other', '.github']:
            with self.subTest(name=name),self.assertRaisesRegex(Blocked,'WORKFLOW_OR_GITHUB_POLICY_MUTATION_FORBIDDEN'):
                prohibit_workflow_mutations([{'filename':name}])
    def test_prohibit_workflow_rename_from_github(self):
        with self.assertRaisesRegex(Blocked,'WORKFLOW_OR_GITHUB_POLICY_MUTATION_FORBIDDEN'):
            prohibit_workflow_mutations([{'filename':'governance/new.py','previous_filename':'.github/workflows/old.yml'}])
    def test_governance_only_still_allowed(self):
        self.assertTrue(prohibit_workflow_mutations([{'filename':'governance/guard.py'}]))

if __name__=='__main__':unittest.main(verbosity=2)
