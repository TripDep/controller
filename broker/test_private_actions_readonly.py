"""Pure synthetic suite for read-only installation/Actions metadata proof."""
import hashlib
import os
import unittest
from unittest.mock import patch
import verify_private_actions_readonly as p

SYNTHETIC = 'SyntheticOrg/fake-private-repo'
class ActionReadonlyTests(unittest.TestCase):
    def setUp(self):
        self.repo={'total_count':1,'repositories':[{'private':True,'full_name':SYNTHETIC}]}
        self.actions={'id':23,'path':p.WORKFLOW,'state':'active'}
        self.blob={'type':'file','path':p.WORKFLOW,'sha':p.EXPECTED_BLOB}

    def test_single_repo_hash_matches(self):
        with patch.object(p,'TARGET_SHA256',hashlib.sha256(SYNTHETIC.encode()).hexdigest()):
            self.assertEqual(p.validate_installation(self.repo),SYNTHETIC)
    def test_wrong_repo(self):
        with self.assertRaises(p.Blocked):p.validate_installation(self.repo)
    def test_additional_repo_blocks(self):
        with self.assertRaises(p.Blocked):p.validate_installation({'total_count':2,'repositories':[self.repo['repositories'][0]]})
    def test_public_repo_blocks(self):
        with patch.object(p,'TARGET_SHA256',hashlib.sha256(SYNTHETIC.encode()).hexdigest()):
            with self.assertRaises(p.Blocked):p.validate_installation({'total_count':1,'repositories':[{'private':False,'full_name':SYNTHETIC}]})
    def test_workflow_record_valid(self):
        self.assertTrue(p.validate_actions_record(self.actions))
    def test_untrusted_workflow_record(self):
        for record in (None,{'id':1,'path':'other.yml','state':'active'},{'id':1,'path':p.WORKFLOW,'state':'disabled_manually'},{'id':0,'path':p.WORKFLOW,'state':'active'}):
            with self.subTest(record=record),self.assertRaises(p.Blocked):p.validate_actions_record(record)
    def test_source_blob_valid(self):
        self.assertTrue(p.validate_source_blob(self.blob))
    def test_changed_source_blob_block(self):
        with self.assertRaisesRegex(p.Blocked,'SOURCE_BLOB_CHANGED'):
            p.validate_source_blob({**self.blob,'sha':'a'*40})
    def test_invalid_content_type_blocks(self):
        with self.assertRaises(p.Blocked):p.validate_source_blob({**self.blob,'type':'dir'})
    def test_no_credentials_blocks_before_network(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY':'TripDep/controller','GITHUB_REF':'refs/heads/main','BROKER_APP_TOKEN':''}):
            with self.assertRaisesRegex(p.Blocked,'APP_TOKEN_UNAVAILABLE'):
                p.run(lambda *_:self.fail('Network must not run'))
    def test_wrong_branch_blocks_before_network(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY':'TripDep/controller','GITHUB_REF':'refs/heads/feature','BROKER_APP_TOKEN':'x'*25}):
            with self.assertRaisesRegex(p.Blocked,'NOT_PROTECTED_PUBLIC_MAIN'):
                p.run(lambda *_:self.fail('Network must not run'))
    def test_mocked_readonly_success(self):
        calls=[]
        def fake_get(route,token):
            calls.append((route,token))
            if route.startswith('/installation/'):return self.repo
            if '/actions/workflows/' in route:return self.actions
            return self.blob
        with patch.dict(os.environ, {'GITHUB_REPOSITORY':'TripDep/controller','GITHUB_REF':'refs/heads/main','BROKER_APP_TOKEN':'a'*24}),patch.object(p,'TARGET_SHA256',hashlib.sha256(SYNTHETIC.encode()).hexdigest()):
            self.assertTrue(p.run(fake_get))
        self.assertEqual(len(calls),3)
        self.assertTrue(all(x[0].startswith('/') for x in calls))
    def test_api_invalid_uri_blocked(self):
        with self.assertRaises(p.Blocked):p.get_json('https://evil.example','a'*24)

if __name__=='__main__':unittest.main(verbosity=2)