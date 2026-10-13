"""Mock-only v3 regression. No credential, Github repo write or secret."""
import copy
import unittest
from unittest.mock import patch

from test_git_release_broker_v2 import SyntheticBrokerTests
import git_release_broker_v3 as v3
import broker_trust_anchors as anchors
import broker_replay_ledger as replay

class VerifyTrustAnchorTests(unittest.TestCase):
    def test_allow_normal_governance_evidence(self):
        self.assertTrue(anchors.validate_no_authority_changes([{'filename':'governance/PROCESS_PROGRESS.json'}]))
    def test_deny_authority_surfaces(self):
        names = ['.github/workflows/gg-phase-guard.yml','governance/gg_phase_guard.py',
                 'governance/gg_controlled_executor.py','governance/gg_broker_service.py',
                 'governance/test_gg_phase_guard.py','governance/test_gg_broker_os_isolation.py',
                 'governance/rule_family_registry.json','governance/sources/MASTER.md',
                 'governance/aaa_catalog.json','GOVERNANCE/TEST_gg_phase_guard.py']
        for name in names:
            with self.subTest(name=name), self.assertRaises(anchors.Blocked):
                anchors.validate_no_authority_changes([{'filename':name}])
    def test_deny_renamed_from_security_surface(self):
        with self.assertRaises(anchors.Blocked):
            anchors.validate_no_authority_changes([{'filename':'governance/notes.md','previous_filename':'governance/gg_phase_guard.py'}])
    def test_deny_non_files(self):
        for value in (None, [], [{}], [None], [{'filename':'hi\\evil'}]):
            with self.subTest(value=value), self.assertRaises(anchors.Blocked):
                anchors.validate_no_authority_changes(value)
    def test_valid_pinned_blob_evidence(self):
        items = {'governance/gg_phase_guard.py': anchors.TRUSTED_GOVERNANCE_BLOBS['governance/gg_phase_guard.py']}
        class FakeAPI:
            def call(self, method, route):
                self_inner.assertEqual(method,'GET')
                self_inner.assertEqual(route, '/contents/governance/gg_phase_guard.py?ref=' + 'b'*40)
                return {'type':'file','path':'governance/gg_phase_guard.py','sha':items['governance/gg_phase_guard.py']}
        self_inner=self
        self.assertTrue(anchors.validate_authority_blobs(FakeAPI(),'b'*40,anchors=items))
    def test_wrong_blob_id_fails(self):
        items = {'governance/gg_phase_guard.py': anchors.TRUSTED_GOVERNANCE_BLOBS['governance/gg_phase_guard.py']}
        class FakeAPI:
            def call(self,method,route):
                return {'type':'file','path':'governance/gg_phase_guard.py','sha':'c'*40}
        with self.assertRaisesRegex(anchors.Blocked,'AUTOMERGE_SOURCE_DRIFT'):
            anchors.validate_authority_blobs(FakeAPI(),'b'*40,anchors=items)
    def test_api_wrong_source_path_fails(self):
        items={'governance/gg_phase_guard.py':anchors.TRUSTED_GOVERNANCE_BLOBS['governance/gg_phase_guard.py']}
        class FakeAPI:
            def call(self,method,route):
                return {'type':'file','path':'governance/other.py','sha':items['governance/gg_phase_guard.py']}
        with self.assertRaises(anchors.Blocked): anchors.validate_authority_blobs(FakeAPI(),'b'*40,anchors=items)
    def test_malformed_base_fails_before_api(self):
        class FakeAPI:
            def call(self,*args): raise AssertionError('No HTTP should happen')
        with self.assertRaises(anchors.Blocked): anchors.validate_authority_blobs(FakeAPI(),'notasha')
    def test_empty_anchors_fail(self):
        class FakeAPI: pass
        with self.assertRaises(anchors.Blocked): anchors.validate_authority_blobs(FakeAPI(),'b'*40,anchors={})

class VerifyReplayTests(unittest.TestCase):
    def setUp(self):
        self.auth={'nonce':'a'*20,'repository':'synthetic/private','pr_number':19,'head_sha':'a'*40,
                   'base_sha':'b'*40,'master_sha256':'c'*64,'public_controller_sha':'d'*40,
                   'decision':'APPROVE_MERGE','expires_at':'2026-10-13T12:30:00Z'}
    def test_same_nonce_different_pr_must_have_same_claim_name(self):
        first = replay.claim_name(self.auth)
        other={**self.auth,'pr_number':20,'head_sha':'f'*40}
        self.assertEqual(first,replay.claim_name(other))
    def test_distinct_nonce_distinct_claim(self):
        self.assertNotEqual(replay.claim_name(self.auth),replay.claim_name({**self.auth,'nonce':'b'*20}))
    def test_different_repo_distinct_claim(self):
        self.assertNotEqual(replay.claim_name(self.auth),replay.claim_name({**self.auth,'repository':'synthetic/elsewhere'}))
    def test_invalid_nonce_rejected(self):
        with self.assertRaises(replay.Blocked): replay.claim_name({**self.auth,'nonce':'../x'})
    def test_claim_exact_one_post(self):
        calls=[]
        class FakeAPI:
            def call(_,method,route,payload):
                calls.append((method,route,payload))
                return {'ref':payload['ref'],'object':{'sha':payload['sha']}}
        self.assertTrue(replay.claim_once(FakeAPI(),self.auth).startswith('refs/heads/gg-broker-claims/'))
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][0:2],('POST','/git/refs'))
    def test_duplicate_claim_api_failure_rejected(self):
        class FakeAPI:
            def call(*args): raise RuntimeError('422')
        with self.assertRaisesRegex(replay.Blocked,'NONCE_CLAIM_FAILED'):
            replay.claim_once(FakeAPI(),self.auth)
    def test_create_claim_unconfirmed_blocks(self):
        class FakeAPI:
            def call(_,method,route,payload): return {'ref':payload['ref'],'object':{'sha':'f'*40}}
        with self.assertRaisesRegex(replay.Blocked,'NONCE_CLAIM_UNVERIFIED'):
            replay.claim_once(FakeAPI(),self.auth)
    def test_fresh_snapshot_success(self):
        a=self.auth
        class FakeAPI:
            def call(_,method,route):
                if route.startswith('/pulls/'):
                    return {'state':'open','draft':False,'mergeable':True,'head':{'sha':a['head_sha']},'base':{'sha':a['base_sha']}}
                return {'commit':{'sha':a['base_sha']}}
        self.assertTrue(replay.verify_pr_still_fresh(FakeAPI(),a))
    def test_moved_base_blocked(self):
        a=self.auth
        class FakeAPI:
            def call(_,method,route):
                if route.startswith('/pulls/'):
                    return {'state':'open','draft':False,'mergeable':True,'head':{'sha':a['head_sha']},'base':{'sha':a['base_sha']}}
                return {'commit':{'sha':'f'*40}}
        with self.assertRaises(replay.Blocked): replay.verify_pr_still_fresh(FakeAPI(),a)

class VerifyIntegrationV3(unittest.TestCase):
    def setUp(self):
        f=SyntheticBrokerTests(methodName='test_valid_synthetic_snapshot');f.setUp()
        self.fixture=f
    def test_positive_only_mock_api_merge(self):
        f=self.fixture
        class FakeAPI:
            merges=0
            def snapshot(_,num,head): return f.pr,f.branch,f.files,f.checks
            def merge(_,num,head): _.merges+=1;return {'merged':True,'sha':'e'*40}
        api=FakeAPI()
        with patch.object(v3.b,'verify_owner_signature',return_value=True), \
             patch.object(v3,'checked_same_trusted_run',return_value=True), \
             patch.object(v3,'validate_authority_blobs',return_value=True), \
             patch.object(v3,'claim_once',return_value=True), \
             patch.object(v3,'verify_pr_still_fresh',return_value=True):
            self.assertEqual(v3.approve_and_merge_v3(f.policy,f.auth,b'sig','/tmp/test',api)['status'],'MERGED')
        self.assertEqual(api.merges,1)
    def test_protected_path_never_reaches_claim(self):
        f=self.fixture
        files=[{'filename':'governance/gg_phase_guard.py'}]
        class FakeAPI:
            def snapshot(_,num,head):return f.pr,f.branch,files,f.checks
            def merge(_,num,head):raise AssertionError('must never merge')
        with patch.object(v3.b,'verify_owner_signature',return_value=True), \
             patch.object(v3,'claim_once',side_effect=AssertionError('must never claim')):
            with self.assertRaisesRegex(v3.Blocked,'AUTOMERGE_PROTECTED_SURFACE'):
                v3.approve_and_merge_v3(f.policy,f.auth,b'sig','/tmp/test',FakeAPI())
    def test_invalid_trust_anchor_does_not_consume_nonce(self):
        f=self.fixture
        class FakeAPI:
            def snapshot(_,num,head):return f.pr,f.branch,f.files,f.checks
            def merge(_,num,head): raise AssertionError('must never merge')
        with patch.object(v3.b,'verify_owner_signature',return_value=True), \
             patch.object(v3,'validate_authority_blobs',side_effect=anchors.Blocked('AUTOMERGE_SOURCE_DRIFT')), \
             patch.object(v3,'claim_once',side_effect=AssertionError('must never claim')):
            with self.assertRaisesRegex(v3.Blocked,'AUTOMERGE_SOURCE_DRIFT'):
                v3.approve_and_merge_v3(f.policy,f.auth,b'sig','/tmp/test',FakeAPI())

if __name__ == '__main__': unittest.main(verbosity=2)
