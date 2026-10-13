import copy
import hashlib
import unittest
from unittest.mock import patch
import broker_auto_review_v4 as auto
from test_broker_authority_alignment_v4 import MASTER,supervisor,broker

PUBLIC_SHA='c'*40
PUBLIC={'name':'main','protected':True,'commit':{'sha':PUBLIC_SHA}}
RULES={'enforcement':'active','bypass_actors':[], 'rules':[
 {'type':'deletion'},{'type':'non_fast_forward'},{'type':'pull_request'},
 {'type':'required_status_checks','parameters':{'required_status_checks':[{'context':'selftests'}]}}
]}
REPO='SyntheticOrg/FakePrivate'
HEAD='a'*40
BASE='b'*40
class FakeAPI:
 def __init__(self):
  self.pr={'number':17,'state':'open','draft':False,'head':{'sha':HEAD,'repo':{'full_name':REPO}},
           'base':{'sha':BASE,'repo':{'full_name':REPO},'ref':'main'},'mergeable':True,'changed_files':1}
  self.branch={'commit':{'sha':BASE}}
  self.files=[{'filename':'governance/progress.txt'}]
  self.checks={'total_count':3,'check_runs':[{'name':name,'head_sha':HEAD,'status':'completed','conclusion':'success','app':{'slug':'github-actions'}} for name in ('guard-tests','phase-guard','public-controller')]}
 def call(self,method,route):
  if method=='GET' and route=='/pulls/17': return self.pr
  raise AssertionError('unexpected GitHub API request:'+route)
 def snapshot(self,num,head):
  assert num==17 and head==HEAD
  return self.pr,self.branch,self.files,self.checks

def preflight_kwargs():
 p=broker();p['repository_sha256']=hashlib.sha256(REPO.encode()).hexdigest()
 return dict(canonical_master=MASTER,private_master=MASTER,supervisor_policy=supervisor(),broker_policy=p,public_branch=copy.deepcopy(PUBLIC),public_ruleset=copy.deepcopy(RULES),private_api=FakeAPI(),pr_number=17,pinned_public_main_sha=PUBLIC_SHA,private_workflow_action_sha='b'*40)

class AutoTests(unittest.TestCase):
 def test_public_good(self):self.assertTrue(auto.public_boundary(PUBLIC,RULES,PUBLIC_SHA))
 def test_no_protection(self):
  args=preflight_kwargs();args['public_branch']['protected']=False
  with self.assertRaisesRegex(auto.Blocked,'NOT_PROTECTED'):auto.assess_routine_eligibility(**args)
 def test_no_rules(self):
  args=preflight_kwargs();args['public_ruleset']['rules']=[]
  with self.assertRaisesRegex(auto.Blocked,'INSUFFICIENT'):auto.assess_routine_eligibility(**args)
 def test_no_selftests(self):
  args=preflight_kwargs();args['public_ruleset']['rules'][-1]['parameters']['required_status_checks']=[]
  with self.assertRaisesRegex(auto.Blocked,'SELFTESTS'):auto.assess_routine_eligibility(**args)
 def test_admin_bypass_blocks(self):
  args=preflight_kwargs();args['public_ruleset']['bypass_actors']=[{'actor_id':123}]
  with self.assertRaisesRegex(auto.Blocked,'BYPASS'):auto.assess_routine_eligibility(**args)
 def test_moved_public_sha(self):
  args=preflight_kwargs();args['public_branch']['commit']['sha']='d'*40
  with self.assertRaisesRegex(auto.Blocked,'MOVED'):auto.assess_routine_eligibility(**args)
 def test_old_master_blocks_before_api(self):
  args=preflight_kwargs();args['private_master']=b'old master bytes'
  with self.assertRaisesRegex(auto.Blocked,'LIBRARY_MASTER'):auto.assess_routine_eligibility(**args)
 def test_old_public_policy_blocks(self):
  args=preflight_kwargs();args['supervisor_policy']['canonical_master_sha256']='e'*64
  with self.assertRaisesRegex(auto.Blocked,'LIBRARY_MASTER'):auto.assess_routine_eligibility(**args)
 def test_moved_private_workflow_pin_fails(self):
  args=preflight_kwargs();args['private_workflow_action_sha']='e'*40
  with self.assertRaisesRegex(auto.Blocked,'LIBRARY_MASTER'):auto.assess_routine_eligibility(**args)
 def test_pr_number_boolean_rejected(self):
  args=preflight_kwargs();args['pr_number']=True
  with self.assertRaisesRegex(auto.Blocked,'PR_ID_INVALID'):auto.assess_routine_eligibility(**args)
 def test_invalid_head_blocks(self):
  args=preflight_kwargs();args['private_api'].pr['head']['sha']='invalid'
  with self.assertRaisesRegex(auto.Blocked,'HEAD_SHA_INVALID'):auto.assess_routine_eligibility(**args)
 def test_auto_routine_precheck_pass_does_not_merge(self):
  args=preflight_kwargs()
  with patch.object(auto,'validate_authority_blobs',return_value=True) as a,patch.object(auto,'checked_same_trusted_run',return_value=True) as p:
   result=auto.assess_routine_eligibility(**args)
  self.assertEqual(result['status'],'ROUTINE_PRECHECK_PASS_ONLY')
  self.assertFalse(result['merge_authorized'])
  self.assertFalse(result['private_write_isolation_verified'])
  a.assert_called_once();p.assert_called_once()
 def test_governance_source_edit_never_autoapproves(self):
  args=preflight_kwargs();args['private_api'].files=[{'filename':'governance/gg_phase_guard.py'}]
  with self.assertRaisesRegex(auto.Blocked,'AUTOMERGE_PROTECTED_SURFACE'):auto.assess_routine_eligibility(**args)
 def test_wrong_check_fails(self):
  args=preflight_kwargs();args['private_api'].checks['check_runs'][0]['conclusion']='failure'
  with self.assertRaises(auto.Blocked):auto.assess_routine_eligibility(**args)
 def test_no_incomplete_job_status(self):
  args=preflight_kwargs();args['private_api'].checks['total_count']=4
  with self.assertRaises(auto.Blocked):auto.assess_routine_eligibility(**args)
 def test_output_has_no_secrets_or_asset_paths(self):
  args=preflight_kwargs()
  with patch.object(auto,'validate_authority_blobs',return_value=True),patch.object(auto,'checked_same_trusted_run',return_value=True):
   result=auto.assess_routine_eligibility(**args)
  self.assertNotIn('token',str(result).lower())
  self.assertNotIn('merge_sha',result)
if __name__=='__main__': unittest.main()
