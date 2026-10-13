import copy
import unittest
from supervisor_context import validate,assess,digest,Blocked

def receipt(role='rescue'):
    r={'library_file_id':'libfile_'+'a'*32,'version':1,'sha256':'a'*64}
    v={'schema':'gg-supervisor-context-v1','role':role,'observed_at':'2020-10-13T18:00:00+00:00','master':r,'state':dict(r),'provider':{'automation_id_sha256':'b'*64,'last_run_time':'2020-10-13T17:30:00+00:00','enabled':True},'checkpoint':{'status':'UNVERIFIED','source':None,'verification':None,'run_id_sha256':None},'dependencies':{'c'*64:'d'*64,'e'*64:'f'*64},'signals':[],'provenance':'OPERATOR_LIBRARY_READBACK_NOT_GIT_VERIFIED_CONTENT','advancement_authorized':False}
    return seal(v)
def seal(v):v['observation_id']=digest({k:x for k,x in v.items() if k!='observation_id'});return v
class Tests(unittest.TestCase):
    def update(self,v):
        n=copy.deepcopy(v);n['observed_at']='2020-10-13T19:00:00+00:00';n['state']['version']+=1;n['state']['sha256']='0'*64;return n
    def test_hourly_gap_does_not_restart(self):
        v=receipt();n=seal(self.update(v));self.assertEqual(assess(v,n,['c'*64])['action'],'CONTEXT_RECORDED_NO_RECHECK')
    def test_unrelated_dependency(self):
        v=receipt();n=self.update(v);n['dependencies']['e'*64]='0'*64;self.assertEqual(assess(v,seal(n),['c'*64])['action'],'CONTEXT_RECORDED_NO_RECHECK')
    def test_relevant_dependency(self):
        v=receipt();n=self.update(v);n['dependencies']['c'*64]='0'*64;self.assertEqual(assess(v,seal(n),['c'*64])['action'],'RECHECK_AFFECTED_CONTROLS')
    def test_master_always_rechecked(self):
        v=receipt();n=self.update(v);n['master']['version']+=1;n['master']['sha256']='0'*64;self.assertTrue(assess(v,seal(n),[])['master_changed'])
    def test_missing_dependency_stops(self):self.assertEqual(assess(None,receipt(),['0'*64])['action'],'STOP_RELEVANT_CONTEXT_UNKNOWN')
    def test_relevant_signal(self):
        v=receipt();v['signals']=[{'dependency':'c'*64,'status':'FAIL'}];self.assertEqual(assess(None,seal(v),['c'*64])['action'],'STOP_RELEVANT_CONTEXT_UNKNOWN')
    def test_unrelated_signal(self):
        v=receipt();v['signals']=[{'dependency':'e'*64,'status':'UNKNOWN'}];self.assertEqual(assess(None,seal(v),['c'*64])['action'],'INITIAL_CONTEXT_CAPTURED')
    def test_global_signal(self):
        v=receipt();v['signals']=[{'dependency':'GLOBAL','status':'REGRESSION'}];self.assertEqual(assess(None,seal(v),[])['action'],'STOP_RELEVANT_CONTEXT_UNKNOWN')
    def test_guardian_launch_is_not_pass(self):self.assertEqual(assess(None,receipt('guardian'),[],True)['action'],'STOP_RELEVANT_CONTEXT_UNKNOWN')
    def test_guardian_unverified_remains_visible(self):self.assertEqual(assess(None,receipt('guardian'),[])['checkpoint_status'],'UNVERIFIED')
    def test_replay(self):
        v=receipt();n=seal(self.update(v))
        with self.assertRaisesRegex(Blocked,'CONTEXT_REPLAY'):assess(n,v,[])
    def test_same_version_tamper(self):
        v=receipt();n=copy.deepcopy(v);n['observed_at']='2020-10-13T19:00:00+00:00';n['state']['sha256']='0'*64
        with self.assertRaisesRegex(Blocked,'CONTEXT_SAME_VERSION_TAMPER'):assess(v,seal(n),[])
    def test_injected_asset(self):
        v=receipt();v['asset_bytes']='bad'
        with self.assertRaisesRegex(Blocked,'CONTEXT_FIELDS'):validate(seal(v))
    def test_pending_cannot_claim_complete(self):
        v=receipt();v['checkpoint']['source']=v['master']
        with self.assertRaisesRegex(Blocked,'CONTEXT_PENDING_NOT_COMPLETE'):validate(seal(v))
    def test_no_work_authority(self):self.assertFalse(assess(None,receipt(),[])['advancement_authorized'])
    def test_digest_tamper(self):
        v=receipt();v['observed_at']='2020-10-13T19:00:00+00:00'
        with self.assertRaisesRegex(Blocked,'CONTEXT_OBSERVATION_DIGEST'):validate(v)
    def test_same_observation_idempotent(self):
        v=receipt();self.assertEqual(assess(v,v,['c'*64])['action'],'CONTEXT_RECORDED_NO_RECHECK')
    def test_future_observation(self):
        v=receipt();v['observed_at']='2100-10-13T19:00:00+00:00'
        with self.assertRaisesRegex(Blocked,'CONTEXT_OBSERVATION_FUTURE'):validate(seal(v))
if __name__=='__main__':unittest.main()
