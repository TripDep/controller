import unittest
import json
from broker_authority_alignment_v4 import normalize_pins, strict_json, master_revision, sha256, Blocked

MASTER=(b'# Pine Haven\n**Revision:** 2026-10-13-R149-S1\n'+b'A'*120)
PIN=sha256(MASTER)
def supervisor(pin=PIN):
    return {'schema':'public-process-supervisor-v1','canonical_master_sha256':pin,
            'non_aaa_id_count':551,'aaa_count':200,'behavior_110_count':110}
def broker(pin=PIN):
    return {'schema':'gg-git-broker-v1','enabled':False,'base_branch':'main',
            'master_sha256':pin,'repository_sha256':'a'*64,'public_controller_sha':'b'*40,
            'reviewer_public_key_sha256':None,'required_checks':['guard-tests','phase-guard','public-controller']}
class Tests(unittest.TestCase):
    def test_aligned(self):
        r=normalize_pins(MASTER,supervisor(),broker(),MASTER,private_action_pin='b'*40)
        self.assertEqual(r['status'],'ALIGNED_METADATA_ONLY')
        self.assertFalse(r['independent_auto_merge_authorized'])
    def test_stale_public_pin_blocks(self):
        r=normalize_pins(MASTER,supervisor('a'*64),broker(),MASTER,private_action_pin='b'*40)
        self.assertEqual(r['status'],'BLOCKED_SOURCE_DRIFT')
    def test_stale_broker_pin_blocks(self):
        self.assertEqual(normalize_pins(MASTER,supervisor(),broker('b'*64),MASTER,private_action_pin='b'*40)['status'],'BLOCKED_SOURCE_DRIFT')
    def test_private_copy_stale_blocks(self):
        r=normalize_pins(MASTER,supervisor(),broker(),b'older bytes',private_action_pin='b'*40)
        self.assertEqual(r['private_source_alignment'],'MISMATCH')
        self.assertEqual(r['status'],'BLOCKED_SOURCE_DRIFT')
    def test_no_private_copy_unknown(self):
        r=normalize_pins(MASTER,supervisor(),broker(),private_action_pin='b'*40)
        self.assertEqual(r['private_source_alignment'],'UNKNOWN')
        self.assertEqual(r['status'],'BLOCKED_SOURCE_DRIFT')
    def test_controller_pin_mismatch_blocks(self):
        r=normalize_pins(MASTER,supervisor(),broker(),MASTER,private_action_pin='c'*40)
        self.assertEqual(r['status'],'BLOCKED_CONTROLLER_PIN_DRIFT')
    def test_pin_missing_not_ready(self):
        r=normalize_pins(MASTER,supervisor(),broker(),MASTER)
        self.assertEqual(r['status'],'BLOCKED_SOURCE_DRIFT')
    def test_no_arming(self):
        b=broker();b['enabled']=True
        with self.assertRaisesRegex(Blocked,'DISABLED'):normalize_pins(MASTER,supervisor(),b,MASTER,private_action_pin='b'*40)
    def test_no_fake_reviewer_enrolment(self):
        b=broker();b['reviewer_public_key_sha256']='f'*64
        with self.assertRaisesRegex(Blocked,'REVIEWER'):normalize_pins(MASTER,supervisor(),b,MASTER,private_action_pin='b'*40)
    def test_counts_must_not_downgrade(self):
        s=supervisor();s['aaa_count']=199
        with self.assertRaisesRegex(Blocked,'COUNT'):normalize_pins(MASTER,s,broker(),MASTER,private_action_pin='b'*40)
    def test_boolean_count_rejected(self):
        s=supervisor();s['aaa_count']=True
        with self.assertRaises(Blocked):normalize_pins(MASTER,s,broker(),MASTER,private_action_pin='b'*40)
    def test_required_checks_must_not_change(self):
        b=broker();b['required_checks']=[]
        with self.assertRaises(Blocked):normalize_pins(MASTER,supervisor(),b,MASTER,private_action_pin='b'*40)
    def test_controller_pin_frozen(self):
        r=normalize_pins(MASTER,supervisor(),broker(),MASTER,private_action_pin='b'*40)
        self.assertEqual(r['must_keep']['immutable_public_action_sha'],'b'*40)
    def test_private_repo_kept(self):
        r=normalize_pins(MASTER,supervisor(),broker(),MASTER,private_action_pin='b'*40)
        self.assertFalse(r['must_keep']['private_repo_public'])
        self.assertFalse(r['must_keep']['assets_on_github'])
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(Blocked,'DUPLICATE'):strict_json(b'{"key":1,"key":2}')
    def test_nonstandard_json_rejected(self):
        with self.assertRaisesRegex(Blocked,'NONSTANDARD'):strict_json(b'{"bad":NaN}')
    def test_bad_json_type_rejected(self):
        with self.assertRaises(Blocked):strict_json(b'{}'*150000)
    def test_master_duplicate_revision_rejected(self):
        with self.assertRaises(Blocked):master_revision(MASTER+b'\n**Revision:** x\n')
    def test_master_no_revision_rejected(self):
        with self.assertRaises(Blocked):master_revision(b'no revision'+b'x'*120)
    def test_base_not_main_rejected(self):
        b=broker();b['base_branch']='develop'
        with self.assertRaises(Blocked):normalize_pins(MASTER,supervisor(),b,MASTER,private_action_pin='b'*40)
    def test_schema_changed_rejected(self):
        s=supervisor();s['schema']='v0'
        with self.assertRaises(Blocked):normalize_pins(MASTER,s,broker(),MASTER,private_action_pin='b'*40)
    def test_pins_must_be_sha(self):
        b=broker();b['repository_sha256']='bad'
        with self.assertRaises(Blocked):normalize_pins(MASTER,supervisor(),b,MASTER,private_action_pin='b'*40)
if __name__=='__main__':unittest.main()
