"""Negative and positive offline-only tests for event/merge separation."""
from __future__ import annotations
import copy
import json
import tempfile
import unittest
from pathlib import Path

import broker_signal_separation_v5 as g

BASE='a'*40
HEAD='b'*40
CURRENT='c'*40
REPO=g.TRUSTED_PRIVATE_REPO

def basic():
    return {'schema':'pinehaven-github-pr-readonly-v1','repository':REPO,'default_branch':'main',
            'current_main_sha':CURRENT,'private_main_protected':False,'total_open_count':1,
            'pull_requests':[{'number':5,'title':'GG_RUN_DONE_TEST','state':'open','draft':False,
                'head_repo':REPO,'base_repo':REPO,'base_ref':'main','head_sha':HEAD,
                'base_sha':BASE,'url':'https://github.com/'+REPO+'/pull/5'}]}

class SignalTests(unittest.TestCase):
    def t(self,data):return g.classify(data)
    def test_positive_signal_not_authorization(self):
        z=self.t(basic());self.assertEqual(z['signal_count'],1);self.assertFalse(z['broker_merge_authorized'])
        self.assertEqual(z['signals'][0]['category'],'SIGNAL_ONLY');self.assertFalse(z['signals'][0]['merge_authorized'])
    def test_old_base_is_only_reported(self):
        z=self.t(basic());self.assertEqual(z['stale_signals'],1);self.assertFalse(z['signals'][0]['base_matches_current_main'])
    def test_new_base_is_event_still_no_merge(self):
        d=basic();d['pull_requests'][0]['base_sha']=CURRENT
        z=self.t(d);self.assertEqual(z['stale_signals'],0);self.assertFalse(z['signals'][0]['merge_authorized'])
    def test_title_prefix_exact(self):
        d=basic();d['pull_requests'][0]['title']=' GG_RUN_DONE'
        z=self.t(d);self.assertEqual(z['signal_count'],0);self.assertEqual(z['other_count'],1)
    def test_non_signal_requires_review(self):
        d=basic();d['pull_requests'][0]['title']='Normal PR'
        z=self.t(d);self.assertEqual(z['other_prs'][0]['category'],'REQUIRES_FULL_BROKER_REVIEW')
        self.assertFalse(z['other_prs'][0]['merge_authorized'])
    def test_missing_open_pr_collection_blocks(self):
        d=basic();d['total_open_count']=2
        with self.assertRaisesRegex(g.Blocked,'NOT_COMPLETE'):self.t(d)
    def test_missing_list_blocks(self):
        d=basic();d.pop('pull_requests')
        with self.assertRaises(g.Blocked):self.t(d)
    def test_boolean_number_blocks(self):
        d=basic();d['pull_requests'][0]['number']=True
        with self.assertRaisesRegex(g.Blocked,'NUMBER'):self.t(d)
    def test_duplicate_pr_number_blocks(self):
        d=basic();d['pull_requests'].append(copy.deepcopy(d['pull_requests'][0]));d['total_open_count']=2
        with self.assertRaisesRegex(g.Blocked,'DUPLICATE'):self.t(d)
    def test_repo_mismatch_blocks(self):
        d=basic();d['repository']='Other/Repo'
        with self.assertRaisesRegex(g.Blocked,'REPOSITORY'):self.t(d)
    def test_cross_repo_blocks(self):
        d=basic();d['pull_requests'][0]['head_repo']='Evil/Repo'
        with self.assertRaisesRegex(g.Blocked,'CROSS_REPO'):self.t(d)
    def test_bad_base_ref_blocks(self):
        d=basic();d['pull_requests'][0]['base_ref']='dev'
        with self.assertRaisesRegex(g.Blocked,'TARGET_BRANCH'):self.t(d)
    def test_bad_url_blocks(self):
        d=basic();d['pull_requests'][0]['url']='https://evil.test'
        with self.assertRaisesRegex(g.Blocked,'URL'):self.t(d)
    def test_bad_sha_blocks(self):
        d=basic();d['pull_requests'][0]['head_sha']='nope'
        with self.assertRaisesRegex(g.Blocked,'SHA'):self.t(d)
    def test_claimed_protected_private_blocks(self):
        d=basic();d['private_main_protected']=True
        with self.assertRaisesRegex(g.Blocked,'PROTECTION'):self.t(d)
    def test_wrong_schema_blocks(self):
        d=basic();d['schema']='legacy'
        with self.assertRaisesRegex(g.Blocked,'SCHEMA'):self.t(d)
    def test_order_independent_signals(self):
        d=basic();x=copy.deepcopy(d['pull_requests'][0]);x['number']=2;x['url']='https://github.com/'+REPO+'/pull/2';d['pull_requests'].append(x);d['total_open_count']=2
        z=self.t(d);self.assertEqual([y['pr_number'] for y in z['signals']],[2,5])
    def test_empty_list(self):
        d=basic();d['pull_requests']=[];d['total_open_count']=0
        z=self.t(d);self.assertEqual(z['signal_count'],0);self.assertFalse(z['broker_merge_authorized'])
    def test_monitor_not_proven(self):
        d=basic();z=self.t(d)
        self.assertEqual(z['signals'][0]['event_received_by_monitor'],'NOT_PROVEN');self.assertEqual(z['signals'][0]['timer_reset'],'NOT_PERFORMED')
    def test_json_duplicate_key_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.json';p.write_text('{"a":1,"a":2}')
            with self.assertRaises(g.Blocked):g.read_snapshot(p)
    def test_json_nan_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.json';p.write_text('{"a":NaN}')
            with self.assertRaises(g.Blocked):g.read_snapshot(p)
    def test_symlink_blocks(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.json';p.write_text('{}');q=Path(t)/'link';q.symlink_to(p)
            with self.assertRaises(g.Blocked):g.read_snapshot(q)
    def test_five_stale_signal_prs_are_not_merge_candidates(self):
        # Public CI uses synthetic records; private observed evidence stays private.
        snapshot=basic()
        snapshot['pull_requests']=[]
        for number in range(1,6):
            record=copy.deepcopy(basic()['pull_requests'][0])
            record['number']=number
            record['title']='GG_RUN_DONE_SYNTHETIC_'+str(number)
            record['url']='https://github.com/'+REPO+'/pull/'+str(number)
            snapshot['pull_requests'].append(record)
        snapshot['total_open_count']=5
        with tempfile.TemporaryDirectory() as directory:
            fixture=Path(directory)/'five_signals.json'
            fixture.write_text(json.dumps(snapshot))
            out=self.t(g.read_snapshot(fixture))
        self.assertEqual(out['signal_count'],5)
        self.assertEqual(out['other_count'],0)
        self.assertEqual(out['stale_signals'],5)
        self.assertFalse(out['broker_merge_authorized'])
        self.assertEqual([p['pr_number'] for p in out['signals']],[1,2,3,4,5])

    def test_cli_local_only(self):
        with tempfile.TemporaryDirectory() as t:
            inp,out=Path(t)/'snap.json',Path(t)/'out.json';inp.write_text(json.dumps(basic()))
            self.assertEqual(g.main(['--snapshot',str(inp),'--output',str(out)]),0)
            self.assertFalse(json.loads(out.read_text())['broker_merge_authorized'])

if __name__=='__main__':unittest.main(verbosity=2)
