"""C07 B original-planning nine-rule macro native consuming broker tests.

Nine exact B literals / eighteen independent source criteria: real original
dependency bytes, lock sets, risk matrix, measured estimates and criteria.
None is certified owner/MG0/asset artistic quality from these source records.
"""
import copy
import hashlib
import unittest
from pathlib import Path

import test_c07_p0_planning_semantics as planning_fixture
from c07_p0_planning_semantics import IDS
from c07_native_source_rule_replayers import (
    build_packet,FULL_LITERAL_REVIEWED,NATIVE_RULES,VALIDATORS,
    native_rule_readback)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding
from c07_mg0_individual import TRIGGERS

class BOriginalNineMacroBroker(unittest.TestCase):
    def fixture(self):
        fx=planning_fixture.Tests(
            'test_nine_distinct_literal_semantics_from_original_files')
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        f=fx.f
        master=('## MG0 — PROCESS FALSIFICATION\n' +
                ''.join('- '+r+'\n' for r in TRIGGERS) +
                'The response is not limited to fixing the asset.\n'
                'invalidate affected states and reapply the corrected process\n'
                ).encode()
        master_sha=hashlib.sha256(master).hexdigest()
        f.master=master
        f.controller.master.write_bytes(master)
        f.work.update(work_item_sha256='e'*64,
                      attempt_number=1,previous_attempt_id=None,
                      master_sha256=master_sha)
        f.inv['canonical_master_sha256']=master_sha
        f.plan['master_sha256']=master_sha
        f.rebuild()
        return fx

    @staticmethod
    def context(fx):
        f=fx.f
        return dict(inventory=f.inv,plan=f.plan,controller=f.controller,
                    asset=f.asset,step=f.step,work=f.work,
                    source_loader=lambda path:Path(path).read_bytes())

    def test_all_nine_planning_lits_are_native_source_replayed_with_eighteen_checks(self):
        fx=self.fixture();ctx=self.context(fx)
        expected=fx.review()
        self.assertEqual(len(IDS),9)
        self.assertEqual(len(set(IDS)&FULL_LITERAL_REVIEWED),0)
        self.assertEqual(len({name for rid in IDS for name in NATIVE_RULES[rid][1]}),18)
        self.assertEqual(expected['source_rule_count'],9)
        for rid in IDS:
            with self.subTest(id=rid):
                packet=build_packet(ctx,rid)
                self.assertEqual(packet['rule']['checks'],
                    expected['rules'][rid]['original_machine_checks'])
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')

    def test_all_nine_remain_unreviewed_for_full_native_authorization(self):
        fx=self.fixture();ctx=self.context(fx)
        for rid in IDS:
            with self.subTest(id=rid):
                expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
                packet=build_packet(ctx,rid,expected=expected)
                spec={'validator_id':VALIDATORS[rid],
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256'],
                      'source_ref':'1'*40}
                with self.assertRaisesRegex(ValueError,'NOT_WHITELISTED'):
                    replay(None,packet,expected,spec,source_context=lambda _:ctx)

    def test_real_original_dependency_cycle_fails_the_dependency_rule(self):
        fx=self.fixture()
        dep=list(fx.f.work['work_dependencies'])[0]
        fx.docs[16]['edges']=[[dep,dep]]
        fx.sync()
        ctx=self.context(fx)
        checks=build_packet(ctx,'AAA-200-B-016')['rule']['checks']
        self.assertTrue(checks['original_dependency_nodes_are_verified'])
        self.assertFalse(checks['original_dependency_edges_refer_to_nodes_and_are_acyclic'])

    def test_protected_approved_asset_cannot_be_in_mutable_list(self):
        fx=self.fixture()
        fx.docs[15]['mutable']=['old_bridge']
        fx.sync()
        packet=build_packet(self.context(fx),'AAA-200-B-015')
        self.assertFalse(packet['rule']['checks']['approved_and_mutable_names_are_disjoint'])

    def test_observed_original_measurements_reject_invented_estimate(self):
        fx=self.fixture()
        fx.docs[19]['tasks'][0]['estimated_hours']=9999
        fx.sync()
        checks=build_packet(self.context(fx),'AAA-200-B-019')['rule']['checks']
        self.assertFalse(checks['time_estimate_uses_measured_task_hours'])
        self.assertTrue(checks['estimate_total_independently_recomputed'])

    def test_fake_acceptance_reference_digest_rejected(self):
        fx=self.fixture()
        fx.docs[20]['criteria'][0]['measurement_source_sha256']='0'*64
        fx.sync()
        checks=build_packet(self.context(fx),'AAA-200-B-020')['rule']['checks']
        self.assertFalse(checks['every_criterion_names_independent_measurement_source'])

    def test_original_dependency_bytes_tampered_before_preflight_rejected(self):
        fx=self.fixture()
        dep=list(fx.f.work['work_dependencies'])[0]
        fx.f.work['work_dependencies'][dep]='0'*64
        fx.f.rebuild()
        with self.assertRaises(ValueError):
            build_packet(self.context(fx),'AAA-200-B-014')

    def test_producer_packet_forgery_cannot_be_promoted(self):
        fx=self.fixture();ctx=self.context(fx)
        rid='AAA-200-B-017'
        packet=build_packet(ctx,rid)
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40}
        with self.assertRaises(ValueError):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_forged_current_attempt_never_replays_planning(self):
        fx=self.fixture();ctx=self.context(fx)
        ctx['work']=dict(ctx['work'],attempt_id='0'*64)
        for rid in ('AAA-200-B-011','AAA-200-B-020'):
            with self.subTest(id=rid):
                with self.assertRaises(ValueError):
                    build_packet(ctx,rid)

if __name__=='__main__':
    unittest.main()
