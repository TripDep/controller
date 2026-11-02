"""C07 P2 macro: fifty G/H/I/J/K source replayers, four asset types.

Each of the 100 original predicates is independently recomputed by the
P2 evidence reader. The consumer must replay only currently DUE asset rules,
deny NOT_DUE, forged original SHA and producer-made PASS. Synthetic fixtures
are evidence of code behavior, never actual Golden Garden FiveM MG0 approval.
"""
import copy
import hashlib
import unittest
from pathlib import Path

from test_c07_p2_fifty_asset_type_domain import FiftyP2,serialized
from c07_p2_fifty_asset_type_domain import IDS,inspect
from c07_native_source_rule_replayers import (
    build_packet,FULL_LITERAL_REVIEWED,NATIVE_RULES,
    VALIDATORS,native_rule_readback)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding
from c07_mg0_individual import TRIGGERS

class P2FiftyNativeMacroTests(unittest.TestCase):
    def fixture(self,asset_type='architecture'):
        t=FiftyP2('test_50_literal_P2_rule_ids_and_100_named_individual_checks')
        t.setUp()
        self.addCleanup(t.doCleanups)
        f=t.f
        f.plan['asset_type']=asset_type
        f.work['asset_type']=asset_type
        master=('## MG0 — PROCESS FALSIFICATION\n' +
                ''.join('- '+x+'\n' for x in TRIGGERS) +
                'The response is not limited to fixing the asset.\n'
                'invalidate affected states and reapply the corrected process\n').encode()
        master_sha=hashlib.sha256(master).hexdigest()
        f.master=master
        f.controller.master.write_bytes(master)
        f.work.update(work_item_sha256='e'*64,
                      attempt_number=1,previous_attempt_id=None,
                      master_sha256=master_sha)
        f.plan['master_sha256']=master_sha
        f.inv['canonical_master_sha256']=master_sha
        t.rebuild()
        return t

    @staticmethod
    def ctx(t):
        f=t.f
        return dict(inventory=f.inv,plan=f.plan,controller=f.controller,
            asset=f.asset,step=f.step,work=f.work,
            source_loader=lambda path:Path(path).read_bytes())

    def test_all_fifty_exact_rule_ids_type_scoped_100_original_predicates(self):
        self.assertEqual(len(IDS),50)
        self.assertEqual(len(set(IDS)&FULL_LITERAL_REVIEWED),0)
        self.assertEqual(len({x for rid in IDS for x in NATIVE_RULES[rid][1]}),100)
        for asset_type,expected_count in (
                ('architecture',20),('organic',10),
                ('vegetation',10),('terrain',10)):
            with self.subTest(asset_type=asset_type):
                fx=self.fixture(asset_type)
                ctx=self.ctx(fx)
                original=fx.run_check()
                due=[rid for rid in IDS if
                     original['rules'][rid]['applicability']=='DUE']
                not_due=[rid for rid in IDS if rid not in due]
                self.assertEqual(len(due),expected_count)
                self.assertEqual(len(not_due),50-expected_count)
                for rid in due:
                    with self.subTest(rule=rid):
                        packet=build_packet(ctx,rid)
                        self.assertEqual(packet['rule']['checks'],
                            original['rules'][rid]['original_native_domain_predicates'])
                        self.assertEqual(packet['rule']['result'],'UNKNOWN')
                        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                # N/A is NOT a positive result and must fail the native packet.
                with self.assertRaisesRegex(ValueError,
                        'C07_P2_FIFTY_NO_NOT_APPLICABLE_OR_FULL_PROMOTION'):
                    build_packet(ctx,not_due[0])

    def test_not_due_organic_rule_refused_in_architecture(self):
        t=self.fixture('architecture');ctx=self.ctx(t)
        for rid in ('AAA-200-I-081','AAA-200-J-100','AAA-200-K-105'):
            with self.subTest(rule=rid):
                with self.assertRaises(ValueError):
                    build_packet(ctx,rid)

    def test_native_source_full_replay_denied_all_asset_types(self):
        for asset_type,rid in (
            ('architecture','AAA-200-G-061'),
            ('organic','AAA-200-I-086'),
            ('vegetation','AAA-200-J-095'),
            ('terrain','AAA-200-K-104')):
            with self.subTest(asset=asset_type,rule=rid):
                t=self.fixture(asset_type);ctx=self.ctx(t)
                packet=build_packet(ctx,rid)
                expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
                spec={'validator_id':VALIDATORS[rid],
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256'],
                      'source_ref':'1'*40}
                with self.assertRaisesRegex(ValueError,'NOT_WHITELISTED'):
                    replay(None,packet,expected,spec,source_context=lambda _:ctx)

    def test_original_vegetation_leaf_alpha_missing_pin_fails_closed(self):
        t=self.fixture('vegetation')
        t.f.plan['p2_evidence_contract']['original_artifact_sha256'].pop(
            'P2_LEAF_CARD_PNG')
        t.f.rebuild()
        packet=build_packet(self.ctx(t),'AAA-200-J-095')
        self.assertFalse(packet['rule']['checks'][
            'original_leaf_card_R_G_B_A_PNG_bytes_decoded'])

    def test_original_terrain_survey_corruption_is_not_elevation_qa(self):
        t=self.fixture('terrain')
        t.add('P2_SURVEY','survey.json',serialized({
            'samples':[{'x':0,'y':0,'z':None}]}))
        t.rebuild()
        packet=build_packet(self.ctx(t),'AAA-200-K-101')
        self.assertFalse(packet['rule']['checks'][
            'original_four_numeric_world_points_checked'])

    def test_native_architecture_primitive_without_reference_not_silhouette_pass(self):
        t=self.fixture('architecture')
        t.f.plan['p2_evidence_contract']['original_artifact_sha256'].pop(
            'REFERENCE_IMAGE')
        t.f.rebuild()
        packet=build_packet(self.ctx(t),'AAA-200-G-062')
        self.assertFalse(packet['rule']['checks'][
            'front_reference_and_actual_front_rasters_decoded'])

    def test_original_pre_d_rule_literal_tampering_fails_before_result(self):
        t=self.fixture('terrain')
        rid='AAA-200-K-110'
        t.f.inv['rules'][rid]['requirement']='just mark complete'
        with self.assertRaises(ValueError):
            build_packet(self.ctx(t),rid)

    def test_forged_packet_digest_never_authorizes_source_rule(self):
        t=self.fixture('organic');ctx=self.ctx(t)
        rid='AAA-200-I-089'
        packet=build_packet(ctx,rid)
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='0'*64
        expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40}
        with self.assertRaises(ValueError):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_changed_current_operation_attempt_fails_closed(self):
        t=self.fixture('architecture');ctx=self.ctx(t)
        ctx['work']=dict(ctx['work'],attempt_id='0'*64)
        with self.assertRaises(ValueError):
            build_packet(ctx,'AAA-200-H-075')

if __name__=='__main__':
    unittest.main()
