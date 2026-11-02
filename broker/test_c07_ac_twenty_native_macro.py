"""C07 A and C macro broker tests: 20 exact pre-D original-source rules.

The same original source manifests, current operation, immutable Controller
and 60 original rule-specific criteria are recomputed in every consumer packet.
Synthetic fixtures cannot prove artistic fitness, copyright, MG0 or FiveM.
"""
import copy
import unittest
from pathlib import Path

from c07_a10_c10_original_evidence import IDS,inspect as read_twenty
from c07_native_source_rule_replayers import (
    build_packet,FULL_LITERAL_REVIEWED,NATIVE_RULES,VALIDATORS,
    native_rule_readback,NativeRuleEvidenceBlocked)
from test_c07_a10_c10_original_evidence import R140Test,png
from supervisor_judgment import binding
from c07_native_replayer_dispatch import replay

class ACOriginalMacroBroker(unittest.TestCase):
    def fixture(self):
        fx=R140Test('test_all_twenty_source_ids_have_three_distinct_factual_checks')
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        # The R140 fixture tests source notes in isolation; the consuming
        # broker additionally requires original work/attempt identity fields.
        fx.f.work.update(work_item_sha256='e'*64,
                         attempt_number=1,previous_attempt_id=None)
        fx.f.rebuild()
        return fx

    @staticmethod
    def context(fx):
        f=fx.f
        return {'inventory':f.inv,'plan':f.plan,'controller':f.controller,
                'asset':f.asset,'step':f.step,'work':f.work,
                'source_loader':lambda path:Path(path).read_bytes()}

    def test_whole_twenty_original_literals_source_bound_in_native_packets(self):
        fx=self.fixture();ctx=self.context(fx)
        baseline=fx.read()
        self.assertEqual(len(IDS),20)
        self.assertEqual(len(set(IDS)&set(FULL_LITERAL_REVIEWED)),0)
        self.assertEqual(len({v for rid in IDS for v in NATIVE_RULES[rid][1]}),60)
        self.assertEqual(baseline['native_conditions_evaluated'],60)
        for rid in IDS:
            with self.subTest(id=rid):
                packet=build_packet(ctx,rid)
                expected=baseline['rules'][rid]['native_original_file_criteria']
                self.assertEqual(packet['rule']['checks'],expected)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertFalse(packet['rule'].get('advancement_authorized',False))

    def test_replay_blocks_unreviewed_full_promotion_for_entire_macro(self):
        fx=self.fixture();ctx=self.context(fx)
        for rid in IDS:
            with self.subTest(id=rid):
                packet=build_packet(ctx,rid)
                row=ctx['inventory']['rules'][rid]
                expected=binding(ctx['work'],row,rid)
                spec={'validator_id':VALIDATORS[rid],
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256'],
                      'source_ref':'1'*40}
                with self.assertRaisesRegex(ValueError,'NOT_WHITELISTED'):
                    replay(None,packet,expected,spec,
                           source_context=lambda _:ctx)

    def test_original_photo_change_recomputes_source_digest_not_only_name(self):
        fx=self.fixture();ctx=self.context(fx)
        rid='AAA-200-C-026'
        before=build_packet(ctx,rid)
        fx.contents['PHOTO_FRONT']=png(183)
        fx.index()
        fx.save_files()
        ctx=self.context(fx)
        after=build_packet(ctx,rid)
        self.assertNotEqual(before['rule']['proof_digest'],
                            after['rule']['proof_digest'])
        self.assertEqual(after['rule']['result'],'UNKNOWN')

    def test_missing_original_reference_pin_is_not_inferred_as_valid_photo(self):
        fx=self.fixture();ctx=self.context(fx)
        ctx['plan']['reference_evidence_contract']['artifact_sha256'].pop('PHOTO_FRONT')
        fx.f.rebuild()
        ctx=self.context(fx)
        packet=build_packet(ctx,'AAA-200-C-021')
        self.assertFalse(packet['rule']['checks'][
            'original_photo_front_is_valid_png_bytes'])

    def test_wrong_license_claim_cannot_certify_license_rights(self):
        fx=self.fixture()
        # Note may be source-pinned, yet licensor identity remains
        # unverifiable. Native source-only rule must NEVER be FULL.
        packet=build_packet(self.context(fx),'AAA-200-C-029')
        self.assertEqual(packet['rule']['result'],'UNKNOWN')
        self.assertNotIn('AAA-200-C-029',FULL_LITERAL_REVIEWED)

    def test_producer_packet_digest_replacement_cannot_authorize(self):
        fx=self.fixture();ctx=self.context(fx)
        rid='AAA-200-A-009'
        packet=build_packet(ctx,rid)
        spoofed=copy.deepcopy(packet)
        spoofed['rule']['proof_digest']='0'*64
        row=ctx['inventory']['rules'][rid]
        expected=binding(ctx['work'],row,rid)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40}
        with self.assertRaises(ValueError):
            native_rule_readback(None,spoofed,expected,spec,
                                 source_context=lambda _:ctx)

    def test_forged_attempt_cannot_replay_any_p0_literal(self):
        fx=self.fixture()
        ctx=self.context(fx)
        ctx['work']=dict(ctx['work'],attempt_id='0'*64)
        for rid in ('AAA-200-A-001','AAA-200-C-030'):
            with self.subTest(id=rid):
                with self.assertRaises(ValueError):
                    build_packet(ctx,rid)

if __name__=='__main__':
    unittest.main()
