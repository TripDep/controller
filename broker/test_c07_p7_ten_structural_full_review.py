"""C07 P7 whole ten-rule family: original-byte positive and adversarial replay.

Fixture XML/GLB/PNG is synthetic and proves implementation only. Never
attests a real CodeWalker/Sollumz/FiveM run or independent MG0/owner PASS.
"""
import copy
import unittest
from pathlib import Path

from test_c07_p7_rage_semantics import Tests as P7Fixture, XML, MANIFEST
from c07_p7_ten_structural_full_review import (
    RULES, STRUCTURAL, CANDIDATE, CRITERIA, inspect)
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS,
    build_packet, native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import REPLAYERS
from supervisor_judgment import binding
from c07_mg0_individual import TRIGGERS
from test_c07_positive_native_process import sha

class P7TenFullStructuralTests(unittest.TestCase):
    def setUp(self):
        self.q=P7Fixture('test_eight_scoped_observations_never_claim_game_or_sollumz_pass')
        self.q.setUp()
        self.addCleanup(self.q.doCleanups)
        # The source-only P7 fixture intentionally lacks the canonical
        # consuming-side binding fields. Supply them BEFORE rebuilding its
        # immutable operation audit; do not fake any MG0 event or PASS.
        f=self.q.f
        master=('## MG0 — PROCESS FALSIFICATION\n' +
                ''.join('- '+trigger+'\n' for trigger in TRIGGERS) +
                'The response is not limited to fixing the asset.\n' +
                'invalidate affected states and reapply the corrected process\n').encode()
        f.master=master
        f.controller.master.write_bytes(master)
        f.work.update(work_item_sha256='e'*64,
                      attempt_number=1,previous_attempt_id=None)
        f.work['master_sha256']=f.plan['master_sha256']=(
            f.inv['canonical_master_sha256'])=sha(master)
        f.rebuild()

    def ctx(self):
        f=self.q.f
        return {'inventory':f.inv,'plan':f.plan,'controller':f.controller,
                'asset':f.asset,'step':f.step,'work':f.work,
                'source_loader':lambda path:Path(path).read_bytes()}

    def test_ten_exact_source_specific_rules_six_structural_four_unattested(self):
        self.assertEqual(len(RULES),10)
        self.assertEqual(len(STRUCTURAL),6)
        self.assertEqual(len(CANDIDATE),4)
        self.assertEqual(STRUCTURAL|CANDIDATE,RULES)
        for n in range(161,171):
            rid='AAA-200-Q-%03d'%n
            with self.subTest(rule=rid):
                self.assertEqual(NATIVE_RULES[rid],
                                 ('p7_ten_structural_full',CRITERIA[n]))
                row=inspect(self.ctx(),rid)
                self.assertEqual(set(row['checks']),set(CRITERIA[n]))
                self.assertEqual(row['attempt_id'],self.q.f.work['attempt_id'])
                self.assertEqual(row['operation_sha256'],
                                 self.q.f.work['operation_sha256'])
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertFalse(row['advancement_authorized'])
                self.assertIs(row['evidence_complete'],rid in STRUCTURAL)
                self.assertIs(rid in FULL_LITERAL_REVIEWED,rid in STRUCTURAL)
                self.assertIs(rid in REPLAYERS,rid in STRUCTURAL)

    def test_six_structural_full_positive_replayed_from_original_bytes(self):
        ctx=self.ctx()
        for rid in sorted(STRUCTURAL):
            with self.subTest(rule=rid):
                expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
                packet=build_packet(ctx,rid,expected=expected)
                self.assertEqual(packet['rule']['result'],'PASS')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertFalse(packet.get('advancement_authorized',False))
                spec={'validator_id':VALIDATORS[rid],
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256']}
                result=native_rule_readback(None,packet,expected,spec,
                                            source_context=lambda _:self.ctx())
                self.assertEqual(result['documentary_result'],'PASS')
                self.assertEqual(result['individual_rule_mg0'],'UNKNOWN')

    def test_four_external_execution_and_shader_claims_never_full(self):
        for rid in sorted(CANDIDATE):
            with self.subTest(rule=rid):
                row=inspect(self.ctx(),rid)
                self.assertFalse(row['evidence_complete'])
                packet=build_packet(self.ctx(),rid)
                self.assertEqual(packet['rule']['result'],'UNKNOWN')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')

    def test_each_ten_literal_rejects_distinct_original_source_mutation(self):
        bad={
            161:('P7_FXMANIFEST',b"game 'gta5'"),
            162:('P7_YDR_XML',b'<Drawable><Name>wrong</Name></Drawable>'),
            163:('P7_YTD_XML',b'<TextureDictionary/>'),
            164:('P7_YTYP_XML',b'<CMapTypes/>'),
            165:('P7_YMAP_XML',b'<CMapData/>'),
            166:('P7_YBN_XML',b'<BoundsFile/>'),
            167:('P7_EXPORT_TRACE',{'addon':'Sollumz','asset':'wrong'}),
            168:('P7_SHADER_POLICY',{'allowed_shader_names':['unsupported']}),
            169:('P7_CODEWALKER_REPORT',{'entity_positions':[],
                                          'lod_near_m':10,'lod_far_m':100}),
            170:('P7_FIVEM_LOG',{'engine':'FiveM','asset':'wrong',
                                    'frame_ms_samples':[16.0]*20}),
        }
        for n,(role,value) in bad.items():
            rid='AAA-200-Q-%03d'%n
            with self.subTest(rule=rid):
                previous=copy.deepcopy(self.q.files[role])
                self.q.files[role]=value
                self.q.put()
                row=inspect(self.ctx(),rid)
                self.assertFalse(all(row['checks'].values()))
                self.assertFalse(row['evidence_complete'])
                packet=build_packet(self.ctx(),rid)
                self.assertNotEqual(packet['rule']['result'],'PASS')
                self.q.files[role]=previous
                self.q.put()

    def test_missing_pre_d_sha_and_cross_attempt_forgery_fail(self):
        rid='AAA-200-Q-165'
        ctx=self.ctx()
        packet=build_packet(ctx,rid)
        expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
        spec={'validator_id':VALIDATORS[rid],
              'criteria':list(NATIVE_RULES[rid][1]),
              'requirement_sha256':expected['requirement_sha256']}
        forged=copy.deepcopy(packet)
        forged['rule']['checks'][NATIVE_RULES[rid][1][0]]=False
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'C07_REPLAYER_PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:self.ctx())
        changed=copy.deepcopy(expected)
        changed['attempt_id']='0'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'C07_REPLAYER_ATTEMPT_OPERATION_SOURCE_MISMATCH'):
            build_packet(self.ctx(),rid,expected=changed)
        self.q.f.plan['p678_evidence_contract']['original_artifact_sha256'].pop(
            'P7_YMAP_XML')
        self.q.f.rebuild()
        self.assertFalse(inspect(self.ctx(),rid)['evidence_complete'])

if __name__=='__main__':
    unittest.main()
