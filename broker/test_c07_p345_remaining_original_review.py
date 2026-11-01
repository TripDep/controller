"""Adversarial source-byte tests for the 13 P3/P4/P5 remaining candidates.

Every literal has an actual original-byte positive observation and a
rule-specific missing-pre-D-pin negative. None is FULL or operational MG0.
"""
import copy
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p345_forty_native_evidence import P345Forty, encoded
from test_c07_p3_uv_semantics import uv_glb
from test_c07_p5_budget_semantics import with_embedded_texture
from test_c07_p4_texture_semantics import material
from test_c07_p5_full_review import two_material_bindings
from test_c07_p5_optimization_semantics import rewrite_glb
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import QUAD, NORMALS
from test_c07_p4_texture_semantics import png, solid, gradient
from c07_p345_remaining_original_review import (
    RULES, CRITERIA, inspect, baked_normal_channels_valid, triangle_counts)
from c07_p345_forty_native_evidence import IDS as P345_IDS
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, build_packet)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding

PIN={
118:'P3_ATLAS_BASELINE',
119:'P3_BAKED_NORMAL',
120:'P3_APPROVED_EXPORT',
133:'P4_GEOMETRY_DEFECT_REPORT',
134:'LIGHT_DIRECT_VIEW',
135:'LIGHT_SHADOW_VIEW',
136:'REFLECTION_VIEW',
139:'VISUAL_VIEW_UNDERSIDE',
140:'P345_QA_REPORT',
143:'P5_HIDDEN_BASELINE',
145:'LOD_EXPORT',
147:'P5_PERF_BUDGET',
150:'P5_RUNTIME_CAPTURE',
}
def tangent_normals():
    return [[(110+8*x,115+8*y,252,255) for x in range(4)]
            for y in range(4)]

def decorated(doc):
    doc['materials'][0]['normalTexture']={'index':0}
    doc['materials'][0]['pbrMetallicRoughness']['metallicFactor']=0.85

def reversed_winding_native():
    # Same triangle coordinates, count, materials and UV, but reversed
    # front-face winding. This can make the approved mesh render differently.
    source=with_embedded_texture(uv_glb(
        faces=[(0,2,1),(0,3,2)],with_texture=False),
        png(tangent_normals()))
    source=rewrite_glb(source,material)
    native=rewrite_glb(source,decorated)
    def second(doc):
        doc['meshes'][0]['primitives'].append(
            copy.deepcopy(doc['meshes'][0]['primitives'][0]))
    return rewrite_glb(native,second)

class RemainingP345Tests(unittest.TestCase):
    def context(self):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P345Forty,'test_p4_30_due_and_p5_40_due')
        test.f.plan['phase']='P5'
        test.f.work['phase']='P5'
        source=with_embedded_texture(uv_glb(with_texture=False),
                                     png(tangent_normals()))
        source=rewrite_glb(source,material)
        native=rewrite_glb(source,decorated)
        # Two real primitives share the same embedded base-color image;
        # reusing one image in two slots of a single primitive is not reuse.
        def second_primitive(doc):
            doc['meshes'][0]['primitives'].append(
                copy.deepcopy(doc['meshes'][0]['primitives'][0]))
        native=rewrite_glb(native,second_primitive)
        baseline=two_material_bindings(native)
        test.add('NATIVE_EXPORT','scene.glb',native)
        test.add('P3_ATLAS_BASELINE','atlas_baseline.glb',baseline)
        test.add('P3_ATLAS_POLICY','atlas_policy.json',encoded({
            'min_material_binding_reduction':1,
            'min_atlas_color_variance':5,
            'max_atlas_sample_rgb_delta':0}))
        test.add('P3_BAKE_POLICY','bake_policy.json',
                 encoded({'normal_bake_required':True}))
        test.add('P3_BAKED_NORMAL','baked_normal.png',png(tangent_normals()))
        test.add('P3_APPROVED_EXPORT','approved_export.glb',native)
        test.add('P4_GEOMETRY_DEFECT_REPORT','defects.json',
                 encoded({'degenerate_triangle_count':0}))
        test.add('P5_HIDDEN_BASELINE','hidden_before.glb',baseline)
        test.add('P5_HIDDEN_GEOMETRY_POLICY','hidden_policy.json',
                 encoded({'min_removed_triangles':2}))
        test.add('LOD_EXPORT','far.glb',
                 glb(QUAD,[(0,1,2),(0,2,3)],NORMALS))
        budget={'max_triangles':200,'material_count_budget':8,
            'shared_material_ids':['metal'], 'max_texture_mb':100,
            'target_frame_ms':16.7,'lod_max_triangle_ratio':0.6,
            'lod_bounds_tolerance_m':0.01,
            'lod_surface_deviation_m':0.01,
            'min_shared_texture_bindings':2,
            'min_reused_texture_variance':5}
        test.add('P5_PERF_BUDGET','perf.json',encoded(budget))
        test.add('P5_RUNTIME_CAPTURE','runtime_capture.json',
                 encoded({'frame_ms_samples':[12]*12}))
        for role,val in [('LIGHT_NEUTRAL_VIEW',90),
                         ('LIGHT_DIRECT_VIEW',180),
                         ('LIGHT_SHADOW_VIEW',30),
                         ('LIGHT_CINEMATIC_VIEW',130),
                         ('REFLECTION_VIEW',170),
                         ('VISUAL_VIEW_UNDERSIDE',110),
                         ('LOD_NEAR_VIEW',80),
                         ('LOD_FAR_VIEW',120)]:
            test.add(role,role.lower()+'.png',png(solid(val)))
        test.sync()
        ctx['controller']=test.f.controller
        return test,ctx

    def test_all_thirteen_have_distinct_real_source_predicates_no_full(self):
        self.assertEqual(len(RULES),13)
        self.assertEqual(len(P345_IDS),40)
        self.assertEqual(set(P345_IDS)&set(NATIVE_RULES),set(P345_IDS))
        self.assertEqual(len(set(x for row in CRITERIA.values()
                                 for x in row)),39)
        _,ctx=self.context()
        for rid in sorted(RULES):
            with self.subTest(rule=rid):
                packet=build_packet(ctx,rid)
                self.assertEqual(set(packet['rule']['checks']),
                                 set(NATIVE_RULES[rid][1]))
                self.assertEqual(packet['rule']['result'],
                    'PASS' if rid in ('AAA-200-L-118','AAA-200-L-119','AAA-200-L-120','AAA-200-O-143')
                    else 'UNKNOWN')
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                self.assertEqual(rid in FULL_LITERAL_REVIEWED,
                    rid in ('AAA-200-L-118','AAA-200-L-119','AAA-200-L-120',
                            'AAA-200-O-143','AAA-200-O-147'))
                self.assertFalse(packet['mg0']['checks'].get(
                    'canonical_triggers_checked',True))
                self.assertFalse(packet['rule']['checks'][
                    CRITERIA[int(rid[-3:])][-1]] if int(rid[-3:]) not in
                    (118,119,120,143,147) else False)

    def test_each_rule_loses_its_source_observation_when_original_pin_removed(self):
        for n,role in PIN.items():
            with self.subTest(rule=n,role=role):
                test,ctx=self.context()
                rid=next(x for x in RULES if int(x[-3:])==n)
                before=build_packet(ctx,rid)
                test.f.plan['p345_evidence_contract'][
                    'original_artifact_sha256'].pop(role)
                test.f.rebuild()
                ctx['controller']=test.f.controller
                after=build_packet(ctx,rid)
                self.assertEqual(after['rule']['result'],'UNKNOWN')
                self.assertNotEqual(before['rule']['checks'],
                                    after['rule']['checks'])

    def test_positive_source_benefits_measured_not_promoted_to_full(self):
        _,ctx=self.context()
        for n in (118,119,133,134,135,136,139,140,143,145,147,150):
            rid=next(x for x in RULES if int(x[-3:])==n)
            with self.subTest(rule=n):
                packet=build_packet(ctx,rid)
                checks=packet['rule']['checks']
                self.assertTrue(checks[CRITERIA[n][0]])
                self.assertTrue(checks[CRITERIA[n][1]])
                self.assertEqual(packet['rule']['result'],
                    'PASS' if n in (118,119,143) else 'UNKNOWN')
        rid=next(x for x in RULES if x.endswith('-120'))
        self.assertTrue(build_packet(ctx,rid)['rule']['checks'][
            CRITERIA[120][1]])

    def test_literal_specific_negative_measurements(self):
        for n,role,new in (
            (118,'P3_ATLAS_BASELINE',None),
            (119,'P3_BAKED_NORMAL',png(solid(20))),
            (120,'P3_APPROVED_EXPORT',glb(QUAD,[(0,1,2)],NORMALS)),
            (133,'P4_GEOMETRY_DEFECT_REPORT',
                 encoded({'degenerate_triangle_count':99})),
            (134,'LIGHT_DIRECT_VIEW',png(solid(20))),
            (135,'LIGHT_SHADOW_VIEW',png(solid(240))),
            (136,'REFLECTION_VIEW',png(solid(90))),
            (139,'P345_QA_REPORT',
                 encoded({'unresolved_findings':['',None]})),
            (140,'LIGHT_CINEMATIC_VIEW',png(solid(90))),
            (143,'P5_HIDDEN_BASELINE',None),
            (145,'LOD_EXPORT',None),
            (147,'P5_PERF_BUDGET',encoded({'min_shared_texture_bindings':9})),
            (150,'P5_RUNTIME_CAPTURE',
                 encoded({'frame_ms_samples':[400]*12})),
        ):
            with self.subTest(rule=n):
                test,ctx=self.context()
                rid=next(x for x in RULES if int(x[-3:])==n)
                before=build_packet(ctx,rid)['rule']['checks']
                if new is None:
                    new=test.art['NATIVE_EXPORT']
                ext=('.glb' if role in ('P3_ATLAS_BASELINE',
                    'P3_APPROVED_EXPORT','P5_HIDDEN_BASELINE','LOD_EXPORT')
                    else '.png' if role in ('P3_BAKED_NORMAL',
                    'LIGHT_DIRECT_VIEW','LIGHT_SHADOW_VIEW',
                    'REFLECTION_VIEW','LIGHT_CINEMATIC_VIEW') else '.json')
                test.add(role,role.lower()+ext,new)
                test.sync()
                ctx['controller']=test.f.controller
                after=build_packet(ctx,rid)['rule']['checks']
                self.assertNotEqual(before,after)
                self.assertFalse(after[CRITERIA[n][1]] if n!=118 else
                                 after[CRITERIA[n][2]])

    def test_baked_normal_original_channels_reject_grayscale_photo(self):
        test,ctx=self.context()
        rid='AAA-200-L-119'
        positive=build_packet(ctx,rid)['rule']['checks']
        self.assertTrue(all(positive.values()))
        invalid=png(gradient())
        self.assertFalse(baked_normal_channels_valid(invalid))
        self.assertTrue(baked_normal_channels_valid(png(tangent_normals())))
        raw=with_embedded_texture(uv_glb(with_texture=False),invalid)
        raw=rewrite_glb(raw,decorated)
        def second(doc):
            doc['meshes'][0]['primitives'].append(
                copy.deepcopy(doc['meshes'][0]['primitives'][0]))
        raw=rewrite_glb(raw,second)
        test.add('NATIVE_EXPORT','scene.glb',raw)
        test.add('P3_BAKED_NORMAL','baked_normal.png',invalid)
        test.sync()
        ctx['controller']=test.f.controller
        negative=build_packet(ctx,rid)['rule']['checks']
        # PNG SHA, GLTF normalTexture and UV are still correct; its actual
        # decoded vectors are not physically usable tangent-space normals.
        self.assertTrue(negative[CRITERIA[119][1]])
        self.assertFalse(negative[CRITERIA[119][2]])

    def test_atlas_requires_same_actual_triangle_surfaces_not_only_bbox(self):
        test,ctx=self.context()
        rid='AAA-200-L-118'
        original=build_packet(ctx,rid)['rule']['checks']
        self.assertTrue(original[CRITERIA[118][2]])
        changed=two_material_bindings(uv_glb(
            faces=[(0,1,3),(1,2,3)],with_texture=True))
        test.add('P3_ATLAS_BASELINE','atlas_baseline.glb',changed)
        test.sync()
        ctx['controller']=test.f.controller
        result=build_packet(ctx,rid)['rule']['checks']
        self.assertTrue(result[CRITERIA[118][1]])
        self.assertFalse(result[CRITERIA[118][2]])

    def test_atlas_color_fidelity_rejects_changed_original_uv_pixels(self):
        test,ctx=self.context()
        rid='AAA-200-L-118'
        self.assertTrue(build_packet(ctx,rid)['rule']['checks'][
            CRITERIA[118][2]])
        changed=with_embedded_texture(uv_glb(with_texture=False),
                                      png(solid(25)))
        changed=rewrite_glb(changed,decorated)
        def second(doc):
            doc['meshes'][0]['primitives'].append(
                copy.deepcopy(doc['meshes'][0]['primitives'][0]))
        changed=rewrite_glb(changed,second)
        changed=two_material_bindings(changed)
        test.add('P3_ATLAS_BASELINE','atlas_baseline.glb',changed)
        test.sync()
        ctx['controller']=test.f.controller
        checks=build_packet(ctx,rid)['rule']['checks']
        self.assertTrue(checks[CRITERIA[118][1]])
        self.assertFalse(checks[CRITERIA[118][2]])

    def test_original_triangle_winding_and_duplicate_multiplicity_are_real_semantics(self):
        original=glb(QUAD,[(0,1,2),(0,2,3)],NORMALS)
        rotated=glb(QUAD,[(1,2,0),(2,3,0)],NORMALS)
        reversed_face=glb(QUAD,[(0,2,1),(0,2,3)],NORMALS)
        extra_duplicate=glb(QUAD,[(0,1,2),(0,2,3),(0,1,2)],NORMALS)
        self.assertEqual(triangle_counts(original),triangle_counts(rotated))
        self.assertNotEqual(triangle_counts(original),
                            triangle_counts(reversed_face))
        self.assertNotEqual(triangle_counts(original),
                            triangle_counts(extra_duplicate))

    def test_original_atlas_and_approved_export_reject_reversed_front_faces(self):
        for n,role in ((118,'P3_ATLAS_BASELINE'),
                       (120,'P3_APPROVED_EXPORT')):
            with self.subTest(rule=n):
                test,ctx=self.context()
                rid='AAA-200-'+('L')+'-%03d'%n
                before=build_packet(ctx,rid)['rule']['checks']
                self.assertTrue(before[CRITERIA[n][2 if n==118 else 1]])
                reversed_glb=reversed_winding_native()
                if n==118:
                    reversed_glb=two_material_bindings(reversed_glb)
                test.add(role,role.lower()+'.glb',reversed_glb)
                test.sync()
                ctx['controller']=test.f.controller
                after=build_packet(ctx,rid)['rule']['checks']
                self.assertFalse(after[CRITERIA[n][2 if n==118 else 1]])
                self.assertEqual(build_packet(ctx,rid)['rule']['result'],
                                 'FAIL' if n in (118,120) else 'UNKNOWN')

    def test_approved_export_same_bbox_and_count_but_different_faces_fails(self):
        test,ctx=self.context()
        rid='AAA-200-L-120'
        self.assertTrue(build_packet(ctx,rid)['rule']['checks'][
            CRITERIA[120][1]])
        changed=uv_glb(faces=[(0,1,3),(1,2,3)],with_texture=False)
        # Preserve both the number of triangles and the original bounding box.
        test.add('P3_APPROVED_EXPORT','approved_export.glb',changed)
        test.sync()
        ctx['controller']=test.f.controller
        result=build_packet(ctx,rid)['rule']['checks']
        self.assertFalse(result[CRITERIA[120][1]])

    def test_hidden_geometry_must_remove_redundant_original_triangles(self):
        test,ctx=self.context()
        rid='AAA-200-O-143'
        self.assertTrue(build_packet(ctx,rid)['rule']['checks'][
            CRITERIA[143][1]])
        changed=glb(QUAD,[(0,1,3),(0,3,2),
                          (0,1,2),(0,2,3),
                          (0,1,3),(0,3,2)],NORMALS)
        test.add('P5_HIDDEN_BASELINE','hidden_before.glb',changed)
        test.sync()
        ctx['controller']=test.f.controller
        result=build_packet(ctx,rid)['rule']['checks']
        self.assertFalse(result[CRITERIA[143][1]])

    def test_lod_missing_half_surface_rejected_despite_same_bbox(self):
        test,ctx=self.context()
        rid='AAA-200-O-145'
        self.assertTrue(build_packet(ctx,rid)['rule']['checks'][
            CRITERIA[145][1]])
        # One diagonal half of the same square retains the full bounding box
        # and satisfies the reduction ratio, but loses half the visible face.
        test.add('LOD_EXPORT','far.glb',
                 glb(QUAD,[(0,1,2)],NORMALS))
        test.sync()
        ctx['controller']=test.f.controller
        checks=build_packet(ctx,rid)['rule']['checks']
        self.assertTrue(checks[CRITERIA[145][0]])
        self.assertFalse(checks[CRITERIA[145][1]])

    def test_reuse_requires_distinct_native_primitives_not_shader_slots(self):
        test,ctx=self.context()
        rid='AAA-200-O-147'
        self.assertTrue(build_packet(ctx,rid)['rule']['checks'][
            CRITERIA[147][1]])
        # The single primitive still references the same PNG in base color
        # and normal slots, but that is not cross-primitive texture reuse.
        def one_primitive(doc):
            doc['meshes'][0]['primitives']=doc['meshes'][0]['primitives'][:1]
        source=rewrite_glb(test.art['NATIVE_EXPORT'],one_primitive)
        test.add('NATIVE_EXPORT','scene.glb',source)
        test.sync()
        ctx['controller']=test.f.controller
        result=build_packet(ctx,rid)['rule']['checks']
        self.assertFalse(result[CRITERIA[147][1]])

    def test_current_attempt_and_original_source_tamper_block(self):
        test,ctx=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):
            build_packet(ctx,'AAA-200-O-150')
        test,ctx=self.context()
        (test.f.root/'scene.glb').write_bytes(b'forged original')
        with self.assertRaises(ValueError):
            build_packet(ctx,'AAA-200-L-118')

    def test_all_candidates_are_explicitly_not_whitelisted_for_dispatch(self):
        _,ctx=self.context()
        for rid in sorted(RULES):
            with self.subTest(rule=rid):
                packet=build_packet(ctx,rid)
                expected=binding(ctx['work'],ctx['inventory']['rules'][rid],rid)
                spec={'validator_id':'native-original-rule-'+
                      rid.lower().replace('-','_')+'-v1',
                      'criteria':list(NATIVE_RULES[rid][1]),
                      'requirement_sha256':expected['requirement_sha256'],
                      'source_ref':'1'*40}
                if rid in ('AAA-200-L-118','AAA-200-L-119',
                           'AAA-200-L-120','AAA-200-O-143','AAA-200-O-147'):
                    result=replay(None,packet,expected,spec,
                        source_context=lambda _:ctx)
                    self.assertEqual(result['documentary_result'],
                        'UNKNOWN' if rid=='AAA-200-O-147' else 'PASS')
                else:
                    with self.assertRaisesRegex(ValueError,'NOT_WHITELISTED'):
                        replay(None,packet,expected,spec,
                               source_context=lambda _:ctx)

if __name__=='__main__':
    unittest.main()
