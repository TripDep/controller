"""Auxiliary dependency tests for 110_ERROR_REGISTRY, not MG0 proofs."""
import copy
import unittest
from c07_macro100_domain import Context, evaluate
from c07_macro100_regressions import REGRESSIONS
from test_c07_macro100_semantics import t,H,J,BLOBS,PERSISTENCE,case,claim,action,run,mutate


def contact(role):
    return {'required_contacts':[{'role':role,'member':'roof','support':'column','max_gap_metres':0.01,'min_overlap_area_m2':0.1}],
            'contact_measurements':[{'member':'roof','support':'column','gap_metres':0,'overlap_area_m2':0.2}]}


def delivery():
    return {'artifact_sha256':H,'at':t(10)}


persist=copy.deepcopy(PERSISTENCE)
persist['writes'][0]['status']='PERSISTED'
CASES=[
case('064',{'world_measurements':[{'id':'m','state':'UNKNOWN'}],
            'world_coordinate_uses':[{'measurement_id':'m','state':'UNKNOWN','value':None}]},('world_coordinate_uses',0,'value'),0),
case('065',{'asset_revisions':[{'id':'v1','state':'FAIL'},{'id':'v2','kind':'CORRECTION','addresses_revision':'v1'}]},('asset_revisions',1,'kind'),'NEW_FEATURE'),
case('066',{'owner_review_states':[{'artifact_sha256':H,'state':'PENDING','lock_state':'LOCKED'}],
            'delivery_events':[dict(delivery(),presented_state='PENDING',lock_state='LOCKED')]},('delivery_events',0,'presented_state'),'ACCEPTED'),
case('067',{'state_snapshots':[{'role':r,'sha256':H,'master_sha256':H,'audit_tail':J,'asset_revision':'v1'}
                             for r in ('MASTER','WORK_STATE','AUDIT','HANDOFF')]},('state_snapshots',2,'audit_tail'),H),
case('068',{'production_graph':{'revision':'R112','sha256':H},'active_graph':{'purpose':'PRODUCTION','revision':'R112','sha256':H}},('active_graph','revision'),'R111'),
case('069',persist,('writes',0,'status'),'FAILED'),
case('070',{'integral_source':{'sha256':H},'integral_copy':{'sha256':H}},('integral_copy','sha256'),J),
case('071',contact('ROOF_CHAIN'),('contact_measurements',0,'gap_metres'),0.1),
case('072',contact('LOAD_BEARING'),('contact_measurements',0,'overlap_area_m2'),0),
case('073',{'structural_members':[{'id':'base','role':'FOUNDATION'},{'id':'roof','role':'ROOF'}],
            'contact_measurements':[{'member':'roof','support':'base','gap_metres':0,'overlap_area_m2':1}],
            'contact_tolerance_metres':0.01},('contact_measurements',0,'gap_metres'),1),
case('074',{'quality_issues':[{'id':'f','artifact_sha256':H,'severity':'HARD_FAIL','resolved_at':t(5)}],
            'delivery_events':[delivery()]},('quality_issues',0,'resolved_at'),None),
case('075',{'asset_revisions':[{'id':'v1','state':'ACCEPTED'}],'selected_baselines':[{'revision_id':'v1'}]},('asset_revisions',0,'state'),'HARD_FAIL'),
case('076',{'asset_statuses':[{'artifact_sha256':H,'geometry':'PASS','materials':'PASS','runtime':'UNKNOWN','owner_acceptance':'PENDING'}],
            'claims':[claim('ASSET_STATUS',artifact_sha256=H,geometry='PASS',materials='PASS',runtime='UNKNOWN',owner_acceptance='PENDING')]},
     ('claims',0,'owner_acceptance'),'ACCEPTED'),
case('077',{'objective':{'owner_id':'owner'},'delivery_receipts':[{'artifact_sha256':H,'recipient':'owner','channel':'CHAT','at':t(5)}],
            'claims':[claim('DELIVERED',artifact_sha256=H,at=t(10))]},('delivery_receipts',0,'channel'),'LOCAL_FILE'),
case('078',{'reference_dimensions':[{'id':'cad','value':11540,'unit':'mm'}],
            'asset_dimensions':[{'reference_id':'cad','value':11.54,'unit':'m','tolerance_metres':0.001}]},('asset_dimensions',0,'value'),11540),
case('079',{'architectural_features':[{'id':'end','function':'WALL','opening_type':'SOLID','construction_type':'TIMBER'}],
            'candidate_features':[{'id':'end','function':'WALL','opening_type':'SOLID','construction_type':'TIMBER'}]},('candidate_features',0,'opening_type'),'WINDOW'),
case('080',{'intersection_measurements':[{'pair_role':'DIAGONAL_PANEL','penetration_metres':0,'allowed_penetration_metres':0.001}]},('intersection_measurements',0,'penetration_metres'),0.2),
case('081',{'tool_trials':[{'tool':'sculpt','demonstrated_capabilities':['organic'],'at':t(1)}],'selected_tool':'sculpt',
            'objective':{'required_capabilities':['organic']},'actions':[dict(action(),kind='MODEL')]},('tool_trials',0,'demonstrated_capabilities'),['boxes']),
case('082',{'method_iterations':[{'method':'sculpt','quality_score':1},{'method':'sculpt','quality_score':2}],
            'abort_policy':{'stagnant_iteration_limit':1}},('method_iterations',1,'quality_score'),1),
case('083',{'asset_revisions':[{'id':'v1','kind':'BASE','state':'ACCEPTED'},
                              {'id':'v2','kind':'PATCH','base_revision':'v1','state':'WIP'}]},('asset_revisions',0,'state'),'REJECTED'),
case('084',{'organic_volume':{'extents_metres':[1,1,0.5],'volume_m3':0.1},
            'organic_volume_reference':{'minimum_depth_ratio':0.3,'maximum_depth_ratio':1}},('organic_volume','extents_metres'),[1,1,0.01]),
case('085',{'anatomical_ratios':[{'feature':'head','minimum':0.3,'maximum':0.5,'style_id':'ref'}],
            'candidate_anatomical_ratios':[{'feature':'head','value':0.4,'style_id':'ref'}]},('candidate_anatomical_ratios',0,'value'),0.9),
case('086',{'body_cross_sections':[{'area_m2':1},{'area_m2':2},{'area_m2':1}],
            'body_reference':{'minimum_area_variation':1.5}},('body_cross_sections',1,'area_m2'),1),
case('087',{'organic_joints':[{'radius_metres':0.2,'minimum_reference_radius':0.1,'gap_metres':0,'maximum_gap_metres':0.01,
                              'anatomical_attachment':'shoulder','reference_attachment':'shoulder'}]},('organic_joints',0,'radius_metres'),0.001),
case('088',{'organic_pose_contacts':[{'support_kind':'ROCK','reference_support_kind':'ROCK','gap_metres':0,'maximum_gap_metres':0.01,
                                    'bearing_area_m2':1,'minimum_bearing_area_m2':0.2}]},('organic_pose_contacts',0,'support_kind'),'ARTIFICIAL_POST'),
case('089',{'visual_reviews':[{'artifact_sha256':H,'conclusion':'ACCEPTABLE'}],
            'claims':[claim('DELIVERABLE',artifact_sha256=H)]},('visual_reviews',0,'conclusion'),'AMORPHOUS'),
case('090',{'objective':{'owner_id':'owner'},'visual_review_policy':{'view_ids':['front','back']},
            'visual_reviews':[{'artifact_sha256':H,'reviewer':'qa','at':t(2),'view_ids':['front','back']}],
            'delivery_events':[delivery()]},('visual_reviews',0,'view_ids'),['front']),
case('091',{'transforms':[{'id':'obj','matrix':[1]*16,'locked_matrix':[1]*16,'tolerance':0.001}]},('transforms',0,'matrix'),[2]*16),
case('092',{'intersection_measurements':[{'pair_role':'ROOF_STRUCTURE','penetration_metres':0,'allowed_penetration_metres':0.001}]},('intersection_measurements',0,'penetration_metres'),0.1),
case('093',{'small_component_alignment':[{'component_center':[0,0,0],'opening_center':[0,0,0],'tolerance_metres':0.001}]},('small_component_alignment',0,'component_center'),[0.1,0,0]),
case('094',{'carpentry_comparisons':[{'joint_type':'mortise','reference_joint_type':'mortise','member_function':'beam',
                                    'reference_member_function':'beam','min_proportion':0.5,'max_proportion':0.7,'measured_proportion':0.6}]},
     ('carpentry_comparisons',0,'joint_type'),'stacked_blocks'),
case('095',{'locked_materials':[{'slot':'roof','material_sha256':H}],
            'material_assignments':[{'slot':'roof','material_sha256':H}]},('material_assignments',0,'material_sha256'),J),
case('096',{'palette_samples':[{'linear_rgb':[0.1,0.1,0.1],'reference_linear_rgb':[0.1,0.1,0.1],'maximum_rgb_distance':0.1}]},
     ('palette_samples',0,'linear_rgb'),[1,1,1]),
case('097',{'glass_optical_trials':[{'shader':'glass','expected_shader':'glass','min_transmission':0.5,'max_transmission':1,
                                    'measured_transmission':0.8,'reflected_energy':0.2,'transmitted_energy':0.8}]},
     ('glass_optical_trials',0,'transmitted_energy'),0),
case('098',{'vegetation_materials':[{'card_count':10,'solid_branch_count':2,'alpha_mode':'MASK','native_shader':'foliage','reference_shader':'foliage'}]},
     ('vegetation_materials',0,'alpha_mode'),'OPAQUE'),
case('099',{'runs':[run(environment='FIVEM',artifact_sha256=H,measured_leaf_displacement_metres=0.1)],
            'claims':[claim('VEGETATION_WIND',run_id='run',artifact_sha256=H)]},('runs',0,'environment'),'BLENDER'),
case('100',{'requested_parts':[{'id':'bread','identity':'bread','minimum_quality':8},{'id':'patty','identity':'patty','minimum_quality':8}],
            'asset_parts':[{'part_id':'bread','identity':'bread','quality_score':9,'object_id':'one'},
                           {'part_id':'patty','identity':'patty','quality_score':9,'object_id':'two'}]},('asset_parts',1,'object_id'),'one'),
case('101',{'objective':{'deliverable_ids':['d'],'deliverable_kind':'MODEL'},'delivery_events':[{'artifact_id':'d','kind':'MODEL'}]},('delivery_events',0,'kind'),'REPORT'),
case('102',{'status_updates':[{'observation_ids':['o'],'at':t(2)}],'result_observations':[{'id':'o','at':t(1)}]},('status_updates',0,'observation_ids'),[]),
case('103',{'complaints':[{'id':'i'}],'repairs':[{'issue_id':'i','verified_at':t(2)}],
            'responses':[{'kind':'APOLOGY','addresses_issue':'i','at':t(1)},{'kind':'APOLOGY','addresses_issue':'i','at':t(3)}]},('repairs',0,'verified_at'),t(4)),
case('104',{'responses':[{'kind':'RESULT'}]},('responses',0,'kind'),'REQUEST_TRUST'),
case('105',{'binary_answers':[{'answer':'NO','qualified_answer':'NO','material_condition_position':1,'answer_position':0}]},('binary_answers',0,'answer'),'YES'),
case('106',{'diagnoses':[{'classification':'BUG','trial_id':'t','scope':'local'}],
            'diagnostic_trials':[{'id':'t','supported_classification':'BUG','scope':'local'}]},('diagnoses',0,'classification'),'PLATFORM_LIMIT'),
case('107',{'deployments':[{'revision':'v1','environment':'prod','connected_at':t(1)}],
            'claims':[claim('PRODUCTION_COMPLETE',revision='v1',environment='prod',at=t(2))]},('claims',0,'revision'),'v2'),
case('108',{'visual_reviews':[{'artifact_sha256':H,'at':t(1),'conclusion':'ACCEPTABLE'}],
            'delivery_events':[delivery()]},('visual_reviews',0,'conclusion'),'UNACCEPTABLE'),
case('109',{'stop_instructions':[{'id':'stop','scope':'C07','at':t(1)}],
            'authorizations':[{'revokes_stop_id':'stop','authority':'OWNER','at':t(2)}],'actions':[action()]},('authorizations',0,'authority'),'PRODUCER'),
case('110',{'settings_readbacks':[{'project_id':'p','settings_sha256':H,'at':t(1)}],
            'claims':[claim('SETTINGS_ACTIVE',project_id='p',settings_sha256=H,at=t(2))]},('settings_readbacks',0,'settings_sha256'),J),
]


class AuxiliaryRegressionTests(unittest.TestCase):
    def test_all_47_dependencies_have_positive_and_counterexample(self):
        self.assertEqual({r[0] for r in CASES},{f'{i:03}' for i in range(64,111)})
        for short,data,path,bad in CASES:
            rid='BEHAVIOR-'+short
            with self.subTest(rule=rid,scenario='positive'):
                got=evaluate(REGRESSIONS[rid],Context(copy.deepcopy(data),BLOBS))
                self.assertEqual(got.result,'OBSERVED',got.reason)
            with self.subTest(rule=rid,scenario='contradiction'):
                got=evaluate(REGRESSIONS[rid],Context(mutate(data,path,bad),BLOBS))
                self.assertEqual(got.result,'FAIL',got.reason)


if __name__=='__main__':
    unittest.main()
