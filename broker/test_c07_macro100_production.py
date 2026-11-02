"""Rule-specific production counterexamples; synthetic, not certification."""
import copy
import unittest
from c07_macro100_domain import Context, evaluate
from c07_macro100_semantics import EVALUATORS
from test_c07_macro100_semantics import (t, H, J, RAW, BLOBS, PROGRESS, TELEMETRY,
                                         action, run, claim, case, mutate)


BRIEF = {'id':'goal','deliverable_ids':['d'],'requirement_ids':['r'],'workstream':'C07','owner_id':'owner'}
REF = {'id':'ref','kind':'PHOTOGRAPH','sha256':H,'subject_id':'building','origin_id':'origin','origin_url':'https://source.example/photo'}
FILE = {'id':'source','path':'sources/building_1_SOURCE_EDITABLE.blend','sha256':H,
        'asset':'building','revision':'1','role':'SOURCE_EDITABLE'}

CASES = [
case('AAA-200-A-001',{'owner_brief':BRIEF,'objective':{**BRIEF,'recorded_at':t(1),'unresolved_questions':[]},'actions':[action()]},
     ('objective','unresolved_questions'),['meaning unresolved']),
case('AAA-200-A-002',{'objective':{'deliverable_ids':['d']},'actions':[action(contributes_to=['d'])]},
     ('actions',0,'contributes_to'),['report']),
case('AAA-200-A-003',{**TELEMETRY,**PROGRESS,'progress':{'active_seconds':60,'completed_deliverables':['d']}},
     ('progress','completed_deliverables'),['activity']),
case('AAA-200-A-004',{'instruction_constraints':[{'id':'cost','subject':'operation','operator':'LE','value':0,'unit':'EUR','observation_id':'x'}],
                     'constraint_observations':[{'id':'x','subject':'operation','value':0,'unit':'EUR'}]},
     ('constraint_observations',0,'value'),10),
case('AAA-200-A-005',{'objective_revisions':[{'objective_id':'g1','at':t(1)},{'objective_id':'g2','at':t(3)}],
                     'authorizations':[{'from_objective':'g1','to_objective':'g2','authority':'OWNER','at':t(2)}],
                     'objective_change_trials':[{'id':'unused'}]}, ('authorizations',0,'authority'),'PRODUCER'),
case('AAA-200-A-006',{'objective':{'deliverable_ids':['d'],'owner_id':'owner'},
                     'quality_responsibility':{'deliverable_ids':['d'],'qa_principal':'producer'},
                     'quality_issues':[{'assigned_to':'producer','artifact_id':'d'}]},
     ('quality_responsibility','qa_principal'),'owner'),
case('AAA-200-A-007',{'quality_findings':[{'id':'f','artifact_sha256':H,'discoverable_pre_delivery':True,'detected_by':'PRODUCER','detected_at':t(1)}],
                     'delivery_events':[{'artifact_sha256':H,'at':t(3)}]}, ('quality_findings',0,'detected_by'),'OWNER'),
case('AAA-200-A-010',{'objective':{'requirement_ids':['r']},'constraints':{'additional_cost_limit':0},'selected_solution':'simple',
                     'solution_alternatives':[{'id':k,'satisfied_requirements':['r'],'additional_cost':0,'dependency_count':n,
                                               'maintenance_steps':1,'setup_steps':1} for k,n in [('simple',1),('complex',3)]]},
     ('selected_solution',),'complex'),
case('AAA-200-C-021',{'references':[REF],'research_subject':{'id':'building'},
                     'reference_origins':[{'id':'origin','image_sha256':H,'medium':'CAMERA_CAPTURE','url':REF['origin_url']}]},
     ('reference_origins',0,'medium'),'GENERATED_IMAGE'),
case('AAA-200-C-022',{'technical_reference_searches':[{'kind':k,'subject_id':'building','available_reference_ids':[k]}
                                                     for k in ('PLAN','SECTION','TECHNICAL_DRAWING')],
                     'references':[{'id':k,'kind':k,'subject_id':'building','sha256':H} for k in ('PLAN','SECTION','TECHNICAL_DRAWING')],
                     'research_subject':{'id':'building'}}, ('references',0,'kind'),'PHOTOGRAPH'),
case('AAA-200-C-023',{'reference_dimensions':[{'id':'w','subject_id':'building','unit':'m','value':12},
                                            {'id':'h','subject_id':'building','unit':'m','value':4}],
                     'proportion_studies':[{'numerator_id':'w','denominator_id':'h','ratio':3}]},
     ('proportion_studies',0,'ratio'),0.333),
case('AAA-200-C-024',{'construction_members':[{'id':'base','role':'FOUNDATION'},{'id':'column','role':'COLUMN'},{'id':'roof','role':'ROOF'}],
                     'construction_joints':[{'member':'column','support':'base','reference_sha256':H},
                                             {'member':'roof','support':'column','reference_sha256':H}]},
     ('construction_joints',0,'support'),'roof'),
case('AAA-200-C-025',{'reference_surfaces':[{'id':'s','reference_sha256':H,'sample_region':[0,0,10,10],
                                           'material':'wood','characteristic_features':['grain']}],
                     'material_studies':[{'surface_id':'s','reference_sha256':H,'sample_region':[0,0,10,10],
                                          'material':'wood','observed_features':['grain']}]},
     ('material_studies',0,'material'),'plastic'),
case('AAA-200-C-026',{'references':[dict(REF,camera_direction=[0,0,1]),dict(REF,id='side',sha256=J,camera_direction=[1,0,0])]},
     ('references',1,'camera_direction'),[0,0,1]),
case('AAA-200-C-027',{'references':[{'id':'plan'},{'id':'photo'}],
                     'reference_assignments':[{'reference_id':'plan','role':'STRUCTURAL'},{'reference_id':'photo','role':'AESTHETIC'}]},
     ('reference_assignments',0,'role'),'AESTHETIC'),
case('AAA-200-C-028',{'research_subject':{'id':'building'},
                     'historical_sources':[{'dimension':k,'sha256':H,'subject_id':'building','value':v}
                                           for k,v in [('period','p'),('place','l'),('culture','c'),('architectural_identity','a')]],
                     'historical_study':{'period':'p','place':'l','culture':'c','architectural_identity':'a'}},
     ('historical_study','place'),'wrong'),
case('AAA-200-C-029',{'references':[dict(REF,license_id='license')],
                     'license_records':[{'id':'license','terms_sha256':H,'covered_sha256':[H],'granted_rights':['REFERENCE'],
                                         'attribution_required':['author'],'territories':['WORLD'],'valid_from':t(0),'valid_until':t(30)}],
                     'reference_uses':[{'reference_id':'ref','rights_required':['REFERENCE'],'attribution_provided':['author'],
                                        'territory':'WORLD','at':t(10)}]}, ('reference_uses',0,'rights_required'),['REDISTRIBUTE']),
case('AAA-200-C-030',{'references':[dict(REF,acquired_at=t(1))],'research_subject':{'id':'building'},
                     'reference_collection':{'reference_ids':['ref'],'frozen_at':t(2)},
                     'actions':[dict(action(),kind='BLOCKOUT')]}, ('reference_collection','frozen_at'),t(30)),
case('AAA-200-R-171',{'source_files':[FILE],'objective':{'asset_id':'building'},
                     'source_layout':{'role_roots':{'SOURCE_EDITABLE':'sources'},'name_template':'{asset}_{revision}_{role}'}},
     ('source_files',0,'path'),'exports/building_1_SOURCE_EDITABLE.blend'),
case('AAA-200-R-172',{'source_files':[FILE,{'id':'export','path':'exports/output.glb','role':'NATIVE_EXPORT','sha256':J},
                                              {'id':'delivery','path':'delivery/output.zip','role':'DELIVERY_PACKAGE','sha256':H}],
                     'export_lineage':[{'source_id':'source','export_id':'export','delivery_id':'delivery','export_sha256':J,'source_sha256':H}]},
     ('export_lineage',0,'source_sha256'),J),
case('AAA-200-R-173',{'version_history':[{'id':'v1','snapshot_sha256':H,'parents':[]},{'id':'v2','snapshot_sha256':J,'parents':['v1']}],
                     'restore_trial':{'revision_id':'v1','restored_sha256':H}}, ('restore_trial','restored_sha256'),J),
case('AAA-200-R-174',{'owner_approvals':[{'decision':'ACCEPT','artifact_sha256':H}],
                     'backup_copies':[{'original_sha256':H,'copy_sha256':H,'copy_path':'/backup','original_path':'/original'}]},
     ('backup_copies',0,'copy_path'),'/original'),
case('AAA-200-R-175',{'automation_comparisons':[{'manual_trials':[{'input_sha256':k,'output_sha256':H,'seconds':10} for k in (H,J)],
                                               'automated_trials':[{'input_sha256':k,'output_sha256':H,'seconds':1} for k in (H,J)],
                                               'expected_repetitions':10,'setup_seconds':20}]},
     ('automation_comparisons',0,'setup_seconds'),1000),
case('AAA-200-R-176',{'runs':[run(exit_code=0,inputs_sha256=J,output_sha256=H)],
                     'script_expectations':[{'run_id':'run','output_sha256':H,'inputs_sha256':J}]}, ('runs',0,'output_sha256'),J),
case('AAA-200-R-177',{'protected_assets':[{'sha256':H,'current_sha256':H,'path':'/approved','locked_at':t(1)}],
                     'writes':[{'path':'/approved','sha256':H,'at':t(2)}]}, ('writes',0,'sha256'),J),
case('AAA-200-R-178',{'task_states':[{'id':'a','state':'DONE','last_event_id':'e1','depends_on':[]},
                                    {'id':'b','state':'RUNNING','last_event_id':'e2','depends_on':['a']}],
                     'task_dependencies':[{'task_id':'b','depends_on':'a','sha256':H}],
                     'task_events':[{'id':'e1','task_id':'a','state':'DONE','at':t(1)},
                                    {'id':'e2','task_id':'b','state':'RUNNING','at':t(2)}]},
     ('task_states',1,'state'),'DONE'),
case('AAA-200-R-179',{'resume':{'checkpoint_id':'cp','state_sha256':H,'at':t(10)},
                     'checkpoints':[{'id':'cp','sha256':H,'state_sha256':H,'completed_operation_ids':['done'],'next_operation':'next'}],
                     'actions':[action(operation_id='next')]}, ('actions',0,'operation_id'),'done'),
case('AAA-200-R-180',PROGRESS, ('progress','completed_deliverables'),['report']),
]


class ProductionDomainTests(unittest.TestCase):
    def test_all_28_positive_and_specific_counterexamples(self):
        self.assertEqual({r[0] for r in CASES},{rid for rid in EVALUATORS if rid.startswith('AAA-')})
        for rid, data, path, bad in CASES:
            with self.subTest(rule=rid,scenario='satisfying_observations'):
                got=evaluate(EVALUATORS[rid],Context(copy.deepcopy(data),BLOBS))
                self.assertEqual(got.result,'OBSERVED',got.reason)
            with self.subTest(rule=rid,scenario='contradiction'):
                got=evaluate(EVALUATORS[rid],Context(mutate(data,path,bad),BLOBS))
                self.assertEqual(got.result,'FAIL',got.reason)

    def test_constraint_operator_not_silently_treated_as_true(self):
        case=next(r for r in CASES if r[0]=='AAA-200-A-004')
        changed=mutate(case[1],('instruction_constraints',0,'operator'),'UNDERSTAND_PROSE')
        self.assertEqual(evaluate(EVALUATORS[case[0]],Context(changed)).result,'UNKNOWN')

    def test_geometry_proximity_is_not_a_support_path(self):
        data=next(r[1] for r in CASES if r[0]=='AAA-200-C-024')
        changed=mutate(data,('construction_joints',1,'support'),'roof')
        self.assertEqual(evaluate(EVALUATORS['AAA-200-C-024'],Context(changed,BLOBS)).result,'FAIL')

    def test_same_photo_reused_for_two_angles_does_not_count(self):
        data=next(r[1] for r in CASES if r[0]=='AAA-200-C-026')
        changed=mutate(data,('references',1,'sha256'),H)
        self.assertEqual(evaluate(EVALUATORS['AAA-200-C-026'],Context(changed,BLOBS)).result,'FAIL')

    def test_license_attribution_and_expiration_are_both_enforced(self):
        data=next(r[1] for r in CASES if r[0]=='AAA-200-C-029')
        for path,bad in [(('reference_uses',0,'attribution_provided'),[]),(('reference_uses',0,'at'),t(31))]:
            with self.subTest(path=path):
                self.assertEqual(evaluate(EVALUATORS['AAA-200-C-029'],Context(mutate(data,path,bad),BLOBS)).result,'FAIL')

    def test_restoring_after_overwrite_does_not_erase_historical_violation(self):
        data=copy.deepcopy(next(r[1] for r in CASES if r[0]=='AAA-200-R-177'))
        data['writes']=[{'path':'/approved','sha256':J,'at':t(2)},{'path':'/approved','sha256':H,'at':t(3)}]
        self.assertEqual(evaluate(EVALUATORS['AAA-200-R-177'],Context(data,BLOBS)).result,'FAIL')

    def test_missing_protected_bytes_stays_unknown(self):
        data=next(r[1] for r in CASES if r[0]=='AAA-200-R-177')
        self.assertEqual(evaluate(EVALUATORS['AAA-200-R-177'],Context(data,{})).result,'UNKNOWN')


if __name__=='__main__':
    unittest.main()
