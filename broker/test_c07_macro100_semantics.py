"""Synthetic development tests; neither native observations nor MG0 evidence."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from c07_macro100_domain import Context, evaluate, interval_union, duration, range_covered
from c07_macro100_semantics import EVALUATORS, BEHAVIOR_ALL, combine, Finding, main
from c07_macro100_evidence_gate import BATCH_IDS
from approved_validators import REVIEWED
from real_work_intake import canonical, sha


def t(second):
    return f'2026-11-02T00:{second//60:02}:{second%60:02}+00:00'


RAW = b'original snapshot\n'
OTHER = b'altered snapshot\n'
H = hashlib.sha256(RAW).hexdigest()
J = hashlib.sha256(OTHER).hexdigest()
BLOBS = {H: RAW, J: OTHER}


def action(**kw):
    return dict(id='a', at=t(20), workstream='C07', kind='IMPLEMENT', **kw)


def run(**kw):
    return dict(id='run', **kw)


def claim(kind, **kw):
    return dict(id='claim', kind=kind, **kw)


def case(rid, data, path, bad):
    return rid, data, path, bad


PROGRESS = {
    'objective': {'deliverable_ids': ['d']},
    'deliverables_before': [{'id': 'd', 'state': 'PENDING', 'sha256': J}],
    'deliverables_after': [{'id': 'd', 'state': 'VERIFIED', 'sha256': H}],
    'progress': {'completed_deliverables': ['d']},
}
TELEMETRY = {
    'window': {'start': t(0), 'end': t(120)},
    'sessions': [{'id': 's1', 'started': t(0), 'work_ended': t(40)},
                 {'id': 's2', 'started': t(30), 'work_ended': t(60)}],
}
PERSISTENCE = {
    'writes': [{'id': 'w', 'sha256': H, 'path': '/canonical', 'version': 7, 'at': t(10)}],
    'readbacks': [{'id': 'r', 'sha256': H, 'path': '/canonical', 'version': 7, 'at': t(11)}],
    'claims': [claim('PERSISTED', write_id='w', readback_id='r', path='/canonical', version=7, at=t(12))],
}


BEHAVIOR_CASES = [
case('001', {'objective': {'workstream': 'C07'}, 'actions': [action()]}, ('actions',0,'workstream'), 'GARDEN'),
case('002', {'active_issue': {'id':'issue'}, 'responses':[{'at':t(1),'addresses_issue':'issue'}]},
     ('responses',0,'addresses_issue'), 'different'),
case('003', {'objective':{'primary_measurement':'duty'}, 'measurements':[{'quantity':'duty','at':t(1)}],
             'actions':[dict(action(),kind='DESIGN')]}, ('measurements',0,'at'), t(21)),
case('004', {'bottleneck':{'target':'production','resolved_at':t(10)},
             'actions':[dict(action(),kind='OPTIMIZE',target='telemetry')]}, ('bottleneck','resolved_at'),t(30)),
case('005', PROGRESS, ('progress','completed_deliverables'), ['report']),
case('006', {'objective':{'workstream':'OLD'},'actions':[action()],
             'scope_changes':[{'from':'OLD','to':'C07','authority':'OWNER','at':t(10)}]},
     ('scope_changes',0,'at'),t(30)),
case('007', {'stages':[{'name':k,'completed_at':t(n)} for k,n in [('A',1),('B',2),('C',3)]],
             'actions':[action()]}, ('stages',1,'completed_at'),t(21)),
case('008', {'objective':{'id':'goal'},'resume':{'checkpoint_id':'cp','objective_id':'goal','state_sha256':H},
             'checkpoints':[{'id':'cp','sha256':H,'objective_id':'goal','state_sha256':H}]},
     ('resume','state_sha256'),J),
case('009', {'active_issue':{'id':'issue','workstream':'C07'},
             'responses':[{'kind':'PROPOSAL','addresses_issue':'issue','workstream':'C07'}]},
     ('responses',0,'workstream'),'GARDEN'),
case('010', {**PROGRESS,'actions':[action()], 'progress':{'completed_deliverables':['d'],'activity_count':1,'delivered_ids':['receipt']},
             'delivery':{'receipt_ids':['receipt']}}, ('progress','activity_count'),99),
case('011', {'prices':[{'resource':'cpu','observed_at':t(10),'valid_until':t(30)}],
             'actions':[action(resources=['cpu'])]}, ('prices',0,'observed_at'),t(25)),
case('012', {'constraints':{'additional_cost_limit':0},
             'resource_proposals':[{'setup_cost':0,'recurring_cost':0,'usage_cost':0}]},
     ('resource_proposals',0,'recurring_cost'),1),
case('013', {'constraints':{'additional_cost_limit':0},
             'entitlements':[{'resource':'api','remaining_included_units':10,'separately_billed':False}],
             'resource_proposals':[{'resource':'api','required_units':10,'unit_price':1,'usage_cost':0}]},
     ('resource_proposals',0,'required_units'),11),
case('014', {'constraints':{'cost':0},'preflight':{'checked_constraints':['cost'],'at':t(1)},'actions':[action()]},
     ('preflight','at'),t(30)),
case('015', {'constraints':{'forbidden_hosts':['PERSONAL_PC']},'runtime_dependencies':[{'host':'EXISTING_RUNNER'}]},
     ('runtime_dependencies',0,'host'),'PERSONAL_PC'),
case('016', {'deployments':[{'id':'deploy','environment':'cloud','revision':'v1','connected_at':t(1)}],
             'claims':[claim('CAPABILITY_AVAILABLE',deployment_id='deploy',environment='cloud',revision='v1',at=t(10))]},
     ('claims',0,'revision'),'v2'),
case('017', {'objective':{'id':'goal'},'environment':{'id':'env'},'constraints':{'cost':0},
             'preflight':{'objective_id':'goal','environment':'env','constraints':{'cost':0},'operation':'op','at':t(2)},
             'authorizations':[{'objective_id':'goal','operation':'op','at':t(1)}]},
     ('preflight','environment'),'different'),
case('018', {'runtime_dependencies':[{'id':'dep'}], 'dependency_trials':[
             {'dependency':'dep','variant':'WITH','inputs_sha256':H,'satisfied_requirements':['r']},
             {'dependency':'dep','variant':'WITHOUT','inputs_sha256':H,'satisfied_requirements':[]}]},
     ('dependency_trials',1,'satisfied_requirements'),['r']),
case('019', {'runs':[run(environment='PRODUCTION',deployment_id='d',health_endpoint='/health',started=t(1),observed_alive_at=t(20))],
             'claims':[claim('PERMANENT_RUNTIME',run_id='run',deployment_id='d',health_endpoint='/health',at=t(10))]},
     ('claims',0,'at'),t(21)),
case('020', {'sequence_correction':{'before':['B','A','C'],'after':['A','B','C'],'required_order':['A','B','C']}},
     ('sequence_correction','after'),['A','C','B']),
case('021', {**TELEMETRY,'claims':[claim('CONTINUITY',calendar_seconds=120,active_seconds=60,continuous=False)]},
     ('claims',0,'continuous'),True),
case('022', {**TELEMETRY,'telemetry_report':{'active_seconds':60,'idle_seconds':60,'duty_cycle':0.5}},
     ('telemetry_report','active_seconds'),70),
case('023', {'scheduler_configurations':[{'id':'cfg','period_seconds':3600}],
             'claims':[claim('SCHEDULER_LIMIT',configuration_id='cfg',scope='CONFIGURATION',period_seconds=3600)]},
     ('claims',0,'scope'),'PLATFORM'),
case('024', {'continuity_alternatives':[{'id':'a'}], 'continuity_trials':[{'alternative_id':'a','outcome':'UNSATISFIED'}],
             'claims':[claim('CONTINUITY_IMPOSSIBLE',scope='TESTED_ALTERNATIVES',alternative_ids=['a'])]},
     ('claims',0,'scope'),'UNIVERSAL'),
case('025', {'provider_limits':[{'id':'l','platform':'p','configuration':'c','max_seconds':60,'valid_from':t(0),'valid_until':t(30)}],
             'claims':[claim('DURATION_MAXIMUM',provider_limit_id='l',platform='p',configuration='c',max_seconds=60,at=t(10))]},
     ('claims',0,'max_seconds'),30),
case('026', {'provider_events':[{'id':'e','run_id':'run','cause':'TIMEOUT'}],
             'claims':[claim('TERMINATION_CAUSE',provider_event_id='e',run_id='run',cause='TIMEOUT')]},
     ('claims',0,'cause'),'EXECUTION_BUDGET'),
case('027', {'runs':[run(final_checkpoint_id='cp')],
             'checkpoints':[{'id':'cp','sha256':H,'run_id':'run','state':'CLOSED','persisted_at':t(10)}],
             'claims':[claim('RUN_COMPLETED',run_id='run',at=t(11))]}, ('checkpoints',0,'state'),'SCHEDULED'),
case('028', {'fault_injections':[{'id':'f','target_revision':'v1','at':t(1)}],
             'monitor_inspections':[{'id':'i','fault_id':'f','target_revision':'v1','at':t(2)}],
             'notifications':[{'inspection_id':'i','delivered_at':t(3)}]}, ('notifications',0,'delivered_at'),None),
case('029', {'runs':[run(environment='PRODUCTION'),{'id':'resumed','environment':'PRODUCTION','trigger':'SCHEDULER',
                       'resumed_checkpoint_id':'cp','started':t(3),'first_operation':'next'}],
             'checkpoints':[{'id':'cp','sha256':H,'run_id':'run','persisted_at':t(2),'next_operation':'next'}],
             'claims':[claim('AUTOMATIC_RESUME',resumed_run_id='resumed',interrupted_run_id='run',environment='PRODUCTION')]},
     ('runs',1,'trigger'),'MANUAL'),
case('030', {'incidents':[{'id':'i','domain':'PLATFORM','affected_projects':['p']}],
             'claims':[claim('PROJECT_BLOCKER',incident_id='i',domain='PLATFORM',project_id='p')]},
     ('claims',0,'domain'),'ASSET_DEFECT'),
case('031', {**TELEMETRY,'telemetry_report':{'at':t(10),'duty_cycle':0.5},
             'actions':[dict(action(),kind='EXPAND_PIPELINE')]}, ('telemetry_report','at'),t(30)),
case('032', {'runs':[run(environment='LOCAL')],
             'claims':[claim('NUMERIC_EXAMPLE',basis='SIMULATION',label='HYPOTHETICAL')]},
     ('claims',0,'label'),'MEASURED'),
case('033', {**TELEMETRY,'claims':[claim('LOST_TIME',basis='OBSERVATION',seconds=60,window=TELEMETRY['window'])]},
     ('claims',0,'seconds'),72000),
case('034', {'remaining_work':[{'id':'part','units':4,'unit':'part'}],
             'throughput_samples':[{'units':2,'unit':'part','active_seconds':10,'method':'m'}],
             'forecast':{'label':'ESTIMATE','active_seconds':20,'remaining_ids':['part'],'method':'m'}},
     ('forecast','active_seconds'),200),
case('035', {'sessions':[{'id':'s','work_ended':t(10),'audit_closed':t(11),'persisted_at':t(12),'execution_ended':t(13)}]},
     ('sessions',0,'execution_ended'),t(10)),
case('036', {'sessions':[{'id':'run','termination_cause':'TIMEOUT','termination_event_id':'e'}],
             'provider_events':[{'id':'e','run_id':'run','cause':'TIMEOUT'}]}, ('provider_events',0,'run_id'),'other'),
case('037', {'runs':[run(environment='PRODUCTION')],
             'monitor_inspections':[{'monitor_id':'m','target_id':'target','started':t(1),'at':t(2),'run_id':'run'}],
             'claims':[claim('WATCHDOG_ACTIVE',monitor_id='m',target_id='target',environment='PRODUCTION',at=t(3))]},
     ('monitor_inspections',0,'target_id'),'other'),
case('038', {'monitor_inspections':[{'monitor_id':'m'}],'notification_settings':{'m':False},
             'claims':[claim('MONITORING_CAPABILITY',monitor_id='m',detection_available=True,notification_enabled=False)]},
     ('claims',0,'detection_available'),False),
case('039', {'runs':[run(environment='LOCAL',exercised_capabilities=['kill_recovery'])],
             'claims':[claim('RECOVERY_TEST',run_id='run',environment='LOCAL',capabilities=['kill_recovery'])]},
     ('claims',0,'environment'),'PRODUCTION'),
case('040', {**TELEMETRY,'checkpoints':[{'id':'cp','sha256':H,'state_sha256':H}],
             'recovery_report':{'checkpoint_id':'cp','recovered_state_sha256':H,'idle_seconds':60,'uninterrupted':False}},
     ('recovery_report','uninterrupted'),True),
case('041', {'runs':[run(environment='PRODUCTION',kind='ACCEPTANCE',satisfied_requirements=['r'])],
             'objective':{'requirement_ids':['r']},'environment':{'id':'PRODUCTION'},
             'claims':[claim('OBJECTIVE_COMPLETE',run_ids=['run'])]}, ('runs',0,'kind'),'UNIT_TEST'),
case('042', {'runs':[run(environment='LOCAL',started=t(1),ended=t(3),workload_sha256=H)],
             'claims':[claim('BENCHMARK',run_id='run',environment='LOCAL',workload_sha256=H,metric='ELAPSED_SECONDS',value=2)]},
     ('claims',0,'environment'),'CLOUD'),
case('043', {'runs':[run(environment='LOCAL')], 'deployments':[{'id':'unused'}],
             'claims':[claim('WORKER_STATE',run_id='run',state='LOCALLY_TESTED_CANDIDATE')]},
     ('claims',0,'state'),'DEPLOYED'),
case('044', {'objective':{'deliverable_ids':['d'],'deliverable_kind':'GAME_ASSET'},
             'deliverables_after':[{'id':'d','kind':'GAME_ASSET'}],'progress':{'completed_deliverables':['d']}},
     ('deliverables_after',0,'kind'),'REPORT'),
case('045', {'deliverables_after':[{'id':'d','kind':'GAME_ASSET','state':'RUNTIME_VERIFIED'}],
             'claims':[claim('GAME_READY_COUNT',artifact_ids=['d'],count=1)]}, ('deliverables_after',0,'kind'),'SCAN_SAMPLE'),
case('046', {'runs':[run(output_sha256=H,kind='ACCEPTANCE',feature_id='f',actual_result=42,expected_result=42,environment='prod')],
             'claims':[claim('FEATURE_USABLE',run_id='run',feature_id='f',environment='prod')]},
     ('runs',0,'actual_result'),0),
case('047', {'runs':[run(prompt_sha256=H,started=t(3),regression_classes=['old_bug'],actual_result=42,expected_result=42)],
             'prompt_changes':[{'id':'change','after_sha256':H,'installed_at':t(2),'failure_class':'old_bug'}],
             'claims':[claim('PROMPT_FIX_COMPLETE',change_id='change',run_id='run')]}, ('runs',0,'prompt_sha256'),J),
case('048', {'runs':[run(intercepted_paths=['/checked'])],
             'claims':[claim('ENFORCEMENT_SCOPE',run_ids=['run'],paths=['/checked'])]},
     ('claims',0,'paths'),['/checked','/unchecked']),
case('049', {'visual_reviews':[{'artifact_sha256':H,'reference_sha256':J,'conclusion':'ACCEPTABLE'}],
             'claims':[claim('ARTISTIC_QUALITY',artifact_sha256=H,reference_sha256=J,conclusion='ACCEPTABLE')]},
     ('visual_reviews',0,'conclusion'),'UNACCEPTABLE'),
case('050', PERSISTENCE, ('readbacks',0,'sha256'),J),
case('051', {'runtime_hooks':[{'entrypoint':'/write','mode':'PRE_ACTION','controller_revision':'v1'}],
             'claims':[claim('MANDATORY_CONTROLLER',paths=['/write'],controller_revision='v1')]},
     ('runtime_hooks',0,'mode'),'MANUAL'),
case('052', {'runtime_hooks':[{'entrypoint':'/reply','mode':'PRE_RESPONSE','controller_revision':'v1'}],
             'claims':[claim('RESPONSE_GATE',response_path='/reply',controller_revision='v1')]},
     ('runtime_hooks',0,'mode'),'MANUAL'),
case('053', {'bypass_probes':[{'path':'/write','fault':f,'environment':'prod','destination_before_sha256':H,
                              'destination_after_sha256':H,'effect_count':0}
                             for f in ('FAIL','UNKNOWN','BACKEND_UNAVAILABLE')],
             'claims':[claim('FAIL_CLOSED',paths=['/write'],environment='prod')]},
     ('bypass_probes',1,'effect_count'),1),
case('054', {'control_additions':[{'diagnosis_id':'d','failure_class':'f','at':t(2)}],
             'enforcement_diagnoses':[{'id':'d','failure_class':'f','at':t(1),'existing_hook_coverage':'MISSING'}]},
     ('enforcement_diagnoses',0,'existing_hook_coverage'),'SUFFICIENT_BUT_UNUSED'),
case('055', {'claims':[claim('CONTROL_GUARANTEE',mechanism='PROJECT_INSTRUCTIONS',guarantee='INSTRUCTION_ONLY')]},
     ('claims',0,'guarantee'),'UNIVERSAL_ENFORCEMENT'),
case('056', {'settings_readbacks':[{'project_id':'p','settings_sha256':H,'at':t(1)}],
             'claims':[claim('SETTINGS_ACTIVE',project_id='p',settings_sha256=H,at=t(2))]},
     ('settings_readbacks',0,'settings_sha256'),J),
case('057', {'bypass_probes':[{'path':'/write','mode':'DIRECT_WITHOUT_CHECKER','principal':'producer','effect_count':0}],
             'claims':[claim('UNBYPASSABLE',paths=['/write'],producer_principal='producer')]},
     ('bypass_probes',0,'effect_count'),1),
case('058', {'controllers':[{'id':'ctl','domain':'ASSET'}],
             'claims':[claim('CONTROL_GUARANTEE',controller_id='ctl',domain='ASSET')]}, ('claims',0,'domain'),'BEHAVIOR'),
case('059', {**PROGRESS,'objective':{'id':'goal','deliverable_ids':['d']},
             'constraints':{'governance_seconds_limit':5},
             'work_allocations':[{'objective_id':'goal','seconds':10,'category':'PRODUCTION'},
                                 {'objective_id':'other','seconds':5,'category':'GOVERNANCE'}]},
     ('work_allocations',1,'seconds'),20),
case('060', {'response_statements':[{'response_id':'r','kind':'LIMITATION','limitation_ids':['l'],'position':1}],
             'claims':[claim('CONTROL_GUARANTEE',response_id='r',known_limitation_ids=['l'],position=0)]},
     ('response_statements',0,'position'),10),
case('061', {'master':{'sha256':H},'source_reads':[{'sha256':H,'at':t(1),'source_kind':'CANONICAL_FILE','byte_range':[0,len(RAW)]}],
             'actions':[action()]}, ('source_reads',0,'byte_range'),[0,3]),
case('062', {'master':{'sha256':H,'path':'/master','version':175},
             'readbacks':[{'sha256':H,'path':'/master','version':175}]}, ('readbacks',0,'version'),174),
case('063', {'objective':{'owner_id':'owner'},'owner_approvals':[{'artifact_sha256':H,'decision':'ACCEPT','owner_id':'owner','at':t(1)}],
             'claims':[claim('OWNER_ACCEPTED',artifact_sha256=H,at=t(2))]}, ('owner_approvals',0,'decision'),'PENDING'),
]


def mutate(data, path, value):
    out = copy.deepcopy(data)
    target = out
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return out


class BehaviorDomainTests(unittest.TestCase):
    def test_all_63_have_distinct_positive_and_counterexample(self):
        self.assertEqual({rid for rid, *_ in BEHAVIOR_CASES}, {f'{i:03}' for i in range(1,64)})
        for short, data, path, bad in BEHAVIOR_CASES:
            rid = 'BEHAVIOR-'+short
            with self.subTest(rule=rid, scenario='satisfying_observations'):
                got = evaluate(EVALUATORS[rid], Context(copy.deepcopy(data), BLOBS))
                self.assertEqual(got.result, 'OBSERVED', got.reason)
            with self.subTest(rule=rid, scenario='contradiction'):
                got = evaluate(EVALUATORS[rid], Context(mutate(data,path,bad), BLOBS))
                self.assertEqual(got.result, 'FAIL', got.reason)

    def test_missing_data_for_every_macro_and_auxiliary_rule_is_unknown(self):
        for rid, fn in {**EVALUATORS, **BEHAVIOR_ALL}.items():
            with self.subTest(rule=rid):
                self.assertEqual(evaluate(fn, Context({})).result, 'UNKNOWN')

    def test_self_reported_pass_map_is_not_observation(self):
        spoof = {'rules': {rid: {'PASS': True, 'mg0': 'PASS', 'independent': True} for rid in BATCH_IDS}}
        for rid, fn in EVALUATORS.items():
            with self.subTest(rule=rid):
                self.assertEqual(evaluate(fn, Context(spoof)).result, 'UNKNOWN')

    def test_parallel_time_is_not_double_counted(self):
        self.assertEqual(duration([(0,40),(30,60)]),60)
        self.assertEqual(interval_union([(20,30),(0,10),(10,20)]),[[0,30]])

    def test_timezone_offsets_represent_same_window(self):
        data = copy.deepcopy(TELEMETRY)
        data['sessions'][0]['started'] = '2026-11-02T01:00:00+01:00'
        self.assertEqual(Context(data).telemetry()['active_seconds'],60)

    def test_sessions_are_clipped_to_observation_window(self):
        data = copy.deepcopy(TELEMETRY)
        data['window'] = {'start':t(20),'end':t(50)}
        self.assertEqual(Context(data).telemetry()['active_seconds'],30)

    def test_read_ranges_must_cover_every_original_byte(self):
        self.assertTrue(range_covered([[0,4],[4,10]],10))
        self.assertFalse(range_covered([[0,4],[5,10]],10))
        self.assertFalse(range_covered([[0,4],[0,4]],10))

    def test_nan_does_not_become_a_number(self):
        rid,data,path,_ = next(r for r in BEHAVIOR_CASES if r[0]=='022')
        self.assertEqual(evaluate(EVALUATORS['BEHAVIOR-'+rid], Context(mutate(data,path,float('nan')))).result,'UNKNOWN')

    def test_changed_original_readback_bytes_are_not_accepted(self):
        forged = {H: OTHER, J:OTHER}
        self.assertEqual(evaluate(EVALUATORS['BEHAVIOR-050'],Context(PERSISTENCE,forged)).result,'UNKNOWN')

    def test_auxiliary_rules_do_not_change_batch_or_trusted_enrollment(self):
        self.assertEqual(set(EVALUATORS),set(BATCH_IDS))
        self.assertEqual(len(BEHAVIOR_ALL),110)
        self.assertEqual(set(BATCH_IDS)&set(REVIEWED),set())

    def test_composite_does_not_drop_failure_when_another_child_is_missing(self):
        got=combine({'a':Finding('FAIL','contradicted'),'b':Finding('UNKNOWN','missing')},'aggregate')
        self.assertEqual(got.result,'FAIL')
        self.assertEqual(set(got.measured['failed']),{'a'})
        self.assertEqual(set(got.measured['unknown']),{'b'})


if __name__ == '__main__':
    unittest.main()
