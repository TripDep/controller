import copy
import unittest
from unittest.mock import patch

from c07_macro100_domain import Context, evaluate, Finding
import c07_macro100_semantics as semantics
from c07_macro100_evidence_gate import require_complete, Macro100Blocked
from real_work_intake import canonical, sha
from test_c07_macro100_semantics import t, H, J, RAW, BLOBS, action, mutate


def audit(events):
    rows=[]
    prior='GENESIS'
    for event in events:
        row={'asset':'ASSET','event':event,'prev_hash':prior}
        row['record_hash']=sha(canonical(row))
        prior=row['record_hash']
        rows.append(row)
    return b'\n'.join(canonical(r) for r in rows)+b'\n',prior


def audit_data():
    before,_=audit(['OPEN','FAIL'])
    after,tail=audit(['OPEN','FAIL','CORRECTION'])
    a,b=sha(before),sha(after)
    return {'audit_snapshots':{'asset':'ASSET','before_sha256':a,'after_sha256':b,'state_tail':tail}}, {a:before,b:after}


QUALITY_CLASSES=['ROOF_SURFACE','RIDGE','ROOF_CENTER','SUPPORT_CHAIN','CARPENTRY','PODIUM_STAIRS',
                 'ROUND_FACETING','INTERSECTIONS','UNDERSIDE','REPETITION','LOCKED_QUALITY_REGRESSION']
CASES=[
('A',{'required_sources':[{'id':'source','sha256':H}],
       'source_reads':[{'sha256':H,'source_kind':'CANONICAL_FILE','at':t(1),'byte_range':[0,len(RAW)]}],
       'actions':[action()]},('source_reads',0,'byte_range'),[0,3]),
('B',{'proposal':{'objective_id':'goal','at':t(10)},
       'analyses':[{'dimension':k,'objective_id':'goal','at':t(1),'source_sha256':[H]}
                   for k in ('CAUSE','DEPENDENCIES','STATE','CONSTRAINTS','REGRESSIONS','IMPLICATIONS')]},
      ('analyses',0,'at'),t(11)),
('ADVERSARIAL_QA',{'adversarial_cases':[{'id':'c','run_id':'run','artifact_sha256':H,'expected_rejection':'REJECT'}],
                   'runs':[{'id':'run','input_sha256':J,'artifact_sha256':H,'actual_result':'REJECT','effect_count':0}],
                   'quality_issues':[{'severity':'MINOR','resolved_at':t(1)}]},('runs',0,'effect_count'),1),
('ARCHITECTURE_1TO1',{'architecture_authorship':[{'asset_type':'architecture','asset_id':'a','at':t(5),
                                                'authorship':'ONE_TO_ONE','source_asset':'NEW','operation':'CREATE'}],
                     'authorizations':[{'authority':'OWNER','operation':'UNRELATED'}]},
                    ('architecture_authorship',0,'authorship'),'PROCEDURAL'),
('ARCHITECTURAL_QUALITY_FLOOR',{'quality_floor':{'sha256':J},
                              'quality_floor_comparisons':[{'class':k,'candidate_sha256':H,'reference_sha256':J,'finding_count':0} for k in QUALITY_CLASSES],
                              'round_elements':[{'id':'ring','visibility':'HERO','radial_segments':48,'visible_faceting':False}]},
                             ('round_elements',0,'radial_segments'),24),
('AUTONOMOUS_PRE_PASS_QUESTION',{'verification_cycles':[{'id':'cycle','closed_at':t(10)}],
                               'autonomous_questions':[{'id':'q','cycle_id':'cycle','at':t(2),'scope':'OUTSIDE_REQUESTED_CHECKLIST','material_finding_ids':['issue']}],
                               'quality_issues':[{'id':'issue','question_id':'q','resolved_at':t(5)}]},
                              ('quality_issues',0,'resolved_at'),None),
]


class MacroTests(unittest.TestCase):
    def test_six_domain_macros_positive_and_contradiction(self):
        for rid,data,path,bad in CASES:
            with self.subTest(rule=rid,case='positive'):
                got=evaluate(semantics.EVALUATORS[rid],Context(data,BLOBS))
                self.assertEqual(got.result,'OBSERVED',got.reason)
            with self.subTest(rule=rid,case='contradiction'):
                got=evaluate(semantics.EVALUATORS[rid],Context(mutate(data,path,bad),BLOBS))
                self.assertEqual(got.result,'FAIL',got.reason)

    def test_append_only_keeps_failures_and_current_state_tail(self):
        data,blobs=audit_data()
        self.assertEqual(evaluate(semantics.append_only,Context(data,blobs)).result,'OBSERVED')
        changed,tail=audit(['OPEN','CORRECTION'])
        key=sha(changed); blobs[key]=changed
        data['audit_snapshots']['after_sha256']=key
        data['audit_snapshots']['state_tail']=tail
        self.assertEqual(evaluate(semantics.append_only,Context(data,blobs)).result,'FAIL')

    def test_error_registry_evaluates_all_110_children_even_after_failure(self):
        called=[]
        def fake(rid):
            def check(c):
                called.append(rid)
                return Finding('FAIL' if rid=='BEHAVIOR-110' else 'OBSERVED','unit test stub')
            return check
        # Only tests aggregate composition. These stubs are NOT rule evidence.
        children={rid:fake(rid) for rid in semantics.BEHAVIOR_ALL}
        with patch.dict(semantics.BEHAVIOR_ALL,children,clear=True):
            got=semantics.error_registry(Context({}))
        self.assertEqual(len(called),110)
        self.assertEqual(got.result,'FAIL')
        self.assertEqual(set(got.measured['failed']),{'BEHAVIOR-110'})

    def test_error_registry_cannot_pass_with_47_omitted_dependencies(self):
        self.assertEqual(set(semantics.BEHAVIOR_ALL),{f'BEHAVIOR-{i:03}' for i in range(1,111)})
        got=semantics.error_registry(Context({}))
        self.assertEqual(got.result,'UNKNOWN')
        self.assertEqual(len(got.measured['unknown']),110)

    def test_protocol_exposes_forbidden_publication_even_when_other_children_missing(self):
        got=evaluate(semantics.behavior_protocol,Context({'artifact_publications':[{'kind':'MODEL','destination':'GITHUB'}]}))
        self.assertEqual(got.result,'FAIL')
        self.assertIn('DELIVERY_DESTINATION',got.measured['failed'])

    def test_candidate_report_is_not_accepted_by_certifier(self):
        candidate={'schema':'gg-c07-macro100-domain-candidate-v1','rule_count':100,'rules':{},'certified_full_count':100}
        with self.assertRaisesRegex(Macro100Blocked,'CERTIFICATE_SCHEMA'):
            require_complete(candidate,{})

    def test_canonical_binding_registry_exactly_covers_cohort_and_110_children(self):
        wanted=set(semantics.BATCH_IDS)|set(semantics.BEHAVIOR_ALL)
        self.assertEqual(set(semantics.CLAUSE_BINDINGS),wanted)
        self.assertEqual(len(semantics.CLAUSE_BINDINGS),147)

    def test_compound_child_exception_is_unknown_not_global_crash(self):
        def missing(c):
            return next(iter([]))
        self.assertEqual(evaluate(missing,Context({})).result,'UNKNOWN')


if __name__=='__main__':
    unittest.main()
