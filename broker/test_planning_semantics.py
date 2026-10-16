import copy
import json
import unittest

import golden_controller as gc
import planning_semantics as p
import supervisor_judgment as j
from test_supervisor_judgment import work


def fixture():
    master = b'Unit authority\nDestination GTA V / FiveM\n'
    mh = p.sha(master)
    rows = []
    for step, event, stamp, category in [('0001','STEP_OPEN','2020-01-01T01:00:00+00:00','ANALYSIS'),
                                       ('0001','STEP_CLOSE','2020-01-01T01:00:10+00:00','ANALYSIS'),
                                       ('0002','STEP_OPEN','2020-01-01T01:01:00+00:00','GENERATION'),
                                       ('0002','STEP_CLOSE','2020-01-01T01:02:00+00:00','GENERATION')]:
        rows.append({'event':event,'step':step,'asset':'UNIT','action':'unit '+step,
                     'authorization_token':'token '+step,'timestamp_utc':stamp,'category':category,
                     'result':'PASS' if event=='STEP_CLOSE' else 'OPEN',
                     'master_check_before':{'sha256':mh},'master_check_after':{'sha256':mh}})
    tail = 'GENESIS'
    for row in rows:
        row['prev_hash'] = tail
        row['record_hash'] = p.sha(gc.canonical_json(row))
        tail = row['record_hash']
    manifest = {'asset':'UNIT','authority':{'master_sha256':mh},
                'checks':{str(i):{'status':'PENDING','evidence':[]} for i in range(1,201)},
                'history':[{'event':'EVIDENCED_PASS','item':12,'step':'0001',
                            'utc':'2020-01-01T01:00:10.200000+00:00','evidence_sha256':'b'*64}]}
    manifest['checks']['12'] = {'status':'PASS','evidence':[{'path':'missing.md','sha256':'b'*64}]}
    documents = {'master':master,'historical_master':master,
                 'work_state':json.dumps({'assets':{'UNIT':{'last_audit_hash':tail}}}).encode(),
                 'audit':('\n'.join(json.dumps(row) for row in rows)+'\n').encode(),
                 'asset_checks':json.dumps(manifest).encode()}
    row = {'family':'AAA-200','source_sha256':'a'*64,'requirement_sha256':'c'*64,
           'catalog_number':12,'catalog_phase':'P0'}
    inv = {'canonical_master_sha256':mh,'families':{'AAA-200':[p.ENGINE_RULE]},
           'rules':{p.ENGINE_RULE:row,'UNIT_PROFILE':{'profile':'FOLIAGE_PROFILE'}}}
    w = work(); w['master_sha256'] = mh
    policy = {'requirement_sha256':'c'*64,'historical_master_sha256':mh,'asset':'UNIT',
              'preflight_step':'0001','generation_step':'0002',
              'canonical_target_line':'Destination GTA V / FiveM','target_engine':'GTA_V_FIVEM'}
    return inv,w,documents,policy


class Tests(unittest.TestCase):
    def setUp(self): self.i,self.w,self.d,self.p = fixture()
    def run_review(self): return p.documented_engine(self.i,self.w,self.d,self.p)
    def manifest(self, change):
        value = json.loads(self.d['asset_checks']);change(value)
        self.d['asset_checks'] = json.dumps(value).encode()

    def test_actual_source_predicate_not_full_mg0_pass(self):
        packet, proof = self.run_review()
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        spec = {'validator_id':p.VALIDATOR,'criteria':p.CRITERIA}
        result = j.semantic_packet(packet,packet['binding'],spec)
        self.assertEqual(result['result'],'UNKNOWN')
        self.assertFalse(proof['asset_execution_verified'])

    def test_no_source_content_no_approval(self):
        self.d.pop('historical_master')
        with self.assertRaises(KeyError): self.run_review()

    def test_changed_master_bytes_rejected(self):
        self.d['master'] += b'changed'
        with self.assertRaisesRegex(j.Blocked,'MASTER_CONTENTS'): self.run_review()

    def test_changed_rule_source_rejected(self):
        self.p['requirement_sha256'] = 'd'*64
        with self.assertRaisesRegex(j.Blocked,'RULE_SOURCE_DRIFT'): self.run_review()

    def test_wrong_engine_cannot_pass(self):
        self.p['canonical_target_line'] = 'Destination Unreal Engine'
        packet,_ = self.run_review()
        self.assertEqual(packet['rule']['result'],'FAIL')

    def test_duplicate_engine_line_not_unique(self):
        raw = self.d['master']*2
        self.d['master'] = self.d['historical_master'] = raw
        self.w['master_sha256'] = self.i['canonical_master_sha256'] = self.p['historical_master_sha256'] = p.sha(raw)
        self.manifest(lambda x:x['authority'].update(master_sha256=p.sha(raw)))
        # Audit bindings also need the actual historical source, so cannot pass.
        packet,_ = self.run_review()
        self.assertEqual(packet['rule']['result'],'FAIL')

    def test_history_after_generation_does_not_pass(self):
        self.manifest(lambda x:x['history'][0].update(utc='2020-01-01T01:01:30+00:00'))
        packet,_ = self.run_review()
        self.assertEqual(packet['rule']['result'],'FAIL')

    def test_individual_preflight_record_required(self):
        self.manifest(lambda x:x.update(history=[]))
        with self.assertRaisesRegex(j.Blocked,'INDIVIDUAL_RECORD'): self.run_review()

    def test_another_asset_manifest_rejected(self):
        self.manifest(lambda x:x.update(asset='OTHER'))
        with self.assertRaisesRegex(j.Blocked,'ASSET_AUTHORITY'): self.run_review()

    def test_audit_tamper_rejected(self):
        self.d['audit'] = self.d['audit'].replace(b'unit 0001',b'tampered')
        with self.assertRaisesRegex(j.Blocked,'AUDIT_CHAIN'): self.run_review()

    def test_audit_tail_must_match_state(self):
        self.d['work_state'] = json.dumps({'assets':{'UNIT':{'last_audit_hash':'f'*64}}}).encode()
        with self.assertRaisesRegex(j.Blocked,'AUDIT_TAIL'): self.run_review()

    def test_upstream_pass_without_contents_stays_unretrieved(self):
        report = p.evidence_availability(json.loads(self.d['asset_checks']),{})
        self.assertEqual(len(report),200)
        self.assertEqual(report['12']['evidence_status'],'NOT_RETRIEVED')
        self.assertFalse(report['12']['semantic_pass'])

    def test_retrieved_contents_not_automatic_semantic_pass(self):
        self.manifest(lambda x:x['checks']['12']['evidence'][0].update(sha256=p.sha(b'actual contents')))
        report = p.evidence_availability(json.loads(self.d['asset_checks']),{'missing.md':b'actual contents'})
        self.assertEqual(report['12']['evidence_status'],'BYTES_RETRIEVED')
        self.assertFalse(report['12']['semantic_pass'])

    def test_wrong_evidence_digest_detected(self):
        report = p.evidence_availability(json.loads(self.d['asset_checks']),{'missing.md':b'wrong'})
        self.assertEqual(report['12']['evidence_status'],'DIGEST_MISMATCH')

    def test_omitted_rule_in_manifest_rejected(self):
        self.manifest(lambda x:x['checks'].pop('60'))
        with self.assertRaisesRegex(j.Blocked,'ALL_200_REQUIRED'):
            p.evidence_availability(json.loads(self.d['asset_checks']),{})

    def test_asset_withholding_is_not_a_missing_report(self):
        q=p.evidence_availability(json.loads(self.d['asset_checks']),{},['missing.md'])
        self.assertEqual(q['12']['evidence_status'],'ASSET_WITHHELD_NOT_CONTENT_VERIFIED')
        self.assertFalse(q['12']['semantic_pass'])

    def test_retrospective_proof_cannot_be_created_as_operational(self):
        self.w['mode']='OPERATIONAL'
        with self.assertRaisesRegex(j.Blocked,'RETROSPECTIVE_REVIEW_ONLY'):self.run_review()


    def test_native_consumer_replays_real_document_contents_and_rejects_forged_log(self):
        # Synthetic source transport: unlike a mocked positive reader result,
        # the real native consumer must actually re-run the canonical predicate.
        inv,w,docs,engine=fixture()
        original,_=p.documented_engine(inv,w,docs,engine)
        paths={
            'master':p.coverage.SOURCES['master'],
            'historical_master':p.coverage.SOURCES['master'],
            'work_state':'governance/supervisor/reviews/test/work_state.json',
            'audit':'governance/supervisor/reviews/test/audit.jsonl',
            'asset_checks':'governance/supervisor/reviews/test/asset_checks.json',
        }
        source={path:b'synthetic-source-fixture' for path in p.coverage.SOURCES.values()}
        source[paths['master']]=docs['master']
        for key,path in paths.items():source[path]=docs[key]
        inputs={key:{'path':path,'sha256':p.sha(docs[key])}
                for key,path in paths.items()}
        policy={'schema':'gg-planning-semantic-review-v1',
                'scope':'RETROSPECTIVE_DOCUMENTARY_PROCESS_REVIEW_NOT_PRODUCTION_AUTHORIZATION',
                'work':w,'engine':engine,'inputs':inputs}
        source[p.NATIVE_POLICY_PATH]=json.dumps(policy).encode()
        class API:
            def __init__(self): self.calls=[]
            def call(self,method,path):
                self.calls.append((method,path))
                return {'path':path.split('/contents/',1)[1].split('?ref=',1)[0]}
        a=API()
        ref='c'*40
        spec={'validator_id':p.VALIDATOR,'criteria':p.CRITERIA,'source_ref':ref}
        def decoded(response,path):return source[path]
        with patch('broker_live_review.decode_file',side_effect=decoded),patch.object(
                p.coverage,'build_inventory',return_value=inv):
            proof=p.native_rule_readback(a,original,original['binding'],spec)
            self.assertEqual(proof['individual_rule_mg0'],'UNKNOWN')
            self.assertFalse(proof['advancement_authorized'])
            self.assertGreater(len(a.calls),5)
            forged=copy.deepcopy(original)
            forged['rule']['result']='FAIL'
            with self.assertRaisesRegex(j.Blocked,
                                        'PLANNING_NATIVE_LOG_CANNOT_OVERRIDE_RECOMPUTED_PROOF'):
                p.native_rule_readback(a,forged,original['binding'],spec)
            old=source[paths['asset_checks']]
            source[paths['asset_checks']]=old+b'tampered'
            with self.assertRaisesRegex(j.Blocked,'PLANNING_NATIVE_INPUT_DIGEST'):
                p.native_rule_readback(a,original,original['binding'],spec)
            source[paths['asset_checks']]=old
            changed=copy.deepcopy(original['binding'])
            changed['attempt_id']='0'*64
            with self.assertRaisesRegex(j.Blocked,'PLANNING_NATIVE_CANONICAL_BINDING'):
                p.native_rule_readback(a,original,changed,spec)
            with self.assertRaisesRegex(j.Blocked,'PLANNING_NATIVE_IMMUTABLE_SOURCE_REF'):
                p.native_rule_readback(a,original,original['binding'],dict(spec,source_ref='main'))


if __name__ == '__main__': unittest.main()
