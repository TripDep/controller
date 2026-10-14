"""C07 source-specific R173 P0 documentary verifier regression tests."""
import copy
import json
import unittest
from unittest.mock import patch

import r173_rule_semantics as r
import supervisor_judgment as j
from test_supervisor_judgment import work,inventory

def fixture():
    bank={'bridge_deck_walkability':'UNKNOWN','water_final_level_gta_z':'UNKNOWN_NO_PLANE_EXPORTED',
          'artist_approval':'PENDING','AAA200':'R172_BLOCKED_NOT_PROMOTED','R98_source_changed':False,
          'stage':'DESIGN_REVIEW_NOT_PRODUCTION'}
    source={'collision_walkability':'UNKNOWN','water_final_Z':'UNKNOWN',
            'status':'ARTISTIC_REVIEW_CANDIDATE_NOT_ACCEPTED_NOT_FIVEM',
            'bridge_landings_pending':[{'name':str(i),'reason':'unverified','start':[i,0],'target':[i,1]} for i in range(8)],
            'max_centerline_designed_grade':0.13793,'slope_over_5percent_total_m':136.24,
            'new_route_count':20,'total_length_m':1102.7,
            'gate_source_copy':'R169 rotated preview only; source R98 untouched',
            'explicitly_rejected_assets':'R170_R171 environment intentionally excluded',
            'terrain':'R101 DESIGN EVIDENCE ONLY, not complete mesh terrain',
            'R101_world_position':'local datum NOT GTA absolute origin',
            'export_GLB_render':'UNVERIFIED_PENDING_INDEPENDENT_REIMPORT',
            'source_R169_SHA256':'a'*64,'source_R101_SHA256':'b'*64}
    road={'slope_collision_artistic':'NOT_ACCEPTED','status':'GEOMETRY_PREVIEW_COLLISION_VOLUMES_NOT_FIVEM_CONVERTED'}
    context={'market':'BLEND NOT INCLUDED -- FOOTPRINT REFERENCE ONLY','acceptance':'NONE',
             'source_old_GLBG_HA':'e'*64,'source_non_gate_accepted_node_count':992}
    reports={
       'R173_BANK_DESIGN_AND_INTEGRATION_QA.json':bank,
       'R173_SOURCE_GEOMETRY_QA.json':source,
       'R173_ROAD_VOLUME_AND_PREVIEW_LODS_QA.json':road,
       'R173_R98_SCHEMATIC_CONTEXT_QA.json':context}
    packet={'reports':{k:{'raw_text':json.dumps(v)} for k,v in reports.items()}}
    requirements={number:text for number,text in r.RULES.values()}
    cat={'schema':'GG_AAA200_CATALOG_V1','catalog':[{'id':i,
           'requirement':requirements.get(i,''),
           'phase':'P0','asset_type':'all'} for i in range(1,201)]}
    return json.dumps(packet).encode(),json.dumps(cat).encode()

class Tests(unittest.TestCase):
    def report(self,packet=None,catalog=None):
        raw,can=fixture()
        raw=packet if packet is not None else raw
        can=catalog if catalog is not None else can
        with patch.object(r,'verify_qa',return_value={'binary_asset_contents_read_by_git':False,
             'advancement_authorized':False,'qa_metadata_contents_and_consistency':'PASS'}),patch.object(r,'CATALOG_SHA',r.sha(can)):
            return r.inspect(raw,can)

    def test_nine_distinct_real_requirement_predicates(self):
        verdict=self.report()
        self.assertEqual(set(verdict['results']),set(r.RULES))
        self.assertTrue(all(x['documentary_result']=='PASS' for x in verdict['results'].values()))
        self.assertEqual(verdict['individual_rule_mg0_passes'],0)
        self.assertFalse(verdict['advancement_authorized'])

    def test_unknown_water_is_required_not_assumed_complete(self):
        raw,cat=fixture();p=json.loads(raw);s=p['reports']['R173_SOURCE_GEOMETRY_QA.json']
        v=json.loads(s['raw_text']);v['water_final_Z']='VERIFIED'
        s['raw_text']=json.dumps(v)
        verdict=self.report(json.dumps(p).encode(),cat)
        self.assertEqual(verdict['results']['AAA-200-A-008']['documentary_result'],'FAIL')
        self.assertEqual(verdict['results']['AAA-200-B-018']['documentary_result'],'FAIL')

    def test_suppressed_r172_block_does_not_pass_risk_rule(self):
        raw,cat=fixture();p=json.loads(raw)
        s=p['reports']['R173_BANK_DESIGN_AND_INTEGRATION_QA.json'];v=json.loads(s['raw_text'])
        v['AAA200']='CLOSED';s['raw_text']=json.dumps(v)
        verdict=self.report(json.dumps(p).encode(),cat)
        self.assertEqual(verdict['results']['AAA-200-B-018']['documentary_result'],'FAIL')

    def test_catalog_requirement_change_rejected(self):
        raw,cat=fixture();c=json.loads(cat);c['catalog'][17]['requirement']='another requirement'
        with self.assertRaisesRegex(ValueError,'R173_RULE_CANONICAL_ID_REQUIREMENT_DRIFT'):
            self.report(raw,json.dumps(c).encode())

    def test_binding_to_current_controller_work_stays_unknown(self):
        doc=self.report()
        inv=inventory()
        inv['canonical_master_sha256']=r.MASTER_SHA
        inv['families']['AAA-200']=list(r.RULES)
        for rid in r.RULES:
            req=r.RULES[rid][1]
            inv['rules'][rid]={'family':'AAA-200','source_sha256':'d'*64,
                               'requirement_sha256':r.sha(req.encode()),
                               'requirement':req}
        w=work();w['master_sha256']=r.MASTER_SHA;w['phase']='P0';w['asset_type']='terrain'
        packets=r.packets_for_current_work(doc,w,inv)
        self.assertEqual(len(packets),len(r.RULES))
        self.assertTrue(all(p['rule']['result']=='PASS' for p in packets.values()))
        self.assertTrue(all(p['mg0']['result']=='UNKNOWN' for p in packets.values()))

    def test_native_consumer_rechecks_actual_rule_checks_and_does_not_accept_pass_tag(self):
        report=self.report()
        inv=inventory()
        inv['canonical_master_sha256']=r.MASTER_SHA
        inv['families']['AAA-200']=list(r.RULES)
        for rid in r.RULES:
            req=r.RULES[rid][1]
            inv['rules'][rid]={'family':'AAA-200','source_sha256':r.CATALOG_SHA,
                               'requirement_sha256':r.sha(req.encode()),
                               'requirement':req}
        w=work();w['master_sha256']=r.MASTER_SHA;w['phase']='P0';w['asset_type']='terrain'
        packets=r.packets_for_current_work(report,w,inv)
        rid='AAA-200-B-018';packet=packets[rid]
        spec={'validator_id':r.VALIDATOR,'criteria':list(packet['rule']['checks']),
              'source_ref':'f'*40,'requirement_sha256':packet['binding']['requirement_sha256']}
        class API:
            def call(self,method,path):return {}
        with patch('broker_live_review.decode_file',return_value=b'fixture'),patch.object(r,'inspect',return_value=report):
            actual=r.native_rule_readback(API(),packet,packet['binding'],spec)
            self.assertEqual(actual['individual_rule_mg0'],'UNKNOWN')
            false=copy.deepcopy(packet);false['rule']['result']='FAIL'
            with self.assertRaisesRegex(ValueError,'R173_RULE_NATIVE_CONTENT_OR_RESULT_MISMATCH'):
                r.native_rule_readback(API(),false,packet['binding'],spec)
            false=copy.deepcopy(packet);false['mg0']['result']='PASS'
            with self.assertRaisesRegex(ValueError,'R173_RULE_NATIVE_FALSE_MG0'):
                r.native_rule_readback(API(),false,packet['binding'],spec)
            wrong=dict(spec,source_ref='mutable')
            with self.assertRaisesRegex(ValueError,'R173_RULE_NATIVE_IMMUTABLE_SOURCE_REF'):
                r.native_rule_readback(API(),packet,packet['binding'],wrong)

    def test_claimed_final_asset_rejected_by_a009_and_b017(self):
        raw,cat=fixture();p=json.loads(raw)
        item=p['reports']['R173_SOURCE_GEOMETRY_QA.json']
        doc=json.loads(item['raw_text'])
        doc['status']='FINAL_ACCEPTED'
        doc['export_GLB_render']='PASS'
        item['raw_text']=json.dumps(doc)
        verdict=self.report(json.dumps(p).encode(),cat)
        self.assertEqual(verdict['results']['AAA-200-A-009']['documentary_result'],'FAIL')
        self.assertEqual(verdict['results']['AAA-200-B-017']['documentary_result'],'FAIL')

    def test_rejected_environment_promoted_is_caught_by_b015(self):
        raw,cat=fixture();p=json.loads(raw)
        item=p['reports']['R173_SOURCE_GEOMETRY_QA.json']
        doc=json.loads(item['raw_text'])
        doc['explicitly_rejected_assets']='R170_R171 restored'
        item['raw_text']=json.dumps(doc)
        verdict=self.report(json.dumps(p).encode(),cat)
        self.assertEqual(verdict['results']['AAA-200-B-015']['documentary_result'],'FAIL')

    def test_dependencies_hidden_is_caught_by_b016(self):
        raw,cat=fixture();p=json.loads(raw)
        item=p['reports']['R173_SOURCE_GEOMETRY_QA.json']
        doc=json.loads(item['raw_text'])
        doc['bridge_landings_pending']=[]
        item['raw_text']=json.dumps(doc)
        verdict=self.report(json.dumps(p).encode(),cat)
        self.assertEqual(verdict['results']['AAA-200-B-016']['documentary_result'],'FAIL')

    def test_scope_documentation_removed_is_caught_by_b011(self):
        raw,cat=fixture();p=json.loads(raw)
        item=p['reports']['R173_SOURCE_GEOMETRY_QA.json']
        doc=json.loads(item['raw_text'])
        doc['new_route_count']=0
        item['raw_text']=json.dumps(doc)
        verdict=self.report(json.dumps(p).encode(),cat)
        self.assertEqual(verdict['results']['AAA-200-B-011']['documentary_result'],'FAIL')

    def test_approved_source_inventory_tamper_fails_b014(self):
        raw,cat=fixture();packet=json.loads(raw)
        item=packet['reports']['R173_R98_SCHEMATIC_CONTEXT_QA.json']
        v=json.loads(item['raw_text'])
        v['source_non_gate_accepted_node_count']=0
        item['raw_text']=json.dumps(v)
        report=self.report(json.dumps(packet).encode(),cat)
        self.assertEqual(report['results']['AAA-200-B-014']['documentary_result'],'FAIL')

    def test_missing_objective_slope_criterion_fails_b020(self):
        raw,cat=fixture();packet=json.loads(raw)
        item=packet['reports']['R173_SOURCE_GEOMETRY_QA.json']
        v=json.loads(item['raw_text'])
        v['slope_over_5percent_total_m']=0
        item['raw_text']=json.dumps(v)
        report=self.report(json.dumps(packet).encode(),cat)
        self.assertEqual(report['results']['AAA-200-B-020']['documentary_result'],'FAIL')

    def test_real_work_scope_mismatch_blocked(self):
        doc=self.report();inv=inventory();w=work()
        with self.assertRaises((ValueError,j.Blocked)):r.packets_for_current_work(doc,w,inv)

if __name__=='__main__':unittest.main()
