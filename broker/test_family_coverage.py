"""Synthetic coverage fixtures only; never model or execution evidence."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
import family_coverage as f

def synthetic_sources():
    parts=[];seen=set()
    for mapping in f.MASTER_BINDINGS.values():
        for prefixes in mapping.values():
            for prefix in prefixes:
                if prefix not in seen and not prefix.startswith('## EXEC-'):
                    parts.append(prefix+'\nSynthetic canonical clause.\n');seen.add(prefix)
    parts += ['## EXEC-'+str(i).zfill(3)+' — Synthetic\nClause.\n' for i in range(1,26)]
    parts += ['### Exact recovered 30-control source list\n'+'\n'.join(str(i)+'. Synthetic readiness.' for i in range(1,31)),
              '## The exact 12 provocation directions\n'+'\n'.join(str(i)+'. **Synthetic provocation**' for i in range(1,13)),
              '## Canonical 300 base questions\n'+'\n'.join(str(i)+'. Synthetic question?' for i in range(1,301)),
              '## 3A. LEGACY / ASSET-BUILD INTERNAL GATES\n'+'\n'.join('- **'+i+' Synthetic**' for i in ['G0','G1','G2','G3','G4','G5','G6','G6B','G7','G8','G9']),
              '# 13. Current Pavilion / Golden Ting state\nSynthetic historical boundary.']
    phases=('P0','P0','P0','P1','P1','P1','P2','P2','P2','P2','P2','P3','P4','P4','P5','P6','P7','P0','P8','P8')
    catalog=[];mapping=[]
    for i in range(1,201):
        section='ABCDEFGHIJKLMNOPQRST'[(i-1)//10];phase=phases[(i-1)//10]
        asset='vegetation' if section=='N' else 'all';requirement='Synthetic requirement '+str(i)+'.'
        catalog.append({'id':i,'section':section,'phase':phase,'asset_type':asset,'requirement':requirement})
        mapping.append({'id':'AAA-200-'+section+'-'+str(i).zfill(3),'catalog_number':i,'catalog_section':section,'catalog_phase':phase})
        parts.append(str(i)+'. ['+section+'] '+requirement+'  **Fase:** `'+phase+'` · **Asset:** `'+asset+'`')
    professional='## 0. Relationship to existing governance\nSynthetic.\n## 1. Professional phase gates\n'
    professional+='\n'.join('### '+p+' — Synthetic\nSynthetic phase.' for p in f.PRO_PHASES)
    professional+='\n## 2. Mandatory asset profiles\nEvery task chooses a profile.\n'
    professional+='\n'.join('### '+p+'_PROFILE\nSynthetic profile.' for p in ['ARCHITECTURE','FOLIAGE','ROCK_ROCKERY','TERRAIN_PATH','WATER_FOUNTAIN','PROP'])
    professional+='\n'+'\n'.join(p+'\nSynthetic system obligation.' for p in list(f.SYSTEM_ANCHORS.values())[1:])
    registry=[]
    for family,rows in f.MASTER_BINDINGS.items():registry.append({'id':family,'required':list(rows)})
    registry += [{'id':'EXECUTION','required':['EXEC-'+str(i).zfill(3) for i in range(1,26)]},
                 {'id':'G0_CONTROLS','required':['G0-'+str(i).zfill(2) for i in range(1,31)]},
                 {'id':'PROVOCATION','required':['PROVOCATION-'+str(i).zfill(2) for i in range(1,13)]},
                 {'id':'QUESTIONS_300','required':['Q-'+str(i).zfill(3) for i in range(1,301)]},
                 {'id':'HISTORICAL_ASSET_GATES','required':['LEGACY_'+p for p in ['G0','G1','G2','G3','G4','G5','G6','G6B','G7','G8','G9']]},
                 {'id':'BEHAVIOR','required':list(f.BEHAVIOR_BINDINGS)},
                 {'id':'BEHAVIOR_110','required':['BEHAVIOR-'+str(i).zfill(3) for i in range(1,111)]},
                 {'id':'PROFESSIONAL_PHASES','required':list(f.PRO_PHASES)}]
    sources={k:b'synthetic canonical auxiliary' for k in f.SOURCES}
    sources.update(master=('\n'.join(parts)+'\n').encode(),professional_phases=professional.encode(),
        error_registry=('\n'.join(str(i).zfill(3)+'. Errore: Synthetic rule.' for i in range(1,111))).encode(),
        aaa_catalog=json.dumps({'schema':'GG_AAA200_CATALOG_V1','catalog':catalog,'phase_order':list(f.PRO_PHASES),'asset_types':list(f.ASSET_TYPES)}).encode(),
        registry=json.dumps({'schema':'gg-rule-family-registry-v1','families':registry}).encode(),
        guard=('PHASES = '+repr(f.PHASES)+'\n').encode())
    sources['namespace']=json.dumps({'schema':'gg-aaa-namespace-policy-v1','master_rule_namespace':'MASTER','aaa_rule_namespace':'AAA-200',
          'catalog_source':f.SOURCES['aaa_catalog'],'catalog_sha256':f.sha(sources['aaa_catalog']),'mapping':mapping}).encode()
    return sources

def synthetic_ledger(inv,phase='P8',asset_type='vegetation',profiles=None):
    profiles=profiles or ['FOLIAGE_PROFILE'];groups={}
    for family,ids in inv['families'].items():
        groups[family]={}
        for rule in ids:
            row=inv['rules'][rule];proof={'ref':'synthetic-fixture/'+rule,'sha256':'e'*64}
            groups[family][rule]={'result':f.expected_result(row,phase,asset_type,profiles),
               'source_sha256':row['source_sha256'],'requirement_sha256':row['requirement_sha256'],
               'evidence':dict(proof),'mg0':{'result':'PASS','rule_id':rule,'phase':phase,
               'master_sha256':inv['canonical_master_sha256'],'evidence':dict(proof)}}
    return {'phase':phase,'families':groups}

class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.raw=synthetic_sources();self.pins=patch.object(f,'AUX_PINS',{k:f.sha(self.raw[k]) for k in f.AUX_PINS});self.pins.start();self.addCleanup(self.pins.stop)
        self.inv=self.build();self.ledger=synthetic_ledger(self.inv)
    def build(self):return f.build_inventory(self.raw,f.sha(self.raw['master']))
    def validate(self,ledger=None,phase='P8'):return f.validate_coverage(self.inv,ledger or self.ledger,phase=phase,asset_type='vegetation',profiles=['FOLIAGE_PROFILE'])
    def test_sources_add_existing_r110_profiles_and_system_requirements(self):
        self.assertEqual(self.inv['rule_count'],763);self.assertEqual(self.inv['family_count'],20);self.assertEqual(self.inv['legacy_rule_count'],551)
        self.assertEqual(len(self.inv['families']['ASSET_PROFILE_READINESS']),6);self.assertEqual(len(self.inv['families']['PROFESSIONAL_SYSTEM']),6)
    def test_complete_structure_never_certifies_work(self):
        r=self.validate();self.assertFalse(r['advancement_authorized']);self.assertEqual(r['actual_work_passes'],0);self.assertFalse(r['actual_evidence_contents_verified'])
    def test_missing_each_family_blocks(self):
        for family in self.inv['families']:
            l=copy.deepcopy(self.ledger);l['families'].pop(family)
            with self.assertRaisesRegex(f.Blocked,'LEDGER_FAMILY_COVERAGE'):self.validate(l)
    def test_missing_each_rule_blocks(self):
        for family,ids in self.inv['families'].items():
            for rule in ids:
                l=copy.deepcopy(self.ledger);l['families'][family].pop(rule)
                with self.assertRaisesRegex(f.Blocked,'LEDGER_RULE_COVERAGE'):self.validate(l)
    def test_missing_mg0_on_each_rule_blocks(self):
        for family,ids in self.inv['families'].items():
            for rule in ids:
                l=copy.deepcopy(self.ledger);l['families'][family][rule].pop('mg0')
                with self.assertRaisesRegex(f.Blocked,'LEDGER_MG0_BINDING'):self.validate(l)
    def test_registry_family_removal_is_detected_independently(self):
        r=json.loads(self.raw['registry']);r['families'].pop();self.raw['registry']=json.dumps(r).encode()
        with self.assertRaisesRegex(f.Blocked,'REGISTRY_FAMILY_'):self.build()
    def test_same_count_replacement_and_cross_family_swap_are_denied(self):
        for swap in (False,True):
            r=json.loads(self.raw['registry'])
            if swap:r['families'][0]['required'][0],r['families'][1]['required'][0]=r['families'][1]['required'][0],r['families'][0]['required'][0]
            else:r['families'][0]['required'][0]='INVENTED_RULE'
            self.raw['registry']=json.dumps(r).encode()
            with self.assertRaisesRegex(f.Blocked,'REGISTRY_RULE_SET'):self.build()
            self.raw=synthetic_sources()
    def test_duplicate_registry_family_or_rule_blocks(self):
        for duplicate_family in (False,True):
            r=json.loads(self.raw['registry'])
            if duplicate_family:r['families'].append(r['families'][0])
            else:r['families'][0]['required'].append(r['families'][0]['required'][0])
            self.raw['registry']=json.dumps(r).encode()
            with self.assertRaises(f.Blocked):self.build()
            self.raw=synthetic_sources()
    def test_master_digest_mismatch_blocks(self):
        with self.assertRaisesRegex(f.Blocked,'CURRENT_MASTER_DIGEST'):f.build_inventory(self.raw,'f'*64)
    def test_auxiliary_source_drift_blocks(self):
        self.raw['professional_phases']+=b'changed'
        with self.assertRaisesRegex(f.Blocked,'CANONICAL_AUX_DRIFT'):self.build()
    def test_master_aaa_requirement_phase_or_type_divergence_blocks(self):
        for old,new in [('Synthetic requirement 1.','Altered requirement 1.'),('**Fase:** `P0`','**Fase:** `P8`'),('**Asset:** `all`','**Asset:** `organic`')]:
            original=self.raw['master'];self.raw['master']=original.replace(old.encode(),new.encode(),1)
            with self.assertRaisesRegex(f.Blocked,'AAA_MASTER_CATALOG_DIVERGENCE'):self.build()
            self.raw['master']=original
    def test_aaa_namespace_collision_or_mapping_change_blocks(self):
        for field in ('master_rule_namespace','mapping'):
            n=json.loads(self.raw['namespace']);n[field]='changed';self.raw['namespace']=json.dumps(n).encode()
            with self.assertRaises(f.Blocked):self.build()
            self.raw=synthetic_sources()
    def test_incomplete_source_set_or_phase_chain_blocks(self):
        old=self.raw['guard'];self.raw['guard']=b'PHASES = ()\n'
        with self.assertRaisesRegex(f.Blocked,'PHASE_CHAIN'):self.build()
        self.raw['guard']=old;self.raw.pop('developer_rules')
        with self.assertRaisesRegex(f.Blocked,'SOURCE_SET'):self.build()
    def test_wrong_phase_wrong_source_or_failed_rule_blocks(self):
        for field,value in [('result','FAIL'),('source_sha256','f'*64),('requirement_sha256','f'*64)]:
            l=copy.deepcopy(self.ledger);l['families']['MASTER_CHAIN']['A'][field]=value
            with self.assertRaises(f.Blocked):self.validate(l)
        l=copy.deepcopy(self.ledger);l['phase']='P0'
        with self.assertRaisesRegex(f.Blocked,'LEDGER_PHASE'):self.validate(l)
    def test_shared_mg0_wrong_id_phase_or_master_is_denied(self):
        for field,value in [('rule_id','B'),('phase','P0'),('master_sha256','f'*64),('result','FAIL')]:
            l=copy.deepcopy(self.ledger);l['families']['MASTER_CHAIN']['A']['mg0'][field]=value
            with self.assertRaisesRegex(f.Blocked,'LEDGER_MG0_BINDING'):self.validate(l)
    def test_missing_rule_or_mg0_evidence_is_denied(self):
        for mg0 in (False,True):
            l=copy.deepcopy(self.ledger);target=l['families']['MASTER_CHAIN']['A']
            if mg0:target=target['mg0']
            target.pop('evidence')
            with self.assertRaises(f.Blocked):self.validate(l)
    def test_future_and_na_remain_visible_not_deleted_or_passed(self):
        l=synthetic_ledger(self.inv,phase='P0');r=self.validate(l,phase='P0');self.assertGreater(r['future_phase_slots'],0);self.assertGreater(r['na_slots'],0)
        l['families']['AAA-200']['AAA-200-Q-161']['result']='PASS'
        with self.assertRaisesRegex(f.Blocked,'LEDGER_RULE_RESULT'):self.validate(l,phase='P0')
    def test_na_cannot_hide_due_rule_or_rule_slot(self):
        l=copy.deepcopy(self.ledger);l['families']['MASTER_CHAIN']['A']['result']='N_A_ASSET_TYPE'
        with self.assertRaisesRegex(f.Blocked,'LEDGER_RULE_RESULT'):self.validate(l)
    def test_unsupported_or_empty_profiles_are_denied(self):
        for profiles in ([],['UNREGISTERED_PROFILE'],['FOLIAGE_PROFILE']*2):
            with self.assertRaisesRegex(f.Blocked,'WORK_PROFILE'):f.validate_coverage(self.inv,self.ledger,phase='P8',asset_type='vegetation',profiles=profiles)
    def test_historical_duplicate_headings_do_not_override_active_rules(self):
        self.raw['master']+='\n## A — Historical shadow\nFake historic rule.\n'.encode()
        inv=self.build();self.assertEqual(inv['rules']['A']['requirement_sha256'],self.inv['rules']['A']['requirement_sha256'])

if __name__=='__main__':unittest.main()
