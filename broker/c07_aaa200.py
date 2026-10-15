"""C07 AAA-200 canonical 200-rule gate.

Source integrity and the absence of observed failures never imply that an asset
passed QA. Real semantic verifiers and MG0 must be independently demonstrated.
Private catalog and 3D assets remain in the private repository / Library.
"""
import hashlib
import json
import re
from collections import Counter

FAMILY = 'AAA-200'
SOURCE = 'aaa_catalog'
SOURCE_PATH = 'governance/sources/AAA_200_CANONICAL_CATALOG.json'
SECTIONS = tuple('ABCDEFGHIJKLMNOPQRST')
PHASES = tuple('P' + str(i) for i in range(9))
ASSET_TYPES = ('architecture', 'organic', 'vegetation', 'terrain')
EVIDENCE_BY_SECTION = {
 'A':'GOAL_AND_CONSTRAINT_DECISION','B':'TRUSTED_PLAN_AND_DEPENDENCIES',
 'C':'REFERENCE_PROVENANCE_AND_LICENSE','D':'ART_DIRECTION_AND_OWNER_REVIEW',
 'E':'SITE_LAYOUT_MEASUREMENTS','F':'BLOCKOUT_AND_SCALE_REVIEW',
 'G':'HARD_SURFACE_GEOMETRY_QA','H':'ARCHITECTURE_AND_JOINT_QA',
 'I':'ORGANIC_MESH_AND_ROCK_QA','J':'FOLIAGE_ALPHA_WIND_LOD_QA',
 'K':'TERRAIN_PATH_WATER_COLLISION_QA','L':'TOPOLOGY_UV_AND_MESH_QA',
 'M':'PBR_MAPS_AND_TEXTURE_QA','N':'MULTIANGLE_LIGHTING_AND_PRESENTATION_QA',
 'O':'LODS_TRIANGLES_AND_PERFORMANCE_QA','P':'PLAYER_WALKABILITY_AND_COLLISION_QA',
 'Q':'FIVEM_RUNTIME_EXPORT_IMPORT_QA','R':'TOOLING_AND_AUDIT_PROVENANCE',
 'S':'INDEPENDENT_QA_AND_REGRESSION','T':'OWNER_DELIVERY_SIGNOFF'
}
class Blocked(ValueError): pass
def need(ok, reason):
    if not ok: raise Blocked(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest()

def parse_catalog(raw):
    need(isinstance(raw, bytes) and raw, 'AAA200_SOURCE_BYTES_REQUIRED')
    def unique(pairs):
        out = {}
        for k, v in pairs:
            need(k not in out, 'AAA200_DUPLICATE_JSON_KEY:'+k)
            out[k] = v
        return out
    doc = json.loads(raw, object_pairs_hook=unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(Blocked('AAA200_NONFINITE')))
    need(isinstance(doc, dict) and doc.get('schema') == 'GG_AAA200_CATALOG_V1'
         and doc.get('phase_order') == list(PHASES)
         and doc.get('asset_types') == list(ASSET_TYPES), 'AAA200_CANONICAL_SCHEMA')
    rows = doc.get('catalog')
    need(isinstance(rows, list) and len(rows) == 200, 'AAA200_CANONICAL_COUNT')
    need([r.get('id') if isinstance(r,dict) else None for r in rows] == list(range(1,201)),
         'AAA200_CANONICAL_SEQUENCE')
    for i, row in enumerate(rows):
        need(row.get('section') == SECTIONS[i//10]
             and isinstance(row.get('section_title'), str) and row['section_title'].strip()
             and isinstance(row.get('requirement'), str) and row['requirement'].strip()
             and row.get('phase') in PHASES
             and row.get('asset_type') in ('all', *ASSET_TYPES),
             'AAA200_CANONICAL_ROW:'+str(i+1))
    return rows

def inspect(inventory, plan, *, catalog_raw=None, master_raw=None,
            audit_raw=None, asset=None, attempt_id=None, reviewed=None):
    from family_coverage import expected_result
    if reviewed is None:
        from approved_validators import REVIEWED as reviewed
    need(isinstance(inventory, dict)
         and inventory.get('schema') == 'gg-effective-family-inventory-v1',
         'AAA200_INVENTORY_SCHEMA')
    families, rules, digests = (inventory.get('families'),
                                inventory.get('rules'), inventory.get('source_digests'))
    need(isinstance(families,dict) and isinstance(rules,dict)
         and isinstance(digests,dict) and
         re.fullmatch('[a-f0-9]{64}', str(digests.get(SOURCE,''))),
         'AAA200_SOURCE_BINDING')
    all_ids = [rid for group in families.values() for rid in group]
    need(inventory.get('rule_count') == 763 and inventory.get('family_count') == 20
         and len(all_ids) == len(set(all_ids)) == len(rules) == 763
         and set(all_ids) == set(rules), 'AAA200_FULL_FAMILY_MEMBERSHIP')
    ids = families.get(FAMILY)
    expected_ids = ['AAA-200-'+SECTIONS[(n-1)//10]+'-'+str(n).zfill(3)
                    for n in range(1,201)]
    need(ids == expected_ids, 'AAA200_RULE_MEMBERSHIP_OR_ORDER')
    need(isinstance(plan,dict)
         and plan.get('master_sha256') == inventory.get('canonical_master_sha256')
         and plan.get('phase') in PHASES and plan.get('asset_type') in ASSET_TYPES
         and isinstance(plan.get('profiles'), list)
         and plan.get('mode') in ('OPERATIONAL','DIAGNOSTIC_ONLY')
         and isinstance(plan.get('enrolled'), dict), 'AAA200_TRUSTED_PLAN')
    catalog = None
    if catalog_raw is not None:
        need(sha(catalog_raw) == digests[SOURCE], 'AAA200_CATALOG_HASH_DRIFT')
        catalog = parse_catalog(catalog_raw)
    has_audit = any(v is not None for v in (master_raw,audit_raw,asset,attempt_id))
    if has_audit:
        need(isinstance(master_raw,bytes) and sha(master_raw) == plan['master_sha256']
             and isinstance(audit_raw,bytes) and isinstance(asset,str) and asset == asset.upper()
             and isinstance(attempt_id,str) and re.fullmatch('[a-f0-9]{64}', attempt_id),
             'AAA200_ATTEMPT_AUDIT_BINDING_REQUIRED')
        from real_work_intake import audit_check
        from c07_mg0_individual import inspect as inspect_mg0
        audits, audit_tail = audit_check(audit_raw,asset)
    else:
        audits, audit_tail = (), None
    entries, missing, failures, mg0_failures, due = {},[],[],[],0
    for n,rid in enumerate(ids,1):
        row = rules[rid]
        clause = row.get('requirement')
        section = SECTIONS[(n-1)//10]
        need(row.get('family') == FAMILY
             and row.get('source') == SOURCE and row.get('source_path') == SOURCE_PATH
             and row.get('source_sha256') == digests[SOURCE]
             and isinstance(clause,str) and clause.strip()
             and row.get('requirement_sha256') == sha(clause.encode('utf-8'))
             and row.get('required_mg0') is True
             and row.get('catalog_number') == n and row.get('catalog_section') == section
             and row.get('catalog_phase') in PHASES
             and row.get('asset_type') in ('all',*ASSET_TYPES),
             'AAA200_RULE_SOURCE_DRIFT:'+rid)
        if catalog is not None:
            source_row = catalog[n-1]
            need(clause == source_row['requirement']
                 and row['catalog_phase'] == source_row['phase']
                 and row['asset_type'] == source_row['asset_type']
                 and row['catalog_section'] == source_row['section'],
                 'AAA200_PRIVATE_CATALOG_DRIFT:'+rid)
        applicability = expected_result(row,plan['phase'],plan['asset_type'],plan['profiles'])
        need(applicability in ('PASS','FUTURE_PHASE','N_A_ASSET_TYPE',
                               'N_A_PROFILE_NOT_SELECTED'), 'AAA200_APPLICABILITY:'+rid)
        is_due = applicability == 'PASS'
        due += is_due
        if is_due and (rid not in reviewed or rid not in plan['enrolled']):
            missing.append(rid)
        rule_fails = ([r['record_hash'] for r in audits if r.get('rule_id') == rid
                       and r.get('attempt_id') == attempt_id
                       and (r.get('result') in ('FAIL','BLOCKED')
                            or r.get('event') == 'VERIFIED_STATE_REVOKED')]
                      if is_due else [])
        if rule_fails: failures.append(rid)
        mg0 = 'UNKNOWN'
        if is_due and has_audit:
            mg0 = inspect_mg0(master_raw,audit_raw,asset,
                              plan['master_sha256'],rid,attempt_id)['individual_rule_mg0']
            need(mg0 in ('UNKNOWN','FAIL'), 'AAA200_MG0_FALSE_PASS:'+rid)
            if mg0 == 'FAIL': mg0_failures.append(rid)
        entries[rid] = {
            'section':section,'catalog_number':n,
            'canonical_phase':row['catalog_phase'],
            'canonical_asset_type':row['asset_type'],
            'source_sha256':row['source_sha256'],
            'requirement_sha256':row['requirement_sha256'],
            'source_integrity':'PASS',
            'required_evidence_contract':EVIDENCE_BY_SECTION[section],
            'applicability':applicability,
            'reviewed_rule_predicate':rid in reviewed,
            'semantic_result':'UNKNOWN' if is_due else 'NOT_DUE',
            'individual_mg0':mg0 if is_due else 'NOT_DUE',
            'observed_fail_hashes':rule_fails,
            'asset_quality_accepted':False,
        }
    need(len(entries) == 200, 'AAA200_RULE_LEDGER_INCOMPLETE')
    return {'schema':'gg-c07-aaa200-rule-source-audit-v1',
            'canonical_master_sha256':plan['master_sha256'],
            'catalog_sha256':digests[SOURCE],
            'catalog_rules_verified':len(entries),
            'section_counts':{s:10 for s in SECTIONS},
            'phase':plan['phase'],'asset_type':plan['asset_type'],
            'due':due,'future_or_not_applicable':200-due,
            'missing_due_semantic_validators':missing,
            'observed_native_fail_rules':failures,
            'observed_uncorrected_mg0_fail_rules':mg0_failures,
            'current_attempt_audit_bound':has_audit,'audit_tail':audit_tail,
            'native_semantic_passes':0,'individual_mg0_passes':0,
            'asset_quality_approvals':0,'advancement_authorized':False,
            'entries':entries}

def require_operational_scope(inventory,plan,**kwargs):
    report=inspect(inventory,plan,**kwargs)
    if plan['mode']=='OPERATIONAL':
        need(not report['missing_due_semantic_validators'],
             'AAA200_MISSING_DUE_SEMANTIC_VALIDATORS:'+
             str(len(report['missing_due_semantic_validators'])))
        need(not report['observed_native_fail_rules'],
             'AAA200_UNRESOLVED_RULE_FAILURE')
        need(not report['observed_uncorrected_mg0_fail_rules'],
             'AAA200_UNCORRECTED_MG0_FAILURE')
    return report
