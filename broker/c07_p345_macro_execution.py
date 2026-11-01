"""C07 P3-P5 macro executor: run all forty canonical rules as ONE operation.

Each current source rule is independently replayed, not padded by a generic
positive flag. All original audit and SHA checks are delegated to the
source-specific consuming-side readers. Unknown/blocked rules remain untrusted.
No registry/fixture/CI run by itself constitutes independent MG0 or FiveM.
"""
from c07_p345_forty_native_evidence import TEXT, IDS, PHASE_INDEX
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, build_packet)
from c07_positive_native_process import sha
from supervisor_judgment import binding

P345_FORTY = tuple(IDS)
PHASES = {'P3':3,'P4':4,'P5':5}
DUE = {
    'P3': tuple(P345_FORTY[:10]),
    'P4': tuple(P345_FORTY[:30]),
    'P5': P345_FORTY,
}

class MacroExecutionBlocked(ValueError):
    pass

def need(ok,code):
    if not ok:
        raise MacroExecutionBlocked(code)

def _verify_canonical_context(ctx):
    need(type(ctx) is dict and set(ctx)=={
        'inventory','plan','controller','asset','step','work','source_loader'},
        'C07_P345_MACRO_TRUSTED_CONTROLLER_CONTEXT_REQUIRED')
    inv,work,plan = (ctx[k] for k in ('inventory','work','plan'))
    need(type(inv) is dict and inv.get('rule_count')==763
         and inv.get('schema')=='gg-effective-family-inventory-v1'
         and type(work) is dict and type(plan) is dict
         and plan.get('phase')==work.get('phase') and
         plan['phase'] in PHASE_INDEX
         and len(P345_FORTY)==40 and len(set(P345_FORTY))==40,
         'C07_P345_MACRO_763_PHASE_OR_COHORT_DRIFT')
    catalog=inv.get('source_digests',{}).get('aaa_catalog')
    need(type(catalog) is str and len(catalog)==64
         and all(c in '0123456789abcdef' for c in catalog),
         'C07_P345_MACRO_CATALOG_SOURCE_REQUIRED')
    for number,rid in zip(range(111,151),P345_FORTY):
        literal,phase=TEXT[str(number)]
        r=inv['rules'].get(rid,{})
        domain,criteria=NATIVE_RULES.get(rid,(None,None))
        need(type(criteria) is tuple and len(criteria)>=2
             and len(set(criteria))==len(criteria)
             and type(domain) is str and domain
             and rid=='AAA-200-'+
                 ('L' if number<=120 else 'M' if number<=130
                  else 'N' if number<=140 else 'O')+'-'+str(number)
             and r.get('family')=='AAA-200'
             and r.get('catalog_number')==number
             and r.get('catalog_phase')==phase
             and r.get('requirement')==literal
             and r.get('requirement_sha256')==sha(literal.encode())
             and r.get('source_sha256')==catalog,
             'C07_P345_MACRO_LITERAL_OR_IMPLEMENTATION_DRIFT:'+rid)
    return inv,plan,work

def run(source_context):
    """Return a forty-rule operation, not forty claimed FULL positives.

    Missing source evidence makes an individual operation BLOCKED, never a
    fabricated positive result. Canonical inventory drift is a hard error.
    Every DUE rule is visited; future rules cannot be evaluated prematurely.
    """
    inv,plan,work=_verify_canonical_context(source_context)
    stage=PHASE_INDEX[plan['phase']]
    due=set(DUE['P3'] if stage==3 else
            DUE['P4'] if stage==4 else DUE['P5'])
    rows={}
    for rid in P345_FORTY:
        number=int(rid.rsplit('-',1)[1])
        phase=TEXT[str(number)][1]
        reviewed=rid in FULL_LITERAL_REVIEWED
        row={'canonical_literal':TEXT[str(number)][0],
             'phase':phase,
             'source_scope':'REVIEWED_LITERAL' if reviewed else
                            'ORIGINAL_SCOPED_CANDIDATE',
             'machine_result':'NOT_DUE',
             'mg0':'NOT_DUE','evidence_proven':False,
             'source_checks':{},'blocked_reason':None,
             'fivem_runtime':'UNVERIFIED',
             'owner_acceptance':'UNVERIFIED'}
        if rid in due:
            expected=binding(work,inv['rules'][rid],rid)
            try:
                packet=build_packet(source_context,rid,expected=expected)
            except (ValueError, KeyError, TypeError, IndexError,
                    AssertionError, OSError) as error:
                row['machine_result']='BLOCKED'
                row['mg0']='UNKNOWN'
                row['blocked_reason']=(
                    type(error).__name__+':'+str(error)[:250])
            else:
                need(packet.get('binding')==expected
                     and packet.get('rule',{}).get('result') in (
                         'PASS','FAIL','UNKNOWN')
                     and packet.get('mg0',{}).get('result') in (
                         'PASS','FAIL','UNKNOWN','NOT_DUE')
                     and type(packet['rule'].get('checks')) is dict
                     and set(packet['rule']['checks'])==
                         set(NATIVE_RULES[rid][1])
                     and all(type(v) is bool for v in
                             packet['rule']['checks'].values()),
                     'C07_P345_MACRO_REPLAY_SCHEMA_DRIFT:'+rid)
                result=packet['rule']['result']
                need(not (result=='PASS' and
                          (not reviewed or not all(
                              packet['rule']['checks'].values()))),
                     'C07_P345_MACRO_FALSE_POSITIVE:'+rid)
                row.update(machine_result=result,
                           mg0=packet['mg0']['result'],
                           evidence_proven=result=='PASS' and reviewed,
                           source_checks=dict(packet['rule']['checks']))
        rows[rid]=row

    need(len(rows)==40 and set(rows)==set(P345_FORTY) and
         sum(rows[rid]['machine_result']=='NOT_DUE'
             for rid in rows)==40-len(due),
         'C07_P345_MACRO_FORTY_COVERAGE_MISMATCH')
    counts={status:sum(
        item['machine_result']==status for item in rows.values())
        for status in ('PASS','FAIL','UNKNOWN','BLOCKED','NOT_DUE')}
    return {
        'schema':'c07-p345-forty-original-source-macro-v1',
        'canonical_rule_count':40,
        'due_count':len(due),
        'reviewed_literal_implementation_count':
            sum(rid in FULL_LITERAL_REVIEWED for rid in P345_FORTY),
        'candidate_count':
            sum(rid not in FULL_LITERAL_REVIEWED for rid in P345_FORTY),
        'visited_due_count':40-counts['NOT_DUE'],
        'result_counts':counts,
        'phase':plan['phase'],
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'rows':rows,
        'full_semantic_coverage':all(rid in FULL_LITERAL_REVIEWED
                                    for rid in P345_FORTY),
        'individual_mg0_independently_approved':False,
        'fivem_runtime_approved':False,
        'owner_approved':False,
        'advancement_authorized':False,
    }

def require_source_execution(report):
    """Certify only execution completeness, NEVER rule correctness or MG0.

    A rule merely visited with BLOCKED must not be presented as a successful
    macro. UNKNOWN is allowed only when its original source predicates were
    independently recomputed; no claim of literal PASS is made.
    """
    need(type(report) is dict and
         report.get('schema')=='c07-p345-forty-original-source-macro-v1' and
         report.get('canonical_rule_count')==40 and
         report.get('due_count')==40 and
         report.get('visited_due_count')==40 and
         set(report.get('rows',{}))==set(P345_FORTY),
         'C07_P345_CERTIFICATE_FULL_40_SOURCE_EXECUTION_REQUIRED')
    for rid in P345_FORTY:
        row=report['rows'][rid]
        need(type(row) is dict and row.get('machine_result') in
             ('PASS','FAIL','UNKNOWN') and row.get('blocked_reason') is None,
             'C07_P345_CERTIFICATE_SOURCE_REPLAY_BLOCKED:'+rid)
        need(type(row.get('source_checks')) is dict and
             set(row['source_checks'])==set(NATIVE_RULES[rid][1]) and
             all(type(v) is bool for v in row['source_checks'].values()),
             'C07_P345_CERTIFICATE_ORIGINAL_CHECKS_MISSING:'+rid)
        # The first rule-specific original-byte criterion is the required
        # pre-D source/contract pin. An UNKNOWN with empty or false pin must
        # NOT become a successful source-execution certificate.
        pin_criterion=NATIVE_RULES[rid][1][0]
        need(row['source_checks'].get(pin_criterion) is True,
             'C07_P345_CERTIFICATE_PRE_D_PIN_NOT_VERIFIED:'+rid)
        need(not (row['machine_result']=='PASS' and
                  (rid not in FULL_LITERAL_REVIEWED or
                   not all(row['source_checks'].values()))),
             'C07_P345_CERTIFICATE_FALSE_RULE_PASS:'+rid)
    counts=report.get('result_counts',{})
    need(type(counts) is dict and
         counts.get('BLOCKED')==0 and counts.get('NOT_DUE')==0 and
         sum(counts.get(k,0) for k in
             ('PASS','FAIL','UNKNOWN','BLOCKED','NOT_DUE'))==40 and
         report.get('advancement_authorized') is False and
         report.get('individual_mg0_independently_approved') is False and
         report.get('fivem_runtime_approved') is False and
         report.get('owner_approved') is False,
         'C07_P345_CERTIFICATE_COUNTS_OR_AUTHORIZATION_UNTRUSTED')
    return {
        'schema':'c07-p345-execution-only-certificate-v1',
        'source_replays_executed':40,
        'source_replays_blocked':0,
        'source_execution_verified':True,
        'full_semantics_verified':False,
        'independent_mg0_verified':False,
        'fivem_verified':False,
        'owner_approved':False,
        'advancement_authorized':False,
    }
