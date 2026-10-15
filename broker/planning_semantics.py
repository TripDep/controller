"""Read actual planning evidence; never promote an upstream PASS label.

The first implemented predicate reviews the documented destination engine
before generation (AAA-200-B-012). It cannot certify individual MG0 recovery,
asset quality, other planning obligations or permission to execute an action.
Private source text stays in the private repository. Public logs carry digests.
"""
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta

import family_coverage as coverage
import supervisor_judgment as j
import golden_controller as gc

ENGINE_RULE = 'AAA-200-B-012'
VALIDATOR = 'documented-engine-before-generation-v1'
CRITERIA = ['canonical_target_documented', 'historical_master_read_before_generation',
            'individual_preflight_record_before_generation']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def context_value(raw):
    return j.context.validate(j.evidence.strict_json(raw, max_size=32000))


def audit_records(raw, asset, expected_tail):
    """Read and verify every record, rather than accepting a claimed chain hash."""
    rows = []
    previous = 'GENESIS'
    for line in raw.decode().splitlines():
        j.need(bool(line.strip()), 'PLANNING_EMPTY_AUDIT_RECORD')
        row = j.evidence.strict_json(line.encode(), max_size=100000)
        claimed = row.get('record_hash')
        value = {k:v for k,v in row.items() if k != 'record_hash'}
        j.need(row.get('prev_hash') == previous and row.get('asset') == asset and
               claimed == sha(gc.canonical_json(value)), 'PLANNING_AUDIT_CHAIN')
        previous = claimed
        rows.append(row)
    j.need(rows and previous == expected_tail, 'PLANNING_AUDIT_TAIL')
    return rows


def closed_step(rows, step):
    opened = [r for r in rows if r.get('event') == 'STEP_OPEN' and r.get('step') == step]
    closed = [r for r in rows if r.get('event') == 'STEP_CLOSE' and r.get('step') == step]
    j.need(len(opened) == len(closed) == 1, 'PLANNING_STEP_PAIR')
    before, after = opened[0], closed[0]
    j.need(rows.index(before) < rows.index(after) and before['authorization_token'] == after['authorization_token']
           and before['action'] == after['action'] and before['category'] == after['category'], 'PLANNING_STEP_BINDING')
    j.need(after['result'] == 'PASS', 'PLANNING_STEP_NOT_PASS')
    return before, after


def evidence_availability(manifest, retrieved, withheld=()):
    """Qualification only: bytes read and exact hash, never semantic/MG0 PASS."""
    checks = manifest.get('checks', {})
    j.need(set(checks) == {str(i) for i in range(1, 201)}, 'PLANNING_ALL_200_REQUIRED')
    result = {}
    for item, check in checks.items():
        refs = check.get('evidence', [])
        seen = []
        for ref in refs:
            raw = retrieved.get(ref['path'])
            seen.append(('ASSET_WITHHELD_NOT_CONTENT_VERIFIED' if ref['path'] in withheld else 'NOT_RETRIEVED') if raw is None else
                        'BYTES_RETRIEVED' if sha(raw) == ref['sha256'] else 'DIGEST_MISMATCH')
        result[item] = {'producer_status':check['status'], 'evidence_status':
                        'DIGEST_MISMATCH' if 'DIGEST_MISMATCH' in seen else
                        'NOT_RETRIEVED' if not seen or 'NOT_RETRIEVED' in seen else 'BYTES_RETRIEVED',
                        'semantic_pass':False, 'mg0_pass':False}
        if seen and 'NOT_RETRIEVED' not in seen and 'DIGEST_MISMATCH' not in seen and 'ASSET_WITHHELD_NOT_CONTENT_VERIFIED' in seen:
            result[item]['evidence_status'] = 'ASSET_WITHHELD_NOT_CONTENT_VERIFIED'
    return result


def documented_engine(inv, work, documents, policy):
    """Only the engine-identification obligation, not format/scale/world-Z.

    Trusted policy is code-reviewed consumer input. Its exact authoritative
    line must occur in BOTH actual historical and current Master contents.
    The individual preflight registration must precede the actual generation
    step. A PASS tag without the source contents cannot satisfy this function.
    """
    j.validate_work(work, inv)
    j.need(work['mode'] == 'DIAGNOSTIC_ONLY' and work['closure_requested'] is False,
           'PLANNING_RETROSPECTIVE_REVIEW_ONLY')
    row = inv['rules'][ENGINE_RULE]
    j.need(row['requirement_sha256'] == policy['requirement_sha256'] and
           row.get('catalog_number') == 12 and row.get('catalog_phase') == 'P0',
           'PLANNING_RULE_SOURCE_DRIFT')
    current = documents['master']
    historical = documents['historical_master']
    j.need(sha(current) == work['master_sha256'] and sha(historical) == policy['historical_master_sha256'],
           'PLANNING_MASTER_CONTENTS')
    state = j.evidence.strict_json(documents['work_state'], max_size=2000000)
    asset = policy['asset']
    st = state['assets'][asset]
    rows = audit_records(documents['audit'], asset, st['last_audit_hash'])
    manifest = j.evidence.strict_json(documents['asset_checks'], max_size=200000)
    j.need(manifest['asset'] == asset and manifest['authority']['master_sha256'] == work['master_sha256'],
           'PLANNING_ASSET_AUTHORITY')
    pre_open, pre_close = closed_step(rows, policy['preflight_step'])
    gen_open, _ = closed_step(rows, policy['generation_step'])
    checks = {}
    line = policy['canonical_target_line']
    j.need(isinstance(line, str) and line.strip() == line and len(line) > 10 and
           policy['target_engine'] == 'GTA_V_FIVEM', 'PLANNING_ENGINE_POLICY')
    checks['canonical_target_documented'] = (
        current.decode().splitlines().count(line) == 1 and
        historical.decode().splitlines().count(line) == 1)
    history = [r for r in manifest['history'] if r.get('event') == 'EVIDENCED_PASS' and r.get('item') == 12]
    j.need(len(history) == 1, 'PLANNING_INDIVIDUAL_RECORD')
    record = history[0]
    # Controller timestamps have second precision; history uses fractional
    # seconds. Permit that precision interval, not an arbitrary time waiver.
    moment = datetime.fromisoformat(record['utc'])
    start = datetime.fromisoformat(pre_open['timestamp_utc'])
    end = datetime.fromisoformat(pre_close['timestamp_utc']) + timedelta(seconds=1)
    generation = datetime.fromisoformat(gen_open['timestamp_utc'])
    checks['historical_master_read_before_generation'] = (
        pre_open['category'] == 'ANALYSIS' and gen_open['category'] in ('GENERATION', 'MUTATION') and
        rows.index(pre_close) < rows.index(gen_open) and
        all(r['master_check_before']['sha256'] == policy['historical_master_sha256'] for r in (pre_open, gen_open)) and
        pre_close['master_check_after']['sha256'] == policy['historical_master_sha256'] and start < generation)
    checks['individual_preflight_record_before_generation'] = (
        manifest['checks']['12']['status'] == 'PASS' and record['step'] == policy['preflight_step'] and
        start <= moment < end and moment < generation and
        any(r['sha256'] == record['evidence_sha256'] for r in manifest['checks']['12']['evidence']))
    result = 'PASS' if all(checks.values()) else 'FAIL'
    proof = {'input_sha256':{k:sha(v) for k,v in documents.items()}, 'criteria':checks,
             'policy_sha256':j.digest(policy), 'rule_id':ENGINE_RULE,
             'review_scope':'DOCUMENTED_ENGINE_IDENTIFICATION_BEFORE_GENERATION_ONLY',
             'target_engine':policy['target_engine'], 'asset_execution_verified':False}
    expected = j.binding(work, row, ENGINE_RULE)
    packet = {'schema':'gg-semantic-rule-v1', 'scope':j.SEMANTIC_SCOPE,
              'validator_id':VALIDATOR, 'binding':expected,
              'rule':{'result':result, 'checks':checks, 'proof_digest':j.digest(proof)},
              # No invented MG0 trigger: the actual per-rule trigger evaluation is absent.
              'mg0':{'binding':copy.deepcopy(expected), 'triggered':None, 'result':'UNKNOWN',
                     'checks':{'canonical_triggers_checked':False},
                     'proof_digest':j.digest({'rule':ENGINE_RULE,
                       'status':'INDIVIDUAL_MG0_TRIGGER_UNRESOLVED_NOT_A_PASS'})}}
    return packet, proof



# Reviewed immutable documentary source, never an arbitrary producer-chosen path.
# This historic case cannot attest the current MASTER automatically: if the
# Controller work has advanced, binding mismatch keeps the result UNKNOWN.
NATIVE_POLICY_PATH = 'governance/supervisor/reviews/r165/policy.json'


def native_rule_readback(api, packet, expected, enrolled_spec):
    """Consumer independently replays B-012 source bytes on private immutable Git.

    A successful workflow log, friendly PASS string, or matching packet hash
    does not make the source predicate true. The consumer obtains the exact
    pinned policy, canonical inputs and audit; repeats the full documentary
    check; and requires a byte-equivalent semantic packet, whose MG0 is UNKNOWN.
    """
    from broker_live_review import decode_file

    ref = enrolled_spec.get('source_ref')
    require(isinstance(ref, str) and re.fullmatch(r'[a-f0-9]{40}', ref),
            'PLANNING_NATIVE_IMMUTABLE_SOURCE_REF')
    require(expected.get('rule_id') == ENGINE_RULE and
            expected.get('family') == 'AAA-200' and
            enrolled_spec.get('validator_id') == VALIDATOR and
            set(enrolled_spec.get('criteria', ())) == set(CRITERIA),
            'PLANNING_NATIVE_SOURCE_RULE_OR_CRITERIA')

    def fetch(path, commit):
        require(isinstance(path, str) and path.startswith('governance/') and
                not path.startswith('governance/../') and
                '..' not in path.split('/') and
                re.fullmatch(r'[a-f0-9]{40}', commit),
                'PLANNING_NATIVE_PATH_OR_REF')
        return decode_file(api.call('GET', '/contents/' + path + '?ref=' + commit),
                           path)

    policy_raw = fetch(NATIVE_POLICY_PATH, ref)
    policy = j.evidence.strict_json(policy_raw, max_size=32000)
    require(policy.get('schema') == 'gg-planning-semantic-review-v1' and
            policy.get('scope') == 'RETROSPECTIVE_DOCUMENTARY_PROCESS_REVIEW_NOT_PRODUCTION_AUTHORIZATION',
            'PLANNING_NATIVE_POLICY_SCOPE')
    work = policy['work']
    require(work['mode'] == 'DIAGNOSTIC_ONLY' and
            work['master_sha256'] == expected['master_sha256'] and
            work['attempt_id'] == expected['attempt_id'] and
            work['operation_sha256'] == expected['operation_sha256'] and
            work['work_item_sha256'] == expected['work_item_sha256'],
            'PLANNING_NATIVE_WORK_OR_MASTER_CHANGED')
    source_inputs = {}
    for key, path in coverage.SOURCES.items():
        source_inputs[key] = fetch(path, ref)
    inv = coverage.build_inventory(source_inputs, work['master_sha256'])
    row = inv['rules'][ENGINE_RULE]
    require(j.binding(work, row, ENGINE_RULE) == expected and
            policy['engine']['requirement_sha256'] == expected['requirement_sha256'],
            'PLANNING_NATIVE_CANONICAL_BINDING')
    inputs = policy['inputs']
    require(set(inputs) == {'master', 'historical_master', 'work_state', 'audit', 'asset_checks'},
            'PLANNING_NATIVE_REQUIRED_DOCUMENTS')
    raw = {}
    for key, value in inputs.items():
        require(isinstance(value, dict) and
                set(value) in ({'path', 'sha256'}, {'path', 'sha256', 'ref'}) and
                isinstance(value['sha256'], str) and
                re.fullmatch(r'[a-f0-9]{64}', value['sha256']),
                'PLANNING_NATIVE_INPUT_SCHEMA:' + key)
        source_ref = value.get('ref', ref)
        require(isinstance(source_ref, str) and
                re.fullmatch(r'[a-f0-9]{40}', source_ref),
                'PLANNING_NATIVE_INPUT_MUTABLE_REF:' + key)
        raw[key] = fetch(value['path'], source_ref)
        require(sha(raw[key]) == value['sha256'],
                'PLANNING_NATIVE_INPUT_DIGEST:' + key)
    recomputed, _ = documented_engine(inv, work, raw, policy['engine'])
    require(recomputed['binding'] == expected and
            packet == recomputed and
            recomputed['mg0']['result'] == 'UNKNOWN' and
            recomputed['mg0']['triggered'] is None,
            'PLANNING_NATIVE_LOG_CANNOT_OVERRIDE_RECOMPUTED_PROOF')
    return {'rule_id': ENGINE_RULE,
            'documentary_result': recomputed['rule']['result'],
            'individual_rule_mg0': 'UNKNOWN',
            'advancement_authorized': False}


def main(argv=None):
    import argparse, os
    from broker_live_review import decode_file
    from git_judgment_origin import OriginAPI, PRIVATE_REPO_SHA
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--verify-run', type=int)
    parser.add_argument('--verify-job', type=int)
    parser.add_argument('--verify-head')
    parser.add_argument('--issuer-blob')
    parser.add_argument('--issuer-public')
    args = parser.parse_args(argv)
    try:
        j.need(re.fullmatch('[a-f0-9]{40}', args.ref), 'PLANNING_IMMUTABLE_REF')
        api = OriginAPI(os.environ['GH_REVIEW_TOKEN'], os.environ['GITHUB_REPOSITORY'])
        j.need(sha(api.repository.encode()) == PRIVATE_REPO_SHA, 'PLANNING_REPOSITORY')
        def fetch(path, ref=args.ref):
            return decode_file(api.call('GET', '/contents/' + path + '?ref=' + ref), path)
        policy = j.evidence.strict_json(fetch(args.policy), max_size=32000)
        documents = {}
        for key, spec in policy['inputs'].items():
            raw = fetch(spec['path'], spec.get('ref', args.ref))
            j.need(sha(raw) == spec['sha256'], 'PLANNING_PINNED_INPUT:' + key)
            documents[key] = raw
        inv = coverage.build_inventory({key:fetch(path) for key,path in coverage.SOURCES.items()},
                                       policy['work']['master_sha256'])
        packet, proof = documented_engine(inv, policy['work'], documents, policy['engine'])
        if args.verify_run is not None:
            origin = {'run_id':args.verify_run,'job_id':args.verify_job,'run_attempt':1,'head_sha':args.verify_head}
            issuer = {'workflow_blob':args.issuer_blob,'public_sha':args.issuer_public}
            spec = {'requirement_sha256':policy['engine']['requirement_sha256'],
                    'validator_id':VALIDATOR,'criteria':CRITERIA,'issuer':issuer}
            backend = j.NativeRuleBackend(api,{ENGINE_RULE:spec})
            offers = {ENGINE_RULE:{'native_origin':origin,'expected_packet_sha256':j.digest(packet)}}
            value = backend.rule(ENGINE_RULE, packet['binding'], offers[ENGINE_RULE])
            j.need(value.get('result') == 'UNKNOWN' and value.get('mg0') == 'UNKNOWN'
                   and value.get('semantic_scope') == j.SEMANTIC_SCOPE and
                   value.get('proof_digest') == j.digest(packet), 'PLANNING_NATIVE_PROOF_NOT_VERIFIED')
            current = {role:context_value(fetch(path)) for role,path in j.context.PATHS.items()}
            matrix = j.judge(inv,policy['work'],offers,backend,current_contexts=current)
            j.need(matrix['rule_count'] == inv['rule_count'] and matrix['family_count'] == inv['family_count']
                   and matrix['advancement_authorized'] is False, 'PLANNING_FALSE_ADVANCEMENT')
            print('C07_NATIVE_PROCESS_JUDGMENT:'+json.dumps(matrix,sort_keys=True))
            wrong = copy.deepcopy(packet['binding']); wrong['attempt_id'] = '0'*64
            denied = backend.rule(ENGINE_RULE,wrong,offers[ENGINE_RULE])
            j.need(denied.get('result') == 'UNKNOWN' and 'REPLAY_OR_CONTEXT' in denied.get('reason',''),
                   'PLANNING_WRONG_ATTEMPT_ACCEPTED')
            print('C07_PLANNING_NATIVE_VERIFIED:'+json.dumps({'origin':origin,'issuer':issuer,
                  'source_predicate':'PASS','individual_mg0':'UNKNOWN','overall_rule':'UNKNOWN',
                  'native_packet_sha256':j.digest(packet),'wrong_attempt_rejected':True,
                  'counts':matrix['counts'],'family_count':matrix['family_count'],
                  'rule_count':matrix['rule_count'],'advancement_authorized':False},sort_keys=True))
            return 0
        print(j.PREFIX + json.dumps(packet, sort_keys=True))
        print('C07_ACTUAL_PLANNING_REVIEW:' + json.dumps(proof, sort_keys=True))
        retrieved = {path:fetch(path) for path in policy['retrieved_reports'].values()}
        # Logical evidence paths remain the original paths from the asset record.
        available = {logical:retrieved[path] for logical,path in policy['retrieved_reports'].items()}
        manifest = json.loads(documents['asset_checks'])
        qualification = evidence_availability(manifest, available, policy['withheld_asset_paths'])
        print('C07_ACTUAL_EVIDENCE_QUALIFICATION:' + json.dumps(qualification, sort_keys=True))
        print('C07_ACTUAL_REVIEW_SUMMARY:' + json.dumps({
            'rule_id':ENGINE_RULE, 'rule_predicate':packet['rule']['result'], 'mg0':'UNKNOWN',
            'actual_asset_passes':0, 'advancement_authorized':False,
            'claims':len(qualification),
            'claimed_passes':sum(r['producer_status']=='PASS' for r in qualification.values()),
            'claimed_passes_asset_contents_withheld':sum(r['producer_status']=='PASS' and r['evidence_status']=='ASSET_WITHHELD_NOT_CONTENT_VERIFIED' for r in qualification.values()),
            'claimed_passes_evidence_not_retrieved':sum(r['producer_status']=='PASS' and r['evidence_status']=='NOT_RETRIEVED' for r in qualification.values())}, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('C07_PLANNING_REVIEW_BLOCKED:' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
