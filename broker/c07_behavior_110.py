"""C07 behavior anti-regression: 110 canonical error -> prevention contracts.

Do not conflate source integrity, absence of an audit observation, or a passing
CI job with proof that an assistant complied with a prevention rule.
Only authentic Controller evidence can ground an observed recurrence; it cannot
by itself prove absence of recurrence or independent owner approval.
"""
from __future__ import annotations

import hashlib
import re

FAMILY = 'BEHAVIOR_110'
SOURCE = 'error_registry'
CANONICAL_PATH = 'governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md'
SECTIONS = (
    ('A', 'PERDITA DELL', 1, 10),
    ('B', 'REQUISITI', 11, 20),
    ('C', 'AFFERMAZIONI', 21, 30),
    ('D', 'TEMPI MORTI', 31, 40),
    ('E', 'PROVE', 41, 50),
    ('F', 'CONTROLLER', 51, 60),
    ('G', 'MASTER', 61, 70),
    ('H', 'TEA HOUSE', 71, 80),
    ('I', 'HERO DRAGON', 81, 90),
    ('J', 'MATERIALI', 91, 100),
    ('K', 'CONSEGNA', 101, 110),
)
FAIL_EVENTS = frozenset(('QUALITY_FINDING', 'USER_REVIEW',
                         'VERIFIED_STATE_REVOKED', 'DELIVERY_GATE_CHECK',
                         'STEP_CLOSE'))


class BehaviorBlocked(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise BehaviorBlocked(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_registry(raw):
    """Read the exact error and prevention clauses from canonical text bytes."""
    require(isinstance(raw, bytes) and raw, 'C07_110_REGISTRY_RAW_REQUIRED')
    text = raw.decode('utf-8', errors='strict')
    rows = re.findall(r'(?m)^(\d{3})\. (Errore:[^\n]+)$', text)
    require([n for n, _ in rows] == [f'{i:03}' for i in range(1, 111)],
            'C07_110_REGISTRY_SEQUENCE_DUPLICATED_OR_OMITTED')
    require(all(re.fullmatch(r'Errore: (.+?) → (.+)', clause)
                for _, clause in rows), 'C07_110_PREVENTION_CLAUSE_MISSING')
    sections = re.findall(r'(?m)^## ([A-K])\. ([^\n]+)$', text)
    require(len(sections) == 11 and
            [s[0] for s in sections] == [s[0] for s in SECTIONS],
            'C07_110_SECTIONS_MISSING_DUPLICATED')
    for idx, (letter, marker, start, end) in enumerate(SECTIONS):
        title = sections[idx][1]
        require(marker.casefold() in title.casefold() and
                f'({start:03}–{end:03})' in title,
                'C07_110_SECTION_RANGE:' + letter)
    return {f'BEHAVIOR-{n}': clause for n, clause in rows}


def inspect(inventory, plan, *, registry_raw=None, master_raw=None,
            audit_raw=None, asset=None, attempt_id=None, reviewed=None):
    """Per-error source/source-hash, applicability, observation and MG0 review."""
    from family_coverage import expected_result
    if reviewed is None:
        from approved_validators import REVIEWED as reviewed

    require(isinstance(inventory, dict) and
            inventory.get('schema') == 'gg-effective-family-inventory-v1',
            'C07_110_SOURCE_INVENTORY')
    families, rules = inventory.get('families'), inventory.get('rules')
    digests = inventory.get('source_digests')
    require(isinstance(families, dict) and isinstance(rules, dict) and
            isinstance(digests, dict) and
            isinstance(digests.get(SOURCE), str) and
            re.fullmatch('[0-9a-f]{64}', digests[SOURCE]),
            'C07_110_CANONICAL_FAMILY_AND_SOURCE_DIGEST')
    ids = families.get(FAMILY)
    expected_ids = [f'BEHAVIOR-{i:03}' for i in range(1, 111)]
    require(ids == expected_ids and all(rid in rules for rid in ids) and
            inventory.get('rule_count') == 763 and
            inventory.get('family_count') == 20 and
            sum(len(g) for g in families.values()) == 763,
            'C07_110_EXACT_CANONICAL_MEMBERSHIP')
    require(isinstance(plan, dict) and
            plan.get('master_sha256') == inventory.get('canonical_master_sha256')
            and plan.get('mode') in ('OPERATIONAL', 'DIAGNOSTIC_ONLY')
            and isinstance(plan.get('enrolled'), dict),
            'C07_110_TRUSTED_PLAN_AND_MASTER')
    if registry_raw is not None:
        require(sha(registry_raw) == digests[SOURCE],
                'C07_110_REGISTRY_DIGEST_DRIFT')
        clauses = parse_registry(registry_raw)
    else:
        clauses = None

    have_any_audit = any(v is not None for v in
                         (master_raw, audit_raw, asset, attempt_id))
    if have_any_audit:
        require(isinstance(master_raw, bytes) and
                sha(master_raw) == plan['master_sha256'] and
                isinstance(audit_raw, bytes) and
                isinstance(asset, str) and asset == asset.upper() and
                isinstance(attempt_id, str) and
                re.fullmatch(r'[a-f0-9]{64}', attempt_id),
                'C07_110_INCOMPLETE_TRUSTED_ATTEMPT')
        from real_work_intake import audit_check
        from c07_mg0_individual import inspect as inspect_mg0
        rows, audit_tail = audit_check(audit_raw, asset)
    else:
        rows, audit_tail = [], None

    entries, missing, observed, mg0_failures = {}, [], [], []
    for index, rid in enumerate(ids, 1):
        item = rules[rid]
        requirement = item.get('requirement')
        require(item.get('family') == FAMILY and
                item.get('source') == SOURCE and
                item.get('source_path') == CANONICAL_PATH and
                item.get('source_sha256') == digests[SOURCE] and
                isinstance(requirement, str) and requirement.strip() and
                re.fullmatch(r'Errore: (.+?) → (.+)', requirement) and
                item.get('requirement_sha256') ==
                sha(requirement.encode('utf-8')) and
                item.get('required_mg0') is True,
                'C07_110_INDIVIDUAL_SOURCE_OR_PREVENTION_DRIFT:' + rid)
        if clauses is not None:
            require(requirement == clauses[rid],
                    'C07_110_REGISTRY_CLAUSE_DIVERGENCE:' + rid)
        match = re.fullmatch(r'Errore: (.+?) → (.+)', requirement)
        section = SECTIONS[(index - 1) // 10][0]
        applicability = expected_result(item, plan.get('phase'),
                                         plan.get('asset_type'),
                                         plan.get('profiles'))
        require(applicability in ('PASS', 'FUTURE_PHASE',
                    'N_A_PROFILE_NOT_SELECTED', 'N_A_ASSET_TYPE'),
                'C07_110_RULE_APPLICABILITY:' + rid)
        due = applicability == 'PASS'
        rule_events = ([row for row in rows if
                        row.get('rule_id') == rid and
                        row.get('attempt_id') == attempt_id] if due else [])
        # Audit events are observations, not independently authenticated owner proof.
        recurrences = [row for row in rule_events
                       if row.get('event') in FAIL_EVENTS and
                       (row.get('result') in ('FAIL', 'BLOCKED') or
                        row.get('event') == 'VERIFIED_STATE_REVOKED' or
                        (row.get('event') == 'QUALITY_FINDING' and
                         row.get('result') != 'PASS'))]
        recurrence_hashes = [row['record_hash'] for row in recurrences]
        if recurrences:
            observed.append(rid)
        mg0 = 'UNKNOWN'
        if due and have_any_audit:
            mg0 = inspect_mg0(master_raw, audit_raw, asset,
                              plan['master_sha256'], rid, attempt_id)[
                                  'individual_rule_mg0']
            require(mg0 in ('FAIL', 'UNKNOWN'),
                    'C07_110_MG0_CANNOT_SELF_CERTIFY_PASS:' + rid)
            if mg0 == 'FAIL':
                mg0_failures.append(rid)
        if due and (rid not in reviewed or rid not in plan['enrolled']):
            missing.append(rid)
        entries[rid] = {
            'source': CANONICAL_PATH, 'category': section,
            'requirement_sha256': item['requirement_sha256'],
            'source_sha256': item['source_sha256'],
            'error_to_prevent': match.group(1),
            'required_prevention': match.group(2),
            'canonical_integrity': 'PASS',
            'applicability': applicability,
            'specific_semantic_validator_implemented': rid in reviewed,
            'semantic_result': 'UNKNOWN' if due else 'NOT_DUE',
            'recurrence_observed': bool(recurrences),
            'recurrence_record_hashes': recurrence_hashes,
            'individual_mg0': mg0 if due else 'NOT_DUE',
            'prevention_verified': False,
        }
    require(len(entries) == 110 and set(entries) == set(expected_ids),
            'C07_110_INDIVIDUAL_LEDGER_INCOMPLETE')
    due_count = sum(e['applicability'] == 'PASS' for e in entries.values())
    return {
        'schema': 'gg-c07-110-canonical-error-prevention-gate-v1',
        'registry_sha256': digests[SOURCE],
        'master_sha256': plan['master_sha256'],
        'individual_error_rules': len(entries),
        'groups': {section[0]: 10 for section in SECTIONS},
        'due': due_count, 'future_or_not_applicable': 110 - due_count,
        'missing_due_semantic_implementations': sorted(missing),
        'recurrence_observed_rule_ids': sorted(observed),
        'uncorrected_mg0_rule_ids': sorted(mg0_failures),
        'audit_scoped_to_attempt': have_any_audit,
        'audit_tail': audit_tail,
        'source_integrity_passes': 110,
        'independently_verified_prevention_passes': 0,
        'individual_mg0_passes': 0,
        'advancement_authorized': False,
        'entries': entries,
    }


def require_operational_scope(inventory, plan, **context):
    report = inspect(inventory, plan, **context)
    if plan['mode'] == 'OPERATIONAL':
        require(not report['missing_due_semantic_implementations'],
                'C07_110_UNVERIFIED_DUE_PREVENTION_RULES:' +
                str(len(report['missing_due_semantic_implementations'])))
        require(not report['recurrence_observed_rule_ids'],
                'C07_110_OBSERVED_REGRESSIONS_REQUIRE_CORRECTION:' +
                ','.join(report['recurrence_observed_rule_ids'][:10]))
        require(not report['uncorrected_mg0_rule_ids'],
                'C07_110_MG0_PROCESS_FAIL_REQUIRES_CORRECTION:' +
                ','.join(report['uncorrected_mg0_rule_ids'][:10]))
        # Absence of a reported recurrence is never an individual prevention PASS.
    return report


def main(argv=None):
    import argparse
    import json
    import os
    from pathlib import Path

    from broker_live_review import ReadOnlyAPI, decode_file
    import family_coverage as coverage

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--policy', type=Path, default=Path('../supervisor/policy.json'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        require(re.fullmatch('[a-f0-9]{40}', args.ref),
                'C07_110_IMMUTABLE_PRIVATE_REF_REQUIRED')
        policy = json.loads(args.policy.read_text(encoding='utf-8'))
        api = ReadOnlyAPI(os.environ['GH_REVIEW_TOKEN'],
                          os.environ['GITHUB_REPOSITORY'])
        raw = {key: decode_file(
                   api.call('GET', '/contents/' + path + '?ref=' + args.ref), path)
               for key, path in coverage.SOURCES.items()}
        inventory = coverage.build_inventory(
            raw, policy['canonical_master_sha256'])
        profiles = [x['profile'] for x in inventory['rules'].values()
                    if 'profile' in x]
        report = inspect(inventory, {
            'master_sha256': policy['canonical_master_sha256'],
            'phase': 'P0', 'asset_type': 'terrain', 'profiles': profiles,
            'mode': 'DIAGNOSTIC_ONLY', 'enrolled': {},
        }, registry_raw=raw[SOURCE])
        if args.output:
            args.output.write_text(
                json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2),
                encoding='utf-8')
        print('C07_110_CANONICAL_AUDIT:' + json.dumps({
            'registry_sha256': report['registry_sha256'],
            'rules': report['individual_error_rules'],
            'sections': len(report['groups']),
            'missing_due_validators': len(
                report['missing_due_semantic_implementations']),
            'semantic_passes': report['independently_verified_prevention_passes'],
            'advancement_authorized': report['advancement_authorized'],
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        print('C07_110_BLOCKED:' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
