"""C07: exact 153 source obligations, conservative semantic and MG0 gate.

All rule IDs, source content and hashes come from the canonical private inventory.
Integrity is NOT semantic rule compliance; absent native evidence is UNKNOWN.
No private sources or 3D binaries belong in the public repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

NON_AAA_FAMILY_COUNTS = {
    'MASTER_CHAIN': 8, 'META': 1, 'GLOBAL_GATES': 5,
    'COGNITIVE': 4, 'D_SUBGATES': 3, 'GLOBAL_COMPLETION': 4,
    'DELIVERY': 9, 'GOVERNANCE': 9, 'DESIGN_STANDARDS': 6,
    'EXECUTION': 25, 'G0_CONTROLS': 30, 'PROVOCATION': 12,
    'HISTORICAL_ASSET_GATES': 11, 'BEHAVIOR': 5,
    'PROFESSIONAL_PHASES': 9, 'ASSET_PROFILE_READINESS': 6,
    'PROFESSIONAL_SYSTEM': 6,
}
OTHER_COUNTS = {'AAA-200': 200, 'BEHAVIOR_110': 110, 'QUESTIONS_300': 300}


class Blocked(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Blocked(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(inventory, plan, *, audit=None, master_raw=None, asset=None,
            attempt_id=None, reviewed=None):
    """Evaluate each canonical non-AAA rule; never manufacture semantic PASS."""
    from family_coverage import SOURCES, expected_result
    if reviewed is None:
        from approved_validators import REVIEWED as reviewed

    require(isinstance(inventory, dict) and
            inventory.get('schema') == 'gg-effective-family-inventory-v1',
            'C07_153_CANONICAL_INVENTORY_REQUIRED')
    families, rules = inventory.get('families'), inventory.get('rules')
    digests = inventory.get('source_digests')
    require(isinstance(families, dict) and isinstance(rules, dict) and
            isinstance(digests, dict), 'C07_153_SOURCE_SCHEMA')
    require(set(families) == set(NON_AAA_FAMILY_COUNTS) | set(OTHER_COUNTS),
            'C07_153_UNEXPECTED_FAMILY_OR_MISSING_FAMILY')
    expected_counts = {**NON_AAA_FAMILY_COUNTS, **OTHER_COUNTS}
    for family, size in expected_counts.items():
        require(len(families[family]) == size,
                'C07_153_FAMILY_COUNT:' + family)
    ids = [rule for group in families.values() for rule in group]
    require(len(ids) == len(set(ids)) == len(rules) == 763 and
            set(ids) == set(rules) and inventory.get('rule_count') == 763 and
            inventory.get('family_count') == 20,
            'C07_153_763_CANONICAL_MEMBERSHIP')
    require(sum(NON_AAA_FAMILY_COUNTS.values()) == 153,
            'C07_153_INTERNAL_FAMILY_REGISTRY')
    require(isinstance(plan, dict) and
            plan.get('master_sha256') == inventory.get('canonical_master_sha256')
            and isinstance(plan.get('enrolled'), dict) and
            plan.get('mode') in ('OPERATIONAL', 'DIAGNOSTIC_ONLY'),
            'C07_153_TRUSTED_PLAN_AND_MASTER')
    require(all(isinstance(rule, str) and rule in rules
                for rule in plan['enrolled']),
            'C07_153_INVALID_ENROLLED_RULE')

    have_audit = any(value is not None for value in
                     (audit, master_raw, asset, attempt_id))
    if have_audit:
        require(isinstance(audit, bytes) and
                isinstance(master_raw, bytes) and
                isinstance(asset, str) and
                isinstance(attempt_id, str) and
                re.fullmatch('[a-f0-9]{64}', attempt_id),
                'C07_153_COMPLETE_REAL_AUDIT_BINDING_REQUIRED')
        require(sha(master_raw) == plan['master_sha256'],
                'C07_153_MASTER_BYTES_DRIFT')
        from c07_mg0_individual import inspect as inspect_mg0

    entries, missing, mg0_failures = {}, [], []
    for family in NON_AAA_FAMILY_COUNTS:
        require(len(set(families[family])) == len(families[family]),
                'C07_153_DUPLICATE_ID:' + family)
        for rid in families[family]:
            row = rules[rid]
            require(row.get('family') == family,
                    'C07_153_RULE_FAMILY:' + rid)
            source, requirement = row.get('source'), row.get('requirement')
            require(source in SOURCES and
                    isinstance(requirement, str) and requirement.strip(),
                    'C07_153_SOURCE_TEXT_MISSING:' + rid)
            require(row.get('source_path') == SOURCES[source] and
                    re.fullmatch('[a-f0-9]{64}', str(digests.get(source, '')))
                    and row.get('source_sha256') == digests[source] and
                    row.get('requirement_sha256') ==
                    sha(requirement.encode('utf-8')) and
                    row.get('required_mg0') is True,
                    'C07_153_SOURCE_REQUIREMENT_DRIFT:' + rid)
            applicability = expected_result(
                row, plan.get('phase'), plan.get('asset_type'),
                plan.get('profiles'))
            require(applicability in
                    ('PASS', 'FUTURE_PHASE', 'N_A_PROFILE_NOT_SELECTED',
                     'N_A_ASSET_TYPE'),
                    'C07_153_APPLICABILITY_UNVERIFIED:' + rid)
            due = applicability == 'PASS'
            mg0 = 'UNKNOWN'
            if have_audit and due:
                evidence = inspect_mg0(master_raw, audit, asset,
                                       plan['master_sha256'], rid, attempt_id)
                mg0 = evidence['individual_rule_mg0']
                require(mg0 in ('FAIL', 'UNKNOWN'),
                        'C07_153_INVALID_MG0_PROMOTION:' + rid)
                if mg0 == 'FAIL':
                    mg0_failures.append(rid)
            if due and (rid not in reviewed or rid not in plan['enrolled']):
                missing.append(rid)
            entries[rid] = {
                'family': family, 'source_path': row['source_path'],
                'source_sha256': row['source_sha256'],
                'requirement_sha256': row['requirement_sha256'],
                'applicability': applicability,
                'canonical_source_integrity': 'PASS',
                'reviewed_specific_semantic_implementation': rid in reviewed,
                'semantic_verdict': 'UNKNOWN' if due else 'NOT_DUE',
                'individual_mg0': mg0 if due else 'NOT_DUE',
                'asset_approved': False,
            }
    require(len(entries) == 153 and set(entries) ==
            {rid for family in NON_AAA_FAMILY_COUNTS
             for rid in families[family]},
            'C07_153_INDIVIDUAL_LEDGER_INCOMPLETE')
    due_count = sum(row['applicability'] == 'PASS' for row in entries.values())
    return {
        'schema': 'gg-c07-153-individual-source-and-mg0-review-v1',
        'canonical_master_sha256': plan['master_sha256'],
        'registered_canonical_rules': 763,
        'evaluated_non_aaa_rules': len(entries),
        'families': {family: len(families[family])
                     for family in NON_AAA_FAMILY_COUNTS},
        'applicable_rules': due_count,
        'future_or_not_applicable_rules': 153 - due_count,
        'missing_due_semantic_validators': sorted(missing),
        'due_observed_mg0_failures': sorted(mg0_failures),
        'audit_bound': have_audit,
        'semantic_passes': 0,
        'individual_mg0_passes': 0,
        'advancement_authorized': False,
        'operational_enrollment_ready': not missing and not mg0_failures,
        'rules': entries,
    }


def require_operational_scope(inventory, plan, **kwargs):
    """Fail closed when due semantic verifiers are absent or MG0 failed."""
    report = inspect(inventory, plan, **kwargs)
    if plan['mode'] == 'OPERATIONAL':
        require(not report['missing_due_semantic_validators'],
                'C07_153_DUE_SEMANTIC_VALIDATORS_MISSING:' +
                str(len(report['missing_due_semantic_validators'])))
        require(not report['due_observed_mg0_failures'],
                'C07_153_UNCORRECTED_MG0_FAIL:' +
                ','.join(report['due_observed_mg0_failures'][:8]))
    return report


def main(argv=None):
    import family_coverage as coverage
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-repo-root', type=Path, required=True)
    parser.add_argument('--public-policy', type=Path, required=True)
    parser.add_argument('--phase', required=True)
    parser.add_argument('--asset-type', required=True)
    parser.add_argument('--profiles', required=True)
    parser.add_argument('--mode',
                        choices=('OPERATIONAL', 'DIAGNOSTIC_ONLY'),
                        default='DIAGNOSTIC_ONLY')
    parser.add_argument('--audit-jsonl', type=Path)
    parser.add_argument('--asset')
    parser.add_argument('--attempt-id')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        raw = {key: (args.private_repo_root / path).read_bytes()
               for key, path in coverage.SOURCES.items()}
        policy = json.loads(args.public_policy.read_text(encoding='utf-8'))
        master_sha = sha(raw['master'])
        require(policy['canonical_master_sha256'] == master_sha,
                'C07_153_PUBLIC_POLICY_CANONICAL_MASTER_MISMATCH')
        inventory = coverage.build_inventory(raw, master_sha)
        plan = {
            'master_sha256': master_sha, 'phase': args.phase,
            'asset_type': args.asset_type,
            'profiles': [p for p in args.profiles.split(',') if p],
            'mode': args.mode, 'enrolled': {},
        }
        context = {}
        if args.audit_jsonl is not None:
            context = {
                'audit': args.audit_jsonl.read_bytes(),
                'master_raw': raw['master'], 'asset': args.asset,
                'attempt_id': args.attempt_id,
            }
        report = require_operational_scope(inventory, plan, **context)
        if args.output:
            args.output.write_text(
                json.dumps(report, sort_keys=True, indent=2),
                encoding='utf-8')
        print(json.dumps({
            key: value for key, value in report.items()
            if key not in ('rules', 'missing_due_semantic_validators')
        }, sort_keys=True))
        print('C07_153_RULES_MISSING_NATIVE_SEMANTICS:' +
              str(len(report['missing_due_semantic_validators'])))
        return 0
    except (ValueError, KeyError, TypeError, OSError, UnicodeError) as exc:
        print('C07_153_FAIL_CLOSED:' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
