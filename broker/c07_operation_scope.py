"""C07 exact-operation validator coverage gate.

The Controller supplies the work plan; the pinned source inventory supplies every
rule and its earliest canonical phase/type/profile. This gate prevents a STATUS
enrollment from disguising missing due source-specific validators as enrolled.
It does NOT establish rule semantics, individual MG0, evidence, or work PASS.
"""
import re

import family_coverage as coverage


class IncompleteOperationScope(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise IncompleteOperationScope(reason)


def inspect(inventory, plan):
    """Compute all due, future and canonical N/A slots; never omit an ID."""
    require(isinstance(inventory, dict) and isinstance(plan, dict),
            'C07_SCOPE_INPUT_SCHEMA')
    groups = inventory.get('families')
    rules = inventory.get('rules')
    require(isinstance(groups, dict) and isinstance(rules, dict) and groups,
            'C07_SCOPE_INVENTORY_SCHEMA')
    flat = [rule for group in groups.values() for rule in group]
    require(len(flat) == len(set(flat)) and set(flat) == set(rules),
            'C07_SCOPE_INVENTORY_MISSING_DUPLICATED_IDS')
    require(inventory.get('rule_count') == len(flat) and
            inventory.get('family_count') == len(groups),
            'C07_SCOPE_INVENTORY_COUNT_CHANGED')
    require(plan.get('master_sha256') == inventory.get('canonical_master_sha256'),
            'C07_SCOPE_MASTER_SOURCE_DRIFT')
    phase = plan.get('phase')
    kind = plan.get('asset_type')
    profiles = plan.get('profiles')
    require(phase in coverage.PHASES and kind in coverage.ASSET_TYPES,
            'C07_SCOPE_PHASE_OR_ASSET_TYPE')
    known_profiles = {r['profile'] for r in rules.values() if 'profile' in r}
    require(isinstance(profiles, list) and len(profiles) == len(set(profiles)) and
            bool(profiles) and set(profiles) <= known_profiles,
            'C07_SCOPE_TRUSTED_PROFILE_REQUIRED')
    enrolled = plan.get('enrolled')
    require(isinstance(enrolled, dict) and set(enrolled) <= set(rules),
            'C07_SCOPE_VALIDATOR_ID_NOT_CANONICAL')
    from c07_contextual_questions import select as context_select
    question_context = context_select(inventory, plan)
    context_excluded = set(question_context['excluded']) if question_context else set()
    slots = {'DUE': [], 'FUTURE_PHASE': [], 'N_A': [], 'N_A_CONTEXT': []}
    bases = {}
    for family, ids in groups.items():
        for rid in ids:
            row = rules[rid]
            require(row.get('family') == family and
                    isinstance(row.get('requirement_sha256'), str) and
                    re.fullmatch(r'[0-9a-f]{64}', row['requirement_sha256']) and
                    isinstance(row.get('source_sha256'), str) and
                    re.fullmatch(r'[0-9a-f]{64}', row['source_sha256']),
                    'C07_SCOPE_SOURCE_ROW_INVALID:' + rid)
            disposition = coverage.expected_result(row, phase, kind, profiles)
            require(disposition in ('PASS', 'FUTURE_PHASE',
                    'N_A_PROFILE_NOT_SELECTED', 'N_A_ASSET_TYPE'),
                    'C07_SCOPE_UNSUPPORTED_APPLICABILITY:' + rid)
            status = ('N_A_CONTEXT' if rid in context_excluded else
                      'DUE' if disposition == 'PASS' else
                      'FUTURE_PHASE' if disposition == 'FUTURE_PHASE' else 'N_A')
            slots[status].append(rid)
            bases[rid] = {'disposition': status, 'canonical_reason': disposition,
                          'family': family, 'source_sha256': row['source_sha256'],
                          'requirement_sha256': row['requirement_sha256']}
            if status == 'N_A_CONTEXT':
                bases[rid]['context_exclusion'] = question_context['rows'][rid]
    missing = sorted(set(slots['DUE']) - set(enrolled))
    # Distinguish "a reviewer implemented this predicate" from "the
    # Controller enrolled that exact reviewer".  Neither one is semantic
    # evidence or a pass for the current asset/attempt.
    from approved_validators import REVIEWED
    due_set = set(slots['DUE'])
    supported_due = due_set & set(REVIEWED)
    no_implementation = sorted(due_set - set(REVIEWED))
    reviewed_not_enrolled = sorted(supported_due - set(enrolled))
    enrolled_without_implementation = sorted(due_set & set(enrolled) - set(REVIEWED))
    family_gaps = {
        family: {
            'due': sum(r in due_set for r in ids),
            'no_reviewed_native_validator': sum(r in no_implementation for r in ids),
            'reviewed_but_not_enrolled': sum(r in reviewed_not_enrolled for r in ids),
        }
        for family, ids in groups.items()
    }
    # Documentary, CI and MG0 PASS are separate; an enrolled issuer is not a PASS.
    return {'schema': 'gg-c07-trusted-operation-applicability-v1',
            'master_sha256': plan['master_sha256'], 'phase': phase,
            'asset_type': kind, 'profiles': list(profiles),
            'rule_count': len(flat), 'family_count': len(groups),
            'due': sorted(slots['DUE']), 'future_phase': sorted(slots['FUTURE_PHASE']),
            'not_applicable': sorted(slots['N_A']),
            'context_excluded': sorted(slots['N_A_CONTEXT']),
            'context_exclusions_with_reasons': {rid: bases[rid]['context_exclusion']
                                                for rid in slots['N_A_CONTEXT']},
            'base_questions_accounted_for': question_context['total_questions'] if question_context else 0,
            'by_rule': bases,
            'missing_due_validators': missing,
            'due_validators_complete': not missing,
            'due_without_reviewed_native_verifier': no_implementation,
            'due_reviewed_but_not_enrolled': reviewed_not_enrolled,
            'due_enrolled_without_reviewed_implementation': enrolled_without_implementation,
            'reviewed_native_validator_count': len(supported_due),
            'native_verifier_implementation_complete': not no_implementation,
            'native_verifier_coverage_by_family': family_gaps,
            'individual_rule_mg0_verified': False,
            'work_advancement_authorized': False}


def require_due_enrolled(inventory, plan):
    """Fail closed before enrolling an OPERATIONAL plan with any due rule absent."""
    report = inspect(inventory, plan)
    require(plan.get('mode') in ('OPERATIONAL', 'DIAGNOSTIC_ONLY'),
            'C07_SCOPE_MODE_UNKNOWN')
    if plan['mode'] == 'OPERATIONAL':
        require(not report['missing_due_validators'],
                'C07_SCOPE_MISSING_DUE_SEMANTIC_VALIDATORS:' +
                str(len(report['missing_due_validators'])) + ':' +
                ','.join(report['missing_due_validators'][:12]))
        require(plan.get('asset_specific_extensions_verified') is True,
                'C07_SCOPE_ASSET_SPECIFIC_EXTENSIONS_UNVERIFIED')
    return report
