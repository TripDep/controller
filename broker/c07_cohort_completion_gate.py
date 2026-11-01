"""C07 frozen 100-rule cohort: code-review progress is NOT an MG0 or asset PASS.

Recompute the current source-specific dispatch/enrollment coverage from code,
rather than relying on an automation prompt, an old PR description or CI green.
An incomplete cohort can never be advertised as implemented/completed.
"""
from c07_batch100_native_replay import COHORT
from approved_validators import REVIEWED
from c07_native_replayer_dispatch import REPLAYERS
from c07_native_source_rule_replayers import (
    REVIEWED_RULES as NATIVE_RULES,
    REVIEWED_VALIDATORS as NATIVE_VALIDATORS,
)

class CohortIncomplete(ValueError):
    pass


def snapshot(*, cohort=None, reviewed=None, replay=None,
             native_rules=None, native_validators=None):
    """Strict code-enrollment inventory, no claim about real-world evidence."""
    ids = tuple(COHORT if cohort is None else cohort)
    approved = REVIEWED if reviewed is None else reviewed
    dispatched = REPLAYERS if replay is None else replay
    natives = NATIVE_RULES if native_rules is None else native_rules
    validators = NATIVE_VALIDATORS if native_validators is None else native_validators
    if (len(ids) != 100 or len(set(ids)) != 100 or
            any(type(x) is not str for x in ids)):
        raise CohortIncomplete('C07_FROZEN_100_COHORT_CHANGED')
    if not all(type(x) is dict for x in (approved, dispatched, natives, validators)):
        raise CohortIncomplete('C07_COMPLETION_REGISTRY_SCHEMA')
    covered = []
    inconsistent = []
    for rid in ids:
        native = natives.get(rid)
        enrollment = approved.get(rid)
        replay_id = dispatched.get(rid)
        validator_id = validators.get(rid)
        is_valid = (
            type(native) is tuple and len(native) == 2 and
            type(native[0]) is str and bool(native[0]) and
            type(native[1]) is tuple and bool(native[1]) and
            len(set(native[1])) == len(native[1]) and
            all(type(v) is str and bool(v) for v in native[1]) and
            type(validator_id) is str and bool(validator_id) and
            type(enrollment) is tuple and len(enrollment) == 2 and
            enrollment == (validator_id, native[1]) and
            replay_id == validator_id
        )
        if is_valid:
            covered.append(rid)
        elif any(x is not None for x in (native, enrollment, replay_id, validator_id)):
            inconsistent.append(rid)
    missing = sorted(set(ids) - set(covered))
    return {
        'schema': 'c07-code-reviewed-100-gate-v1',
        'cohort_count': 100,
        'code_reviewed_count': len(covered),
        'code_reviewed_ids': sorted(covered),
        'code_missing_count': len(missing),
        'code_missing_ids': missing,
        'registry_inconsistent_ids': sorted(inconsistent),
        'code_100_ready': len(covered) == 100 and not inconsistent,
        # Code registration is not evidence of a real MG0 or FiveM PASS.
        'operational_mg0': 'UNVERIFIED',
        'owner_acceptance': 'UNVERIFIED',
        'fivem_runtime': 'UNVERIFIED',
        'c07_finished': False,
    }


def require_code100(report):
    """Never let partial code enrollment masquerade as a completed cohort."""
    if (type(report) is not dict or report.get('schema') !=
            'c07-code-reviewed-100-gate-v1' or
            report.get('cohort_count') != 100 or
            report.get('code_100_ready') is not True or
            report.get('code_reviewed_count') != 100 or
            report.get('code_missing_count') != 0 or
            report.get('code_missing_ids') != [] or
            report.get('registry_inconsistent_ids') != []):
        raise CohortIncomplete('C07_100_SEMANTIC_REPLAYERS_NOT_COMPLETED')
    return True


def refuse_full_completion(report):
    """No code-only fixture can authorize C07 FINITO or production."""
    require_code100(report)
    raise CohortIncomplete('C07_MG0_OWNER_FIVEM_PROOF_NOT_VERIFIED')
