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



# Immutable 100-ID source cohort partitioned into WHOLE multi-rule macros.
# These are grouped completeness gates, not newly invented validators.
MACRO_GROUPS = (
    ('P1_DESIGN_SITE_BLOCKOUT_30', tuple(COHORT[:30])),
    ('P3_P5_GEOMETRY_MATERIAL_LOD_40', tuple(COHORT[30:70])),
    ('P6_P8_COLLISION_RAGE_QA_30', tuple(COHORT[70:])),
)
FROZEN_MACRO_PREFIXES = (
    ('D', 'E', 'F'),
    ('L', 'M', 'N', 'O'),
    ('P', 'Q', 'S'),
)


def macro_snapshot():
    """Recompute complete macro-family code coverage; never count micro PASSes.

    Every AAA-200 alphabetic family must have all TEN source-specific native
    consumers. A single partial reviewer cannot certify a family or macro.
    Operational MG0/asset acceptance are separate, unverified authorizations.
    """
    current = snapshot()
    seen = set()
    groups = []
    for (name, members), expected_letters in zip(
            MACRO_GROUPS, FROZEN_MACRO_PREFIXES):
        expected = set()
        families = []
        for letter in expected_letters:
            family = tuple(x for x in members if
                           x.split('-')[2] == letter)
            if len(family) != 10:
                raise CohortIncomplete(
                    'C07_MACRO_FAMILY_NOT_TEN_CANONICAL_RULES:' + letter)
            numbers = [int(x.rsplit('-', 1)[1]) for x in family]
            expected_numbers = list(range(
                (ord(letter) - ord('A')) * 10 + 1,
                (ord(letter) - ord('A') + 1) * 10 + 1))
            if numbers != expected_numbers:
                raise CohortIncomplete(
                    'C07_MACRO_FAMILY_NONCANONICAL_LITERAL_ORDER:' + letter)
            expected.update(family)
            reviewed = sorted(set(family) & set(current['code_reviewed_ids']))
            missing = sorted(set(family) - set(reviewed))
            inconsistent = sorted(set(family) &
                                  set(current['registry_inconsistent_ids']))
            families.append({
                'family': letter, 'rule_count': 10,
                'code_reviewed': len(reviewed), 'missing': len(missing),
                'missing_ids': missing, 'inconsistent_ids': inconsistent,
                'code_family_ready': not missing and not inconsistent,
                'operational_mg0': 'UNVERIFIED',
                'asset_acceptance': 'UNVERIFIED',
            })
        if set(members) != expected or seen.intersection(members):
            raise CohortIncomplete('C07_MACRO_FAMILY_COHORT_DRIFT:' + name)
        seen.update(members)
        groups.append({
            'macro': name, 'rule_count': len(members),
            'family_count': len(families), 'families': families,
            'code_reviewed': sum(f['code_reviewed'] for f in families),
            'code_missing': sum(f['missing'] for f in families),
            'code_macro_ready': all(f['code_family_ready'] for f in families),
            'independent_mg0': 'UNVERIFIED',
            'owner_acceptance': 'UNVERIFIED',
            'fivem_runtime': 'UNVERIFIED',
            'advancement_authorized': False,
        })
    if seen != set(COHORT) or len(seen) != 100 or len(groups) != 3:
        raise CohortIncomplete('C07_MACRO_FROZEN_100_PARTITION_INVALID')
    return {
        'schema': 'c07-frozen100-whole-family-macro-code-gate-v1',
        'cohort_count': 100, 'macro_count': 3, 'family_count': 10,
        'code_reviewed': current['code_reviewed_count'],
        'code_missing': current['code_missing_count'],
        'macros': groups, 'code_all_macros_ready': all(
            g['code_macro_ready'] for g in groups),
        'independent_mg0': 'UNVERIFIED',
        'owner_acceptance': 'UNVERIFIED',
        'fivem_runtime': 'UNVERIFIED',
        'c07_finished': False,
        'advancement_authorized': False,
    }


def require_macro_code_ready(name, report):
    """Independent recount rejects forged macro totals and partial families."""
    actual = macro_snapshot()
    if (type(report) is not dict or report != actual or
            name not in {g['macro'] for g in actual['macros']}):
        raise CohortIncomplete('C07_MACRO_SOURCE_CODE_RECOUNT_MISMATCH')
    group = next(g for g in actual['macros'] if g['macro'] == name)
    if not group['code_macro_ready']:
        raise CohortIncomplete('C07_MACRO_WHOLE_FAMILIES_INCOMPLETE:' + name)
    return True


def require_code100(report):
    """Recount the real registries; reject a forged '100/100' report."""
    current = snapshot()
    if (type(report) is not dict or report != current or
            not current['code_100_ready'] or
            current['code_reviewed_count'] != 100 or
            current['code_missing_count'] != 0 or
            current['registry_inconsistent_ids'] != []):
        raise CohortIncomplete('C07_100_SEMANTIC_REPLAYERS_NOT_COMPLETED')
    return True


def refuse_full_completion(report):
    """No code-only fixture can authorize C07 FINITO or production."""
    require_code100(report)
    raise CohortIncomplete('C07_MG0_OWNER_FIVEM_PROOF_NOT_VERIFIED')
