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

# All 20 AAA-200 families, rather than just the frozen 100 source cohort.
# This is a structural/source-code gate: NO MG0, artistic or FiveM PASS.
AAA_CATALOG_SHA = 'f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9'


def catalog200_macro_snapshot(inventory):
    """Audit *whole* canonical A-T families and group them by catalog phase.

    A phase macro is code-ready only if every one of its full ten-rule
    families has a consuming-side native reader registered in all three
    authoritative code registries. No micro observation can fill a missing
    source-specific rule. An entire missing family remains UNKNOWN, not FAIL.
    """
    import hashlib
    from collections import OrderedDict

    if (type(inventory) is not dict or
            inventory.get('schema') != 'gg-effective-family-inventory-v1' or
            inventory.get('rule_count') != 763 or
            type(inventory.get('rules')) is not dict or
            len(inventory['rules']) != 763 or
            inventory.get('source_digests', {}).get('aaa_catalog') !=
            AAA_CATALOG_SHA):
        raise CohortIncomplete('C07_AAA200_CANONICAL_763_CATALOG_REQUIRED')
    phase_groups = OrderedDict()
    seen = set()
    for index, letter in enumerate('ABCDEFGHIJKLMNOPQRST'):
        ids = tuple('AAA-200-' + letter + '-' + str(number).zfill(3)
                    for number in range(index * 10 + 1, index * 10 + 11))
        phase = None
        ready = []
        inconsistent = []
        for rid in ids:
            row = inventory['rules'].get(rid)
            if (type(row) is not dict or
                    row.get('family') != 'AAA-200' or
                    row.get('catalog_number') != int(rid.rsplit('-', 1)[1]) or
                    type(row.get('requirement')) is not str or
                    not row['requirement'].strip() or
                    hashlib.sha256(row['requirement'].encode('utf-8')).hexdigest()
                    != row.get('requirement_sha256') or
                    row.get('source_sha256') != AAA_CATALOG_SHA or
                    row.get('catalog_phase') not in
                    ('P0','P1','P2','P3','P4','P5','P6','P7','P8')):
                raise CohortIncomplete(
                    'C07_AAA200_ORIGINAL_LITERAL_OR_PHASE_DRIFT:' + rid)
            current_phase = row['catalog_phase']
            if phase is None:
                phase = current_phase
            if phase != current_phase:
                raise CohortIncomplete(
                    'C07_AAA200_FAMILY_SPLIT_ACROSS_PHASES:' + letter)
            native = NATIVE_RULES.get(rid)
            validator = NATIVE_VALIDATORS.get(rid)
            enrolled = REVIEWED.get(rid)
            replayed = REPLAYERS.get(rid)
            if (type(native) is tuple and len(native) == 2 and
                    type(native[1]) is tuple and len(native[1]) >= 2 and
                    len(set(native[1])) == len(native[1]) and
                    type(validator) is str and validator and
                    enrolled == (validator, native[1]) and
                    replayed == validator):
                ready.append(rid)
            # Documentary R173 registrations are valid, but are not native
            # full-literal code review; do not count or mislabel them as a
            # native-registry inconsistency.
            elif native is not None or validator is not None:
                inconsistent.append(rid)
        if not ids or seen.intersection(ids):
            raise CohortIncomplete('C07_AAA200_DUPLICATE_FAMILY_IDS')
        seen.update(ids)
        missing = sorted(set(ids) - set(ready))
        phase_groups.setdefault(phase, []).append({
            'family': letter, 'canonical_rule_count': 10,
            'reviewed_native_code': len(ready), 'missing_native_code': len(missing),
            'missing_ids': missing, 'registry_inconsistencies': inconsistent,
            'whole_family_code_ready': not missing and not inconsistent,
            'independent_mg0': 'UNVERIFIED',
            'full_semantic_asset_verdict': 'UNKNOWN',
        })
    if len(seen) != 200 or len(phase_groups) > 9:
        raise CohortIncomplete('C07_AAA200_200_RULE_PARTITION_DRIFT')
    macros = []
    for phase, families in sorted(phase_groups.items()):
        macros.append({
            'phase': phase, 'families': families,
            'rule_count': len(families) * 10,
            'whole_family_count': len(families),
            'native_code_reviewed': sum(f['reviewed_native_code']
                                        for f in families),
            'missing_native_code': sum(f['missing_native_code']
                                       for f in families),
            'whole_macro_code_ready': all(f['whole_family_code_ready']
                                          for f in families),
            'operational_mg0': 'UNVERIFIED',
            'advancement_authorized': False,
        })
    return {
        'schema': 'c07-aaa200-whole-family-phase-macro-code-gate-v1',
        'canonical_rule_count': 200, 'family_count': 20,
        'phase_macro_count': len(macros),
        'native_code_reviewed': sum(x['native_code_reviewed']
                                    for x in macros),
        'missing_native_code': sum(x['missing_native_code']
                                   for x in macros),
        'macros': macros,
        'all_macro_code_ready': all(x['whole_macro_code_ready']
                                    for x in macros),
        'independent_mg0': 'UNVERIFIED', 'owner_acceptance': 'UNVERIFIED',
        'fivem_runtime': 'UNVERIFIED',
        'advancement_authorized': False, 'c07_finished': False,
    }

