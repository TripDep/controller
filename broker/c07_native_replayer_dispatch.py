"""Explicit consuming-side dispatch for the twelve *documentary* C07 replayers.

A producer's signed log is not an independent semantic or MG0 proof. Only
these source-byte-reopening implementations are permitted. Other original-byte
observers remain SCOPED/UNKNOWN, even if their synthetic tests are green.
No new REVIEWED ID is introduced here.
"""
import re

from approved_validators import REVIEWED, R173_VALIDATOR
from planning_semantics import VALIDATOR as PLANNING_VALIDATOR
from c07_native_source_rule_replayers import (REVIEWED_RULES as NATIVE_RULES, REVIEWED_VALIDATORS as NATIVE_VALIDATORS,
                                               native_rule_readback as native_source_readback)

R173_IDS = frozenset((
    'AAA-200-A-008', 'AAA-200-A-009', 'AAA-200-B-011',
    'AAA-200-B-013', 'AAA-200-B-014', 'AAA-200-B-015',
    'AAA-200-B-016', 'AAA-200-B-017', 'AAA-200-B-018',
    'AAA-200-B-019', 'AAA-200-B-020',
))
REPLAYERS = {
    'AAA-200-B-012': PLANNING_VALIDATOR,
    **{rid: R173_VALIDATOR for rid in R173_IDS},
    **NATIVE_VALIDATORS,
}
BINDING_KEYS = frozenset((
    'work_item_sha256', 'attempt_id', 'operation_sha256',
    'attempt_number', 'previous_attempt_id', 'phase', 'family',
    'rule_id', 'master_sha256', 'source_sha256',
    'requirement_sha256', 'work_dependencies',
))
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


class SourceReplayBlocked(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise SourceReplayBlocked(reason)


def replay(api, packet, expected, spec, *, source_context=None):
    """Reopen original private Git bytes via the *rule-specific* replayer.

    This function is not a new semantic predicate or MG0 verifier. It only
    dispatches to already-reviewed, independently source-recomputing readers.
    A source reader's partial/documentary PASS is never an operational PASS.
    """
    require(type(expected) is dict and set(expected) == BINDING_KEYS and
            type(spec) is dict and type(packet) is dict,
            'C07_NATIVE_REPLAY_EXACT_CONTEXT')
    rid = expected['rule_id']
    require(type(rid) is str and
            rid in REPLAYERS and rid in REVIEWED and
            spec.get('validator_id') == REPLAYERS[rid] == REVIEWED[rid][0],
            'C07_NATIVE_REPLAY_RULE_NOT_WHITELISTED')
    require(type(spec.get('source_ref')) is str and
            HEX40.fullmatch(spec['source_ref']) is not None and
            spec.get('requirement_sha256') == expected['requirement_sha256'] and
            type(spec.get('criteria')) is list and
            set(spec['criteria']) == set(REVIEWED[rid][1]),
            'C07_NATIVE_REPLAY_IMMUTABLE_SOURCE_OR_CRITERIA')
    require(all(type(expected[k]) is str and HEX64.fullmatch(expected[k])
                for k in ('work_item_sha256', 'attempt_id',
                          'operation_sha256', 'master_sha256',
                          'source_sha256', 'requirement_sha256')) and
            type(expected['attempt_number']) is int and
            expected['attempt_number'] > 0 and
            type(expected['work_dependencies']) is dict and
            bool(expected['work_dependencies']) and
            all(type(k) is str and HEX64.fullmatch(k) and
                type(v) is str and HEX64.fullmatch(v)
                for k, v in expected['work_dependencies'].items()) and
            ((expected['attempt_number'] == 1 and
              expected['previous_attempt_id'] is None) or
             (expected['attempt_number'] > 1 and
              type(expected['previous_attempt_id']) is str and
              HEX64.fullmatch(expected['previous_attempt_id']) and
              expected['previous_attempt_id'] != expected['attempt_id'])),
            'C07_NATIVE_REPLAY_ATTEMPT_OPERATION_SOURCE_SHA')
    require(packet.get('binding') == expected and
            type(packet.get('mg0')) is dict and
            packet['mg0'].get('binding') == expected,
            'C07_NATIVE_REPLAY_CROSS_ATTEMPT_OR_OPERATION')
    # Only existing documentary replayers are eligible; each independently
    # fetches original bytes at an immutable SHA and recomputes its own rule.
    if rid == 'AAA-200-B-012':
        from planning_semantics import native_rule_readback
    elif rid in R173_IDS:
        from r173_rule_semantics import native_rule_readback
    elif rid in NATIVE_RULES:
        result = native_source_readback(api, packet, expected, spec,
                                        source_context=source_context)
        require(type(result) is dict and result.get('rule_id') == rid and
                result.get('documentary_result') in ('PASS', 'FAIL') and
                result.get('individual_rule_mg0') in ('UNKNOWN', 'FAIL') and
                packet.get('mg0', {}).get('result') == result['individual_rule_mg0'] and
                result.get('advancement_authorized') is False and
                result.get('asset_advancement_authorized') is False,
                'C07_NATIVE_REPLAY_SOURCE_RULE_CANNOT_AUTHORIZE')
        return result
    else:
        raise SourceReplayBlocked('C07_NATIVE_REPLAY_NO_SOURCE_REPLAYER')
    result = native_rule_readback(api, packet, expected, spec)
    require(type(result) is dict and result.get('rule_id') == rid and
            result.get('documentary_result') in ('PASS', 'FAIL') and
            type(packet.get('rule')) is dict and
            packet['rule'].get('result') == result['documentary_result'] and
            result.get('individual_rule_mg0') == 'UNKNOWN' and
            packet['mg0'].get('result') == 'UNKNOWN' and
            packet['mg0'].get('triggered') is None and
            result.get('advancement_authorized') is not True and
            result.get('asset_advancement_authorized') is not True,
            'C07_NATIVE_REPLAY_SCOPED_RESULT_CANNOT_AUTHORIZE')
    return result
