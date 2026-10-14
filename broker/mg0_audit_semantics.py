"""Classify MG0 process falsification from current Controller audit bytes.

An audited MG0 failure establishes a process trigger, not a per-rule MG0 PASS.
Absent explicit evidence remains UNKNOWN. No asset binaries are read or uploaded.
"""
import argparse
import json
from pathlib import Path

from real_work_intake import audit_check, sha, require

CANONICAL = (b"## MG0 \xe2\x80\x94 PROCESS FALSIFICATION",
             b"Canonical trigger pattern recovered from the old chat:",
             b"The response is not limited to fixing the asset.")


def inspect(master_raw, audit_raw, asset, master_sha256, rule_id=None):
    require(sha(master_raw) == master_sha256, 'MG0_MASTER_SHA_CHANGED')
    require(all(marker in master_raw for marker in CANONICAL),
            'MG0_CANONICAL_SOURCE_MISSING')
    rows, tail = audit_check(audit_raw, asset)
    opens = {r['step']: r for r in rows
             if r.get('event') == 'STEP_OPEN' and 'step' in r}
    closes = {r['step']: r for r in rows
              if r.get('event') == 'STEP_CLOSE' and 'step' in r}
    require(len(opens) == len([r for r in rows if r.get('event') == 'STEP_OPEN']),
            'MG0_DUPLICATE_STEP_OPEN')
    require(len(closes) == len([r for r in rows if r.get('event') == 'STEP_CLOSE']),
            'MG0_DUPLICATE_STEP_CLOSE')
    identified = []
    for n, close in enumerate(rows):
        if close.get('event') != 'STEP_CLOSE' or close.get('result') != 'FAIL':
            continue
        step = close.get('step')
        opened = opens.get(step)
        if not opened or opened.get('authorization_token') != close.get('authorization_token'):
            continue
        if rows.index(opened) >= n:
            continue
        action = str(close.get('action', ''))
        detail = str(close.get('evidence_operation', ''))
        if ('MG0' not in action or 'process' not in action.lower() or
                'MG0 confirmed process inconsistency:' not in detail):
            continue
        mention = ('Controller MG0 step `' + str(step) + '` closed `FAIL`').encode()
        require(mention in master_raw, 'MG0_MASTER_AUDIT_INCIDENT_NOT_RECONCILED')
        repairs = []
        for j, other in enumerate(rows[n+1:], n+1):
            if other.get('event') != 'BLOCKER_RESOLVED' or str(other.get('resolves')) != str(step):
                continue
            corrected = closes.get(other.get('step'))
            operation = opens.get(other.get('step'))
            if (not corrected or not operation or corrected.get('result') != 'PASS' or
                    rows.index(corrected) > j or
                    rows.index(operation) > rows.index(corrected) or
                    step not in operation.get('resolves', [])):
                continue
            repairs.append({'correction_step': corrected['step'],
                            'close_record_sha256': corrected['record_hash'],
                            'blocker_resolved_sha256': other['record_hash']})
        identified.append({'step': step, 'failed_record_sha256': close['record_hash'],
                           'opened_record_sha256': opened['record_hash'],
                           'correction_records': repairs,
                           'trigger': 'CONFIRMED_BY_MASTER_AND_HASH_CHAINED_CONTROLLER'})
    linked = (any(str(r.get('rule_id')) == rule_id and
                  r.get('event') == 'MG0_RULE_VERIFIED' for r in rows)
              if rule_id is not None else False)
    return {'schema': 'gg-mg0-actual-audit-triage-v1', 'asset': asset,
            'canonical_master_sha256': master_sha256,
            'audit_file_sha256': sha(audit_raw), 'audit_tail_sha256': tail,
            'audit_events_checked': len(rows),
            'global_trigger': 'CONFIRMED' if identified else 'UNKNOWN',
            'trigger_events': identified,
            'rule_id': rule_id, 'individual_rule_mg0': 'UNKNOWN',
            'rule_mapping_observed': linked,
            'current_attempt_reapplication_verified': False,
            'advancement_authorized': False,
            'scope': 'PROCESS_TRIGGER_TRIAGE_ONLY_NOT_NATIVE_RULE_VERDICT'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--master', type=Path, required=True)
    p.add_argument('--audit', type=Path, required=True)
    p.add_argument('--asset', required=True)
    p.add_argument('--expected-master-sha', required=True)
    p.add_argument('--rule-id')
    a = p.parse_args(argv)
    try:
        report = inspect(a.master.read_bytes(), a.audit.read_bytes(), a.asset,
                         a.expected_master_sha, a.rule_id)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, TypeError, KeyError, OSError) as e:
        print('MG0_AUDIT_INVALID:' + str(e))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
