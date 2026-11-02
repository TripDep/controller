"""Domain computations for the immutable macro100 cohort.

These are development-time predicates over explicit observations, not trusted
reviewer enrollment. OBSERVED means the supplied records satisfy a predicate;
it does not authenticate those records, certify MG0 or authorize execution.
Missing evidence is UNKNOWN, never the empty-set/vacuous success of a rule.
"""
from dataclasses import dataclass
from datetime import datetime
import hashlib
import math


class MissingEvidence(ValueError):
    pass


def require(value, reason):
    if not value:
        raise MissingEvidence(reason)


def number(value):
    require(type(value) in (int, float) and math.isfinite(value), 'finite number required')
    return value


def instant(value):
    require(type(value) is str, 'timestamp required')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise MissingEvidence('invalid timestamp') from exc
    require(parsed.tzinfo is not None, 'timestamp must include timezone')
    return parsed.timestamp()


def ids(rows, key='id'):
    values = [row[key] for row in rows]
    require(all(type(x) is str and x for x in values), 'nonempty identifiers required')
    require(len(values) == len(set(values)), 'duplicate identifiers')
    return set(values)


def interval_union(intervals):
    """Clip before calling; overlapping parallel sessions count only once."""
    ordered = sorted((number(a), number(b)) for a, b in intervals)
    require(all(a < b for a, b in ordered), 'empty or reversed time interval')
    merged = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def duration(intervals):
    return sum(b-a for a, b in interval_union(intervals))


def range_covered(ranges, size):
    require(type(size) is int and size > 0, 'positive source byte length required')
    require(bool(ranges), 'no source read ranges')
    require(all(type(a) is int and type(b) is int and 0 <= a < b <= size
                for a, b in ranges), 'invalid source byte range')
    return interval_union(ranges) == [[0, size]]


@dataclass(frozen=True)
class Finding:
    result: str
    reason: str
    measured: object = None


def verdict(ok, reason, measured=None):
    require(type(ok) is bool, 'predicate must compute a boolean')
    return Finding('OBSERVED' if ok else 'FAIL', reason, measured)


class Context:
    """An untrusted recorded observation set; no bool/YES-to-PASS adapter."""
    def __init__(self, observations, blobs=None):
        require(type(observations) is dict, 'observation object required')
        self.data = observations
        self.blobs = {} if blobs is None else blobs

    def get(self, key):
        require(key in self.data, 'missing observation: '+key)
        return self.data[key]

    def rows(self, key):
        rows = self.get(key)
        require(type(rows) is list and bool(rows) and all(type(r) is dict for r in rows),
                'nonempty records required: '+key)
        return rows

    def blob(self, sha):
        require(type(sha) is str and sha in self.blobs, 'original bytes unavailable: '+str(sha))
        raw = self.blobs[sha]
        require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == sha,
                'original bytes do not match digest')
        return raw

    def telemetry(self):
        window = self.get('window')
        start, end = instant(window['start']), instant(window['end'])
        require(start < end, 'invalid observation window')
        sessions = self.rows('sessions')
        ids(sessions)
        intervals = []
        for row in sessions:
            a, b = instant(row['started']), instant(row['work_ended'])
            require(a < b, 'invalid session interval')
            if max(a, start) < min(b, end):
                intervals.append((max(a, start), min(b, end)))
        active = duration(intervals)
        return {'calendar_seconds': end-start, 'active_seconds': active,
                'idle_seconds': end-start-active, 'duty_cycle': active/(end-start)}

    def claims(self, kind):
        rows = [r for r in self.rows('claims') if r['kind'] == kind]
        require(bool(rows), 'no claim of type: '+kind)
        ids(rows)
        return rows

    def runs(self):
        rows = self.rows('runs')
        ids(rows)
        return {r['id']: r for r in rows}

    def actions(self):
        rows = self.rows('actions')
        ids(rows)
        require([instant(r['at']) for r in rows] == sorted(instant(r['at']) for r in rows),
                'actions out of order')
        return rows

    def production_delta(self):
        before = self.rows('deliverables_before')
        after = self.rows('deliverables_after')
        ids(before); ids(after)
        requested = set(self.get('objective')['deliverable_ids'])
        require(bool(requested), 'requested deliverables required')
        previous = {r['id']: r for r in before}
        accepted = set()
        for row in after:
            if row['id'] not in requested:
                continue
            self.blob(row['sha256'])
            old = previous.get(row['id'])
            if row['state'] == 'VERIFIED' and (old is None or old['state'] != 'VERIFIED'
                                              or old['sha256'] != row['sha256']):
                accepted.add(row['id'])
        return accepted

    def checkpoints(self):
        rows = self.rows('checkpoints')
        ids(rows)
        return {r['id']: r for r in rows}


def evaluate(fn, context):
    try:
        result = fn(context)
        require(type(result) is Finding, 'invalid evaluator return')
        return result
    except (MissingEvidence, KeyError, TypeError, ValueError, IndexError, OverflowError, StopIteration) as exc:
        return Finding('UNKNOWN', str(exc))
