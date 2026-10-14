"""C07 read-only intake of one real Library/Golden Controller work item.

This is NOT an asset verdict or an authorization. It uses current Library bytes,
verifies the whole Controller audit chain, and reports asset-scoped blockers.
A stale *different* asset is irrelevant to the requested work item.
"""
import argparse
import hashlib
import json
from pathlib import Path


class IntakeBlocked(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise IntakeBlocked(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(row):
    return json.dumps(row, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_json(raw):
    def pairs(items):
        doc = {}
        for key, value in items:
            require(key not in doc, "INTAKE_DUPLICATE_JSON_KEY")
            doc[key] = value
        return doc
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(IntakeBlocked("INTAKE_NONFINITE")))


def audit_check(raw, asset):
    require(len(raw) <= 40_000_000, "INTAKE_AUDIT_OVERSIZE")
    rows = []
    prior = "GENESIS"
    for n, line in enumerate(raw.splitlines(), 1):
        require(bool(line.strip()), "INTAKE_AUDIT_BLANK:" + str(n))
        row = strict_json(line)
        require(isinstance(row, dict) and row.get("asset") == asset,
                "INTAKE_AUDIT_ASSET:" + str(n))
        require(row.get("prev_hash") == prior, "INTAKE_AUDIT_CHAIN:" + str(n))
        h = row.get("record_hash")
        require(isinstance(h, str) and len(h) == 64 and
                h == sha(canonical({k: v for k, v in row.items() if k != "record_hash"})),
                "INTAKE_AUDIT_RECORD:" + str(n))
        prior = h
        rows.append(row)
    require(bool(rows), "INTAKE_EMPTY_AUDIT")
    return rows, prior


def inspect(master_raw, state_raw, audit_raw, asset, expected_master_sha):
    require(isinstance(asset, str) and bool(asset) and asset == asset.upper() and
            not any(x in asset for x in ("/", "\\", "..")), "INTAKE_ASSET_ID")
    require(isinstance(expected_master_sha, str) and len(expected_master_sha) == 64,
            "INTAKE_MASTER_EXPECTED_SHA")
    master_sha = sha(master_raw)
    require(master_sha == expected_master_sha, "INTAKE_MASTER_LIBRARY_DRIFT")
    require(b"Golden Controller enforcement" in master_raw and
            b"Persistent observable audit trail" in master_raw,
            "INTAKE_MASTER_AUTHORITY_MARKERS")
    state = strict_json(state_raw)
    require(isinstance(state, dict) and isinstance(state.get("assets"), dict),
            "INTAKE_STATE_SCHEMA")
    require(asset in state["assets"], "INTAKE_ASSET_NOT_IN_CANONICAL_STATE")
    st = state["assets"][asset]
    require(isinstance(st, dict) and isinstance(st.get("unresolved"), dict),
            "INTAKE_ASSET_STATE_SCHEMA")
    rows, tail = audit_check(audit_raw, asset)
    found = next((n for n, row in enumerate(rows)
                  if row["record_hash"] == st.get("last_audit_hash")), None)
    if tail == st.get("last_audit_hash"):
        audit_alignment = "EXACT"
    elif found is not None:
        audit_alignment = "STATE_BEHIND_AUDIT"
    else:
        audit_alignment = "STATE_AUDIT_DISCONNECTED"

    blockers = []
    if audit_alignment != "EXACT":
        blockers.append("CURRENT_WORK_STATE_AUDIT_RECONCILIATION_REQUIRED")
    if st.get("active_step") is not None:
        blockers.append("CURRENT_WORK_ACTIVE_STEP")
    if st["unresolved"]:
        blockers.append("CURRENT_WORK_UNRESOLVED_CONTROLLER_FAIL")
    if not st.get("d_authorized"):
        blockers.append("CURRENT_WORK_D0_NOT_AUTHORIZED")
    if not st.get("d_authorization_evidence"):
        blockers.append("CURRENT_WORK_D0_EVIDENCE_MISSING")
    # A historical D0 is never automatically a new owner artistic approval.
    last_open = next((r for r in reversed(rows)
                      if r.get("event") == "STEP_OPEN"), None)
    last_close = next((r for r in reversed(rows)
                       if r.get("event") == "STEP_CLOSE"), None)
    prior_master = (st.get("last_master") or {}).get("sha256")
    last_phase = last_open.get("aaa_phase") if last_open else None
    if prior_master and prior_master != master_sha:
        blockers.append("WORK_MASTER_DEPENDENCIES_NEED_REVIEW")
    return {
        "schema": "gg-c07-real-work-intake-v1",
        "asset": asset,
        "library_master_sha256": master_sha,
        "work_state_sha256": sha(state_raw),
        "audit_file_sha256": sha(audit_raw),
        "audit_chain_valid": True,
        "audit_event_count": len(rows),
        "audit_tail": tail,
        "state_audit_tail": st.get("last_audit_hash"),
        "state_audit_alignment": audit_alignment,
        "state_lag_events": len(rows) - 1 - found if found is not None else None,
        "last_observed_phase": last_phase,
        "last_closed_step": last_close.get("step") if last_close else None,
        "last_closed_result": last_close.get("result") if last_close else None,
        "next_step_from_state": st.get("next_step"),
        "unresolved_blocker_ids": sorted(st["unresolved"]),
        "owner_d0_evidence_present": bool(st.get("d_authorization_evidence")),
        "operation_enrolled": False,
        "semantic_rules_and_mg0_verified": False,
        "controller_preflight_ready": not blockers,
        "advancement_authorized": False,
        "blockers": sorted(set(blockers)),
        "next_required_action": (
            "RECONCILE_THIS_ASSET_STATE" if audit_alignment != "EXACT"
            else "RESOLVE_THIS_ASSET_CONTROLLER_BLOCKERS" if st["unresolved"]
            else "ENROLL_EXACT_OPERATION_AND_VERIFY_ALL_DUE_RULES_MG0"
        ),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--library-master", type=Path, required=True)
    p.add_argument("--work-state", type=Path, required=True)
    p.add_argument("--work-audit", type=Path, required=True)
    p.add_argument("--asset", required=True)
    p.add_argument("--expected-master-sha", required=True)
    a = p.parse_args(argv)
    try:
        report = inspect(a.library_master.read_bytes(), a.work_state.read_bytes(),
                         a.work_audit.read_bytes(), a.asset, a.expected_master_sha)
        print(json.dumps(report, sort_keys=True))
        # Read-only inspection succeeds even when the work itself is blocked.
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        print("C07_REAL_INTAKE_INVALID:" + str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
