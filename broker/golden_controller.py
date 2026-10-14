#!/usr/bin/env python3
"""Golden Garden Controller

Mechanical enforcement layer for the Golden Garden workflow.
It does not judge artistic quality. It enforces observable process state:
Master re-read/hash, D authorization, single active step, append-only hash-chained
JSONL audit, unresolved failure blocking, artifact hashes, and delivery prerequisites.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

VERSION = "1.2.0-AAA200"
MUTATING_CATEGORIES = {"MUTATION", "GENERATION", "EXPORT", "STATUS", "DELIVERY", "MASTER_UPDATE"}
READONLY_CATEGORIES = {"READ", "ANALYSIS", "QA"}
RESULTS = {"PASS", "FAIL", "UNKNOWN", "BLOCKED"}

REQUIRED_MASTER_MARKERS = [
    "MASTER CONTINUOUS AUTHORITY + LOCK MATRIX",
    "Persistent observable audit trail",
    "A/B/C/D + explicit D0 start",
    "Golden Controller enforcement",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def atomic_write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_asset(asset: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", asset.strip()).strip("._")
    if not value:
        raise SystemExit("ERROR: invalid asset/work-item name")
    return value.upper()


def parse_master(master_path: Path) -> Dict[str, str]:
    if not master_path.exists():
        raise SystemExit(f"BLOCKED: Master not found: {master_path}")
    data = master_path.read_bytes()
    text = data.decode("utf-8", errors="strict")
    missing = [m for m in REQUIRED_MASTER_MARKERS if m not in text]
    if missing:
        raise SystemExit("BLOCKED: Master missing required control markers: " + ", ".join(missing))
    m = re.search(r"\*\*Revision:\*\*\s*([^\n]+)", text)
    revision = m.group(1).strip() if m else "UNKNOWN_REVISION"
    return {
        "path": str(master_path.resolve()),
        "revision": revision,
        "sha256": sha256_bytes(data),
        "size_bytes": str(len(data)),
    }


class Controller:
    def __init__(self, root: Path, master: Path):
        self.root = root.resolve()
        self.master = master.resolve()
        self.control = self.root / "_CONTROL"
        self.audit_dir = self.control / "AUDIT"
        self.state_path = self.control / "WORK_STATE.json"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.state = read_json(self.state_path, {"schema": 1, "controller_version": VERSION, "assets": {}})
        self.state.setdefault("schema", 1)
        self.state["controller_version"] = VERSION
        self.state.setdefault("assets", {})

    def master_identity(self) -> Dict[str, str]:
        return parse_master(self.master)

    def asset_state(self, asset: str) -> Dict[str, Any]:
        asset = safe_asset(asset)
        assets = self.state["assets"]
        if asset not in assets:
            assets[asset] = {
                "created_at": utc_now(),
                "d_authorized": False,
                "d_authorization_evidence": None,
                "active_step": None,
                "next_step": 1,
                "unresolved": {},
                "artifacts": [],
                "last_master": None,
                "last_audit_hash": "GENESIS",
                "delivery_status": "NOT_DELIVERABLE",
            }
        return assets[asset]

    def audit_path(self, asset: str) -> Path:
        return self.audit_dir / f"{safe_asset(asset)}_WORK_AUDIT.jsonl"

    def append_event(self, asset: str, event: Dict[str, Any]) -> Dict[str, Any]:
        st = self.asset_state(asset)
        record = dict(event)
        record["asset"] = safe_asset(asset)
        record["timestamp_utc"] = utc_now()
        record["controller_version"] = VERSION
        record["prev_hash"] = st.get("last_audit_hash", "GENESIS")
        digest = sha256_bytes(canonical_json(record))
        record["record_hash"] = digest
        p = self.audit_path(asset)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        st["last_audit_hash"] = digest
        atomic_write_json(self.state_path, self.state)
        return record

    def verify_audit_chain(self, asset: str) -> Dict[str, Any]:
        p = self.audit_path(asset)
        if not p.exists():
            return {"ok": True, "records": 0, "last_hash": "GENESIS"}
        prev = "GENESIS"
        count = 0
        with p.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                claimed = rec.pop("record_hash", None)
                if rec.get("prev_hash") != prev:
                    return {"ok": False, "error": f"prev_hash mismatch at line {lineno}", "records": count}
                actual = sha256_bytes(canonical_json(rec))
                if claimed != actual:
                    return {"ok": False, "error": f"record_hash mismatch at line {lineno}", "records": count}
                prev = claimed
                count += 1
        st = self.asset_state(asset)
        if st.get("last_audit_hash") not in (None, prev):
            return {"ok": False, "error": "WORK_STATE last_audit_hash does not match audit chain", "records": count}
        return {"ok": True, "records": count, "last_hash": prev}

    def save(self) -> None:
        atomic_write_json(self.state_path, self.state)

    def init_asset(self, asset: str, scope: str) -> Dict[str, Any]:
        asset = safe_asset(asset)
        master = self.master_identity()
        st = self.asset_state(asset)
        st["scope"] = scope
        st["last_master"] = master
        rec = self.append_event(asset, {
            "event": "WORK_INIT",
            "action": "Initialize controlled work item",
            "master_check_before": master,
            "locks_applied": ["Continuous Master authority", "Persistent observable audit trail"],
            "state_before": "READY",
            "evidence_operation": scope,
            "master_check_after": master,
            "regression_check": "No project mutation performed by init.",
            "result": "PASS",
            "next_authority": "Read/analysis allowed; mutation requires D authorization and open controlled step.",
        })
        self.save()
        return rec

    def authorize_d(self, asset: str, evidence: str) -> Dict[str, Any]:
        asset = safe_asset(asset)
        master = self.master_identity()
        st = self.asset_state(asset)
        if st.get("active_step"):
            raise SystemExit("BLOCKED: cannot change D authorization while a step is open")
        st["d_authorized"] = True
        st["d_authorization_evidence"] = evidence
        st["last_master"] = master
        rec = self.append_event(asset, {
            "event": "D_AUTHORIZED",
            "action": "Record explicit D0 authorization",
            "master_check_before": master,
            "locks_applied": ["A/B/C/D + explicit D0 start"],
            "state_before": "READY",
            "evidence_operation": evidence,
            "master_check_after": master,
            "regression_check": "Authorization changes permission state only; no asset mutation.",
            "result": "PASS",
            "next_authority": "Mutating controlled steps may be opened if no unresolved blocker exists.",
        })
        self.save()
        return rec

    def blockers(self, st: Dict[str, Any], excluding: Optional[List[str]] = None) -> Dict[str, Any]:
        excluding = set(excluding or [])
        return {k: v for k, v in st.get("unresolved", {}).items() if k not in excluding}

    def aaa_check(self, asset: str, phase: str) -> Dict[str, Any]:
        # No kill-switch: a missing/unreadable AAA implementation blocks delivery.
        import importlib.util
        path = self.control / "AAA_200" / "aaa_200_controller.py"
        if not path.is_file():
            raise SystemExit("BLOCKED: mandatory AAA200 controller code missing")
        try:
            spec = importlib.util.spec_from_file_location("pinehaven_aaa200", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.AAA200(self.root, self.master).assess(asset, phase)
        except Exception as e:
            raise SystemExit(f"BLOCKED: AAA200 check unavailable: {e}")

    def begin(self, asset: str, action: str, category: str, locks: List[str], sections: List[str], evidence_before: str, resolves: List[str], aaa_phase: Optional[str] = None) -> Dict[str, Any]:
        asset = safe_asset(asset)
        category = category.upper()
        if category not in MUTATING_CATEGORIES | READONLY_CATEGORIES:
            raise SystemExit(f"ERROR: invalid category {category}")
        master = self.master_identity()
        st = self.asset_state(asset)
        chain = self.verify_audit_chain(asset)
        if not chain.get("ok"):
            raise SystemExit("BLOCKED: audit chain verification failed: " + chain.get("error", "unknown"))
        if st.get("active_step"):
            raise SystemExit(f"BLOCKED: step {st['active_step']['step']} already open")
        if category in MUTATING_CATEGORIES and not st.get("d_authorized"):
            raise SystemExit("BLOCKED: D not explicitly authorized for this work item")
        unresolved = self.blockers(st, excluding=resolves)
        if unresolved:
            raise SystemExit("BLOCKED: unresolved FAIL/UNKNOWN/BLOCKED steps: " + ", ".join(sorted(unresolved)))
        for r in resolves:
            if r not in st.get("unresolved", {}):
                raise SystemExit(f"BLOCKED: --resolves references non-open blocker {r}")
        if category in {"MUTATION", "GENERATION", "EXPORT"} and asset != "PINE_HAVEN_AAA200_CONTROLLER_V1":
            if not aaa_phase:
                raise SystemExit("BLOCKED: AAA200 --aaa-phase required before a 3D action")
            aa = self.aaa_check(asset, aaa_phase)
            if aa["status"] != "PASS":
                raise SystemExit("BLOCKED: AAA200 pre-action gate failed: " + "; ".join(aa["reasons"][:6]))
        step = f"{int(st.get('next_step', 1)):04d}"
        st["next_step"] = int(st.get("next_step", 1)) + 1
        token_material = f"{asset}|{step}|{master['sha256']}|{action}|{utc_now()}".encode("utf-8")
        token = sha256_bytes(token_material)[:24]
        active = {
            "step": step,
            "token": token,
            "action": action,
            "category": category,
            "locks": locks,
            "sections": sections,
            "evidence_before": evidence_before,
            "aaa_phase": aaa_phase,
            "master_before": master,
            "resolves": resolves,
            "opened_at": utc_now(),
        }
        st["active_step"] = active
        st["last_master"] = master
        self.append_event(asset, {
            "event": "STEP_OPEN",
            "step": step,
            "authorization_token": token,
            "action": action,
            "category": category,
            "master_check_before": master,
            "locks_applied": locks,
            "applicable_sections": sections,
            "state_before": "READY",
            "evidence_operation": evidence_before,
            "resolves": resolves,
            "result": "OPEN",
            "next_authority": "Only the described action is authorized under this token; next significant action remains blocked until close.",
        })
        self.save()
        return active

    def close(self, asset: str, step: str, token: str, result: str, evidence: str, regression: str, sections_after: List[str], critical: bool) -> Dict[str, Any]:
        asset = safe_asset(asset)
        result = result.upper()
        if result not in RESULTS:
            raise SystemExit(f"ERROR: invalid result {result}")
        st = self.asset_state(asset)
        active = st.get("active_step")
        if not active:
            raise SystemExit("BLOCKED: no active step")
        if active["step"] != step or active["token"] != token:
            raise SystemExit("BLOCKED: step/token mismatch")
        master_after = self.master_identity()
        master_changed = master_after["sha256"] != active["master_before"]["sha256"]
        if master_changed and active["category"] != "MASTER_UPDATE":
            result = "BLOCKED"
            evidence = evidence + " | Controller detected Master changed during non-MASTER_UPDATE step."
            critical = True
        if result == "PASS" and active.get("aaa_phase"):
            aaa = self.aaa_check(asset, active["aaa_phase"])
            if aaa["status"] != "PASS":
                result = "BLOCKED"
                evidence += " | AAA200 post-action verification failed: " + "; ".join(aaa["reasons"][:6])
                critical = True
        event = self.append_event(asset, {
            "event": "STEP_CLOSE",
            "step": step,
            "authorization_token": token,
            "action": active["action"],
            "category": active["category"],
            "master_check_before": active["master_before"],
            "locks_applied": active["locks"],
            "applicable_sections_before": active["sections"],
            "state_before": "READY",
            "evidence_operation": evidence,
            "master_check_after": master_after,
            "applicable_sections_after": sections_after,
            "regression_check": regression,
            "result": result,
            "critical": bool(critical),
            "next_authority": "PASS may progress if no blockers remain." if result == "PASS" else "Blocked until a controlled corrective step resolves this record.",
        })
        if result in {"FAIL", "UNKNOWN", "BLOCKED"} and critical:
            st.setdefault("unresolved", {})[step] = {
                "result": result,
                "action": active["action"],
                "record_hash": event["record_hash"],
                "opened_at": active["opened_at"],
                "closed_at": utc_now(),
            }
        if result == "PASS":
            for ref in active.get("resolves", []):
                old = st.get("unresolved", {}).pop(ref, None)
                self.append_event(asset, {
                    "event": "BLOCKER_RESOLVED",
                    "step": step,
                    "resolves": ref,
                    "evidence_operation": evidence,
                    "resolved_record": old,
                    "master_check_after": master_after,
                    "result": "PASS",
                    "next_authority": "Referenced blocker closed by this corrective PASS.",
                })
        st["active_step"] = None
        st["last_master"] = master_after
        if result != "PASS":
            st["delivery_status"] = "NOT_DELIVERABLE"
        self.save()
        return event

    def record_artifact(self, asset: str, path: Path, role: str) -> Dict[str, Any]:
        asset = safe_asset(asset)
        st = self.asset_state(asset)
        if st.get("active_step") is None:
            raise SystemExit("BLOCKED: artifact recording requires an open controlled step")
        if not path.exists() or not path.is_file():
            raise SystemExit(f"BLOCKED: artifact not found: {path}")
        info = {
            "path": str(path.resolve()),
            "role": role,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
            "recorded_at": utc_now(),
            "step": st["active_step"]["step"],
        }
        st.setdefault("artifacts", []).append(info)
        rec = self.append_event(asset, {
            "event": "ARTIFACT_RECORDED",
            "step": st["active_step"]["step"],
            "action": "Record artifact evidence",
            "evidence_operation": info,
            "master_check_after": self.master_identity(),
            "result": "PASS",
            "next_authority": "Artifact is evidence only; active step still must be closed.",
        })
        self.save()
        return rec

    def status(self, asset: str) -> Dict[str, Any]:
        asset = safe_asset(asset)
        st = self.asset_state(asset)
        chain = self.verify_audit_chain(asset)
        return {
            "asset": asset,
            "controller_version": VERSION,
            "master_now": self.master_identity(),
            "d_authorized": st.get("d_authorized"),
            "active_step": st.get("active_step"),
            "unresolved": st.get("unresolved", {}),
            "delivery_status": st.get("delivery_status"),
            "artifact_count": len(st.get("artifacts", [])),
            "audit_chain": chain,
        }

    def gate_delivery(self, asset: str, gate_file: Path, machine_pass: bool, visual_pass: bool, reimport_pass: bool, qa_evidence: List[Path]) -> Dict[str, Any]:
        asset = safe_asset(asset)
        master = self.master_identity()
        st = self.asset_state(asset)
        chain = self.verify_audit_chain(asset)
        reasons = []
        if not chain.get("ok"):
            reasons.append("audit chain invalid")
        if st.get("active_step"):
            reasons.append("active step still open")
        if st.get("unresolved"):
            reasons.append("unresolved critical FAIL/UNKNOWN/BLOCKED exists")
        if not st.get("d_authorized"):
            reasons.append("D not authorized")
        if not machine_pass:
            reasons.append("machine gate not PASS")
        if not visual_pass:
            reasons.append("visual/adversarial gate not PASS")
        if not reimport_pass:
            reasons.append("export→reimport not PASS")
        missing_qa = [str(p) for p in qa_evidence if not p.exists()]
        if not qa_evidence:
            reasons.append("no QA evidence supplied")
        if missing_qa:
            reasons.append("missing QA evidence: " + ", ".join(missing_qa))
        gate_payload = None
        if not gate_file.exists():
            reasons.append("DELIVERY_GATE.json missing")
        else:
            try:
                gate_payload = json.loads(gate_file.read_text(encoding="utf-8"))
                if gate_payload.get("status") != "DELIVERABLE":
                    reasons.append("DELIVERY_GATE.json status is not DELIVERABLE")
            except Exception as e:
                reasons.append(f"DELIVERY_GATE.json invalid: {e}")
        # Existing historic acceptances remain immutable; every NEW delivery
        # check (including for historic items being revised) must pass all 200.
        try:
            aaa = self.aaa_check(asset, "P8")
            if aaa["status"] != "PASS":
                reasons.append("AAA200 P8 BLOCKED: " + "; ".join(aaa["reasons"][:8]))
        except SystemExit as e:
            reasons.append(str(e))
        status = "DELIVERABLE" if not reasons else "BLOCKED"
        st["delivery_status"] = status
        st["last_master"] = master
        rec = self.append_event(asset, {
            "event": "DELIVERY_GATE_CHECK",
            "action": "Mechanical delivery authorization check",
            "master_check_before": master,
            "locks_applied": ["Delivery Firewall", "Persistent observable audit trail", "User-as-QA"],
            "state_before": "READY",
            "evidence_operation": {
                "machine_pass": machine_pass,
                "visual_pass": visual_pass,
                "export_reimport_pass": reimport_pass,
                "delivery_gate_file": str(gate_file),
                "delivery_gate_payload": gate_payload,
                "qa_evidence": [str(p) for p in qa_evidence],
            },
            "master_check_after": self.master_identity(),
            "regression_check": "No unresolved controlled blockers; audit chain and required delivery evidence checked.",
            "result": "PASS" if status == "DELIVERABLE" else "BLOCKED",
            "block_reasons": reasons,
            "next_authority": "User-facing delivery mechanically authorized; artistic truth still depends on actual visual QA evidence." if status == "DELIVERABLE" else "Delivery blocked.",
        })
        self.save()
        return {"status": status, "reasons": reasons, "record_hash": rec["record_hash"]}


def print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def selftest(master: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="golden_controller_test_") as td:
        root = Path(td)
        (root / "_CONTROL" / "AUDIT").mkdir(parents=True)
        c = Controller(root, master)
        c.init_asset("SELFTEST", "Controller enforcement self-test")
        blocked_without_d = False
        try:
            c.begin("SELFTEST", "mutate before D", "MUTATION", ["A/B/C/D + explicit D0 start"], ["0.0"], "selftest", [])
        except SystemExit:
            blocked_without_d = True
        c.authorize_d("SELFTEST", "SELFTEST explicit D authorization")
        s1 = c.begin("SELFTEST", "intentional failing action", "QA", ["Persistent observable audit trail"], ["0.0A"], "selftest", [])
        c.close("SELFTEST", s1["step"], s1["token"], "FAIL", "intentional selftest fail", "selftest", ["0.0A"], True)
        blocked_on_fail = False
        try:
            c.begin("SELFTEST", "must block", "QA", ["Persistent observable audit trail"], ["0.0A"], "selftest", [])
        except SystemExit:
            blocked_on_fail = True
        s2 = c.begin("SELFTEST", "corrective action", "QA", ["Persistent observable audit trail"], ["0.0A"], "selftest correction", [s1["step"]])
        c.close("SELFTEST", s2["step"], s2["token"], "PASS", "corrected", "no regression", ["0.0A"], True)
        chain = c.verify_audit_chain("SELFTEST")
        status = c.status("SELFTEST")
        ok = blocked_without_d and blocked_on_fail and chain.get("ok") and not status["unresolved"] and status["active_step"] is None
        print_json({
            "selftest": "PASS" if ok else "FAIL",
            "blocked_without_d": blocked_without_d,
            "blocked_on_unresolved_fail": blocked_on_fail,
            "hash_chain_valid": chain.get("ok"),
            "unresolved_after_corrective_pass": status["unresolved"],
            "records": chain.get("records"),
        })
        return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Golden Garden controlled workflow/audit enforcer")
    p.add_argument("--root", type=Path, default=Path.cwd(), help="Golden Garden project root containing _CONTROL/")
    p.add_argument("--master", type=Path, help="Path to the currently materialized authoritative Master")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init")
    sp.add_argument("--asset", required=True)
    sp.add_argument("--scope", required=True)

    sp = sub.add_parser("authorize-d")
    sp.add_argument("--asset", required=True)
    sp.add_argument("--evidence", required=True)

    sp = sub.add_parser("begin")
    sp.add_argument("--asset", required=True)
    sp.add_argument("--action", required=True)
    sp.add_argument("--category", required=True, choices=sorted(MUTATING_CATEGORIES | READONLY_CATEGORIES))
    sp.add_argument("--lock", action="append", default=[])
    sp.add_argument("--section", action="append", default=[])
    sp.add_argument("--evidence-before", required=True)
    sp.add_argument("--resolves", action="append", default=[])
    sp.add_argument("--aaa-phase", choices=[f"P{i}" for i in range(9)], help="Mandatory AAA200 asset stage for geometry mutation, generation and export")

    sp = sub.add_parser("close")
    sp.add_argument("--asset", required=True)
    sp.add_argument("--step", required=True)
    sp.add_argument("--token", required=True)
    sp.add_argument("--result", required=True, choices=sorted(RESULTS))
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--regression", required=True)
    sp.add_argument("--section-after", action="append", default=[])
    sp.add_argument("--noncritical", action="store_true")

    sp = sub.add_parser("record-artifact")
    sp.add_argument("--asset", required=True)
    sp.add_argument("--path", type=Path, required=True)
    sp.add_argument("--role", required=True)

    sp = sub.add_parser("status")
    sp.add_argument("--asset", required=True)

    sp = sub.add_parser("verify-audit")
    sp.add_argument("--asset", required=True)

    sp = sub.add_parser("gate-delivery")
    sp.add_argument("--asset", required=True)
    sp.add_argument("--delivery-gate", type=Path, required=True)
    sp.add_argument("--machine-pass", action="store_true")
    sp.add_argument("--visual-pass", action="store_true")
    sp.add_argument("--reimport-pass", action="store_true")
    sp.add_argument("--qa-evidence", type=Path, action="append", default=[])

    sp = sub.add_parser("selftest")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if not args.master:
        raise SystemExit("ERROR: --master is required; controller must read the real current Master on every command")
    if args.cmd == "selftest":
        return selftest(args.master)
    c = Controller(args.root, args.master)
    if args.cmd == "init":
        print_json(c.init_asset(args.asset, args.scope))
    elif args.cmd == "authorize-d":
        print_json(c.authorize_d(args.asset, args.evidence))
    elif args.cmd == "begin":
        print_json(c.begin(args.asset, args.action, args.category, args.lock, args.section, args.evidence_before, args.resolves, args.aaa_phase))
    elif args.cmd == "close":
        print_json(c.close(args.asset, args.step, args.token, args.result, args.evidence, args.regression, args.section_after, not args.noncritical))
    elif args.cmd == "record-artifact":
        print_json(c.record_artifact(args.asset, args.path, args.role))
    elif args.cmd == "status":
        print_json(c.status(args.asset))
    elif args.cmd == "verify-audit":
        print_json(c.verify_audit_chain(args.asset))
    elif args.cmd == "gate-delivery":
        print_json(c.gate_delivery(args.asset, args.delivery_gate, args.machine_pass, args.visual_pass, args.reimport_pass, args.qa_evidence))
    else:
        raise SystemExit("ERROR: unsupported command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
