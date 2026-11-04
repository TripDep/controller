"""C07 ninth 25 native semantics: adversarial synthetic fixtures, no asset PASS."""
import hashlib
import unittest
from unittest.mock import patch
import c07_aaa25_gap_semantics as gate
from c07_aaa25_gap_canonical import IDS, NUMBERS
from c07_a10_c10_original_evidence import TEXT as CT
from c07_p1_thirty_native_domain import TEXT as DT
from c07_p345_forty_native_evidence import TEXT as LT
from c07_r171_r180_source_native import CLAUSES as RT
def sec(n):return "C" if n<=30 else "D" if n<=35 else "L" if n<=120 else "R"
def source(n):
    return (CT[n],"P0") if n<=30 else (
        (DT[str(n)],"P1") if n<=35 else (
        (LT[str(n)][0],"P3") if n<=120 else (RT[n],"P0")))
from c07_bf50_canonical import CATALOG_SHA
from c07_bf50_predicates import SPEC

H="a"*64
def h(s):return hashlib.sha256(s.encode("utf-8")).hexdigest()
class Original25Tests(unittest.TestCase):
    def setUp(self):
        self.inv={"schema":"gg-effective-family-inventory-v1","rule_count":763,
                  "source_digests":{"aaa_catalog":CATALOG_SHA},"rules":{}}
        for n,rid in zip(NUMBERS,IDS):
            t,phase=source(n)
            self.inv["rules"][rid]={"family":"AAA-200","catalog_number":n,
                "catalog_section":sec(n),"catalog_phase":phase,"asset_type":"all",
                "requirement":t,"requirement_sha256":h(t),
                "source_sha256":CATALOG_SHA}
        self.ctx={"inventory":self.inv,"plan":{"phase":"P3"},
            "controller":object(),"asset":"TEST_ONLY","step":"TEST_ONLY",
            "source_loader":lambda p:b"TEST_ONLY",
            "work":{"phase":"P3","attempt_id":H,"operation_sha256":H}}
        self.ac={"rules":{}};self.bf={"rules":{}}
        self.p1={"rules":{}};self.p345={"rules":{}};self.proc={"rules":{}}
        self.neg={"audit_tail_sha256":H,"rules":{}}
        for n,rid in zip(NUMBERS,IDS):
            identity={"rule_id":rid,"source_sha256":CATALOG_SHA,
                      "requirement_sha256":self.inv["rules"][rid]["requirement_sha256"],
                      "advancement_authorized":False}
            if n<=30:
                m={k:True for k in SPEC[n][:3]}
                self.ac["rules"][rid]={**identity,"native_original_file_criteria":m,
                    "full_rule_pass":False,"individual_mg0":"UNKNOWN",
                    "owner_approval":"UNKNOWN"}
                self.bf["rules"][rid]={**identity,"original_native_predicates":
                    {**m,SPEC[n][-1]:False},"full_rule_semantics":"UNKNOWN"}
            elif n<=35:
                self.bf["rules"][rid]={**identity,"original_native_predicates":
                    {k:True for k in SPEC[n]},"full_rule_semantics":"UNKNOWN",
                    "applicability":"DUE"}
                self.p1["rules"][rid]={**identity,"original_native_measured_criteria":
                    {"angle":True,"plan":True,"layout":False},
                    "full_rule_semantics":"UNKNOWN"}
            elif n<=120:
                self.p345["rules"][rid]={**identity,"machine_observations":
                    {"topology_original":True,"qa_receipt":False},
                    "earliest_phase":"P3","applicability":"DUE",
                    "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                    "owner_acceptance":"UNKNOWN"}
            else:
                self.proc["rules"][rid]={**identity,"original_machine_criteria":
                    {"source":True,"readback":True,"audit":False,"qa":False},
                    "full_rule_pass":False,"independent_mg0":"UNKNOWN"}
            self.neg["rules"][rid]={"verdict":"UNKNOWN",
                "uncorrected_failure_count":0,"observation_sha256":H}
    def run_gate(self):
        with patch.object(gate,"source_readback",return_value=(
             (self.ac,self.bf,self.p1,self.p345,self.proc),self.neg,H)):
            return gate.inspect(self.ctx)
    def test_25_exact_source_checks_no_certification(self):
        out=self.run_gate()
        self.assertEqual((out["rule_count"],out["machine_subchecks_checked"]),(25,90))
        self.assertEqual(set(out["rules"]),set(IDS))
        self.assertEqual(out["individual_mg0_passes"],0)
        self.assertFalse(out["advancement_authorized"])
        for v in out["rules"].values():
            self.assertFalse(v["full_rule_semantics_certified"])
            self.assertFalse(v["independent_mg0_certified"])
    def test_different_original_text_is_blocked(self):
        self.inv["rules"][IDS[0]]["requirement"]="FORGED"
        with self.assertRaisesRegex(ValueError,"CANONICAL_CLAUSE_CHANGED"):self.run_gate()
    def test_changed_digest_is_blocked(self):
        self.inv["rules"][IDS[10]]["requirement_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"CANONICAL_CLAUSE_CHANGED"):self.run_gate()
    def test_c_duplicate_machine_proof_is_not_counted_twice(self):
        self.bf["rules"][IDS[0]]["original_native_predicates"][SPEC[26][0]]=False
        with self.assertRaisesRegex(ValueError,"NOT_DUPLICATED"):self.run_gate()
    def test_c_claiming_independent_approval_is_blocked(self):
        self.ac["rules"][IDS[0]]["owner_approval"]="PASS"
        with self.assertRaisesRegex(ValueError,"NOT_DUPLICATED"):self.run_gate()
    def test_d_missing_native_criterion_is_blocked(self):
        self.p1["rules"][IDS[5]]["original_native_measured_criteria"].pop("plan")
        with self.assertRaisesRegex(ValueError,"EXACT_NATIVE_CRITERIA"):self.run_gate()
    def test_missing_observation_remains_unknown(self):
        self.p1["rules"][IDS[5]]["original_native_measured_criteria"]["angle"]=False
        out=self.run_gate()
        self.assertEqual(out["rules"][IDS[5]]["semantic_verdict"],"UNKNOWN")
        self.assertTrue(out["rules"][IDS[5]]["missing_native_checks"])
    def test_l_topology_future_phase_cannot_be_advanced(self):
        self.p345["rules"][IDS[10]]["applicability"]="FUTURE_PHASE"
        with self.assertRaisesRegex(ValueError,"ORIGINAL_TOPOLOGY_SCOPE"):self.run_gate()
    def test_r_forged_full_pass_rejected(self):
        self.proc["rules"][IDS[20]]["full_rule_pass"]=True
        with self.assertRaisesRegex(ValueError,"ORIGINAL_PROCESS_SCOPE"):self.run_gate()
    def test_mg0_success_is_not_inferred(self):
        self.neg["rules"][IDS[24]]["verdict"]="PASS"
        with self.assertRaisesRegex(ValueError,"MG0_ORIGINAL_NEGATIVE"):self.run_gate()
    def test_mg0_actual_failure_is_not_hidden(self):
        self.neg["rules"][IDS[24]]["verdict"]="FAIL"
        out=self.run_gate()
        self.assertEqual(out["rules"][IDS[24]]["semantic_verdict"],"FAIL")
        self.assertEqual(out["mg0_failures"],1)
    def test_source_identity_mismatch_rejected(self):
        self.p345["rules"][IDS[10]]["source_sha256"]="a"*64
        with self.assertRaisesRegex(ValueError,"SOURCE_IDENTITY_DRIFT"):self.run_gate()

if __name__=="__main__":unittest.main()
