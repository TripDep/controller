"""Adversarial S-181..190 original GLB, PNG and QA-source fixtures.

All evidence is synthetic. Scoped machine observations are not full REVIEWED,
independent MG0, owner approval or actual FiveM verification.
"""
import copy
import json
import struct
import zlib
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import with_embedded_texture,QUAD,NORMALS
from test_c07_p4_texture_semantics import png,solid
from c07_p678_forty_native_domain import TEXT
from c07_p8_final_qa_semantics import IDS,inspect,OriginalFinalQABlocked
from c07_positive_native_process import NativeEvidenceBlocked

def same_pixels_different_png_encoding(raw):
    """Recompress an unchanged RGBA scanline stream; byte SHA must change."""
    chunks=[];off=8
    while off<len(raw):
        n=struct.unpack_from(">I",raw,off)[0]
        typ=raw[off+4:off+8]
        data=raw[off+8:off+8+n]
        chunks.append((typ,data))
        off+=n+12
    def pack(typ,data):
        return (struct.pack(">I",len(data))+typ+data+
                struct.pack(">I",zlib.crc32(typ+data)&0xffffffff))
    return (raw[:8]+b"".join(pack(typ,zlib.compress(
        zlib.decompress(data),0) if typ==b"IDAT" else data)
        for typ,data in chunks))

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P8"
        self.f.work["phase"]="P8"
        for n,rid in zip(range(181,191),IDS):
            literal,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"S","catalog_phase":phase,
                "requirement":literal,
                "requirement_sha256":fixture.sha(literal.encode()),
                "source_sha256":"c"*64}
        self.native=with_embedded_texture(glb(QUAD,[(0,1,2),(0,2,3)],NORMALS))
        self.baseline=glb(QUAD[:3],[(0,1,2)],NORMALS[:3])
        self.views={v:png(solid(20+30*i)) for i,v in enumerate(
            ("FRONT","REAR","LEFT","RIGHT","TOP","UNDERSIDE"))}
        self.material=png(solid(215))
        self.context=png(solid(225))
        self.docs={
          "P8_ALIGNMENT_REPORT":{"actual_bounds_xyz":[[0,0,0],[1,1,0]],
             "expected_origin_xyz":[0,0,0],"max_axis_error_m":0.01},
          "P8_INTERSECTION_REPORT":{"forbidden_regions":[
             {"min_xyz":[10,10,10],"max_xyz":[11,11,11]}]},
          "P8_NORMALS_REPORT":{"native_sha256":fixture.sha(self.native)},
          "P8_REGRESSION_REPORT":{"before_sha256":fixture.sha(self.baseline),
             "after_sha256":fixture.sha(self.native),
             "checks":[{"id":"geometry","status":"RUN"}]},
          "P8_MACHINE_REPORT":{"native_sha256":fixture.sha(self.native),
             "checks":[{"id":"original_mesh","status":"RUN"}]},
          "P8_TEST_MATRIX":{"tests":[
              {"id":"AUTOMATED_NATIVE","category":"AUTOMATED","status":"RUN",
               "evidence_role":"NATIVE_EXPORT",
               "evidence_sha256":fixture.sha(self.native)},
              {"id":"VISUAL_SIX","category":"VISUAL","status":"RUN",
               "view_sha256":{"VISUAL_VIEW_"+v:fixture.sha(raw)
                              for v,raw in self.views.items()}},
              {"id":"FIVEM_RUNTIME","category":"ENGINE","status":"NOT_RUN",
               "evidence_role":None,"evidence_sha256":None}]},
          "P8_INTERNAL_QA":{"owner_approved":False,
             "original_sha256":{"NATIVE_EXPORT":fixture.sha(self.native),
                 **{"VISUAL_VIEW_"+v:fixture.sha(raw)
                    for v,raw in self.views.items()}}},
        }
        self.put()
        self.add_critical()

    def put(self):
        self.f.add_item("NATIVE_EXPORT","scene.glb",self.native)
        self.f.add_item("BASELINE_SNAPSHOT","baseline.glb",self.baseline)
        for role,data in self.docs.items():
            self.f.add_item(role,role.lower()+".json",
                            json.dumps(data,separators=(",",":")).encode())
        for v,raw in self.views.items():
            self.f.add_item("VISUAL_VIEW_"+v,v.lower()+".png",raw)
        self.f.add_item("P8_MATERIAL_RENDER","material.png",self.material)
        self.f.add_item("P8_AREA_CONTEXT","context.png",self.context)
        self.f.plan["p678_evidence_contract"]={
          "original_artifact_sha256":{role:row["sha256"]
               for role,row in self.f.items.items()}}
        self.f.rebuild()

    def add_critical(self):
        prior=self.f.records[-1]["record_hash"]
        row={"asset":self.f.asset,"event":"QUALITY_FINDING","step":self.f.step,
             "severity":"CRITICAL","status":"OPEN","prev_hash":prior}
        row["record_hash"]=fixture.sha(fixture.canonical(row))
        self.f.records.append(row)
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b"".join(fixture.canonical(x)+b"\n" for x in self.f.records))
        self.f.controller._state["last_audit_hash"]=row["record_hash"]

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
            self.f.asset,self.f.step,self.f.work,
            source_loader=lambda p:Path(p).read_bytes())

    def test_ten_distinct_original_scoped_observations_not_full_review(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["source_rule_count"],10)
        self.assertEqual(r["machine_positive_obligations"],10)
        self.assertEqual(r["metrics"]["decoded_views"],6)
        self.assertEqual(r["metrics"]["triangle_count"],2)
        self.assertEqual(r["metrics"]["critical_open_audit_findings"],1)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_ten_extra_original_semantic_checks_are_distinct_and_scoped(self):
        report=self.examine()
        self.assertEqual(set(report["rules"]),set(IDS))
        names=set()
        for n,rid in zip(range(181,191),IDS):
            with self.subTest(rule=rid):
                deep=report["rules"][rid]["original_cross_source_semantic"]
                self.assertEqual(len(deep),1)
                self.assertFalse(names.intersection(deep))
                names.update(deep)
                self.assertIsInstance(next(iter(deep.values())),bool)
                self.assertEqual(report["rules"][rid]["full_rule_semantics"],
                                 "UNKNOWN")
                self.assertFalse(report["rules"][rid]["advancement_authorized"])
        self.assertEqual(len(names),10)
        self.assertGreaterEqual(
            report["original_cross_source_positive_obligations"],5)
        # Historical/producer critical and QA are not independent attestation.
        for n in (189,190):
            self.assertFalse(next(iter(report["rules"][
                "AAA-200-S-%03d"%n]["original_cross_source_semantic"].values())))

    def test_each_original_rule_has_independent_adversarial_negative(self):
        changes={
          181:("views","REAR",self.views["FRONT"]),
          182:("doc","P8_ALIGNMENT_REPORT",("expected_origin_xyz",[9,9,9])),
          183:("doc","P8_INTERSECTION_REPORT",("forbidden_regions",[
              {"min_xyz":[0,0,-1],"max_xyz":[1,1,1]}])),
          184:("doc","P8_NORMALS_REPORT",("native_sha256","0"*64)),
          185:("material",None,b"invalid-png"),
          186:("context",None,self.views["FRONT"]),
          187:("doc","P8_REGRESSION_REPORT",("before_sha256","0"*64)),
          188:("doc","P8_MACHINE_REPORT",("native_sha256","0"*64)),
          189:("state",None,"DELIVERABLE"),
          190:("doc","P8_INTERNAL_QA",("original_sha256",{})),
        }
        for n,(kind,key,bad) in changes.items():
            with self.subTest(rule=n):
                if kind=="views":old=self.views[key];self.views[key]=bad
                elif kind=="doc":
                    field,value=bad
                    old=copy.deepcopy(self.docs[key][field])
                    self.docs[key][field]=value
                elif kind=="state":
                    old=self.f.controller._state.get("delivery_status")
                    self.f.controller._state["delivery_status"]=bad
                else:old=getattr(self,kind);setattr(self,kind,bad)
                if kind!="state":
                    self.put()
                    self.add_critical()
                r=self.examine()
                self.assertEqual(r["rules"]["AAA-200-S-%03d"%n]["machine_scope"],
                                 "UNKNOWN_OR_DEFECT")
                self.assertEqual(r["rules"]["AAA-200-S-%03d"%n]["individual_mg0"],
                                 "UNKNOWN")
                self.assertFalse(next(iter(r["rules"][
                    "AAA-200-S-%03d"%n]["original_cross_source_semantic"].values())))
                if kind=="views":self.views[key]=old
                elif kind=="doc":self.docs[key][field]=old
                elif kind=="state":
                    if old is None:self.f.controller._state.pop("delivery_status",None)
                    else:self.f.controller._state["delivery_status"]=old
                else:setattr(self,kind,old)
                if kind!="state":
                    self.put()
                    self.add_critical()

    def test_forged_in_game_test_or_swapped_visual_categories_never_pass(self):
        for fake in ("engine_run","swapped_category"):
            with self.subTest(fake=fake):
                original=copy.deepcopy(self.docs["P8_TEST_MATRIX"])
                rows=self.docs["P8_TEST_MATRIX"]["tests"]
                if fake=="engine_run":
                    rows[2]["status"]="RUN"
                else:
                    rows[1]["category"]="AUTOMATED"
                self.put()
                self.add_critical()
                report=self.examine()
                self.assertFalse(report["rules"]["AAA-200-S-188"][
                    "original_machine_checks"][
                    "original_test_categories_and_unattested_engine_separated"])
                self.docs["P8_TEST_MATRIX"]=original
                self.put()
                self.add_critical()

    def test_identical_pixels_with_different_png_encoding_not_six_views(self):
        original=self.views["FRONT"]
        repacked=same_pixels_different_png_encoding(original)
        self.assertNotEqual(fixture.sha(original),fixture.sha(repacked))
        self.views["REAR"]=repacked
        self.put();self.add_critical()
        r=self.examine()
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[7]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_no_critical_event_is_not_automatic_rule_189_pass(self):
        self.put()
        self.assertEqual(self.examine()["rules"][IDS[8]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_missing_original_pre_d_pin_prevents_positive(self):
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"].pop(
            "VISUAL_VIEW_FRONT")
        self.f.rebuild();self.add_critical()
        r=self.examine()
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],"UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[-1]]["machine_scope"],"UNKNOWN_OR_DEFECT")

    def test_tamper_original_png_and_cross_attempt_replay_blocked(self):
        (self.f.root/"front.png").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,"ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put();self.add_critical()
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,"EXACT_RESERVED_WORK"):
            self.examine()

    def test_original_literal_change_blocked(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="forged"
        with self.assertRaisesRegex(OriginalFinalQABlocked,
                                    "FINAL_LITERAL_CHANGED"):
            self.examine()

    def test_duplicate_original_json_keys_blocked(self):
        self.f.add_item("P8_ALIGNMENT_REPORT","p8_alignment_report.json",
                        b'{"actual_bounds_xyz":[],"actual_bounds_xyz":[]}')
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"][
            "P8_ALIGNMENT_REPORT"]=self.f.items["P8_ALIGNMENT_REPORT"]["sha256"]
        self.f.rebuild();self.add_critical()
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            self.examine()

if __name__=="__main__":unittest.main()
