"""Adversarial original P8 delivery source/ZIP/manifest tests."""
import io
import json
import unittest
from pathlib import Path
from zipfile import ZipFile

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from c07_p678_forty_native_domain import TEXT
from c07_p8_delivery_semantics import IDS,inspect,OriginalDeliveryBlocked
from c07_positive_native_process import NativeEvidenceBlocked

SOURCE=b"BLENDER-synthetic-source-not-a-real-production-blend"
EXPORT=glb([(0,0,0),(1,0,0),(0,1,0)],[(0,1,2)],[(0,0,1)]*3)

def plan():
    return {"asset":"TEST","version":"v1",
            "source_member":"scene.blend","export_member":"scene.glb",
            "required_members":["scene.blend","scene.glb","DELIVERY_MANIFEST.json"],
            "source_sha256":fixture.sha(SOURCE),
            "export_sha256":fixture.sha(EXPORT)}

def package(p,*,missing=None,wrong_source=False,wrong_version=False):
    manifest={"asset":p["asset"],
              "version":"wrong" if wrong_version else p["version"],
              "source_member":p["source_member"],
              "export_member":p["export_member"],
              "source_sha256":p["source_sha256"],
              "export_sha256":p["export_sha256"]}
    contents={
        "scene.blend":b"wrong" if wrong_source else SOURCE,
        "scene.glb":EXPORT,
        "DELIVERY_MANIFEST.json":json.dumps(manifest).encode(),
    }
    if missing:contents.pop(missing)
    b=io.BytesIO()
    with ZipFile(b,"w") as z:
        for name,raw in contents.items():z.writestr(name,raw)
    return b.getvalue()

class Tests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"]="P8"
        self.f.work["phase"]="P8"
        for n,rid in zip((191,192,193,194),IDS):
            source,phase=TEXT[str(n)]
            self.f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"T","catalog_phase":phase,
                "requirement":source,
                "requirement_sha256":fixture.sha(source.encode()),
                "source_sha256":"c"*64}
        self.put()

    def put(self,p=None,archive=None):
        p=plan() if p is None else p
        self.f.add_item("SOURCE_EDITABLE","scene.blend",SOURCE)
        self.f.add_item("NATIVE_EXPORT","scene.glb",EXPORT)
        self.f.add_item("P8_DELIVERY_PLAN","delivery_plan.json",
                        json.dumps(p).encode())
        self.f.add_item("DELIVERY_PACKAGE","scene.zip",
                        package(p) if archive is None else archive)
        self.f.plan["p678_evidence_contract"]={
            "original_artifact_sha256":{
                role:self.f.items[role]["sha256"]
                for role in ("SOURCE_EDITABLE","NATIVE_EXPORT",
                             "P8_DELIVERY_PLAN","DELIVERY_PACKAGE")}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_four_original_delivery_oracles_no_false_fivem_pass(self):
        r=self.examine()
        self.assertEqual(set(r["rules"]),set(IDS))
        self.assertEqual(r["machine_positive_obligations"],4)
        self.assertEqual(r["original_delivery_metrics"]["archive_member_count"],3)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

    def test_missing_required_file_detected(self):
        self.put(archive=package(plan(),missing="scene.blend"))
        r=self.examine()
        self.assertEqual(r["rules"][IDS[1]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")
        self.assertEqual(r["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_modified_exported_source_in_archive_detected(self):
        self.put(archive=package(plan(),wrong_source=True))
        self.assertEqual(self.examine()["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_wrong_original_version_rejected(self):
        self.put(archive=package(plan(),wrong_version=True))
        self.assertEqual(self.examine()["rules"][IDS[3]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_corrupt_zip_not_passed(self):
        self.put(archive=b"NOT-A-ZIP")
        self.assertEqual(self.examine()["machine_positive_obligations"],0)

    def test_missing_pre_d_pin_is_not_delivery_proof(self):
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"].pop(
            "DELIVERY_PACKAGE")
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"],0)

    def test_registered_archive_tamper_fails_closed(self):
        (self.f.root/"scene.zip").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.examine()

    def test_canonical_literal_cannot_be_replaced(self):
        self.f.inv["rules"][IDS[0]]["requirement"]="forged"
        with self.assertRaisesRegex(OriginalDeliveryBlocked,
                                    "ORIGINAL_LITERAL_CHANGED"):
            self.examine()

    def test_cross_attempt_replay_rejected(self):
        self.f.work["attempt_id"]="f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.examine()

if __name__=="__main__":
    unittest.main()
