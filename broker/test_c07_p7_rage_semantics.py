"""Adversarial exact-source P7 CodeWalker/Sollumz preflight tests.

All CodeWalker XML, screenshots and runtime logs here are SYNTHETIC FIXTURES.
They do not attest native RAGE compatibility or a live FiveM game.
"""
import copy
import json
import struct
import unittest
import zlib
from pathlib import Path

import test_c07_positive_native_process as fixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p5_budget_semantics import QUAD, NORMALS
from test_c07_p5_optimization_semantics import rewrite_glb
from c07_p678_forty_native_domain import TEXT
from c07_p7_rage_semantics import IDS, inspect, OriginalRageBlocked
from c07_positive_native_process import NativeEvidenceBlocked

def uv_glb():
    raw = glb(QUAD, [(0,1,2),(0,2,3)], NORMALS)
    jsz = struct.unpack_from("<I", raw, 12)[0]
    doc = json.loads(raw[20:20+jsz])
    binary = bytearray(raw[28+jsz:])
    coords = struct.pack("<8f", 0,0,1,0,1,1,0,1)
    offset = len(binary)
    binary.extend(coords)
    doc["bufferViews"].append({"buffer":0,"byteOffset":offset,
                                "byteLength":len(coords)})
    doc["accessors"].append({"bufferView":len(doc["bufferViews"])-1,
                              "componentType":5126,"count":4,"type":"VEC2"})
    doc["meshes"][0]["primitives"][0]["attributes"]["TEXCOORD_0"] = len(doc["accessors"])-1
    doc["buffers"][0]["byteLength"] = len(binary)
    js = json.dumps(doc, separators=(",", ":")).encode()
    js += b" " * (-len(js) % 4)
    return (struct.pack("<4sII", b"glTF", 2, 28+len(js)+len(binary)) +
            struct.pack("<I4s", len(js), b"JSON") + js +
            struct.pack("<I4s", len(binary), b"BIN\x00") + bytes(binary))

def png(pixel):
    def chunk(tag, data):
        return (struct.pack(">I", len(data))+tag+data+
                struct.pack(">I", zlib.crc32(tag+data)&0xffffffff))
    header = struct.pack(">IIBBBBB", 2,2,8,6,0,0,0)
    row = b"\x00" + bytes(pixel)*2
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"IDAT", zlib.compress(row*2)) + chunk(b"IEND", b""))

XML = {
    "P7_YDR_XML": b'<Drawable><Name>scene_drawable</Name><ShaderGroup><Shaders><Item><Name>normal_spec</Name></Item></Shaders></ShaderGroup><TextureName>leaf_diffuse</TextureName></Drawable>',
    "P7_YTD_XML": b'<TextureDictionary><Textures><Item><Name>leaf_diffuse</Name></Item></Textures></TextureDictionary>',
    "P7_YTYP_XML": b'<CMapTypes><archetypes><Item type="CBaseArchetypeDef"><name>scene_arch</name><assetName>scene_drawable</assetName></Item></archetypes></CMapTypes>',
    "P7_YMAP_XML": b'<CMapData><entities><Item type="CEntityDef"><archetypeName>scene_arch</archetypeName><position x="1" y="2" z="3"/></Item></entities></CMapData>',
    "P7_YBN_XML": (b'<BoundsFile><Bounds type="Composite"><Children>'
                   b'<Item type="Box"><Min x="-0.1" y="-0.1" z="-0.1"/>'
                   b'<Max x="1.1" y="1.1" z="0.1"/></Item>'
                   b'</Children></Bounds></BoundsFile>'),
}
MANIFEST = (b"fx_version 'cerulean'\ngame 'gta5'\n"
            b"this_is_a_map 'yes'\nfiles {'stream/scene.ytyp'}\n"
            b"data_file 'DLC_ITYP_REQUEST' 'stream/scene.ytyp'\n")

class Tests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"] = "P7"
        self.f.work["phase"] = "P7"
        for n, rid in zip(range(161,171), IDS):
            literal, phase = TEXT[str(n)]
            self.f.inv["rules"][rid] = {
                "family": "AAA-200", "catalog_number": n,
                "catalog_section": "Q", "catalog_phase": phase,
                "requirement": literal,
                "requirement_sha256": fixture.sha(literal.encode()),
                "source_sha256": "c"*64,
            }
        self.files = dict(XML)
        self.files["P7_FXMANIFEST"] = MANIFEST
        self.files["P7_SHADER_POLICY"] = {"allowed_shader_names": ["normal_spec"]}
        self.files["P7_CODEWALKER_REPORT"] = {
            "entity_positions": [{"archetype":"scene_arch","xyz":[1.0,2.0,3.0]}],
            "lod_near_m": 10.0, "lod_far_m": 100.0}
        self.files["P7_FIVEM_LOG"] = {
            "engine": "FiveM", "asset": self.f.asset,
            "frame_ms_samples": [16.0]*20}
        self.files["P7_VIEW_FRONT"] = png((255,0,0,255))
        self.files["P7_VIEW_SIDE"] = png((0,255,0,255))
        self.files["P7_VIEW_TOP"] = png((0,0,255,255))
        self.files["NATIVE_EXPORT"] = uv_glb()
        self.files["P7_EXPORT_TRACE"] = {
            "addon": "Sollumz", "addon_version": "2.7.0",
            "asset": self.f.asset,
            "source_sha256": self.f.items["SOURCE_EDITABLE"]["sha256"],
            "export_sha256": fixture.sha(self.files["NATIVE_EXPORT"])}
        self.put()

    def put(self):
        for role, raw in self.files.items():
            suffix = (".lua" if role == "P7_FXMANIFEST"
                      else ".xml" if role.endswith("_XML")
                      else ".png" if role.startswith("P7_VIEW_")
                      else ".glb" if role == "NATIVE_EXPORT"
                      else ".json")
            if type(raw) is dict:
                raw = json.dumps(raw, separators=(",", ":")).encode()
            self.f.add_item(role, role.lower()+suffix, raw)
        roles = set(self.files) | {"SOURCE_EDITABLE"}
        self.f.plan["p678_evidence_contract"] = {
            "original_artifact_sha256": {
                role: self.f.items[role]["sha256"] for role in roles}}
        self.f.rebuild()

    def examine(self):
        return inspect(self.f.inv, self.f.plan, self.f.controller,
                       self.f.asset, self.f.step, self.f.work,
                       source_loader=lambda p: Path(p).read_bytes())

    def test_eight_scoped_observations_never_claim_game_or_sollumz_pass(self):
        result = self.examine()
        self.assertEqual(set(result["rules"]), set(IDS))
        self.assertEqual(result["machine_positive_obligations"], 8)
        self.assertEqual(result["metrics"]["entities"], 1)
        self.assertEqual(result["metrics"]["archetypes"], 1)
        self.assertEqual(result["metrics"]["original_views"], 3)
        for n in (167,170):
            row = result["rules"]["AAA-200-Q-%03d" % n]
            self.assertEqual(row["machine_scope"], "UNKNOWN_OR_DEFECT")
        self.assertEqual(result["full_rule_semantic_passes"], 0)
        self.assertEqual(result["individual_mg0_passes"], 0)
        self.assertFalse(result["advancement_authorized"])

    def test_ten_distinct_original_cross_source_semantics(self):
        report = self.examine()
        self.assertEqual(
            report["original_cross_source_positive_obligations"], 8)
        self.assertEqual(set(report["rules"]), set(IDS))
        seen = set()
        for n, rid in zip(range(161, 171), IDS):
            with self.subTest(rule=rid):
                row = report["rules"][rid]
                deep = row["original_cross_source_semantic"]
                self.assertEqual(len(deep), 1)
                self.assertTrue(seen.isdisjoint(deep))
                seen.update(deep)
                self.assertIs(next(iter(deep.values())),
                              n not in (167, 170))
                self.assertEqual(row["full_rule_semantics"], "UNKNOWN")
                self.assertEqual(row["individual_mg0"], "UNKNOWN")
                self.assertFalse(row["advancement_authorized"])
        self.assertEqual(len(seen), 10)

    def test_all_ten_cross_file_predicates_reject_original_mutations(self):
        changes = {
            161: ("P7_FXMANIFEST", MANIFEST +
                  b"files {'stream/scene.ytyp'}\\n"),
            162: ("P7_YTYP_XML",
                  b'<CMapTypes><archetypes>'
                  b'<Item type="CBaseArchetypeDef"><name>scene_arch</name>'
                  b'<assetName>scene_drawable</assetName></Item>'
                  b'<Item type="CBaseArchetypeDef"><name>scene_extra</name>'
                  b'<assetName>scene_drawable</assetName></Item>'
                  b'</archetypes></CMapTypes>'),
            163: ("P7_YDR_XML",
                  XML["P7_YDR_XML"].replace(
                      b"</Drawable>",
                      b"<TextureName>leaf_diffuse</TextureName></Drawable>")),
            164: ("P7_YTYP_XML",
                  b'<CMapTypes><archetypes>'
                  b'<Item type="CBaseArchetypeDef"><name>scene_arch</name>'
                  b'<assetName>scene_other</assetName></Item>'
                  b'<Item type="CBaseArchetypeDef"><name>unused_arch</name>'
                  b'<assetName>scene_drawable</assetName></Item>'
                  b'</archetypes></CMapTypes>'),
            165: ("P7_CODEWALKER_REPORT",
                  {"entity_positions": [
                      {"archetype":"scene_arch","xyz":[2.0,2.0,3.0]}],
                   "lod_near_m":10.0,"lod_far_m":100.0}),
            166: ("P7_YBN_XML",
                  b'<BoundsFile><Bounds type="Composite"><Children>'
                  b'<Item type="UnknownBound"/></Children></Bounds></BoundsFile>'),
            167: ("P7_EXPORT_TRACE",
                  {"addon":"Sollumz","addon_version":"2.7.0",
                   "asset":self.f.asset,
                   "source_sha256":self.f.items["SOURCE_EDITABLE"]["sha256"],
                   "export_sha256":fixture.sha(self.files["NATIVE_EXPORT"]),
                   "self_reported_independent_provenance":True}),
            168: ("P7_SHADER_POLICY",
                  {"allowed_shader_names":["unsupported_shader"]}),
            169: ("P7_VIEW_TOP", self.files["P7_VIEW_FRONT"]),
            170: ("P7_FIVEM_LOG",
                  {"engine":"FiveM","asset":self.f.asset,
                   "frame_ms_samples":[16.0]*20,
                   "self_reported_owner_approved":True}),
        }
        for n, (role, bad) in changes.items():
            with self.subTest(rule=n):
                previous = copy.deepcopy(self.files[role])
                self.files[role] = bad
                self.put()
                row = self.examine()["rules"]["AAA-200-Q-%03d" % n]
                self.assertIs(
                    next(iter(row["original_cross_source_semantic"].values())),
                    False)
                self.assertEqual(row["full_rule_semantics"], "UNKNOWN")
                self.files[role] = previous
                self.put()

    def test_each_literal_has_independent_adversarial_negative(self):
        mutations = {
            161: ("P7_FXMANIFEST", b"game 'gta5'"),
            162: ("P7_YDR_XML", b"<Drawable><Name>unknown</Name></Drawable>"),
            163: ("P7_YTD_XML", b"<TextureDictionary/>"),
            164: ("P7_YTYP_XML", b"<CMapTypes/>"),
            165: ("P7_YMAP_XML", b"<CMapData/>"),
            166: ("P7_YBN_XML", b"<BoundsFile/>"),
            167: ("P7_EXPORT_TRACE", {"addon":"Sollumz","addon_version":"2.7.0",
                                       "asset":"TEST","source_sha256":"0"*64,
                                       "export_sha256":"0"*64}),
            168: ("P7_SHADER_POLICY", {"allowed_shader_names":["unsupported"]}),
            169: ("P7_CODEWALKER_REPORT", {"entity_positions":[],
                                            "lod_near_m":10,"lod_far_m":100}),
            170: ("P7_FIVEM_LOG", {"engine":"FiveM","asset":"TEST",
                                     "frame_ms_samples":[1.0]*20}),
        }
        for n, (role, bad) in mutations.items():
            with self.subTest(rule=n):
                old = copy.deepcopy(self.files[role])
                self.files[role] = bad
                self.put()
                row = self.examine()["rules"]["AAA-200-Q-%03d" % n]
                self.assertEqual(row["machine_scope"], "UNKNOWN_OR_DEFECT")
                self.assertEqual(row["individual_mg0"], "UNKNOWN")
                self.files[role] = old
                self.put()

    def test_manifest_original_source_semantics_rejects_six_spoofs(self):
        from c07_p7_manifest_source_semantics import parse
        self.assertTrue(parse(MANIFEST)["valid"])
        spoofs = {
            "comment_only_data_file":
                MANIFEST.replace(b"data_file 'DLC_ITYP_REQUEST'",
                                 b"-- data_file 'DLC_ITYP_REQUEST'"),
            "wrong_ityp_resource":
                MANIFEST.replace(b"data_file 'DLC_ITYP_REQUEST'",
                                 b"data_file 'DLC_WRONG_REQUEST'"),
            "mismatched_registered_resource":
                MANIFEST.replace(b"data_file 'DLC_ITYP_REQUEST' 'stream/scene.ytyp'",
                                 b"data_file 'DLC_ITYP_REQUEST' 'stream/other.ytyp'"),
            "comment_only_file":
                MANIFEST.replace(b"files {'stream/scene.ytyp'}",
                                 b"-- files {'stream/scene.ytyp'}"),
            "duplicate_active_file":
                MANIFEST + b"files {'stream/scene.ytyp'}\n",
            "block_comment_spoof":
                MANIFEST.replace(b"data_file 'DLC_ITYP_REQUEST' 'stream/scene.ytyp'",
                                 b"--[[data_file 'DLC_ITYP_REQUEST' 'stream/scene.ytyp']]"),
            "string_spoof":
                MANIFEST.replace(b"data_file 'DLC_ITYP_REQUEST' 'stream/scene.ytyp'",
                                 b"print(\"data_file 'DLC_ITYP_REQUEST' 'stream/scene.ytyp'\")"),
        }
        for name, raw in spoofs.items():
            with self.subTest(spoof=name):
                self.assertFalse(parse(raw)["valid"])
                self.files["P7_FXMANIFEST"] = raw
                self.put()
                result = self.examine()
                for n in (161, 162, 163, 164, 165, 166, 169):
                    row = result["rules"]["AAA-200-Q-%03d" % n]
                    self.assertFalse(next(iter(
                        row["original_cross_source_semantic"].values())))
                    self.assertEqual(row["full_rule_semantics"], "UNKNOWN")
                self.files["P7_FXMANIFEST"] = MANIFEST
                self.put()

    def test_manifest_quoted_comment_markers_are_not_comments(self):
        from c07_p7_manifest_source_semantics import parse
        self.assertTrue(parse(MANIFEST)["valid"])
        raw = MANIFEST + b"author 'literal -- is inside string'\n"
        self.assertTrue(parse(raw)["valid"])
        self.assertFalse(parse(MANIFEST + b"--[[unclosed")["valid"])
        self.assertFalse(parse(MANIFEST.replace(
            b"stream/scene.ytyp", b"stream/../escape.ytyp"))["valid"])

    def test_q166_native_collision_envelope_rejects_false_source_box(self):
        # A real GLB spans [0,1] in X/Y. A syntactically valid YBN Box that
        # covers only one corner or is displaced cannot establish collision.
        for name, bounds in (
            ("tiny", (0,0,0,0.2,0.2,0.2)),
            ("displaced", (4,4,-1,5,5,1)),
        ):
            with self.subTest(case=name):
                lo=bounds[:3]
                hi=bounds[3:]
                self.files["P7_YBN_XML"] = (
                    '<BoundsFile><Bounds type="Composite"><Children>'
                    '<Item type="Box"><Min x="%s" y="%s" z="%s"/>'
                    '<Max x="%s" y="%s" z="%s"/></Item>'
                    '</Children></Bounds></BoundsFile>' % (*lo,*hi)
                ).encode()
                self.put()
                row=self.examine()["rules"]["AAA-200-Q-166"]
                self.assertTrue(row["original_machine_checks"][
                    "original_ybn_bound_children_structurally_parsed"])
                self.assertFalse(next(iter(
                    row["original_cross_source_semantic"].values())))
                self.assertEqual(row["full_rule_semantics"], "UNKNOWN")
        self.files["P7_YBN_XML"] = XML["P7_YBN_XML"]
        self.put()
        good=self.examine()["rules"]["AAA-200-Q-166"]
        self.assertTrue(next(iter(
            good["original_cross_source_semantic"].values())))
        self.assertEqual(good["individual_mg0"], "UNKNOWN")

    def test_manifest_ytyp_path_traversal_cannot_pass(self):
        self.files["P7_FXMANIFEST"] = MANIFEST.replace(
            b"stream/scene.ytyp", b"../escape.ytyp")
        self.put()
        self.assertEqual(self.examine()["rules"][IDS[0]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_invalid_original_glb_uv_accessor_cannot_pass_shader_preflight(self):
        def corrupt(doc):
            doc["meshes"][0]["primitives"][0]["attributes"]["TEXCOORD_0"] = 999
        self.files["NATIVE_EXPORT"] = rewrite_glb(uv_glb(), corrupt)
        self.files["P7_EXPORT_TRACE"]["export_sha256"] = fixture.sha(
            self.files["NATIVE_EXPORT"])
        self.put()
        self.assertEqual(self.examine()["rules"][IDS[7]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_nonfinite_original_glb_uv_float_cannot_pass_shader_preflight(self):
        raw = bytearray(uv_glb())
        jsz = struct.unpack_from("<I", raw, 12)[0]
        doc = json.loads(raw[20:20+jsz])
        accessor = doc["accessors"][
            doc["meshes"][0]["primitives"][0]["attributes"]["TEXCOORD_0"]]
        view = doc["bufferViews"][accessor["bufferView"]]
        struct.pack_into("<f", raw, 28+jsz+view["byteOffset"], float("nan"))
        self.files["NATIVE_EXPORT"] = bytes(raw)
        self.files["P7_EXPORT_TRACE"]["export_sha256"] = fixture.sha(bytes(raw))
        self.put()
        self.assertEqual(self.examine()["rules"][IDS[7]]["machine_scope"],
                         "UNKNOWN_OR_DEFECT")

    def test_original_fivem_and_sollumz_self_report_never_attested(self):
        result = self.examine()
        self.assertTrue(result["rules"][IDS[6]]["original_machine_checks"][
            "registered_blend_and_glb_bytes_match_original_sollumz_trace"])
        self.assertFalse(result["rules"][IDS[6]]["original_machine_checks"][
            "independent_sollumz_execution_provenance_confirmed"])
        self.assertTrue(result["rules"][IDS[9]]["original_machine_checks"][
            "source_fivem_log_contains_numeric_samples"])
        self.assertFalse(result["rules"][IDS[9]]["original_machine_checks"][
            "independent_in_game_execution_and_owner_provenance"])

    def test_missing_pre_d_source_pins_is_not_positive(self):
        self.f.plan["p678_evidence_contract"]["original_artifact_sha256"].clear()
        self.f.rebuild()
        self.assertEqual(self.examine()["machine_positive_obligations"], 0)

    def test_invalid_xml_dtd_rejected_not_expanded(self):
        self.files["P7_YTYP_XML"] = b'<!DOCTYPE a [<!ENTITY x "fake">]><CMapTypes>&x;</CMapTypes>'
        self.put()
        with self.assertRaisesRegex(OriginalRageBlocked, "UNSAFE_XML"):
            self.examine()

    def test_registered_binary_tamper_and_cross_attempt_replay(self):
        (self.f.root / "p7_ymap_xml.xml").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked, "ARTIFACT_BYTES_CHANGED"):
            self.examine()
        self.put()
        self.f.work["attempt_id"] = "f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked, "EXACT_RESERVED_WORK"):
            self.examine()

    def test_canonical_literal_changed_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"] = "fake"
        with self.assertRaisesRegex(OriginalRageBlocked, "LITERAL_SOURCE_CHANGED"):
            self.examine()

if __name__ == "__main__":
    unittest.main()
