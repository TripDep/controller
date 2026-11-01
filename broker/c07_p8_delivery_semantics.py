"""C07 P8 T-191..194: original delivery ZIP/source/export proof oracles.

A CRC-valid ZIP, original-byte SHA match and parseable GLB are concrete
machine facts, NOT FiveM usability, independent MG0 or owner acceptance.
"""
import hashlib
import io
import json
from pathlib import PurePosixPath
from zipfile import ZipFile, BadZipFile

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry
from c07_p5_budget_semantics import _json
from c07_p678_forty_native_domain import TEXT, PHASES

NUMBERS=(191,192,193,194)
IDS=tuple("AAA-200-T-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p8-four-original-delivery-oracles-v1"

class OriginalDeliveryBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:raise OriginalDeliveryBlocked(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def safe_member(name):
    if type(name) is not str or not name or len(name)>180 or "\\" in name:
        return False
    path=PurePosixPath(name)
    return (not path.is_absolute() and ".." not in path.parts
            and str(path)==name and not name.endswith("/"))

def _zip(raw):
    if type(raw) is not bytes or not 32<=len(raw)<=60_000_000:
        return None
    try:
        with ZipFile(io.BytesIO(raw)) as z:
            infos=z.infolist()
            names=[x.filename for x in infos]
            need(len(infos)>0 and len(infos)<=128
                 and len(names)==len(set(names))
                 and all(safe_member(n) for n in names)
                 and all(not ((i.external_attr>>16)&0o170000)==0o120000
                         for i in infos),
                 "C07_P8_UNSAFE_ARCHIVE_MEMBERS")
            need(sum(x.file_size for x in infos)<=60_000_000
                 and all(x.file_size<=30_000_000 for x in infos),
                 "C07_P8_ARCHIVE_SIZE_LIMIT")
            if z.testzip() is not None:return None
            return {name:z.read(name) for name in names}
    except (BadZipFile,OSError,RuntimeError,EOFError,ValueError):
        return None

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASES
         and PHASES[plan["phase"]]>=8
         and plan["phase"]==work.get("phase") and callable(source_loader),
         "C07_P8_ORIGINAL_OPERATION_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P8_ORIGINAL_CATALOG")
    for n,rid in zip(NUMBERS,IDS):
        source,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P8" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="T"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==source
             and row.get("requirement_sha256")==sha(source.encode())
             and row.get("source_sha256")==catalog,
             "C07_P8_ORIGINAL_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P8_ORIGINAL_AUDIT_DRIFT")
    records=_registered_artifacts(audit,state,step,source_loader,work)
    found={}
    wanted={"P8_DELIVERY_PLAN","SOURCE_EDITABLE","NATIVE_EXPORT",
            "DELIVERY_PACKAGE"}
    for role,path,digest,raw in records:
        if role in wanted:
            need(role not in found,"C07_P8_DUPLICATE_ROLE:"+role)
            found[role]=(path,digest,raw)
    contract=plan.get("p678_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,suffix):
        item=found.get(role)
        return (item[2] if item and item[0].lower().endswith(suffix)
                and pins.get(role)==item[1] and sha(item[2])==item[1]
                else None)
    delivery_plan_raw=original("P8_DELIVERY_PLAN",".json")
    delivery_plan=_json(delivery_plan_raw) if delivery_plan_raw is not None else {}
    source=original("SOURCE_EDITABLE",".blend")
    export=original("NATIVE_EXPORT",".glb")
    archive=original("DELIVERY_PACKAGE",".zip")
    members=_zip(archive) if archive is not None else None
    source_name=delivery_plan.get("source_member")
    export_name=delivery_plan.get("export_member")
    required=delivery_plan.get("required_members")
    names_ok=(safe_member(source_name) and safe_member(export_name)
              and source_name!=export_name
              and type(required) is list and 2<=len(required)<=128
              and all(safe_member(n) for n in required)
              and len(required)==len(set(required))
              and {source_name,export_name,"DELIVERY_MANIFEST.json"}<=set(required))
    originals_match=(names_ok and members is not None
                     and source is not None and export is not None
                     and members.get(source_name)==source
                     and members.get(export_name)==export)
    complete=(names_ok and members is not None
              and set(required)<=set(members))
    parsed=False
    if originals_match:
        parsed=bool(source.startswith(b"BLENDER")
                    and len(source)>16
                    and geometry(export))
    manifest={}
    if members is not None and "DELIVERY_MANIFEST.json" in members:
        manifest=_json(members["DELIVERY_MANIFEST.json"])
    identity=(originals_match and type(delivery_plan.get("version")) is str
              and bool(delivery_plan["version"])
              and delivery_plan.get("asset")==asset
              and manifest.get("asset")==asset
              and manifest.get("version")==delivery_plan["version"]
              and manifest.get("source_member")==source_name
              and manifest.get("export_member")==export_name
              and manifest.get("source_sha256")==sha(source)
              and manifest.get("export_sha256")==sha(export)
              and delivery_plan.get("source_sha256")==sha(source)
              and delivery_plan.get("export_sha256")==sha(export))
    checks={
        191:{
            "real_source_and_export_binary_members_present":
                bool(originals_match),
            "delivery_contains_nonempty_source_not_only_report":
                bool(originals_match and len(source)>16 and len(export)>52),
        },
        192:{
            "original_required_delivery_member_set_explicit":
                bool(names_ok),
            "all_original_required_members_present":
                bool(complete),
        },
        193:{
            "archive_crc_and_all_members_read_independently":
                members is not None and bool(members),
            "actual_export_glb_and_editable_source_headers_parsed":
                bool(parsed),
        },
        194:{
            "registered_source_export_bytes_equal_archive_members":
                bool(originals_match),
            "original_manifest_asset_version_and_hashes_match":
                bool(identity),
        },
    }
    rules={}
    for n,rid in zip(NUMBERS,IDS):
        measured=checks[n]
        rules[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,"exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":measured,
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(measured.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False,
        }
    return {"schema":SCHEMA,"source_rule_count":4,"rules":rules,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_delivery_metrics":{
                "archive_member_count":len(members) if members else 0,
                "required_members":len(required) if names_ok else 0,
                "source_export_bytes_match":bool(originals_match)},
            "machine_positive_obligations":sum(
                v["machine_scope"]=="OBSERVED_SCOPE_PASS"
                for v in rules.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}
