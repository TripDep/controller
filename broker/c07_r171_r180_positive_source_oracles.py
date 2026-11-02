"""C07 R-176/R-177/R-179: real positive source-specific machine oracles.

The *source obligation* is always authoritative. These are bounded,
independently recomputed positive machine components, not complete semantic
rule PASS, owner sign-off, individual MG0 PASS or FiveM runtime QA.

Any missing originally registered source bytes, timestamp order, real source
oracle, or exact current attempt -> False, never an affirmative claim.
"""
import hashlib
import json
from pathlib import Path
from glb_machine_qa import audit_bytes,parse,read_accessor,GLBError,MAX_BYTES
from c07_exec25_true_measurements import measured_original_glb,criteria_well_formed

def _single(artifacts,role):
    rows=artifacts.get(role,())
    return rows[0] if len(rows)==1 else None

def _mesh_signature(raw):
    """Exact original mesh coordinates, primitives and world transforms.

    Triangle counts alone are NOT sufficient: a modified vertex with the
    same counts must fail. This conservative signature may reject equivalent
    triangulations; it never claims visual/FiveM acceptance.
    """
    document,blob=parse(raw)
    meshes=[]
    for mesh in document.get("meshes",[]):
        primitives=[]
        for primitive in mesh.get("primitives",[]):
            attrs=primitive.get("attributes",{})
            if "POSITION" not in attrs:return None
            positions=read_accessor(document,blob,attrs["POSITION"],"VEC3")
            indices=(read_accessor(document,blob,primitive["indices"],"SCALAR")
                     if "indices" in primitive else [(i,) for i in range(len(positions))])
            primitives.append({
                "positions":positions,
                "indices":indices,
                "mode":primitive.get("mode",4),
            })
        meshes.append(primitives)
    if not meshes:return None
    geometry={
        "meshes":meshes,
        "nodes":document.get("nodes",[]),
        "scenes":document.get("scenes",[]),
        "scene":document.get("scene"),
    }
    return hashlib.sha256(json.dumps(geometry,sort_keys=True,
        separators=(",",":"),allow_nan=False).encode()).hexdigest()

def native_script_output_matches_oracle(plan,artifacts):
    """R176, verify true output and independent reimport vs measured criteria.

    Both raw binaries were already authenticated by original Controller
    provenance, and independent native audit is recomputed directly on both.
    Merely having 'QA PASS' named in audit does not supply a positive.
    """
    if not criteria_well_formed(plan):return False
    actual=_single(artifacts,"NATIVE_EXPORT")
    reimport=_single(artifacts,"NATIVE_REIMPORT")
    if not actual or not reimport:return False
    if actual[0].suffix.lower()!=".glb" or reimport[0].suffix.lower()!=".glb":
        return False
    if (actual[0]==reimport[0] or
        type(actual[2]) is not bytes or type(reimport[2]) is not bytes or
        not 0<len(actual[2])<=MAX_BYTES or
        not 0<len(reimport[2])<=MAX_BYTES):return False
    try:
        first=audit_bytes(actual[2])
        second=audit_bytes(reimport[2])
    except (GLBError,ValueError,TypeError,KeyError,IndexError,OverflowError):
        return False
    if not (measured_original_glb(plan,first) and
            measured_original_glb(plan,second)):return False
    # Exact original mesh geometry, not merely matching triangle counts.
    try:
        mesh1=_mesh_signature(actual[2])
        mesh2=_mesh_signature(reimport[2])
    except (GLBError,ValueError,TypeError,KeyError,IndexError,OverflowError):
        return False
    return (first["triangles_examined"]>0 and
            mesh1 is not None and mesh1==mesh2 and
            all(first.get(k)==second.get(k) for k in (
                "triangles_examined","vertices_examined","mesh_primitives",
                "nonfinite_positions","invalid_indices","degenerate_triangles")))

def automation_preserved_approved_bytes(records,artifacts,work,step):
    """R177, immutable audit ordering + original-source pre/post byte equality.

    The pre-approved identity must be established by an explicit original
    approval in Controller audit; no fake document title creates approval.
    """
    original=_single(artifacts,"BASELINE_SNAPSHOT")
    after=_single(artifacts,"APPROVED_COPY_POST_AUTOMATION")
    if not original or not after:return False
    if (original[0]==after[0] or
        type(original[2]) is not bytes or
        type(after[2]) is not bytes or
        original[1]!=after[1] or original[2]!=after[2]):
        return False
    def bound(r):
        return (r.get("attempt_id")==work.get("attempt_id") and
                r.get("operation_sha256")==work.get("operation_sha256") and
                r.get("step")==step)
    # Signed reviewer identity remains unverified by this machine proof.
    def witness(role,digest):
        return [i for i,r in enumerate(records)
                if r.get("event")=="ARTIFACT_RECORDED" and
                r.get("step")==step and r.get("result")=="PASS" and
                type(r.get("evidence_operation")) is dict and
                r["evidence_operation"].get("role")==role and
                r["evidence_operation"].get("sha256")==digest]
    before=witness("BASELINE_SNAPSHOT",original[1])
    later=witness("APPROVED_COPY_POST_AUTOMATION",after[1])
    execution=[i for i,r in enumerate(records)
               if r.get("event")=="AUTOMATED_ORIGINAL_OUTPUT_CHECK" and bound(r)]
    approvals=[i for i,r in enumerate(records)
               if r.get("event")=="OWNER_APPROVED_ASSET_COPY_VERIFIED" and
               bound(r) and r.get("result")=="PASS" and
               r.get("approved_original_sha256")==original[1]]
    return (len(before)==len(later)==len(execution)==len(approvals)==1
            and before[0]<=approvals[0]<execution[0]<later[0])

def real_checkpoint_restored_without_duplicate(records,artifacts,work,step,
                                               source_loader=None):
    """R179, source of checkpoint predates current attempt and restored bytes.

    This proves the checkpoint's binary identity/lineage, not that all
    downstream model tasks or visual state were independently verified.
    """
    restored=_single(artifacts,"CHECKPOINT_RESTORED_SOURCE")
    if not restored or type(restored[2]) is not bytes or not restored[2]:
        return False
    parents=[(i,r) for i,r in enumerate(records) if
             r.get("event")=="CHECKPOINT_CREATED" and
             r.get("result")=="PASS" and
             r.get("checkpoint_sha256")==restored[1] and
             r.get("attempt_id")==work.get("previous_attempt_id")]
    current=[(i,r) for i,r in enumerate(records) if
             r.get("event")=="CHECKPOINT_RESTORED_AND_VERIFIED" and
             r.get("step")==step and
             r.get("attempt_id")==work.get("attempt_id") and
             r.get("operation_sha256")==work.get("operation_sha256") and
             r.get("checkpoint_sha256")==restored[1]]
    artifact_rows=[(i,r) for i,r in enumerate(records) if
             r.get("event")=="ARTIFACT_RECORDED" and
             r.get("step")==step and r.get("result")=="PASS" and
             type(r.get("evidence_operation")) is dict and
             r["evidence_operation"].get("role")=="CHECKPOINT_RESTORED_SOURCE" and
             r["evidence_operation"].get("sha256")==restored[1]]
    # A historical event naming a checkpoint SHA is NOT a source readback.
    # Demand its original registered checkpoint bytes, reread independently
    # through the original Controller source reader.
    previous=[(i,r) for i,r in enumerate(records) if
             r.get("event")=="ARTIFACT_RECORDED" and
             r.get("result")=="PASS" and
             type(r.get("evidence_operation")) is dict and
             r["evidence_operation"].get("role")=="CHECKPOINT_SOURCE" and
             r["evidence_operation"].get("sha256")==restored[1] and
             r.get("step")!=step]
    if not (len(parents)==len(current)==len(artifact_rows)==len(previous)==1
            and callable(source_loader) and
            type(work.get("previous_attempt_id")) is str and
            work["previous_attempt_id"]!=work.get("attempt_id") and
            parents[0][0]<previous[0][0]<artifact_rows[0][0]<current[0][0]):
        return False
    past=previous[0][1]["evidence_operation"]
    path=past.get("path")
    if (type(path) is not str or not Path(path).is_absolute() or
        Path(path).resolve()!=Path(path) or Path(path).is_symlink() or
        type(past.get("size_bytes")) is not int or
        past["size_bytes"]!=len(restored[2])):
        return False
    try:
        original=source_loader(path)
    except (OSError,ValueError,TypeError,KeyError):
        return False
    if type(original) is not bytes or original!=restored[2] or (
        hashlib.sha256(original).hexdigest()!=past["sha256"]):
        return False
    duplicate=[r for r in records if r.get("event") in (
        "SUPERVISOR_OPERATION_RESERVED","SUPERVISOR_OPERATION_CLOSED")
        and r.get("attempt_id")==work.get("attempt_id") and
        r.get("step")!=step]
    return not duplicate
