"""Reviewed per-rule verifier enrollment, not a generic PASS-list registry.

The canonically sourced work inventory contains 763 IDs. Only specific
reviewed source predicates may be enrolled. Unknown validators cannot become
operational by writing a friendly PASS or 64-char proof_digest in Git logs.
Missing rules remain UNKNOWN; this list makes no claim of full coverage.
"""
import re

from planning_semantics import ENGINE_RULE, VALIDATOR as PLANNING_VALIDATOR, CRITERIA as PLANNING_CRITERIA
from r173_rule_semantics import VALIDATOR as R173_VALIDATOR

R173_CRITERIA={
 'AAA-200-A-008':('uncertain_walkability_explicit','unknown_world_water_z_explicit',
                   'artistic_result_not_assumed','reliability_scope_limited'),
 'AAA-200-A-009':('r173_not_claimed_final','scope_not_misrepresented_as_production',
                   'owner_approval_not_forged','runtime_collision_not_declared_pass',
                   'independent_binary_not_falsely_claimed'),
 'AAA-200-B-011':('actual_path_scope_counted','real_path_extent_documented',
                   'path_review_not_final_asset','bank_rework_purpose_explicit'),
 'AAA-200-B-014':('historic_r169_source_identified',
                   'terrain_r101_source_identified',
                   'existing_r98_inventory_recorded',
                   'retained_r98_not_claimed_mutable'),
 'AAA-200-B-015':('protected_r98_explicitly_not_modified','rejected_r170_r171_excluded',
                   'r173_pending_not_accepted','golden_market_not_integrated'),
 'AAA-200-B-016':('landing_dependencies_named','terrain_design_not_world_surface',
                   'water_and_collision_unknown','r98_dependency_preserved'),
 'AAA-200-B-017':('review_candidate_scope_explicit','geometry_export_not_signed_off',
                   'owner_delivery_acceptance_pending','final_fivem_runtime_not_claimed'),
 'AAA-200-B-020':('measurable_slope_5pct_risk_observed',
                   'measurable_landing_count_unresolved',
                   'walkability_acceptance_pending',
                   'runtime_acceptance_not_forged'),
 'AAA-200-B-018':('prior_block_named','eight_landing_risks_documented',
                   'grade_risk_quantified','water_collision_risks_unresolved',
                   'prior_approved_source_intact'),
}
REVIEWED={
 ENGINE_RULE:(PLANNING_VALIDATOR,tuple(PLANNING_CRITERIA)),
 **{rule:(R173_VALIDATOR,criteria) for rule,criteria in R173_CRITERIA.items()},
}

class InvalidEnrollment(ValueError):pass

def require(ok,msg):
    if not ok:raise InvalidEnrollment(msg)

def validate(enrolled,inventory):
    require(isinstance(enrolled,dict),'VALIDATOR_ENROLLMENT_SCHEMA')
    for rid,spec in enrolled.items():
        require(rid in inventory['rules'],'VALIDATOR_UNREGISTERED_RULE:'+str(rid))
        require(rid in REVIEWED,'VALIDATOR_NOT_IMPLEMENTED_FOR_RULE:'+rid)
        require(isinstance(spec,dict),'VALIDATOR_SPEC_SCHEMA:'+rid)
        validator,criteria=REVIEWED[rid]
        require(spec.get('validator_id')==validator,
                'VALIDATOR_ID_NOT_REVIEWED:'+rid)
        require(isinstance(spec.get('criteria'),list) and
                len(spec['criteria'])==len(set(spec['criteria'])) and
                set(spec['criteria'])==set(criteria),
                'VALIDATOR_REQUIRED_SEMANTIC_CRITERIA:'+rid)
        row=inventory['rules'][rid]
        require(spec.get('requirement_sha256')==row['requirement_sha256'],
                'VALIDATOR_CANONICAL_REQUIREMENT_CHANGED:'+rid)
        issuer=spec.get('issuer')
        require(isinstance(issuer,dict) and
                set(issuer)=={'workflow_blob','public_sha'} and
                re.fullmatch('[a-f0-9]{40}',issuer['workflow_blob']) and
                re.fullmatch('[a-f0-9]{40}',issuer['public_sha']),
                'VALIDATOR_GIT_ORIGIN_MISSING:'+rid)
        if validator==PLANNING_VALIDATOR:
            require(re.fullmatch('[a-f0-9]{40}', str(spec.get('source_ref',''))),
                    'VALIDATOR_PLANNING_EVIDENCE_IMMUTABLE_REF:'+rid)
        if validator==R173_VALIDATOR:
            require(re.fullmatch('[a-f0-9]{40}',str(spec.get('source_ref',''))),
                    'VALIDATOR_R173_EVIDENCE_IMMUTABLE_REF:'+rid)
    return {'reviewed_enrolled_count':len(enrolled),
            'reviewed_rule_ids':sorted(enrolled),
            'complete_763_rule_coverage':False,'work_authorized':False}
