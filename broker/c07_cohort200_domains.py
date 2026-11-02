FAMILY_LANES = {
 "EXECUTION": ("P:operation.action", "R:NATIVE_EXPORT", "X:original_dependencies"),
 "DELIVERY": ("R:DELIVERY_PACKAGE", "R:DELIVERY_MANIFEST", "X:delivery_status"),
 "ASSET_PROFILE_READINESS": ("P:asset_type", "R:SOURCE_EDITABLE", "E:SUPERVISOR_NATIVE_QA"),
 "BEHAVIOR": ("R:BEHAVIOR_POLICY", "E:SUPERVISOR_C07_ANSWER_CHECK", "X:regression_source"),
 "COGNITIVE": ("R:COGNITIVE_CHECK", "E:SUPERVISOR_QUESTION_BATCH", "X:current_audit"),
 "DESIGN_STANDARDS": ("R:REFERENCE_IMAGE", "R:VISUAL_VIEW_FRONT", "M:glb_geometry"),
 "D_SUBGATES": ("P:operation.action", "E:SUPERVISOR_OPERATION_OPENED", "X:lock_present"),
}
