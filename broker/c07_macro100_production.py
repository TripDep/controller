"""Objective, research and production predicates for macro100.

The computations require observations with concrete subjects/units/lineage.
They do not infer authenticity, visual quality or understanding from filenames,
nonempty prose or a producer's PASS flag.
"""
import math
import re
from pathlib import PurePosixPath
from c07_macro100_domain import require, verdict, number, instant, ids, range_covered
from c07_macro100_behavior import b005, b007, b050, b061, b063


def a001(c):
    brief = c.get('owner_brief')
    objective = c.get('objective')
    first = min(instant(r['at']) for r in c.actions())
    fields = ('id', 'deliverable_ids', 'requirement_ids', 'workstream', 'owner_id')
    return verdict(all(objective[k] == brief[k] for k in fields) and
                   instant(objective['recorded_at']) < first and not objective['unresolved_questions'],
                   'pre-action objective agrees with owner brief and has no unresolved questions')


def a002(c):
    objective = c.get('objective')
    actions = c.actions()
    requested = set(objective['deliverable_ids'])
    require(bool(requested), 'deliverable set required')
    return verdict(all(set(a['contributes_to']) <= requested and bool(a['contributes_to']) for a in actions)
                   and not ids(actions).intersection(requested),
                   'activities explicitly contribute to separately identified requested results')


def a003(c):
    measured = c.telemetry()
    report = c.get('progress')
    produced = c.production_delta()
    return verdict(number(report['active_seconds']) == measured['active_seconds']
                   and set(report['completed_deliverables']) == produced,
                   'worked time and completed deliverables computed independently',
                   {'active_seconds': measured['active_seconds'], 'deliverable_ids': sorted(produced)})


def a004(c):
    constraints = c.rows('instruction_constraints')
    observations = {r['id']: r for r in c.rows('constraint_observations')}
    ids(constraints)
    for constraint in constraints:
        observed = observations[constraint['observation_id']]
        require(observed['subject'] == constraint['subject'], 'constraint subject mismatch')
        actual, expected = observed['value'], constraint['value']
        op = constraint['operator']
        if op == 'EQ':
            matches = actual == expected
        elif op == 'LE':
            matches = number(actual) <= number(expected) and observed['unit'] == constraint['unit']
        elif op == 'EXCLUDES':
            require(type(actual) is list and type(expected) is list, 'exclusion sets required')
            matches = not set(actual).intersection(expected)
        elif op == 'PRESERVE_BYTES':
            matches = c.blob(actual) == c.blob(expected)
        else:
            require(False, 'instruction requires an unimplemented semantic operator: '+str(op))
        if not matches:
            return verdict(False, 'applicable instruction violated', constraint['id'])
    return verdict(True, 'all supplied applicable instruction constraints evaluated')


def a005(c):
    revisions = c.rows('objective_revisions')
    authorizations = c.rows('authorizations')
    experiments = {r['id']: r for r in c.rows('objective_change_trials')}
    for previous, current in zip(revisions, revisions[1:]):
        if previous['objective_id'] == current['objective_id']:
            continue
        owner = any(r['from_objective'] == previous['objective_id'] and
                    r['to_objective'] == current['objective_id'] and r['authority'] == 'OWNER'
                    and instant(r['at']) < instant(current['at']) for r in authorizations)
        technical = False
        if current.get('trial_id') in experiments:
            trial = experiments[current['trial_id']]
            technical = (trial['original_objective'] == previous['objective_id'] and
                         trial['replacement_objective'] == current['objective_id'] and
                         trial['original_failure'] in ('IMPOSSIBLE_CONSTRAINT', 'UNAVAILABLE_DEPENDENCY')
                         and instant(trial['at']) < instant(current['at']))
        if not (owner or technical):
            return verdict(False, 'changed objective lacks prior authorization or causal technical observation')
    return verdict(True, 'objective transitions have prior owner or technical basis')


def a006(c):
    issues = c.rows('quality_issues')
    responsibility = c.get('quality_responsibility')
    required = set(c.get('objective')['deliverable_ids'])
    return verdict(set(responsibility['deliverable_ids']) == required and
                   responsibility['qa_principal'] != c.get('objective')['owner_id'] and
                   all(r['assigned_to'] == responsibility['qa_principal'] and
                       r['artifact_id'] in required for r in issues),
                   'production QA responsibility covers requested deliverables without delegation to owner')


def a007(c):
    findings = c.rows('quality_findings')
    deliveries = c.rows('delivery_events')
    for delivery in deliveries:
        relevant = [f for f in findings if f['artifact_sha256'] == delivery['artifact_sha256']]
        require(bool(relevant), 'no quality inspection for delivered artifact')
        for finding in relevant:
            if finding['discoverable_pre_delivery'] and (finding['detected_by'] == 'OWNER' or
                    instant(finding['detected_at']) >= instant(delivery['at'])):
                return verdict(False, 'internally discoverable defect escaped to owner', finding['id'])
    return verdict(True, 'observed discoverable defects identified internally before delivery')


def a010(c):
    alternatives = c.rows('solution_alternatives')
    ids(alternatives)
    required = set(c.get('objective')['requirement_ids'])
    require(bool(required), 'requirements required for alternative comparison')
    feasible = [r for r in alternatives if required <= set(r['satisfied_requirements']) and
                number(r['additional_cost']) <= number(c.get('constraints')['additional_cost_limit'])]
    require(bool(feasible), 'no feasible solution observed')
    selected = c.get('selected_solution')
    chosen = next(r for r in feasible if r['id'] == selected)
    score = lambda r: (number(r['dependency_count']), number(r['maintenance_steps']), number(r['setup_steps']))
    chosen_score = score(chosen)
    dominated = any(all(a <= b for a,b in zip(score(r), chosen_score)) and
                    any(a < b for a,b in zip(score(r), chosen_score)) for r in feasible)
    return verdict(not dominated,
                   'no observed feasible alternative is simpler on every measured dimension')


def c021(c):
    references = c.rows('references')
    origin = {r['id']: r for r in c.rows('reference_origins')}
    requested = c.get('research_subject')
    photos = [r for r in references if r['kind'] == 'PHOTOGRAPH']
    require(bool(photos), 'no photographic references')
    for photo in photos:
        c.blob(photo['sha256'])
        source = origin[photo['origin_id']]
        if not (source['image_sha256'] == photo['sha256'] and source['medium'] == 'CAMERA_CAPTURE'
                and photo['subject_id'] == requested['id'] and photo['origin_url'] == source['url']):
            return verdict(False, 'photograph origin or relevance differs from requested subject')
    return verdict(True, 'photographic reference identity and subject match origin observations')


def c022(c):
    searches = c.rows('technical_reference_searches')
    references = {r['id']: r for r in c.rows('references')}
    required = {'PLAN', 'SECTION', 'TECHNICAL_DRAWING'}
    require({r['kind'] for r in searches} == required, 'plan/section/drawing searches required')
    for search in searches:
        require(search['subject_id'] == c.get('research_subject')['id'], 'technical search wrong subject')
        available = search['available_reference_ids']
        require(type(available) is list, 'availability observation missing')
        for rid in available:
            row = references[rid]
            c.blob(row['sha256'])
            if row['kind'] != search['kind'] or row['subject_id'] != search['subject_id']:
                return verdict(False, 'available technical reference not acquired in correct role')
    return verdict(True, 'available plans, sections and drawings acquired for each searched category')


def c023(c):
    measurements = c.rows('reference_dimensions')
    comparisons = c.rows('proportion_studies')
    dimensions = {r['id']: r for r in measurements}
    ids(measurements)
    for study in comparisons:
        width, height = dimensions[study['numerator_id']], dimensions[study['denominator_id']]
        require(width['subject_id'] == height['subject_id'] and width['unit'] == height['unit'],
                'incomparable reference measurements')
        w, h = number(width['value']), number(height['value'])
        require(w > 0 and h > 0, 'reference dimensions must be positive')
        expected = w/h
        if abs(number(study['ratio'])-expected) > 1e-9:
            return verdict(False, 'studied proportion differs from original measurements', expected)
    return verdict(True, 'proportions recomputed from same-subject dimensions in same units')


def c024(c):
    members = c.rows('construction_members')
    joints = c.rows('construction_joints')
    known = ids(members)
    foundations = {r['id'] for r in members if r['role'] == 'FOUNDATION'}
    require(bool(foundations), 'foundation identification required')
    supported = set(foundations)
    for joint in joints:
        require(joint['member'] in known and joint['support'] in known, 'construction joint unknown member')
        c.blob(joint['reference_sha256'])
    for _ in range(len(members)):
        supported |= {r['member'] for r in joints if r['support'] in supported}
    bearing = {r['id'] for r in members if r['role'] in ('COLUMN', 'BEAM', 'ROOF', 'FLOOR')}
    require(bool(bearing), 'load-bearing members required')
    return verdict(bearing <= supported, 'documented construction support paths reach foundation', sorted(bearing-supported))


def c025(c):
    surfaces = c.rows('reference_surfaces')
    studies = {r['surface_id']: r for r in c.rows('material_studies')}
    ids(surfaces)
    for surface in surfaces:
        c.blob(surface['reference_sha256'])
        study = studies[surface['id']]
        if not (study['reference_sha256'] == surface['reference_sha256'] and
                study['sample_region'] == surface['sample_region'] and
                study['material'] == surface['material'] and
                set(study['observed_features']) >= set(surface['characteristic_features'])):
            return verdict(False, 'material study does not cover original reference surface features')
    return verdict(True, 'material studies correspond to original sampled reference surfaces')


def c026(c):
    photos = [r for r in c.rows('references') if r['kind'] == 'PHOTOGRAPH']
    require(len(photos) >= 2, 'at least two photographic viewpoints required')
    rays = []
    for photo in photos:
        c.blob(photo['sha256'])
        vector = photo['camera_direction']
        require(type(vector) is list and len(vector) == 3, 'three-component camera direction')
        length = math.sqrt(sum(number(x)**2 for x in vector))
        require(length > 0, 'zero camera direction')
        rays.append(tuple(x/length for x in vector))
    subjects = {p['subject_id'] for p in photos}
    separation = max(math.degrees(math.acos(max(-1, min(1, sum(a*b for a,b in zip(x,y))))))
                     for x in rays for y in rays)
    return verdict(len(subjects) == 1 and len({p['sha256'] for p in photos}) > 1 and separation > 1e-7,
                   'same subject observed from distinct measured camera directions', separation)


def c027(c):
    references = c.rows('references')
    assignments = c.rows('reference_assignments')
    known = ids(references)
    require({a['reference_id'] for a in assignments} == known, 'reference role assignment incomplete')
    return verdict(all(a['role'] in ('STRUCTURAL', 'AESTHETIC') for a in assignments)
                   and any(a['role'] == 'STRUCTURAL' for a in assignments)
                   and any(a['role'] == 'AESTHETIC' for a in assignments),
                   'all reference uses classified explicitly as structural or aesthetic')


def c028(c):
    subject = c.get('research_subject')
    records = c.rows('historical_sources')
    study = c.get('historical_study')
    by_dimension = {dimension: [r for r in records if r['dimension'] == dimension]
                    for dimension in ('period', 'place', 'culture', 'architectural_identity')}
    for dimension, sources in by_dimension.items():
        require(bool(sources), 'historical source missing for '+dimension)
        values = set()
        for row in sources:
            c.blob(row['sha256'])
            require(row['subject_id'] == subject['id'], 'historical source concerns another subject')
            values.add(row['value'])
        if len(values) != 1 or study[dimension] not in values:
            return verdict(False, 'historical study conflicts with source observations', dimension)
    return verdict(True, 'period, place, culture and identity individually reconciled against sources')


def c029(c):
    references = c.rows('references')
    licenses = {r['id']: r for r in c.rows('license_records')}
    uses = c.rows('reference_uses')
    require({r['reference_id'] for r in uses} == ids(references), 'license check omits references')
    by_id = {r['id']: r for r in references}
    for use in uses:
        reference = by_id[use['reference_id']]
        license = licenses[reference['license_id']]
        c.blob(license['terms_sha256'])
        if not (reference['sha256'] in license['covered_sha256']
                and set(use['rights_required']) <= set(license['granted_rights'])
                and set(license['attribution_required']) <= set(use['attribution_provided'])
                and use['territory'] in license['territories']
                and instant(license['valid_from']) <= instant(use['at']) <= instant(license['valid_until'])):
            return verdict(False, 'actual reference use exceeds recorded license rights or obligations', reference['id'])
    return verdict(True, 'each model/texture/photo use checked against exact license rights, attribution and validity')


def c030(c):
    references = c.rows('references')
    index = c.get('reference_collection')
    first = min(instant(r['at']) for r in c.actions() if r['kind'] == 'BLOCKOUT')
    return verdict(set(index['reference_ids']) == ids(references)
                   and instant(index['frozen_at']) < first
                   and all(instant(r['acquired_at']) <= instant(index['frozen_at']) and
                           r['subject_id'] == c.get('research_subject')['id'] for r in references),
                   'complete same-subject reference collection frozen before blockout')


def r171(c):
    files = c.rows('source_files')
    naming = c.get('source_layout')
    paths = [PurePosixPath(r['path']) for r in files]
    require(len(paths) == len(set(paths)), 'duplicate source paths')
    for row, path in zip(files, paths):
        c.blob(row['sha256'])
        root = PurePosixPath(naming['role_roots'][row['role']])
        if path.is_absolute() or '..' in path.parts or not path.is_relative_to(root):
            return verdict(False, 'source outside its declared role directory', str(path))
        expected = naming['name_template'].format(asset=row['asset'], revision=row['revision'], role=row['role'])
        if path.stem != expected or row['asset'] != c.get('objective')['asset_id']:
            return verdict(False, 'source name inconsistent with asset, revision or role', str(path))
    return verdict(True, 'actual source bytes follow enrolled role directories and naming convention')


def r172(c):
    files = c.rows('source_files')
    required = {'SOURCE_EDITABLE', 'NATIVE_EXPORT', 'DELIVERY_PACKAGE'}
    require(required <= {r['role'] for r in files}, 'source/export/delivery role missing')
    linkage = c.rows('export_lineage')
    by_id = {r['id']: r for r in files}
    ids(files)
    for link in linkage:
        source, export, delivery = (by_id[link[k]] for k in ('source_id', 'export_id', 'delivery_id'))
        if [r['role'] for r in (source, export, delivery)] != ['SOURCE_EDITABLE', 'NATIVE_EXPORT', 'DELIVERY_PACKAGE']:
            return verdict(False, 'source/export/delivery lineage roles interchanged')
        if len({r['path'] for r in (source, export, delivery)}) != 3:
            return verdict(False, 'source/export/delivery paths alias each other')
        for r in (source, export, delivery):
            c.blob(r['sha256'])
        if link['export_sha256'] != export['sha256'] or link['source_sha256'] != source['sha256']:
            return verdict(False, 'export lineage binds different source or export bytes')
    return verdict(True, 'source/export/delivery distinguished with exact byte lineage')


def r173(c):
    revisions = c.rows('version_history')
    ids(revisions)
    known = set()
    for row in revisions:
        c.blob(row['snapshot_sha256'])
        require(type(row['parents']) is list, 'version parents required')
        if not set(row['parents']) <= known:
            return verdict(False, 'version history has missing parent or non-topological lineage')
        if known and not row['parents']:
            return verdict(False, 'version history silently starts a second root')
        known.add(row['id'])
    restore = c.get('restore_trial')
    original = next(r for r in revisions if r['id'] == restore['revision_id'])
    return verdict(c.blob(original['snapshot_sha256']) == c.blob(restore['restored_sha256']),
                   'version history preserves ancestry and selected revision restores exact bytes')


def r174(c):
    approvals = c.rows('owner_approvals')
    copies = c.rows('backup_copies')
    accepted = [r for r in approvals if r['decision'] == 'ACCEPT']
    require(bool(accepted), 'no approved asset snapshot to check')
    for approval in accepted:
        originals = c.blob(approval['artifact_sha256'])
        matches = [r for r in copies if r['original_sha256'] == approval['artifact_sha256']]
        require(bool(matches), 'approved asset has no recoverable backup')
        if not any(c.blob(r['copy_sha256']) == originals and r['copy_path'] != r['original_path']
                   for r in matches):
            return verdict(False, 'approved asset backup is aliased or differs from approved bytes')
    return verdict(True, 'each approved asset has distinct byte-verifiable preserved copy')


def r175(c):
    measurements = c.rows('automation_comparisons')
    for row in measurements:
        manual, automated = row['manual_trials'], row['automated_trials']
        require(len(manual) >= 2 and len(automated) >= 2, 'repeated manual and automatic trials required')
        require(len(manual) == len(automated) and
                len({r['input_sha256'] for r in manual}) == len(manual) and
                len({r['input_sha256'] for r in automated}) == len(automated),
                'automation comparisons require one paired trial per workload')
        require({r['input_sha256'] for r in manual} == {r['input_sha256'] for r in automated},
                'automation comparison has different workloads')
        expected = {r['input_sha256']: r['output_sha256'] for r in manual}
        if not all(r['output_sha256'] == expected[r['input_sha256']] for r in automated):
            return verdict(False, 'automation changes check results')
        saved = sum(number(r['seconds']) for r in manual)-sum(number(r['seconds']) for r in automated)
        net = number(row['expected_repetitions']) * saved/len(manual)-number(row['setup_seconds'])
        if net <= 0:
            return verdict(False, 'automation benefit does not repay observed setup cost', net)
    return verdict(True, 'repeatable checks retain results and show positive amortized benefit')


def r176(c):
    runs = c.runs()
    expectations = c.rows('script_expectations')
    for expected in expectations:
        run = runs[expected['run_id']]
        if run['exit_code'] != 0:
            return verdict(False, 'script did not finish successfully', run['id'])
        if c.blob(run['output_sha256']) != c.blob(expected['output_sha256']):
            return verdict(False, 'script exited zero but produced unexpected output bytes', run['id'])
        if run['inputs_sha256'] != expected['inputs_sha256']:
            return verdict(False, 'script output evaluated against wrong input set', run['id'])
    return verdict(True, 'actual script outputs compared with exact input-bound expected outputs')


def r177(c):
    approvals = c.rows('protected_assets')
    writes = c.rows('writes')
    for approved in approvals:
        c.blob(approved['sha256'])
        for write in writes:
            if write['path'] == approved['path'] and instant(write['at']) >= instant(approved['locked_at']):
                if write['sha256'] != approved['sha256']:
                    return verdict(False, 'automatic write changed protected bytes even if later restored', approved['path'])
        if c.blob(approved['current_sha256']) != c.blob(approved['sha256']):
            return verdict(False, 'current protected asset differs from approved copy', approved['path'])
    return verdict(True, 'protected bytes unchanged through observed writes and current readback')


def r178(c):
    tasks = c.rows('task_states')
    dependencies = c.rows('task_dependencies')
    events = c.rows('task_events')
    known = ids(tasks)
    for dep in dependencies:
        require(dep['task_id'] in known and dep['depends_on'] in known, 'dependency references unknown task')
        c.blob(dep['sha256'])
    for task in tasks:
        observed = [r for r in events if r['task_id'] == task['id']]
        require(bool(observed), 'task state lacks actual events')
        latest = max(observed, key=lambda r: instant(r['at']))
        if task['state'] != latest['state'] or task['last_event_id'] != latest['id']:
            return verdict(False, 'recorded task state differs from latest event', task['id'])
        if set(task['depends_on']) != {r['depends_on'] for r in dependencies if r['task_id'] == task['id']}:
            return verdict(False, 'persisted task dependencies omit observed edges', task['id'])
    return verdict(True, 'recorded task state and dependencies agree with observed events and original bytes')


def r179(c):
    resume = c.get('resume')
    checkpoint = c.checkpoints()[resume['checkpoint_id']]
    c.blob(checkpoint['sha256'])
    actions = c.actions()
    completed = set(checkpoint['completed_operation_ids'])
    resumed = [r for r in actions if instant(r['at']) >= instant(resume['at'])]
    require(bool(resumed), 'no resumed operations observed')
    return verdict(resume['state_sha256'] == checkpoint['state_sha256']
                   and resumed[0]['operation_id'] == checkpoint['next_operation']
                   and not completed.intersection(r['operation_id'] for r in resumed)
                   and len({r['operation_id'] for r in resumed}) == len(resumed),
                   'resume uses checkpoint next operation without replaying completed work')


def r180(c):
    return b005(c)


PRODUCTION = {
    **{f'AAA-200-A-{n:03}': globals()[f'a{n:03}'] for n in (1, 2, 3, 4, 5, 6, 7, 10)},
    **{f'AAA-200-C-{n:03}': globals()[f'c{n:03}'] for n in range(21, 31)},
    **{f'AAA-200-R-{n:03}': globals()[f'r{n:03}'] for n in range(171, 181)},
}
