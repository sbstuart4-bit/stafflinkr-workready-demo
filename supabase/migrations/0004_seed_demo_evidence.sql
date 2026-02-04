-- /supabase/migrations/0004_seed_demo_evidence.sql
-- Demo evidence for a demo worker:
-- - Valid CPR (issued 1 year ago, 36 month validity => valid)
-- - Expired VSC (issued 400 days ago, 365 day validity => expired)
-- - Diploma present (non-expiring)
--
-- IMPORTANT:
-- - Replace DEMO_WORKER_ID with the same UUID used in 0003_seed_demo_org.sql
-- - This script only seeds EVIDENCE. It does NOT compute snapshots.
--   Your app/engine should compute credential_status_snapshots + gate_decision_snapshots.
--
-- Safe to re-run: it marks prior demo evidence as superseded and inserts new "active" rows.

begin;

do $$
declare
  demo_worker_id uuid := '44444444-4444-4444-4444-444444444444'; -- REPLACE WITH REAL USER UUID

  cpr_type_id uuid;
  vsc_type_id uuid;
  diploma_type_id uuid;

  demo_college_org_id uuid := '00000000-0000-0000-0000-000000000001';

  cpr_evidence_id uuid;
  vsc_evidence_id uuid;
  diploma_evidence_id uuid;

  today date := current_date;
begin
  -- ----------------------------------------------------------
  -- 0) Lookup credential types
  -- ----------------------------------------------------------
  select id into cpr_type_id from public.credential_types where code = 'CPR' limit 1;
  select id into vsc_type_id from public.credential_types where code = 'VSC' limit 1;
  select id into diploma_type_id from public.credential_types where code = 'DIPLOMA' limit 1;

  if cpr_type_id is null or vsc_type_id is null or diploma_type_id is null then
    raise exception 'Missing credential_types seed (CPR/VSC/DIPLOMA). Run 0002_seed_workready.sql first.';
  end if;

  -- ----------------------------------------------------------
  -- 1) Supersede previous demo evidence
  -- ----------------------------------------------------------
  update public.credential_evidence
     set status = 'superseded'
   where profile_id = demo_worker_id
     and status = 'active'
     and credential_type_id in (cpr_type_id, vsc_type_id, diploma_type_id);

  -- ----------------------------------------------------------
  -- 2) Insert CPR evidence (VALID)
  -- ----------------------------------------------------------
  insert into public.credential_evidence (
    profile_id,
    credential_type_id,
    file_id,
    created_by_profile_id,
    created_by_org_id,
    source,
    issuer_name,
    issue_date,
    expiry_date,
    license_number,
    jurisdiction,
    status
  )
  values (
    demo_worker_id,
    cpr_type_id,
    null,
    demo_worker_id,
    demo_college_org_id,
    'worker_upload',
    'St John Ambulance (Demo)',
    (today - interval '365 days')::date,
    null, -- let engine compute using rule validity_days
    null,
    'ON',
    'active'
  )
  returning id into cpr_evidence_id;

  -- Optional extra fields (key/value)
  insert into public.credential_evidence_fields (evidence_id, field_key, field_value, confidence_score)
  values
    (cpr_evidence_id, 'course_type', 'CPR-C + First Aid', null),
    (cpr_evidence_id, 'card_number', 'CPR-DEMO-12345', null)
  on conflict (evidence_id, field_key) do update
    set field_value = excluded.field_value,
        confidence_score = excluded.confidence_score;

  -- ----------------------------------------------------------
  -- 3) Insert VSC evidence (EXPIRED)
  -- ----------------------------------------------------------
  insert into public.credential_evidence (
    profile_id,
    credential_type_id,
    file_id,
    created_by_profile_id,
    created_by_org_id,
    source,
    issuer_name,
    issue_date,
    expiry_date,
    license_number,
    jurisdiction,
    status
  )
  values (
    demo_worker_id,
    vsc_type_id,
    null,
    demo_worker_id,
    demo_college_org_id,
    'worker_upload',
    'Windsor Police Service (Demo)',
    (today - interval '400 days')::date,
    null, -- engine computes expiry via validity_days=365
    'VSC-DEMO-98765',
    'ON',
    'active'
  )
  returning id into vsc_evidence_id;

  insert into public.credential_evidence_fields (evidence_id, field_key, field_value, confidence_score)
  values
    (vsc_evidence_id, 'document_id', 'VSC-DOC-DEMO-0001', null)
  on conflict (evidence_id, field_key) do update
    set field_value = excluded.field_value,
        confidence_score = excluded.confidence_score;

  -- ----------------------------------------------------------
  -- 4) Insert Diploma evidence (PRESENT)
  -- ----------------------------------------------------------
  insert into public.credential_evidence (
    profile_id,
    credential_type_id,
    file_id,
    created_by_profile_id,
    created_by_org_id,
    source,
    issuer_name,
    issue_date,
    expiry_date,
    license_number,
    jurisdiction,
    status
  )
  values (
    demo_worker_id,
    diploma_type_id,
    null,
    demo_worker_id,
    demo_college_org_id,
    'school_admin',
    'WorkReady Demo College',
    (today - interval '30 days')::date,
    null,
    null,
    'ON',
    'active'
  )
  returning id into diploma_evidence_id;

  insert into public.credential_evidence_fields (evidence_id, field_key, field_value, confidence_score)
  values
    (diploma_evidence_id, 'program', 'PSW (Demo Program)', null),
    (diploma_evidence_id, 'student_number', 'STU-DEMO-2026-001', null)
  on conflict (evidence_id, field_key) do update
    set field_value = excluded.field_value,
        confidence_score = excluded.confidence_score;

end $$;

commit;
