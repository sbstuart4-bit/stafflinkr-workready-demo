-- /supabase/migrations/0002_seed_workready.sql
-- Seed data for WorkReady MVP:
-- Credential Types: CPR, VSC, DIPLOMA
-- Gates: PLACEMENT, GRAD_READY
-- Rule Set: Global Default v1
-- Gate requirements wired up to the rule set
--
-- Safe to run multiple times (uses UPSERT patterns)

begin;

-- ------------------------------------------------------------
-- 0) (Optional) Create a default org for demos
-- ------------------------------------------------------------
insert into public.orgs (id, name, org_type)
values ('00000000-0000-0000-0000-000000000001', 'WorkReady Demo College', 'college')
on conflict (id) do nothing;

-- ------------------------------------------------------------
-- 1) Credential Types
-- ------------------------------------------------------------

-- CPR / First Aid
insert into public.credential_types (
  code, name, description, expires, default_validity_days,
  default_renewal_required, default_renewal_window_days, default_grace_period_days,
  default_warning_days, default_verification_policy
)
values (
  'CPR',
  'CPR / First Aid',
  'Cardio Pulmonary Resuscitation + First Aid certification',
  true,
  1095, -- ~36 months
  true,
  60,
  0,
  '{90,30,7}',
  'manual'
)
on conflict (code) do update set
  name = excluded.name,
  description = excluded.description,
  expires = excluded.expires,
  default_validity_days = excluded.default_validity_days,
  default_renewal_required = excluded.default_renewal_required,
  default_renewal_window_days = excluded.default_renewal_window_days,
  default_grace_period_days = excluded.default_grace_period_days,
  default_warning_days = excluded.default_warning_days,
  default_verification_policy = excluded.default_verification_policy;

-- Vulnerable Sector Check
insert into public.credential_types (
  code, name, description, expires, default_validity_days,
  default_renewal_required, default_renewal_window_days, default_grace_period_days,
  default_warning_days, default_verification_policy
)
values (
  'VSC',
  'Vulnerable Sector Check',
  'Police background check (Vulnerable Sector) required for placements',
  true,
  365,
  true,
  90,
  0,
  '{90,30,7}',
  'manual'
)
on conflict (code) do update set
  name = excluded.name,
  description = excluded.description,
  expires = excluded.expires,
  default_validity_days = excluded.default_validity_days,
  default_renewal_required = excluded.default_renewal_required,
  default_renewal_window_days = excluded.default_renewal_window_days,
  default_grace_period_days = excluded.default_grace_period_days,
  default_warning_days = excluded.default_warning_days,
  default_verification_policy = excluded.default_verification_policy;

-- Diploma / Transcript
insert into public.credential_types (
  code, name, description, expires, default_validity_days,
  default_renewal_required, default_renewal_window_days, default_grace_period_days,
  default_warning_days, default_verification_policy
)
values (
  'DIPLOMA',
  'Diploma / Transcript',
  'School-issued completion document. Issuer-trusted.',
  false,
  null,
  false,
  null,
  null,
  '{}',
  'none'
)
on conflict (code) do update set
  name = excluded.name,
  description = excluded.description,
  expires = excluded.expires,
  default_validity_days = excluded.default_validity_days,
  default_renewal_required = excluded.default_renewal_required,
  default_renewal_window_days = excluded.default_renewal_window_days,
  default_grace_period_days = excluded.default_grace_period_days,
  default_warning_days = excluded.default_warning_days,
  default_verification_policy = excluded.default_verification_policy;

-- ------------------------------------------------------------
-- 2) Evidence requirements (what fields must exist)
-- ------------------------------------------------------------

-- CPR requires issuer_name, issue_date
insert into public.credential_type_requirements (credential_type_id, field_key, is_required, notes)
select ct.id, req.field_key, req.is_required, req.notes
from public.credential_types ct
join (values
  ('CPR', 'issuer_name', true, 'Name of training provider'),
  ('CPR', 'issue_date',  true, 'Date certificate was issued')
) as req(code, field_key, is_required, notes)
  on req.code = ct.code
on conflict (credential_type_id, field_key) do update set
  is_required = excluded.is_required,
  notes = excluded.notes;

-- VSC requires issuer_name, issue_date, expiry_date (or computed)
insert into public.credential_type_requirements (credential_type_id, field_key, is_required, notes)
select ct.id, req.field_key, req.is_required, req.notes
from public.credential_types ct
join (values
  ('VSC', 'issuer_name', true, 'Police service / issuing body'),
  ('VSC', 'issue_date',  true, 'Issue date on the document'),
  ('VSC', 'expiry_date', false, 'Some orgs compute expiry; if present store it')
) as req(code, field_key, is_required, notes)
  on req.code = ct.code
on conflict (credential_type_id, field_key) do update set
  is_required = excluded.is_required,
  notes = excluded.notes;

-- Diploma requires issuer_name + issue_date
insert into public.credential_type_requirements (credential_type_id, field_key, is_required, notes)
select ct.id, req.field_key, req.is_required, req.notes
from public.credential_types ct
join (values
  ('DIPLOMA', 'issuer_name', true, 'College / university'),
  ('DIPLOMA', 'issue_date',  true, 'Graduation or issuance date')
) as req(code, field_key, is_required, notes)
  on req.code = ct.code
on conflict (credential_type_id, field_key) do update set
  is_required = excluded.is_required,
  notes = excluded.notes;

-- ------------------------------------------------------------
-- 3) Global Default Rule Set (v1)
-- ------------------------------------------------------------

insert into public.rule_sets (org_id, name, version, status)
values (null, 'Global Default', 1, 'active')
on conflict (org_id, name, version) do update set
  status = excluded.status;

-- Grab rule_set_id
with rs as (
  select id
  from public.rule_sets
  where org_id is null and name = 'Global Default' and version = 1
  limit 1
),
ct as (
  select id, code
  from public.credential_types
  where code in ('CPR','VSC','DIPLOMA')
)
insert into public.credential_rules (
  rule_set_id, credential_type_id,
  expires, expiry_method, validity_days,
  renewal_required, renewal_window_days, grace_period_days,
  warning_days, verification_policy
)
select
  rs.id,
  ct.id,
  case when ct.code = 'DIPLOMA' then false else true end as expires,
  case when ct.code = 'DIPLOMA' then 'none' else 'from_issue_days' end as expiry_method,
  case when ct.code = 'CPR' then 1095
       when ct.code = 'VSC' then 365
       else null end as validity_days,
  case when ct.code in ('CPR','VSC') then true else false end as renewal_required,
  case when ct.code = 'CPR' then 60
       when ct.code = 'VSC' then 90
       else null end as renewal_window_days,
  0 as grace_period_days,
  case when ct.code = 'DIPLOMA' then '{}'::int[] else '{90,30,7}'::int[] end as warning_days,
  case when ct.code = 'DIPLOMA' then 'none' else 'manual' end as verification_policy
from rs, ct
on conflict do nothing;

-- ------------------------------------------------------------
-- 4) Gates
-- ------------------------------------------------------------

-- Placement Gate (global)
insert into public.gates (org_id, code, name, description)
values (
  null,
  'PLACEMENT',
  'Placement Eligibility',
  'Determines if a worker can accept / be placed on a shift.'
)
on conflict (org_id, code) do update set
  name = excluded.name,
  description = excluded.description;

-- Graduation Readiness Gate (global)
insert into public.gates (org_id, code, name, description)
values (
  null,
  'GRAD_READY',
  'Graduation Readiness',
  'Determines if student has required documents / certifications to graduate work-ready.'
)
on conflict (org_id, code) do update set
  name = excluded.name,
  description = excluded.description;

-- ------------------------------------------------------------
-- 5) Wire gates to rule_set (gate_rules)
-- ------------------------------------------------------------

with rs as (
  select id
  from public.rule_sets
  where org_id is null and name = 'Global Default' and version = 1
  limit 1
),
g as (
  select id, code
  from public.gates
  where org_id is null and code in ('PLACEMENT','GRAD_READY')
)
insert into public.gate_rules (gate_id, rule_set_id, status)
select g.id, rs.id, 'active'
from rs, g
on conflict (gate_id, rule_set_id) do update set
  status = excluded.status;

-- ------------------------------------------------------------
-- 6) Gate Requirements
-- ------------------------------------------------------------

-- Placement requires CPR + VSC (blocking)
with g as (
  select id, code
  from public.gates
  where org_id is null and code = 'PLACEMENT'
  limit 1
),
ct as (
  select id, code
  from public.credential_types
  where code in ('CPR','VSC')
)
insert into public.gate_requirements (
  gate_id, credential_type_id, required, min_status, fail_severity, notes
)
select
  g.id,
  ct.id,
  true,
  'valid',
  'block',
  case ct.code
    when 'CPR' then 'Must have CPR/First Aid valid at time of placement'
    when 'VSC' then 'Must have a valid Vulnerable Sector Check'
    else null
  end as notes
from g, ct
on conflict (gate_id, credential_type_id) do update set
  required = excluded.required,
  min_status = excluded.min_status,
  fail_severity = excluded.fail_severity,
  notes = excluded.notes;

-- Graduation readiness requires DIPLOMA + CPR
with g as (
  select id, code
  from public.gates
  where org_id is null and code = 'GRAD_READY'
  limit 1
),
ct as (
  select id, code
  from public.credential_types
  where code in ('DIPLOMA','CPR')
)
insert into public.gate_requirements (
  gate_id, credential_type_id, required, min_status, fail_severity, notes
)
select
  g.id,
  ct.id,
  true,
  'valid',
  'block',
  case ct.code
    when 'DIPLOMA' then 'School-issued diploma/transcript must be present'
    when 'CPR' then 'CPR must be valid at graduation'
    else null
  end as notes
from g, ct
on conflict (gate_id, credential_type_id) do update set
  required = excluded.required,
  min_status = excluded.min_status,
  fail_severity = excluded.fail_severity,
  notes = excluded.notes;

commit;
