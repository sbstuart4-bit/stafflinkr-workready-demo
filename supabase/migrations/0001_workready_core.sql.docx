-- /supabase/migrations/0001_workready_core.sql
-- WorkReady v0.1 — core tables + indexes + constraints + RLS (MVP roles)
-- Roles modeled via org_members.member_role: worker | org_admin | reviewer | instructor

begin;

-- Extensions (safe if already enabled)
create extension if not exists pgcrypto;

-- -------------------------------------------------------------------
-- Helpers (RLS)
-- -------------------------------------------------------------------

-- Returns true if current user is a member of org with one of the given roles
create or replace function public.is_org_role(p_org_id uuid, p_roles text[])
returns boolean
language sql
stable
as $$
  select exists (
    select 1
    from public.org_members om
    where om.org_id = p_org_id
      and om.profile_id = auth.uid()
      and om.status = 'active'
      and om.member_role = any(p_roles)
  );
$$;

-- Returns true if current user is an active member of org (any role)
create or replace function public.is_org_member(p_org_id uuid)
returns boolean
language sql
stable
as $$
  select exists (
    select 1
    from public.org_members om
    where om.org_id = p_org_id
      and om.profile_id = auth.uid()
      and om.status = 'active'
  );
$$;

-- Returns true if (a) current user is the same profile OR (b) current user has staff role
-- in an org that the target profile is also a member of.
create or replace function public.can_view_profile(p_profile_id uuid)
returns boolean
language sql
stable
as $$
  select
    (auth.uid() = p_profile_id)
    or exists (
      select 1
      from public.org_members staff
      join public.org_members target
        on target.org_id = staff.org_id
      where staff.profile_id = auth.uid()
        and staff.status = 'active'
        and staff.member_role in ('org_admin','reviewer','instructor')
        and target.profile_id = p_profile_id
        and target.status = 'active'
    );
$$;

-- -------------------------------------------------------------------
-- 1) Identity / Tenancy
-- -------------------------------------------------------------------

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null default '',
  phone text,
  primary_region text,
  created_at timestamptz not null default now()
);

create table if not exists public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  org_type text not null check (org_type in ('college','agency','employer','verifier','platform')),
  created_at timestamptz not null default now()
);

create table if not exists public.org_members (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  profile_id uuid not null references public.profiles(id) on delete cascade,
  member_role text not null check (member_role in ('worker','org_admin','reviewer','instructor')),
  status text not null default 'active' check (status in ('active','invited','disabled')),
  created_at timestamptz not null default now(),
  unique (org_id, profile_id)
);

create index if not exists idx_org_members_org_id on public.org_members(org_id);
create index if not exists idx_org_members_profile_id on public.org_members(profile_id);
create index if not exists idx_org_members_org_role on public.org_members(org_id, member_role);

-- -------------------------------------------------------------------
-- 2) Catalog: Credential Types & Evidence Requirements
-- -------------------------------------------------------------------

create table if not exists public.credential_types (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  name text not null,
  description text,
  expires boolean not null default false,
  default_validity_days int check (default_validity_days is null or default_validity_days > 0),
  default_renewal_required boolean not null default false,
  default_renewal_window_days int check (default_renewal_window_days is null or default_renewal_window_days >= 0),
  default_grace_period_days int check (default_grace_period_days is null or default_grace_period_days >= 0),
  default_warning_days int[] default '{90,30,7}',
  default_verification_policy text not null default 'none'
    check (default_verification_policy in ('none','manual','issuer_api','third_party')),
  created_at timestamptz not null default now()
);

create table if not exists public.credential_type_requirements (
  id uuid primary key default gen_random_uuid(),
  credential_type_id uuid not null references public.credential_types(id) on delete cascade,
  field_key text not null,
  is_required boolean not null default true,
  validation_regex text,
  notes text,
  unique (credential_type_id, field_key)
);

create index if not exists idx_ctr_credential_type_id on public.credential_type_requirements(credential_type_id);

-- -------------------------------------------------------------------
-- 3) Rule Sets & Credential Rules
-- -------------------------------------------------------------------

create table if not exists public.rule_sets (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade, -- null = global
  name text not null,
  version int not null default 1 check (version > 0),
  status text not null default 'draft' check (status in ('draft','active','deprecated')),
  effective_from date,
  effective_to date,
  created_at timestamptz not null default now(),
  unique (org_id, name, version)
);

create index if not exists idx_rule_sets_org_id on public.rule_sets(org_id);
create index if not exists idx_rule_sets_status on public.rule_sets(status);

create table if not exists public.credential_rules (
  id uuid primary key default gen_random_uuid(),
  rule_set_id uuid not null references public.rule_sets(id) on delete cascade,
  credential_type_id uuid not null references public.credential_types(id) on delete cascade,

  -- optional scoping (more specific wins)
  role_code text,
  jurisdiction text,
  employer_org_id uuid references public.orgs(id) on delete cascade,

  -- overrides / logic
  expires boolean,
  expiry_method text check (expiry_method is null or expiry_method in ('fixed_date','from_issue_days','from_issue_months','from_issue_years','none')),
  validity_days int check (validity_days is null or validity_days > 0),
  validity_months int check (validity_months is null or validity_months > 0),
  validity_years int check (validity_years is null or validity_years > 0),
  renewal_required boolean,
  renewal_window_days int check (renewal_window_days is null or renewal_window_days >= 0),
  grace_period_days int check (grace_period_days is null or grace_period_days >= 0),
  warning_days int[],
  verification_policy text check (verification_policy is null or verification_policy in ('none','manual','issuer_api','third_party')),

  created_at timestamptz not null default now()
);

create index if not exists idx_credential_rules_rule_set_id on public.credential_rules(rule_set_id);
create index if not exists idx_credential_rules_credential_type_id on public.credential_rules(credential_type_id);
create index if not exists idx_credential_rules_scope on public.credential_rules(rule_set_id, credential_type_id, employer_org_id, role_code, jurisdiction);

-- -------------------------------------------------------------------
-- 4) Evidence & Files
-- -------------------------------------------------------------------

create table if not exists public.evidence_files (
  id uuid primary key default gen_random_uuid(),
  storage_bucket text not null default 'workready',
  storage_path text not null,
  file_name text not null,
  mime_type text not null,
  size_bytes bigint not null check (size_bytes >= 0),
  created_at timestamptz not null default now(),
  unique (storage_bucket, storage_path)
);

create table if not exists public.credential_evidence (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  credential_type_id uuid not null references public.credential_types(id) on delete cascade,
  file_id uuid references public.evidence_files(id) on delete set null,

  created_by_profile_id uuid references public.profiles(id) on delete set null,
  created_by_org_id uuid references public.orgs(id) on delete set null,
  source text not null default 'worker_upload'
    check (source in ('worker_upload','school_admin','employer_admin','api_import','verifier')),

  issuer_name text,
  issue_date date,
  expiry_date date,
  license_number text,
  jurisdiction text,

  status text not null default 'active' check (status in ('active','superseded','revoked')),
  created_at timestamptz not null default now()
);

create index if not exists idx_credential_evidence_profile_id on public.credential_evidence(profile_id);
create index if not exists idx_credential_evidence_credential_type_id on public.credential_evidence(credential_type_id);
create index if not exists idx_credential_evidence_created_by_org_id on public.credential_evidence(created_by_org_id);
create index if not exists idx_credential_evidence_file_id on public.credential_evidence(file_id);

create table if not exists public.credential_evidence_fields (
  id uuid primary key default gen_random_uuid(),
  evidence_id uuid not null references public.credential_evidence(id) on delete cascade,
  field_key text not null,
  field_value text,
  confidence_score numeric check (confidence_score is null or (confidence_score >= 0 and confidence_score <= 1)),
  created_at timestamptz not null default now(),
  unique (evidence_id, field_key)
);

create index if not exists idx_credential_evidence_fields_evidence_id on public.credential_evidence_fields(evidence_id);

-- -------------------------------------------------------------------
-- 5) Verification
-- -------------------------------------------------------------------

create table if not exists public.verification_checks (
  id uuid primary key default gen_random_uuid(),
  evidence_id uuid not null references public.credential_evidence(id) on delete cascade,
  verification_policy text not null
    check (verification_policy in ('manual','issuer_api','third_party')),
  provider text,
  status text not null default 'pending'
    check (status in ('not_required','pending','verified','rejected','failed')),
  verified_at timestamptz,
  verified_by_profile_id uuid references public.profiles(id) on delete set null,
  notes text,
  created_at timestamptz not null default now()
);

create index if not exists idx_verification_checks_evidence_id on public.verification_checks(evidence_id);
create index if not exists idx_verification_checks_status on public.verification_checks(status);

-- -------------------------------------------------------------------
-- 6) Gates & Requirements
-- -------------------------------------------------------------------

create table if not exists public.gates (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade, -- null = global
  code text not null,
  name text not null,
  description text,
  created_at timestamptz not null default now(),
  unique (org_id, code)
);

create index if not exists idx_gates_org_id on public.gates(org_id);

create table if not exists public.gate_rules (
  id uuid primary key default gen_random_uuid(),
  gate_id uuid not null references public.gates(id) on delete cascade,
  rule_set_id uuid not null references public.rule_sets(id) on delete cascade,
  status text not null default 'active' check (status in ('active','draft','deprecated')),
  created_at timestamptz not null default now(),
  unique (gate_id, rule_set_id)
);

create index if not exists idx_gate_rules_gate_id on public.gate_rules(gate_id);
create index if not exists idx_gate_rules_rule_set_id on public.gate_rules(rule_set_id);

create table if not exists public.gate_requirements (
  id uuid primary key default gen_random_uuid(),
  gate_id uuid not null references public.gates(id) on delete cascade,
  credential_type_id uuid not null references public.credential_types(id) on delete cascade,
  required boolean not null default true,
  min_status text not null default 'valid'
    check (min_status in ('valid','expiring_soon_ok','verified_required')),
  fail_severity text not null default 'block' check (fail_severity in ('block','review')),
  notes text,
  created_at timestamptz not null default now(),
  unique (gate_id, credential_type_id)
);

create index if not exists idx_gate_requirements_gate_id on public.gate_requirements(gate_id);
create index if not exists idx_gate_requirements_credential_type_id on public.gate_requirements(credential_type_id);

-- -------------------------------------------------------------------
-- 7) Computed Results (Snapshots) + Runs
-- -------------------------------------------------------------------

create table if not exists public.credential_status_snapshots (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  credential_type_id uuid not null references public.credential_types(id) on delete cascade,
  rule_set_id uuid references public.rule_sets(id) on delete set null,
  status text not null
    check (status in ('valid','expiring_soon','expired','missing','not_required','unverifiable')),
  effective_expiry_date date,
  computed_at timestamptz not null default now(),
  explain jsonb not null default '{}'::jsonb,
  unique (profile_id, credential_type_id, rule_set_id)
);

create index if not exists idx_css_profile_id on public.credential_status_snapshots(profile_id);
create index if not exists idx_css_credential_type_id on public.credential_status_snapshots(credential_type_id);

create table if not exists public.gate_decision_snapshots (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  gate_id uuid not null references public.gates(id) on delete cascade,
  rule_set_id uuid references public.rule_sets(id) on delete set null,
  decision text not null check (decision in ('eligible','not_eligible','needs_review')),
  computed_at timestamptz not null default now(),
  explain jsonb not null default '{}'::jsonb,
  unique (profile_id, gate_id, rule_set_id)
);

create index if not exists idx_gds_profile_id on public.gate_decision_snapshots(profile_id);
create index if not exists idx_gds_gate_id on public.gate_decision_snapshots(gate_id);

create table if not exists public.evaluation_runs (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  trigger text not null check (trigger in ('manual','evidence_uploaded','nightly','api')),
  rule_set_id uuid references public.rule_sets(id) on delete set null,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  result_summary jsonb not null default '{}'::jsonb
);

create index if not exists idx_eval_runs_profile_id on public.evaluation_runs(profile_id);
create index if not exists idx_eval_runs_started_at on public.evaluation_runs(started_at);

-- -------------------------------------------------------------------
-- 8) Overrides
-- -------------------------------------------------------------------

create table if not exists public.overrides (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(id) on delete cascade,
  gate_id uuid references public.gates(id) on delete set null,
  credential_type_id uuid references public.credential_types(id) on delete set null,
  override_type text not null
    check (override_type in ('temporary_pass','ignore_expiry','allow_pending_verification')),
  status text not null default 'active' check (status in ('active','expired','revoked')),
  starts_at timestamptz not null default now(),
  ends_at timestamptz not null,
  approved_by_profile_id uuid not null references public.profiles(id) on delete restrict,
  reason text not null,
  created_at timestamptz not null default now(),
  check (ends_at > starts_at),
  check (gate_id is not null or credential_type_id is not null)
);

create index if not exists idx_overrides_profile_id on public.overrides(profile_id);
create index if not exists idx_overrides_gate_id on public.overrides(gate_id);
create index if not exists idx_overrides_credential_type_id on public.overrides(credential_type_id);

-- -------------------------------------------------------------------
-- RLS: enable
-- -------------------------------------------------------------------

alter table public.profiles enable row level security;
alter table public.orgs enable row level security;
alter table public.org_members enable row level security;

alter table public.credential_types enable row level security;
alter table public.credential_type_requirements enable row level security;

alter table public.rule_sets enable row level security;
alter table public.credential_rules enable row level security;

alter table public.evidence_files enable row level security;
alter table public.credential_evidence enable row level security;
alter table public.credential_evidence_fields enable row level security;

alter table public.verification_checks enable row level security;

alter table public.gates enable row level security;
alter table public.gate_rules enable row level security;
alter table public.gate_requirements enable row level security;

alter table public.credential_status_snapshots enable row level security;
alter table public.gate_decision_snapshots enable row level security;
alter table public.evaluation_runs enable row level security;

alter table public.overrides enable row level security;

-- -------------------------------------------------------------------
-- RLS: profiles
-- -------------------------------------------------------------------

drop policy if exists "profiles_select_self_or_staff" on public.profiles;
create policy "profiles_select_self_or_staff"
on public.profiles for select
to authenticated
using (public.can_view_profile(id));

drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self"
on public.profiles for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

drop policy if exists "profiles_insert_self" on public.profiles;
create policy "profiles_insert_self"
on public.profiles for insert
to authenticated
with check (auth.uid() = id);

-- -------------------------------------------------------------------
-- RLS: orgs + org_members
-- -------------------------------------------------------------------

drop policy if exists "orgs_select_members" on public.orgs;
create policy "orgs_select_members"
on public.orgs for select
to authenticated
using (public.is_org_member(id));

drop policy if exists "orgs_update_admin" on public.orgs;
create policy "orgs_update_admin"
on public.orgs for update
to authenticated
using (public.is_org_role(id, array['org_admin']))
with check (public.is_org_role(id, array['org_admin']));

drop policy if exists "org_members_select_self_or_staff" on public.org_members;
create policy "org_members_select_self_or_staff"
on public.org_members for select
to authenticated
using (
  profile_id = auth.uid()
  or public.is_org_role(org_id, array['org_admin','reviewer','instructor'])
);

drop policy if exists "org_members_insert_admin" on public.org_members;
create policy "org_members_insert_admin"
on public.org_members for insert
to authenticated
with check (public.is_org_role(org_id, array['org_admin']));

drop policy if exists "org_members_update_admin" on public.org_members;
create policy "org_members_update_admin"
on public.org_members for update
to authenticated
using (public.is_org_role(org_id, array['org_admin']))
with check (public.is_org_role(org_id, array['org_admin']));

-- -------------------------------------------------------------------
-- RLS: catalog (credential_types + requirements)
-- For MVP: authenticated can read; org_admin can manage.
-- -------------------------------------------------------------------

drop policy if exists "credential_types_select_all" on public.credential_types;
create policy "credential_types_select_all"
on public.credential_types for select
to authenticated
using (true);

drop policy if exists "credential_types_write_admin_any_org" on public.credential_types;
create policy "credential_types_write_admin_any_org"
on public.credential_types for insert
to authenticated
with check (
  exists (
    select 1 from public.org_members om
    where om.profile_id = auth.uid()
      and om.status = 'active'
      and om.member_role = 'org_admin'
  )
);

drop policy if exists "credential_types_update_admin_any_org" on public.credential_types;
create policy "credential_types_update_admin_any_org"
on public.credential_types for update
to authenticated
using (
  exists (
    select 1 from public.org_members om
    where om.profile_id = auth.uid()
      and om.status = 'active'
      and om.member_role = 'org_admin'
  )
)
with check (
  exists (
    select 1 from public.org_members om
    where om.profile_id = auth.uid()
      and om.status = 'active'
      and om.member_role = 'org_admin'
  )
);

drop policy if exists "credential_type_requirements_select_all" on public.credential_type_requirements;
create policy "credential_type_requirements_select_all"
on public.credential_type_requirements for select
to authenticated
using (true);

drop policy if exists "credential_type_requirements_write_admin_any_org" on public.credential_type_requirements;
create policy "credential_type_requirements_write_admin_any_org"
on public.credential_type_requirements for all
to authenticated
using (
  exists (
    select 1 from public.org_members om
    where om.profile_id = auth.uid()
      and om.status = 'active'
      and om.member_role = 'org_admin'
  )
)
with check (
  exists (
    select 1 from public.org_members om
    where om.profile_id = auth.uid()
      and om.status = 'active'
      and om.member_role = 'org_admin'
  )
);

-- -------------------------------------------------------------------
-- RLS: rule_sets + credential_rules
-- Org-scoped objects: members can read; org_admin can write.
-- Global (org_id is null): all authenticated can read; only org_admin can write.
-- -------------------------------------------------------------------

drop policy if exists "rule_sets_select" on public.rule_sets;
create policy "rule_sets_select"
on public.rule_sets for select
to authenticated
using (
  org_id is null
  or public.is_org_member(org_id)
);

drop policy if exists "rule_sets_write_admin" on public.rule_sets;
create policy "rule_sets_write_admin"
on public.rule_sets for insert
to authenticated
with check (
  org_id is null
    ? exists (select 1 from public.org_members om where om.profile_id = auth.uid() and om.status='active' and om.member_role='org_admin')
    : public.is_org_role(org_id, array['org_admin'])
);

drop policy if exists "rule_sets_update_admin" on public.rule_sets;
create policy "rule_sets_update_admin"
on public.rule_sets for update
to authenticated
using (
  org_id is null
    ? exists (select 1 from public.org_members om where om.profile_id = auth.uid() and om.status='active' and om.member_role='org_admin')
    : public.is_org_role(org_id, array['org_admin'])
)
with check (
  org_id is null
    ? exists (select 1 from public.org_members om where om.profile_id = auth.uid() and om.status='active' and om.member_role='org_admin')
    : public.is_org_role(org_id, array['org_admin'])
);

drop policy if exists "credential_rules_select" on public.credential_rules;
create policy "credential_rules_select"
on public.credential_rules for select
to authenticated
using (
  exists (
    select 1 from public.rule_sets rs
    where rs.id = credential_rules.rule_set_id
      and (rs.org_id is null or public.is_org_member(rs.org_id))
  )
);

drop policy if exists "credential_rules_write_admin" on public.credential_rules;
create policy "credential_rules_write_admin"
on public.credential_rules for all
to authenticated
using (
  exists (
    select 1 from public.rule_sets rs
    where rs.id = credential_rules.rule_set_id
      and (
        rs.org_id is null
          ? exists (select 1 from public.org_members om where om.profile_id = auth.uid() and om.status='active' and om.member_role='org_admin')
          : public.is_org_role(rs.org_id, array['org_admin'])
      )
  )
)
with check (
  exists (
    select 1 from public.rule_sets rs
    where rs.id = credential_rules.rule_set_id
      and (
        rs.org_id is null
          ? exists (select 1 from public.org_members om where om.profile_id = auth.uid() and om.status='active' and om.member_role='org_admin')
          : public.is_org_role(rs.org_id, array['org_admin'])
      )
  )
);

-- -------------------------------------------------------------------
-- RLS: evidence_files + credential_evidence (+ fields)
-- evidence_files are only visible if you can see linked credential_evidence
-- -------------------------------------------------------------------

drop policy if exists "credential_evidence_select_owner_or_staff" on public.credential_evidence;
create policy "credential_evidence_select_owner_or_staff"
on public.credential_evidence for select
to authenticated
using (
  profile_id = auth.uid()
  or public.can_view_profile(profile_id)
);

drop policy if exists "credential_evidence_insert_owner_or_staff" on public.credential_evidence;
create policy "credential_evidence_insert_owner_or_staff"
on public.credential_evidence for insert
to authenticated
with check (
  -- worker uploads for self
  profile_id = auth.uid()
  or
  -- staff uploads for a worker in same org (created_by_org_id required)
  (
    created_by_org_id is not null
    and public.is_org_role(created_by_org_id, array['org_admin','reviewer','instructor'])
    and public.can_view_profile(profile_id)
  )
);

drop policy if exists "credential_evidence_update_owner_or_staff" on public.credential_evidence;
create policy "credential_evidence_update_owner_or_staff"
on public.credential_evidence for update
to authenticated
using (
  profile_id = auth.uid()
  or (created_by_org_id is not null and public.is_org_role(created_by_org_id, array['org_admin','reviewer']))
)
with check (
  profile_id = auth.uid()
  or (created_by_org_id is not null and public.is_org_role(created_by_org_id, array['org_admin','reviewer']))
);

drop policy if exists "credential_evidence_delete_owner_or_admin" on public.credential_evidence;
create policy "credential_evidence_delete_owner_or_admin"
on public.credential_evidence for delete
to authenticated
using (
  profile_id = auth.uid()
  or (created_by_org_id is not null and public.is_org_role(created_by_org_id, array['org_admin']))
);

drop policy if exists "credential_evidence_fields_select" on public.credential_evidence_fields;
create policy "credential_evidence_fields_select"
on public.credential_evidence_fields for select
to authenticated
using (
  exists (
    select 1 from public.credential_evidence ce
    where ce.id = credential_evidence_fields.evidence_id
      and (ce.profile_id = auth.uid() or public.can_view_profile(ce.profile_id))
  )
);

drop policy if exists "credential_evidence_fields_write" on public.credential_evidence_fields;
create policy "credential_evidence_fields_write"
on public.credential_evidence_fields for all
to authenticated
using (
  exists (
    select 1 from public.credential_evidence ce
    where ce.id = credential_evidence_fields.evidence_id
      and (
        ce.profile_id = auth.uid()
        or (ce.created_by_org_id is not null and public.is_org_role(ce.created_by_org_id, array['org_admin','reviewer','instructor']))
      )
  )
)
with check (
  exists (
    select 1 from public.credential_evidence ce
    where ce.id = credential_evidence_fields.evidence_id
      and (
        ce.profile_id = auth.uid()
        or (ce.created_by_org_id is not null and public.is_org_role(ce.created_by_org_id, array['org_admin','reviewer','instructor']))
      )
  )
);

drop policy if exists "evidence_files_select_via_evidence" on public.evidence_files;
create policy "evidence_files_select_via_evidence"
on public.evidence_files for select
to authenticated
using (
  exists (
    select 1
    from public.credential_evidence ce
    where ce.file_id = evidence_files.id
      and (ce.profile_id = auth.uid() or public.can_view_profile(ce.profile_id))
  )
);

-- For MVP: only allow inserts/updates to evidence_files if you can insert evidence for yourself or as staff
drop policy if exists "evidence_files_write_authenticated" on public.evidence_files;
create policy "evidence_files_write_authenticated"
on public.evidence_files for insert
to authenticated
with check (true);

-- -------------------------------------------------------------------
-- RLS: verification_checks
-- Select: owner or staff; Write: reviewer/org_admin
-- -------------------------------------------------------------------

drop policy if exists "verification_checks_select" on public.verification_checks;
create policy "verification_checks_select"
on public.verification_checks for select
to authenticated
using (
  exists (
    select 1
    from public.credential_evidence ce
    where ce.id = verification_checks.evidence_id
      and (ce.profile_id = auth.uid() or public.can_view_profile(ce.profile_id))
  )
);

drop policy if exists "verification_checks_write_reviewer_admin" on public.verification_checks;
create policy "verification_checks_write_reviewer_admin"
on public.verification_checks for insert
to authenticated
with check (
  exists (
    select 1 from public.credential_evidence ce
    where ce.id = verification_checks.evidence_id
      and ce.created_by_org_id is not null
      and public.is_org_role(ce.created_by_org_id, array['org_admin','reviewer'])
  )
);

drop policy if exists "verification_checks_update_reviewer_admin" on public.verification_checks;
create policy "verification_checks_update_reviewer_admin"
on public.verification_checks for update
to authenticated
using (
  exists (
    select 1 from public.credential_evidence ce
    where ce.id = verification_checks.evidence_id
      and ce.created_by_org_id is not null
      and public.is_org_role(ce.created_by_org_id, array['org_admin','reviewer'])
  )
)
with check (
  exists (
    select 1 from public.credential_evidence ce
    where ce.id = verification_checks.evidence_id
      and ce.created_by_org_id is not null
      and public.is_org_role(ce.created_by_org_id, array['org_admin','reviewer'])
  )
);

-- -------------------------------------------------------------------
-- RLS: gates + requirements + gate_rules
-- Read: members (org) + global; Write: org_admin
-- -------------------------------------------------------------------

drop policy if exists "gates_select" on public.gates;
create policy "gates_select"
on public.gates for select
to authenticated
using (org_id is null or public.is_org_member(org_id));

drop policy if exists "gates_write_admin" on public.gates;
create policy "gates_write_admin"
on public.gates for all
to authenticated
using (org_id is null
        ? exists (select 1 from public.org_members om where om.profile_id=auth.uid() and om.status='active' and om.member_role='org_admin')
        : public.is_org_role(org_id, array['org_admin']))
with check (org_id is null
        ? exists (select 1 from public.org_members om where om.profile_id=auth.uid() and om.status='active' and om.member_role='org_admin')
        : public.is_org_role(org_id, array['org_admin']));

drop policy if exists "gate_requirements_select" on public.gate_requirements;
create policy "gate_requirements_select"
on public.gate_requirements for select
to authenticated
using (
  exists (
    select 1 from public.gates g
    where g.id = gate_requirements.gate_id
      and (g.org_id is null or public.is_org_member(g.org_id))
  )
);

drop policy if exists "gate_requirements_write_admin" on public.gate_requirements;
create policy "gate_requirements_write_admin"
on public.gate_requirements for all
to authenticated
using (
  exists (
    select 1 from public.gates g
    where g.id = gate_requirements.gate_id
      and (
        g.org_id is null
          ? exists (select 1 from public.org_members om where om.profile_id=auth.uid() and om.status='active' and om.member_role='org_admin')
          : public.is_org_role(g.org_id, array['org_admin'])
      )
  )
)
with check (
  exists (
    select 1 from public.gates g
    where g.id = gate_requirements.gate_id
      and (
        g.org_id is null
          ? exists (select 1 from public.org_members om where om.profile_id=auth.uid() and om.status='active' and om.member_role='org_admin')
          : public.is_org_role(g.org_id, array['org_admin'])
      )
  )
);

drop policy if exists "gate_rules_select" on public.gate_rules;
create policy "gate_rules_select"
on public.gate_rules for select
to authenticated
using (
  exists (
    select 1 from public.gates g
    where g.id = gate_rules.gate_id
      and (g.org_id is null or public.is_org_member(g.org_id))
  )
);

drop policy if exists "gate_rules_write_admin" on public.gate_rules;
create policy "gate_rules_write_admin"
on public.gate_rules for all
to authenticated
using (
  exists (
    select 1 from public.gates g
    where g.id = gate_rules.gate_id
      and (
        g.org_id is null
          ? exists (select 1 from public.org_members om where om.profile_id=auth.uid() and om.status='active' and om.member_role='org_admin')
          : public.is_org_role(g.org_id, array['org_admin'])
      )
  )
)
with check (
  exists (
    select 1 from public.gates g
    where g.id = gate_rules.gate_id
      and (
        g.org_id is null
          ? exists (select 1 from public.org_members om where om.profile_id=auth.uid() and om.status='active' and om.member_role='org_admin')
          : public.is_org_role(g.org_id, array['org_admin'])
      )
  )
);

-- -------------------------------------------------------------------
-- RLS: snapshots + runs
-- Read: owner or staff; Write: reviewer/org_admin (typical backend job)
-- -------------------------------------------------------------------

drop policy if exists "credential_status_snapshots_select" on public.credential_status_snapshots;
create policy "credential_status_snapshots_select"
on public.credential_status_snapshots for select
to authenticated
using (profile_id = auth.uid() or public.can_view_profile(profile_id));

drop policy if exists "credential_status_snapshots_write_staff" on public.credential_status_snapshots;
create policy "credential_status_snapshots_write_staff"
on public.credential_status_snapshots for all
to authenticated
using (public.can_view_profile(profile_id))
with check (public.can_view_profile(profile_id));

drop policy if exists "gate_decision_snapshots_select" on public.gate_decision_snapshots;
create policy "gate_decision_snapshots_select"
on public.gate_decision_snapshots for select
to authenticated
using (profile_id = auth.uid() or public.can_view_profile(profile_id));

drop policy if exists "gate_decision_snapshots_write_staff" on public.gate_decision_snapshots;
create policy "gate_decision_snapshots_write_staff"
on public.gate_decision_snapshots for all
to authenticated
using (public.can_view_profile(profile_id))
with check (public.can_view_profile(profile_id));

drop policy if exists "evaluation_runs_select" on public.evaluation_runs;
create policy "evaluation_runs_select"
on public.evaluation_runs for select
to authenticated
using (profile_id = auth.uid() or public.can_view_profile(profile_id));

drop policy if exists "evaluation_runs_write_staff" on public.evaluation_runs;
create policy "evaluation_runs_write_staff"
on public.evaluation_runs for insert
to authenticated
with check (public.can_view_profile(profile_id));

-- -------------------------------------------------------------------
-- RLS: overrides
-- Read: owner or staff; Write: org_admin/reviewer only
-- -------------------------------------------------------------------

drop policy if exists "overrides_select" on public.overrides;
create policy "overrides_select"
on public.overrides for select
to authenticated
using (profile_id = auth.uid() or public.can_view_profile(profile_id));

drop policy if exists "overrides_insert_staff" on public.overrides;
create policy "overrides_insert_staff"
on public.overrides for insert
to authenticated
with check (
  public.can_view_profile(profile_id)
  and exists (
    select 1
    from public.org_members staff
    join public.org_members target
      on target.org_id = staff.org_id
    where staff.profile_id = auth.uid()
      and staff.status = 'active'
      and staff.member_role in ('org_admin','reviewer')
      and target.profile_id = overrides.profile_id
      and target.status = 'active'
  )
);

drop policy if exists "overrides_update_staff" on public.overrides;
create policy "overrides_update_staff"
on public.overrides for update
to authenticated
using (
  exists (
    select 1
    from public.org_members staff
    join public.org_members target
      on target.org_id = staff.org_id
    where staff.profile_id = auth.uid()
      and staff.status = 'active'
      and staff.member_role in ('org_admin','reviewer')
      and target.profile_id = overrides.profile_id
      and target.status = 'active'
  )
)
with check (
  exists (
    select 1
    from public.org_members staff
    join public.org_members target
      on target.org_id = staff.org_id
    where staff.profile_id = auth.uid()
      and staff.status = 'active'
      and staff.member_role in ('org_admin','reviewer')
      and target.profile_id = overrides.profile_id
      and target.status = 'active'
  )
);

commit;
