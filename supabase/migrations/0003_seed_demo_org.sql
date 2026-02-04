-- /supabase/migrations/0003_seed_demo_org.sql
-- Demo org + basic memberships.
--
-- IMPORTANT:
-- - You must replace the placeholder UUIDs with REAL auth.users IDs from your Supabase Auth table.
-- - This seed is safe to re-run (UPSERT patterns).
--
-- What it creates:
-- - Demo College org (if not already created)
-- - Demo Agency org (optional, useful for staffing workflow)
-- - Org members for each (org_admin / reviewer / instructor / worker)

begin;

-- ------------------------------------------------------------
-- 1) Orgs
-- ------------------------------------------------------------

-- Demo College
insert into public.orgs (id, name, org_type)
values ('00000000-0000-0000-0000-000000000001', 'WorkReady Demo College', 'college')
on conflict (id) do update set
  name = excluded.name,
  org_type = excluded.org_type;

-- Demo Agency (useful for StaffLinkr later)
insert into public.orgs (id, name, org_type)
values ('00000000-0000-0000-0000-000000000002', 'WorkReady Demo Agency', 'agency')
on conflict (id) do update set
  name = excluded.name,
  org_type = excluded.org_type;

-- ------------------------------------------------------------
-- 2) Demo Users (PROFILES) - replace these IDs with real auth.users UUIDs
-- ------------------------------------------------------------
-- How to get real UUIDs:
-- Supabase Dashboard -> Authentication -> Users -> copy the user ID (uuid)

-- >>> REPLACE THESE <<<
-- College staff
--   DEMO_COLLEGE_ADMIN_ID: org_admin
--   DEMO_COLLEGE_REVIEWER_ID: reviewer
--   DEMO_COLLEGE_INSTRUCTOR_ID: instructor
-- Worker / student
--   DEMO_WORKER_ID: worker
--
-- Agency staff
--   DEMO_AGENCY_ADMIN_ID: org_admin (optional)
--   DEMO_AGENCY_REVIEWER_ID: reviewer (optional)

-- Put your real UUIDs here:
-- Example:
-- set local demo.college_admin_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

do $$
declare
  demo_college_admin_id uuid := '11111111-1111-1111-1111-111111111111';
  demo_college_reviewer_id uuid := '22222222-2222-2222-2222-222222222222';
  demo_college_instructor_id uuid := '33333333-3333-3333-3333-333333333333';
  demo_worker_id uuid := '44444444-4444-4444-4444-444444444444';

  demo_agency_admin_id uuid := '55555555-5555-5555-5555-555555555555';
  demo_agency_reviewer_id uuid := '66666666-6666-6666-6666-666666666666';
begin
  -- ----------------------------------------------------------
  -- 2A) Ensure profile rows exist for each demo user
  -- ----------------------------------------------------------

  insert into public.profiles (id, full_name, email)
  values (demo_college_admin_id, 'Demo College Admin', 'demo.college.admin@example.com')
  on conflict (id) do update set
    full_name = excluded.full_name,
    email = excluded.email;

  insert into public.profiles (id, full_name, email)
  values (demo_college_reviewer_id, 'Demo College Reviewer', 'demo.college.reviewer@example.com')
  on conflict (id) do update set
    full_name = excluded.full_name,
    email = excluded.email;

  insert into public.profiles (id, full_name, email)
  values (demo_college_instructor_id, 'Demo College Instructor', 'demo.college.instructor@example.com')
  on conflict (id) do update set
    full_name = excluded.full_name,
    email = excluded.email;

  insert into public.profiles (id, full_name, email)
  values (demo_worker_id, 'Demo Worker / Student', 'demo.worker@example.com')
  on conflict (id) do update set
    full_name = excluded.full_name,
    email = excluded.email;

  -- Agency (optional but useful)
  insert into public.profiles (id, full_name, email)
  values (demo_agency_admin_id, 'Demo Agency Admin', 'demo.agency.admin@example.com')
  on conflict (id) do update set
    full_name = excluded.full_name,
    email = excluded.email;

  insert into public.profiles (id, full_name, email)
  values (demo_agency_reviewer_id, 'Demo Agency Reviewer', 'demo.agency.reviewer@example.com')
  on conflict (id) do update set
    full_name = excluded.full_name,
    email = excluded.email;

  -- ----------------------------------------------------------
  -- 2B) Memberships: College
  -- ----------------------------------------------------------

  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000001', demo_college_admin_id, 'org_admin', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000001', demo_college_reviewer_id, 'reviewer', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000001', demo_college_instructor_id, 'instructor', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

  -- Demo worker is also a member of the college (as a worker/student)
  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000001', demo_worker_id, 'worker', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

  -- ----------------------------------------------------------
  -- 2C) Memberships: Agency (optional)
  -- ----------------------------------------------------------

  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000002', demo_agency_admin_id, 'org_admin', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000002', demo_agency_reviewer_id, 'reviewer', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

  -- Demo worker is also a member of the agency (so agency can view work-ready status)
  insert into public.org_members (org_id, profile_id, member_role, status)
  values ('00000000-0000-0000-0000-000000000002', demo_worker_id, 'worker', 'active')
  on conflict (org_id, profile_id) do update set
    member_role = excluded.member_role,
    status = excluded.status;

end $$;

commit;
