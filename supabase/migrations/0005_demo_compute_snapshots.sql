-- /supabase/migrations/0005_demo_compute_snapshots.sql
-- Demo "compute engine in SQL" to populate:
--   - credential_status_snapshots
--   - gate_decision_snapshots
--
-- This is intentionally MVP/simple logic so your seeded demo "works immediately"
-- after 0001..0004 without writing backend code yet.
--
-- Assumptions:
-- - Uses the ACTIVE Global Default rule set (org_id NULL, name 'Global Default', version 1)
-- - Uses ACTIVE gate_rules mappings
-- - Uses the most recent ACTIVE evidence per (profile_id, credential_type_id)
-- - Treats "manual/issuer_api/third_party" verification as REQUIRED and VERIFIED-only
--   (if not verified => UNVERIFIABLE)
--
-- You can re-run safely: UPSERT updates snapshots.

begin;

-- ------------------------------------------------------------
-- 0) Find the active global default rule_set_id
-- ------------------------------------------------------------
with rs as (
  select id as rule_set_id
  from public.rule_sets
  where org_id is null
    and name = 'Global Default'
    and version = 1
    and status = 'active'
  limit 1
),

-- ------------------------------------------------------------
-- 1) Latest ACTIVE evidence per person + credential_type
-- ------------------------------------------------------------
latest_evidence as (
  select distinct on (ce.profile_id, ce.credential_type_id)
    ce.id as evidence_id,
    ce.profile_id,
    ce.credential_type_id,
    ce.issuer_name,
    ce.issue_date,
    ce.expiry_date,
    ce.license_number,
    ce.jurisdiction,
    ce.created_at
  from public.credential_evidence ce
  where ce.status = 'active'
  order by ce.profile_id, ce.credential_type_id, ce.created_at desc
),

-- ------------------------------------------------------------
-- 2) Effective rule selection (demo: only global rule_set rules, no scoped overrides)
-- ------------------------------------------------------------
selected_rules as (
  select
    cr.rule_set_id,
    cr.credential_type_id,
    coalesce(cr.expires, ct.expires) as expires,
    coalesce(cr.expiry_method, case when ct.expires then 'from_issue_days' else 'none' end) as expiry_method,
    cr.validity_days,
    cr.validity_months,
    cr.validity_years,
    coalesce(cr.renewal_required, ct.default_renewal_required) as renewal_required,
    coalesce(cr.renewal_window_days, ct.default_renewal_window_days) as renewal_window_days,
    coalesce(cr.grace_period_days, ct.default_grace_period_days) as grace_period_days,
    coalesce(cr.warning_days, ct.default_warning_days) as warning_days,
    coalesce(cr.verification_policy, ct.default_verification_policy) as verification_policy
  from rs
  join public.credential_rules cr
    on cr.rule_set_id = rs.rule_set_id
  join public.credential_types ct
    on ct.id = cr.credential_type_id
),

-- ------------------------------------------------------------
-- 3) Required field checks (issuer_name / issue_date / expiry_date / etc.)
--    For MVP demo, we only validate required fields that are in the base columns
--    (issuer_name, issue_date, expiry_date, license_number, jurisdiction)
-- ------------------------------------------------------------
required_fields as (
  select
    ctr.credential_type_id,
    array_agg(ctr.field_key) filter (where ctr.is_required) as required_keys
  from public.credential_type_requirements ctr
  group by ctr.credential_type_id
),

field_validation as (
  select
    le.profile_id,
    le.credential_type_id,
    le.evidence_id,
    rf.required_keys,

    -- Compute "missing required fields" count for base columns.
    (
      coalesce(
        (case when rf.required_keys @> array['issuer_name'] and (le.issuer_name is null or btrim(le.issuer_name) = '') then 1 else 0 end), 0
      ) +
      coalesce(
        (case when rf.required_keys @> array['issue_date'] and le.issue_date is null then 1 else 0 end), 0
      ) +
      coalesce(
        (case when rf.required_keys @> array['expiry_date'] and le.expiry_date is null then 1 else 0 end), 0
      ) +
      coalesce(
        (case when rf.required_keys @> array['license_number'] and (le.license_number is null or btrim(le.license_number) = '') then 1 else 0 end), 0
      ) +
      coalesce(
        (case when rf.required_keys @> array['jurisdiction'] and (le.jurisdiction is null or btrim(le.jurisdiction) = '') then 1 else 0 end), 0
      )
    ) as missing_required_count
  from latest_evidence le
  left join required_fields rf
    on rf.credential_type_id = le.credential_type_id
),

-- ------------------------------------------------------------
-- 4) Verification check (if policy != 'none' then must be verified)
-- ------------------------------------------------------------
verification_state as (
  select
    le.evidence_id,
    -- if any verification_checks row is verified => verified
    bool_or(vc.status = 'verified') as is_verified
  from latest_evidence le
  left join public.verification_checks vc
    on vc.evidence_id = le.evidence_id
  group by le.evidence_id
),

-- ------------------------------------------------------------
-- 5) Compute effective expiry date
-- ------------------------------------------------------------
computed_expiry as (
  select
    le.profile_id,
    le.credential_type_id,
    le.evidence_id,
    sr.rule_set_id,
    sr.expires,
    sr.expiry_method,
    sr.validity_days,
    sr.grace_period_days,
    sr.warning_days,
    sr.verification_policy,
    le.issue_date,
    le.expiry_date as evidence_expiry_date,

    -- Effective expiry date:
    case
      when sr.expires is false or sr.expiry_method = 'none' then null
      when le.expiry_date is not null then le.expiry_date
      when le.issue_date is not null and sr.expiry_method = 'from_issue_days' and sr.validity_days is not null
        then (le.issue_date + (sr.validity_days || ' days')::interval)::date
      else null
    end as effective_expiry_date
  from latest_evidence le
  join rs on true
  join selected_rules sr
    on sr.credential_type_id = le.credential_type_id
),

-- ------------------------------------------------------------
-- 6) Determine credential status
-- ------------------------------------------------------------
credential_status as (
  select
    p.id as profile_id,
    ct.id as credential_type_id,
    rs.rule_set_id,

    -- evidence (may be null => missing)
    ce.evidence_id,
    ce.effective_expiry_date,

    -- derived flags
    case when le.evidence_id is null then true else false end as is_missing,
    case when fv.missing_required_count is not null and fv.missing_required_count > 0 then true else false end as missing_fields,
    case
      when le.evidence_id is null then false
      when ce.verification_policy = 'none' then false
      else coalesce(vs.is_verified, false) is false
    end as fails_verification,
    ce.expires,
    ce.grace_period_days,
    ce.warning_days

  from public.profiles p
  cross join rs
  cross join public.credential_types ct
  -- only compute for credential types that are part of the selected_rules set (keeps it small)
  join selected_rules sr2 on sr2.credential_type_id = ct.id

  left join latest_evidence le
    on le.profile_id = p.id and le.credential_type_id = ct.id
  left join computed_expiry ce
    on ce.profile_id = p.id and ce.credential_type_id = ct.id and ce.evidence_id = le.evidence_id
  left join field_validation fv
    on fv.profile_id = p.id and fv.credential_type_id = ct.id and fv.evidence_id = le.evidence_id
  left join verification_state vs
    on vs.evidence_id = le.evidence_id
),

credential_status_final as (
  select
    cs.profile_id,
    cs.credential_type_id,
    cs.rule_set_id,
    cs.effective_expiry_date,
    now() as computed_at,

    case
      when cs.is_missing then 'missing'
      when cs.missing_fields or cs.fails_verification then 'unverifiable'
      when cs.expires is false then 'valid'
      when cs.effective_expiry_date is null then 'unverifiable'
      else
        case
          when current_date > (cs.effective_expiry_date + (cs.grace_period_days || ' days')::interval)::date
            then 'expired'
          when cs.warning_days is not null
               and array_length(cs.warning_days, 1) is not null
               and current_date >= (cs.effective_expiry_date - (select max(x) from unnest(cs.warning_days) x) * interval '1 day')::date
            then 'expiring_soon'
          else 'valid'
        end
    end as status,

    jsonb_build_object(
      'evidence_id', cs.evidence_id,
      'effective_expiry_date', cs.effective_expiry_date,
      'missing_fields', cs.missing_fields,
      'fails_verification', cs.fails_verification,
      'note', 'Demo SQL compute v0.1'
    ) as explain

  from (
    select
      cs.*,
      le.evidence_id
    from credential_status cs
    left join latest_evidence le
      on le.profile_id = cs.profile_id and le.credential_type_id = cs.credential_type_id
  ) cs
),

-- ------------------------------------------------------------
-- 7) UPSERT credential_status_snapshots
-- ------------------------------------------------------------
upsert_css as (
  insert into public.credential_status_snapshots (
    profile_id, credential_type_id, rule_set_id, status, effective_expiry_date, computed_at, explain
  )
  select
    profile_id, credential_type_id, rule_set_id, status, effective_expiry_date, computed_at, explain
  from credential_status_final
  on conflict (profile_id, credential_type_id, rule_set_id)
  do update set
    status = excluded.status,
    effective_expiry_date = excluded.effective_expiry_date,
    computed_at = excluded.computed_at,
    explain = excluded.explain
  returning 1
),

-- ------------------------------------------------------------
-- 8) Gate decisions
-- ------------------------------------------------------------
active_gate_rule_set as (
  select
    g.id as gate_id,
    g.code as gate_code,
    gr.rule_set_id
  from public.gates g
  join public.gate_rules gr
    on gr.gate_id = g.id
   and gr.status = 'active'
  join rs
    on rs.rule_set_id = gr.rule_set_id
),

reqs as (
  select
    agrs.gate_id,
    agrs.gate_code,
    agrs.rule_set_id,
    r.credential_type_id,
    r.required,
    r.min_status,
    r.fail_severity
  from active_gate_rule_set agrs
  join public.gate_requirements r
    on r.gate_id = agrs.gate_id
),

active_overrides as (
  select
    o.profile_id,
    o.gate_id,
    o.credential_type_id
  from public.overrides o
  where o.status = 'active'
    and now() between o.starts_at and o.ends_at
),

gate_eval as (
  select
    p.id as profile_id,
    reqs.gate_id,
    reqs.rule_set_id,

    -- Evaluate each requirement as pass/fail/review using credential_status_snapshots
    -- Override => pass
    reqs.credential_type_id,
    reqs.required,
    reqs.min_status,
    reqs.fail_severity,

    css.status as credential_status,

    case
      when exists (
        select 1
        from active_overrides ao
        where ao.profile_id = p.id
          and (ao.gate_id = reqs.gate_id or ao.credential_type_id = reqs.credential_type_id)
      ) then true

      when reqs.required is false then true

      when reqs.min_status = 'valid' then (css.status = 'valid')
      when reqs.min_status = 'expiring_soon_ok' then (css.status in ('valid','expiring_soon'))
      when reqs.min_status = 'verified_required' then (css.status in ('valid','expiring_soon')) -- verification enforced via status logic
      else false
    end as passes

  from public.profiles p
  join reqs on true
  left join public.credential_status_snapshots css
    on css.profile_id = p.id
   and css.credential_type_id = reqs.credential_type_id
   and css.rule_set_id = reqs.rule_set_id
),

gate_rollup as (
  select
    ge.profile_id,
    ge.gate_id,
    ge.rule_set_id,

    -- If any blocking requirement fails => not_eligible
    bool_or((ge.passes = false) and ge.fail_severity = 'block') as any_block_fail,

    -- If any review requirement fails (and no block fail) => needs_review
    bool_or((ge.passes = false) and ge.fail_severity = 'review') as any_review_fail,

    jsonb_agg(
      jsonb_build_object(
        'credential_type_id', ge.credential_type_id,
        'required', ge.required,
        'min_status', ge.min_status,
        'fail_severity', ge.fail_severity,
        'credential_status', ge.credential_status,
        'passes', ge.passes
      )
      order by ge.fail_severity desc
    ) as req_details

  from gate_eval ge
  group by ge.profile_id, ge.gate_id, ge.rule_set_id
),

gate_decisions as (
  select
    gr.profile_id,
    gr.gate_id,
    gr.rule_set_id,
    now() as computed_at,

    case
      when gr.any_block_fail then 'not_eligible'
      when gr.any_review_fail then 'needs_review'
      else 'eligible'
    end as decision,

    jsonb_build_object(
      'note', 'Demo SQL compute v0.1',
      'requirements', gr.req_details
    ) as explain

  from gate_rollup gr
),

-- ------------------------------------------------------------
-- 9) UPSERT gate_decision_snapshots
-- ------------------------------------------------------------
upsert_gds as (
  insert into public.gate_decision_snapshots (
    profile_id, gate_id, rule_set_id, decision, computed_at, explain
  )
  select
    profile_id, gate_id, rule_set_id, decision, computed_at, explain
  from gate_decisions
  on conflict (profile_id, gate_id, rule_set_id)
  do update set
    decision = excluded.decision,
    computed_at = excluded.computed_at,
    explain = excluded.explain
  returning 1
)

select 'ok' as result;

commit;
