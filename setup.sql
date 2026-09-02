-- ==================== 01_schema.sql ====================
-- =====================================================================
--  TELECALLING APP — DATABASE SCHEMA
--  Target: Supabase (PostgreSQL) free tier
--  Run this in: Supabase Dashboard → SQL Editor → New query → Run
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. ENUMS
-- ---------------------------------------------------------------------

create type user_role as enum ('agent', 'supervisor');

-- The five call outcomes from the spec.
create type call_status as enum (
  'SWITCHED_OFF',
  'WRONG_NUMBER',
  'NOT_INTERESTED',
  'CALL_LATER',
  'LEAD'
);

-- Sub-qualification, only meaningful when call_status = 'LEAD'.
create type lead_quality as enum ('HOT', 'WARM', 'COLD');


-- ---------------------------------------------------------------------
-- 2. PROFILES  (extends Supabase's built-in auth.users)
-- ---------------------------------------------------------------------

create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text,
  employee_id text,
  role        user_role   not null default 'agent',
  active      boolean     not null default true,
  created_at  timestamptz not null default now()
);

-- Auto-create a profile row whenever a new auth user is created.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    coalesce((new.raw_user_meta_data->>'role')::user_role, 'agent')
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ---------------------------------------------------------------------
-- 3. LEADS  (the data the caller sees)
-- ---------------------------------------------------------------------

create table public.leads (
  id                  bigserial primary key,

  -- ---- Fields visible to the caller (per spec) ----
  name                text        not null,
  pan                 text,
  mobile              text        not null,
  email               text,
  dob                 date,
  annual_income_range text,
  company             text,               -- renamed from "PP Code Company Name"
  ici_cr_lmt          numeric(14,2),      -- ICICI credit limit

  -- ---- Workflow / assignment ----
  assigned_to   uuid references public.profiles(id) on delete set null,
  locked_by     uuid references public.profiles(id) on delete set null,
  locked_at     timestamptz,

  -- ---- Denormalised latest outcome (keeps the queue query cheap) ----
  last_status    call_status,
  last_remarks   text,
  last_called_at timestamptz,
  attempts       int         not null default 0,
  callback_at    timestamptz,             -- set when status = CALL_LATER
  is_closed      boolean     not null default false,

  -- ---- Provenance ----
  batch      text,                        -- e.g. 'ICICI_PREAPPROVED_SEP2026'
  created_at timestamptz not null default now()
);

-- Queue lookups: "give me this agent's open leads, callbacks first".
create index leads_queue_idx
  on public.leads (is_closed, assigned_to, callback_at);

-- Dedupe / search by phone.
create index leads_mobile_idx on public.leads (mobile);

-- Prevent the same number being loaded twice within one batch.
create unique index leads_batch_mobile_uniq
  on public.leads (batch, mobile)
  where batch is not null;


-- ---------------------------------------------------------------------
-- 4. CALL DISPOSITIONS  (the caller's output — one row per attempt)
-- ---------------------------------------------------------------------
-- This is an append-only history. leads.last_status is only a cache of
-- the most recent row here. Never update a disposition; insert a new one.

create table public.call_dispositions (
  id           bigserial primary key,
  lead_id      bigint      not null references public.leads(id) on delete cascade,
  agent_id     uuid        not null references public.profiles(id),

  status       call_status not null,
  lead_quality lead_quality,             -- required iff status = 'LEAD'
  remarks      text,                     -- free-text, always available
  callback_at  timestamptz,              -- required iff status = 'CALL_LATER'

  sim_slot     int,                      -- which SIM placed the call (1 or 2)
  called_at    timestamptz not null default now(),
  created_at   timestamptz not null default now(),

  -- Enforce the conditional fields at the database level rather than
  -- trusting the client to do it.
  constraint lead_quality_only_for_leads check (
    (status = 'LEAD' and lead_quality is not null)
    or (status <> 'LEAD' and lead_quality is null)
  ),
  constraint callback_required_for_call_later check (
    (status = 'CALL_LATER' and callback_at is not null)
    or (status <> 'CALL_LATER')
  ),
  constraint remarks_length check (char_length(remarks) <= 2000)
);

create index dispositions_agent_idx on public.call_dispositions (agent_id, called_at desc);
create index dispositions_lead_idx  on public.call_dispositions (lead_id, called_at desc);
create index dispositions_status_idx on public.call_dispositions (status, called_at desc);


-- ---------------------------------------------------------------------
-- 5. ACCESS LOG
-- ---------------------------------------------------------------------
-- You chose to show PAN / DOB / income / credit limit unmasked. That
-- removes the technical control, so this is the compensating one: every
-- time an agent opens a lead record, it is recorded. If data ever leaks
-- you can answer "who saw this record and when".

create table public.lead_access_log (
  id        bigserial   primary key,
  lead_id   bigint      not null references public.leads(id) on delete cascade,
  agent_id  uuid        not null references public.profiles(id),
  viewed_at timestamptz not null default now()
);

create index lead_access_log_idx on public.lead_access_log (agent_id, viewed_at desc);


-- ---------------------------------------------------------------------
-- 6. HELPER: is the current user a supervisor?
-- ---------------------------------------------------------------------

create or replace function public.is_supervisor()
returns boolean
language sql
stable
security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'supervisor' and active
  );
$$;


-- ---------------------------------------------------------------------
-- 7. ROW LEVEL SECURITY
-- ---------------------------------------------------------------------

alter table public.profiles          enable row level security;
alter table public.leads             enable row level security;
alter table public.call_dispositions enable row level security;
alter table public.lead_access_log   enable row level security;

-- --- profiles ---
create policy "read own profile"
  on public.profiles for select
  using (id = auth.uid() or public.is_supervisor());

create policy "update own name"
  on public.profiles for update
  using (id = auth.uid())
  with check (id = auth.uid());

-- --- leads ---
-- An agent may ONLY read leads currently assigned to them. They cannot
-- browse or export the wider database.
create policy "agents read assigned leads"
  on public.leads for select
  using (assigned_to = auth.uid() or public.is_supervisor());

-- Agents never write to leads directly; the RPCs below (security definer)
-- do it for them. Supervisors can manage the pool.
create policy "supervisors manage leads"
  on public.leads for all
  using (public.is_supervisor())
  with check (public.is_supervisor());

-- --- call_dispositions ---
create policy "agents insert own dispositions"
  on public.call_dispositions for insert
  with check (agent_id = auth.uid());

create policy "read own dispositions"
  on public.call_dispositions for select
  using (agent_id = auth.uid() or public.is_supervisor());

-- --- lead_access_log ---
create policy "agents insert own access log"
  on public.lead_access_log for insert
  with check (agent_id = auth.uid());

create policy "supervisors read access log"
  on public.lead_access_log for select
  using (public.is_supervisor());


-- ---------------------------------------------------------------------
-- 8. RPC: claim the next lead  (atomic — no two agents get the same one)
-- ---------------------------------------------------------------------
-- FOR UPDATE SKIP LOCKED is the important bit. Without it, two agents
-- hitting "next lead" at the same instant both read the same row and both
-- call the same customer. SKIP LOCKED makes concurrent callers step over
-- each other's rows instead of blocking or colliding.

-- Returns SETOF so an empty queue is an empty JSON array rather than a row
-- of nulls — unambiguous for the client to interpret.

create or replace function public.claim_next_lead()
returns setof public.leads
language plpgsql
security definer set search_path = public
as $$
declare
  stale_after constant interval := '30 minutes';
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and active) then
    raise exception 'inactive or unknown user';
  end if;

  return query
  with picked as (
    select c.id
      from public.leads c
     where c.is_closed = false
       -- unassigned, already mine, or abandoned by someone else
       and (c.assigned_to is null
            or c.assigned_to = auth.uid()
            or c.locked_at < now() - stale_after)
       -- skip callbacks that are not due yet
       and (c.callback_at is null or c.callback_at <= now())
     order by
       -- due callbacks first, then oldest untouched leads
       (c.callback_at is not null) desc,
       c.callback_at asc nulls last,
       c.id asc
     limit 1
     for update skip locked
  ),
  claimed as (
    update public.leads l
       set assigned_to = auth.uid(),
           locked_by   = auth.uid(),
           locked_at   = now()
      from picked p
     where l.id = p.id
    returning l.*
  )
  select * from claimed;
end;
$$;


-- ---------------------------------------------------------------------
-- 9. RPC: save a disposition  (insert history + update lead, atomically)
-- ---------------------------------------------------------------------

create or replace function public.save_disposition(
  p_lead_id      bigint,
  p_status       call_status,
  p_lead_quality lead_quality default null,
  p_remarks      text         default null,
  p_callback_at  timestamptz  default null,
  p_sim_slot     int          default null
)
returns bigint                 -- id of the disposition row that was written
language plpgsql
security definer set search_path = public
as $$
declare
  new_id bigint;
begin
  -- The agent must actually hold this lead. Without this check any agent
  -- could post outcomes against any lead id they guessed.
  if not exists (
    select 1 from public.leads
     where id = p_lead_id
       and (assigned_to = auth.uid() or public.is_supervisor())
  ) then
    raise exception 'lead % is not assigned to you', p_lead_id;
  end if;

  insert into public.call_dispositions
    (lead_id, agent_id, status, lead_quality, remarks, callback_at, sim_slot)
  values
    (p_lead_id, auth.uid(), p_status, p_lead_quality,
     nullif(btrim(p_remarks), ''), p_callback_at, p_sim_slot)
  returning id into new_id;

  update public.leads
     set last_status    = p_status,
         last_remarks   = nullif(btrim(p_remarks), ''),
         last_called_at = now(),
         attempts       = attempts + 1,
         callback_at    = case when p_status = 'CALL_LATER' then p_callback_at else null end,
         -- Wrong number / not interested / converted lead are terminal.
         -- Switched off stays open for a retry.
         is_closed      = p_status in ('WRONG_NUMBER', 'NOT_INTERESTED', 'LEAD'),
         locked_by      = null,
         locked_at      = null,
         -- release the record unless we owe them a callback
         assigned_to    = case when p_status = 'CALL_LATER' then assigned_to else null end
   where id = p_lead_id;

  return new_id;
end;
$$;


-- ---------------------------------------------------------------------
-- 10. RPC: log that an agent viewed a lead's sensitive fields
-- ---------------------------------------------------------------------

create or replace function public.log_lead_view(p_lead_id bigint)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.lead_access_log (lead_id, agent_id)
  values (p_lead_id, auth.uid());
end;
$$;


-- ---------------------------------------------------------------------
-- 11. SUPERVISOR REPORTING VIEWS
-- ---------------------------------------------------------------------

create or replace view public.v_agent_performance
with (security_invoker = true) as
select
  p.id                        as agent_id,
  p.full_name,
  count(d.id)                                                as total_calls,
  count(*) filter (where d.status = 'LEAD')                  as leads,
  count(*) filter (where d.status = 'NOT_INTERESTED')        as not_interested,
  count(*) filter (where d.status = 'CALL_LATER')            as call_later,
  count(*) filter (where d.status = 'SWITCHED_OFF')          as switched_off,
  count(*) filter (where d.status = 'WRONG_NUMBER')          as wrong_number,
  round(
    100.0 * count(*) filter (where d.status = 'LEAD')
    / nullif(count(d.id), 0), 1
  )                                                          as conversion_pct,
  max(d.called_at)                                           as last_activity
from public.profiles p
left join public.call_dispositions d on d.agent_id = p.id
where p.role = 'agent'
group by p.id, p.full_name;


create or replace view public.v_daily_summary
with (security_invoker = true) as
select
  date_trunc('day', called_at)::date as day,
  status,
  count(*) as calls
from public.call_dispositions
group by 1, 2
order by 1 desc, 2;


-- ==================== 03_login_id_and_address.sql ====================
-- =====================================================================
--  MIGRATION 03 — login IDs instead of email, plus lead address
--  Run this in: Supabase Dashboard → SQL Editor → New query → Run
--  Safe to re-run.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. ADDRESS on leads
-- ---------------------------------------------------------------------
-- A tenth field visible to the caller. Capped at 2000 characters and
-- enforced here, not only in the UI — same rule as `remarks`.

alter table public.leads add column if not exists address text;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'leads_address_length'
  ) then
    alter table public.leads
      add constraint leads_address_length check (char_length(address) <= 2000);
  end if;
end$$;


-- ---------------------------------------------------------------------
-- 2. LOGIN ID on profiles
-- ---------------------------------------------------------------------
-- Agents never see or type an email address. The supervisor issues them a
-- login ID; the app turns "<login_id>" into "<login_id>@<LOGIN_DOMAIN>"
-- before it talks to GoTrue. That keeps Supabase Auth — and therefore
-- auth.uid(), every RLS policy, session refresh and password hashing —
-- exactly as it was. The synthetic address is an internal detail; it is
-- never shown to an agent and never receives mail.
--
-- login_id is stored here so a supervisor can see "rahul.k" in the
-- dashboard rather than "rahul.k@telecall.local".

alter table public.profiles add column if not exists login_id text;

-- Case-insensitive uniqueness: "Rahul.K" and "rahul.k" must not coexist.
create unique index if not exists profiles_login_id_uniq
  on public.profiles (lower(login_id));


-- ---------------------------------------------------------------------
-- 3. Populate login_id on signup
-- ---------------------------------------------------------------------
-- Replaces the version in 01_schema.sql. Same behaviour as before, plus
-- login_id taken from the local-part of the address the supervisor typed.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role, login_id)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    coalesce((new.raw_user_meta_data->>'role')::user_role, 'agent'),
    lower(split_part(new.email, '@', 1))
  );
  return new;
end;
$$;


-- ---------------------------------------------------------------------
-- 4. Backfill anyone who signed up before this migration
-- ---------------------------------------------------------------------

update public.profiles p
   set login_id = lower(split_part(u.email, '@', 1))
  from auth.users u
 where u.id = p.id
   and p.login_id is null;


-- ==================== 04_upsertable_batch_index.sql ====================
-- =====================================================================
--  MIGRATION 04 — make the (batch, mobile) index usable by ON CONFLICT
--  Run this in: Supabase Dashboard → SQL Editor → New query → Run
--  Safe to re-run.
-- =====================================================================
--
-- The dashboard's CSV import upserts with
--   .upsert(chunk, { onConflict: "batch,mobile", ignoreDuplicates: true })
-- so that a part-finished import can simply be re-uploaded: chunks are not
-- one transaction, and with a plain INSERT the already-committed rows
-- collide on retry and the whole import fails.
--
-- That needs Postgres to *infer* the index from `on conflict (batch, mobile)`.
-- It cannot infer a PARTIAL index unless the statement repeats the index
-- predicate, and PostgREST gives no way to express that. The original
-- definition was partial:
--
--   create unique index leads_batch_mobile_uniq
--     on public.leads (batch, mobile) where batch is not null;
--
-- which fails with:
--   ERROR 42P10: there is no unique or exclusion constraint matching the
--   ON CONFLICT specification
--
-- Dropping the WHERE predicate changes nothing semantically. Postgres treats
-- NULLs as distinct in a unique index by default, so rows with batch IS NULL
-- still never conflict with each other — exactly as before. The index simply
-- becomes inferable.

drop index if exists public.leads_batch_mobile_uniq;

create unique index if not exists leads_batch_mobile_uniq
  on public.leads (batch, mobile);


-- ==================== 05_fix_profile_privilege_escalation.sql ====================
-- =====================================================================
--  MIGRATION 05 — SECURITY FIX: agents could promote themselves
--  Run this in: Supabase Dashboard → SQL Editor → New query → Run
--  Safe to re-run.
-- =====================================================================
--
-- THE BUG
-- -------
-- 01_schema.sql created this policy:
--
--   create policy "update own name"
--     on public.profiles for update
--     using (id = auth.uid())
--     with check (id = auth.uid());
--
-- The name says "own name", but an RLS policy constrains which ROWS you may
-- touch, never which COLUMNS. So the policy allowed an agent to update any
-- column of their own profile row — including `role`.
--
-- Confirmed against a live project: a plain agent ran
--
--   PATCH /rest/v1/profiles?id=eq.<their own id>   {"role":"supervisor"}
--
-- and it succeeded. Once `role = 'supervisor'`, public.is_supervisor() returns
-- true, which unlocks:
--   * "agents read assigned leads"  -> or public.is_supervisor()  = read EVERY lead
--   * "supervisors manage leads"    -> for all                    = write EVERY lead
--   * "supervisors read access log" -> the whole audit trail
--
-- i.e. any agent could dump the entire KYC-grade PII database and edit the
-- lead pool. The anon key needed is embedded in the APK and is extractable,
-- so the only thing an attacker needs beyond that is one valid agent login.
-- This defeats the "never give agents direct write access to leads" rule in
-- section 8 of CLAUDE.md — the agent just grants it to themselves.
--
-- THE FIX
-- -------
-- RLS cannot express column restrictions, so use column-level privileges,
-- which is the correct Postgres mechanism. `authenticated` keeps UPDATE on
-- exactly one harmless column and loses it everywhere else on this table.
-- `role` and `active` then become writable only by something that bypasses
-- RLS/grants — the SQL editor, or a security-definer function.

revoke update on public.profiles from authenticated;
grant  update (full_name) on public.profiles to authenticated;

-- Belt and braces: even if a future migration re-grants UPDATE on the whole
-- table, refuse a role/active change that did not come from a supervisor or
-- from a security-definer context. Cheap, and it fails loudly instead of
-- silently handing out admin.
create or replace function public.prevent_self_privilege_escalation()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  if (new.role is distinct from old.role)
     or (new.active is distinct from old.active) then
    -- auth.uid() is null for the service role and for SQL-editor sessions,
    -- so administrative changes still work.
    if auth.uid() is not null and not public.is_supervisor() then
      raise exception 'not permitted: only a supervisor may change role or active';
    end if;
    -- And nobody may promote themselves, supervisor or not.
    if auth.uid() is not null and new.id = auth.uid()
       and (new.role is distinct from old.role) then
      raise exception 'not permitted: you cannot change your own role';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_block_privilege_escalation on public.profiles;
create trigger profiles_block_privilege_escalation
  before update on public.profiles
  for each row execute function public.prevent_self_privilege_escalation();

-- Rename the policy so the next reader is not misled by "update own name"
-- into thinking columns were ever constrained by it.
alter policy "update own name" on public.profiles rename to "update own profile row";


-- ==================== 06_agent_edit_lead_details.sql ====================
-- =====================================================================
--  MIGRATION 06 — let an agent correct customer details from the call
--  Run this in: Supabase Dashboard → SQL Editor → New query → Run
--  Safe to re-run.
-- =====================================================================
--
-- Leads increasingly arrive with little more than a mobile number, so the
-- agent learns the real details on the call and previously had nowhere to
-- put them.
--
-- Agents still have NO direct write access to `leads` — that rule in
-- section 8 of CLAUDE.md stands. This works exactly like save_disposition:
-- a security-definer RPC that first proves the lead belongs to the caller,
-- then writes a fixed set of columns. An agent cannot reach the table any
-- other way, and cannot widen the column list from the client.


-- ---------------------------------------------------------------------
-- 1. EDIT LOG
-- ---------------------------------------------------------------------
-- lead_access_log records who READ a record. This is its counterpart for
-- writes. The data is KYC-grade PII, so a change an agent makes has to be
-- attributable and reversible — without this, a wrong name silently
-- overwrites the bank's own data with no way to see what it used to be.

create table if not exists public.lead_edit_log (
  id        bigserial   primary key,
  lead_id   bigint      not null references public.leads(id) on delete cascade,
  agent_id  uuid        not null references public.profiles(id),
  field     text        not null,
  old_value text,
  new_value text,
  edited_at timestamptz not null default now()
);

create index if not exists lead_edit_log_lead_idx  on public.lead_edit_log (lead_id, edited_at desc);
create index if not exists lead_edit_log_agent_idx on public.lead_edit_log (agent_id, edited_at desc);

alter table public.lead_edit_log enable row level security;

drop policy if exists "supervisors read edit log" on public.lead_edit_log;
create policy "supervisors read edit log"
  on public.lead_edit_log for select
  using (public.is_supervisor());

drop policy if exists "agents read own edits" on public.lead_edit_log;
create policy "agents read own edits"
  on public.lead_edit_log for select
  using (agent_id = auth.uid());


-- ---------------------------------------------------------------------
-- 2. RPC: save details learned on the call
-- ---------------------------------------------------------------------
-- Editable:     name, email, dob, company, annual_income_range, address
--
-- Deliberately NOT editable, and simply absent from the UPDATE below so it
-- cannot be reached at all:
--   * mobile      — the number being dialled and half of the (batch, mobile)
--                   duplicate key. Changing it would let an agent redirect a
--                   lead and would corrupt de-duplication. A bad number is a
--                   WRONG_NUMBER outcome, not an edit.
--   * pan         — KYC identity supplied by the bank. Typo-prone and the
--                   most damaging field to get wrong. Add it here only if
--                   capturing PAN on the call is a deliberate decision.
--   * ici_cr_lmt  — the bank's offer, not the agent's to change.
--   * every workflow column (assigned_to, is_closed, last_status, batch …)
--
-- NULL means "leave this column as it is". Agents add what they learn;
-- clearing a field is a supervisor action, not something to do mid-call.

create or replace function public.save_lead_details(
  p_lead_id              bigint,
  p_name                 text default null,
  p_email                text default null,
  p_dob                  date default null,
  p_company              text default null,
  p_annual_income_range  text default null,
  p_address              text default null
)
returns setof public.leads
language plpgsql
security definer set search_path = public
as $$
declare
  before public.leads%rowtype;
begin
  -- Same ownership rule as save_disposition. Without it any agent could
  -- rewrite any lead by guessing an id.
  select * into before
    from public.leads
   where id = p_lead_id
     and (assigned_to = auth.uid() or public.is_supervisor());

  if not found then
    raise exception 'lead % is not assigned to you', p_lead_id;
  end if;

  update public.leads set
      name                = coalesce(nullif(btrim(p_name), ''),                name),
      email               = coalesce(nullif(btrim(p_email), ''),               email),
      dob                 = coalesce(p_dob,                                    dob),
      company             = coalesce(nullif(btrim(p_company), ''),             company),
      annual_income_range = coalesce(nullif(btrim(p_annual_income_range), ''), annual_income_range),
      address             = coalesce(nullif(btrim(p_address), ''),             address)
   where id = p_lead_id;

  -- One row per field that actually changed.
  insert into public.lead_edit_log (lead_id, agent_id, field, old_value, new_value)
  select p_lead_id, auth.uid(), f.field, f.old_value, f.new_value
    from public.leads l,
    lateral (values
      ('name',                before.name,                l.name),
      ('email',               before.email,               l.email),
      ('dob',                 before.dob::text,           l.dob::text),
      ('company',             before.company,             l.company),
      ('annual_income_range', before.annual_income_range, l.annual_income_range),
      ('address',             before.address,             l.address)
    ) as f(field, old_value, new_value)
   where l.id = p_lead_id
     and f.old_value is distinct from f.new_value;

  return query select * from public.leads where id = p_lead_id;
end;
$$;


-- ==================== 02_seed_sample_leads.sql ====================
-- =====================================================================
--  SAMPLE LEADS — for testing only. Do NOT run against production.
--  These are fabricated records; the PANs are structurally valid but
--  belong to nobody.
--
--  *** RUN THIS LAST, NOT SECOND. ***
--
--  Despite the 02 in the filename, this file inserts `address`, and that
--  column is not created until 03. Running the files in numeric order
--  therefore fails with: column "address" of relation "leads" does not
--  exist. The working order on a fresh project is:
--
--      01 → 03 → 04 → 05 → 06 → 02
--
--  The number is kept only so existing notes and links still make sense.
-- =====================================================================

insert into public.leads
  (name, pan, mobile, email, dob, annual_income_range, company, ici_cr_lmt, address, batch)
values
  ('Rohit Sharma',      'ABCPS1234K', '9876543210', 'rohit.sharma@example.com',   '1988-04-30', '10L - 15L',  'Infosys Ltd',            250000.00, 'Flat 402, Skyline Residency, 14th Cross, Indiranagar, Bengaluru, Karnataka 560038', 'DEMO_BATCH_01'),
  ('Priya Nair',        'BXQPN5678L', '9812345678', 'priya.nair@example.com',     '1992-11-12', '15L - 25L',  'Tata Consultancy Svcs',  400000.00, 'B-7, Palm Grove Apartments, Marine Drive, Kochi, Kerala 682031', 'DEMO_BATCH_01'),
  ('Amit Deshpande',    'CDEPD9012M', '9900112233', 'amit.d@example.com',         '1985-01-22', '5L - 10L',   'Wipro Technologies',     150000.00, '221, Shivaji Nagar, Near FC Road, Pune, Maharashtra 411005', 'DEMO_BATCH_01'),
  ('Sneha Iyer',        'DFGPI3456N', '9765432100', 'sneha.iyer@example.com',     '1995-07-08', '10L - 15L',  'HCL Technologies',       300000.00, 'No. 18, 3rd Main, Adyar, Chennai, Tamil Nadu 600020', 'DEMO_BATCH_01'),
  ('Vikram Singh',      'EHIPS7890P', '9988776655', 'vikram.singh@example.com',   '1979-03-15', '25L+',       'Reliance Industries',    750000.00, 'Villa 9, Emerald Heights, Vasant Kunj, New Delhi 110070', 'DEMO_BATCH_01'),
  ('Ananya Bose',       'FJKPB2345Q', '9871234560', 'ananya.bose@example.com',    '1990-09-25', '15L - 25L',  'Accenture India',        500000.00, '55/2, Salt Lake Sector V, Kolkata, West Bengal 700091', 'DEMO_BATCH_01'),
  ('Karthik Reddy',     'GLMPR6789R', '9845012345', 'karthik.r@example.com',      '1993-12-01', '5L - 10L',   'Tech Mahindra',          125000.00, 'Plot 12, Jubilee Hills Road No. 36, Hyderabad, Telangana 500033', 'DEMO_BATCH_01'),
  ('Meera Joshi',       'HNOPJ0123S', '9820011223', 'meera.joshi@example.com',    '1987-06-18', '10L - 15L',  'Larsen & Toubro',        275000.00, 'A-304, Runwal Greens, Mulund West, Mumbai, Maharashtra 400080', 'DEMO_BATCH_01'),
  ('Arjun Menon',       'IPQPM4567T', '9633445566', 'arjun.menon@example.com',    '1991-02-27', '15L - 25L',  'Cognizant',              450000.00, '7, Panampilly Nagar, Ernakulam, Kerala 682036', 'DEMO_BATCH_01'),
  ('Divya Kapoor',      'JRSPK8901U', '9811223344', 'divya.kapoor@example.com',   '1994-10-05', '25L+',       'Deloitte India',         800000.00, 'C-11, Sushant Lok Phase I, Gurugram, Haryana 122009', 'DEMO_BATCH_01');

-- ---------------------------------------------------------------------
-- Promote a user to supervisor (run AFTER the supervisor has created them in
-- Authentication → Users; see section 6 of CLAUDE.md):
--
--   update public.profiles set role = 'supervisor' where login_id = 'rahul.k';
-- ---------------------------------------------------------------------


