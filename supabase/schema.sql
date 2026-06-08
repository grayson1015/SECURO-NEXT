create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  created_at timestamptz not null default now()
);

create table if not exists public.allowed_users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  role text not null check (role in ('owner', 'admin', 'moderator')),
  created_at timestamptz not null default now()
);

create table if not exists public.access_keys (
  id uuid primary key default gen_random_uuid(),
  key_code text unique not null,
  assigned_email text,
  assigned_user_id uuid references auth.users(id) on delete set null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.access_keys add column if not exists license_type text not null default 'standard';
alter table public.access_keys add column if not exists max_emails integer not null default 1;
alter table public.access_keys add column if not exists expires_at timestamptz;

do $$
begin
  alter table public.access_keys
    add constraint access_keys_license_type_check check (license_type in ('standard', 'business'));
exception
  when duplicate_object then null;
end $$;

do $$
begin
  alter table public.access_keys
    drop constraint if exists access_keys_max_emails_check;
  alter table public.access_keys
    add constraint access_keys_max_emails_check check (max_emails between 1 and 20);
exception
  when duplicate_object then null;
end $$;

create table if not exists public.business_license_users (
  id uuid primary key default gen_random_uuid(),
  license_key text not null references public.access_keys(key_code) on delete cascade,
  email text not null,
  activated_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists public.pins (
  id uuid primary key default gen_random_uuid(),
  pin_code text not null,
  owner_user_id uuid references auth.users(id) on delete cascade,
  owner_email text,
  status text not null default 'queued' check (status in ('queued', 'scanning', 'completed', 'failed', 'timeout')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '15 minutes'
);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  pin_id uuid not null references public.pins(id) on delete cascade,
  owner_user_id uuid references auth.users(id) on delete cascade,
  owner_email text,
  uploaded_at timestamptz not null default now(),
  hostname text not null,
  scan_time timestamptz not null,
  risk_level text not null,
  evidence_score integer not null default 0,
  report_json jsonb not null
);

alter table public.pins alter column owner_user_id drop not null;
alter table public.reports alter column owner_user_id drop not null;
alter table public.pins add column if not exists owner_email text;
alter table public.pins add column if not exists scan_profile text not null default 'standard';
alter table public.reports add column if not exists owner_email text;
alter table public.pins add column if not exists scan_stage text;
alter table public.pins add column if not exists scan_progress integer not null default 0;
alter table public.pins add column if not exists files_scanned integer not null default 0;
alter table public.pins add column if not exists last_successful_operation text;
alter table public.pins add column if not exists diagnostics jsonb not null default '{}'::jsonb;
alter table public.pins add column if not exists status_updated_at timestamptz not null default now();
alter table public.pins alter column status set default 'queued';
update public.pins set status = 'queued' where status = 'pending';
update public.pins set status = 'scanning' where status = 'connected';
do $$
begin
  alter table public.pins drop constraint if exists pins_status_check;
  alter table public.pins
    add constraint pins_status_check check (status in ('queued', 'scanning', 'completed', 'failed', 'timeout'));
end $$;

do $$
begin
  alter table public.pins drop constraint if exists pins_scan_profile_check;
  alter table public.pins
    add constraint pins_scan_profile_check check (scan_profile in ('quick', 'standard', 'deep'));
end $$;

create index if not exists pins_owner_status_idx on public.pins(owner_user_id, status, created_at desc);
create index if not exists pins_pin_code_status_idx on public.pins(pin_code, status, expires_at);
create index if not exists reports_owner_uploaded_idx on public.reports(owner_user_id, uploaded_at desc);
create index if not exists pins_owner_email_idx on public.pins(lower(owner_email), created_at desc);
create index if not exists reports_owner_email_idx on public.reports(lower(owner_email), uploaded_at desc);
create index if not exists reports_report_json_gin_idx on public.reports using gin(report_json);
create index if not exists access_keys_assigned_user_idx on public.access_keys(assigned_user_id);
create index if not exists access_keys_assigned_email_idx on public.access_keys(lower(assigned_email));
create index if not exists access_keys_license_type_idx on public.access_keys(license_type, created_at desc);
create index if not exists business_license_users_license_idx on public.business_license_users(upper(license_key), last_seen_at desc);
create unique index if not exists business_license_users_license_email_idx on public.business_license_users(upper(license_key), lower(email));

alter table public.profiles enable row level security;
alter table public.allowed_users enable row level security;
alter table public.access_keys enable row level security;
alter table public.business_license_users enable row level security;
alter table public.pins enable row level security;
alter table public.reports enable row level security;

drop policy if exists "profiles are self readable" on public.profiles;
create policy "profiles are self readable"
on public.profiles for select
using (id = auth.uid());

drop policy if exists "profiles are self insertable" on public.profiles;
create policy "profiles are self insertable"
on public.profiles for insert
with check (id = auth.uid());

drop policy if exists "allowed users can read own approval" on public.allowed_users;
create policy "allowed users can read own approval"
on public.allowed_users for select
using (lower(email) = lower((auth.jwt() ->> 'email')));

drop policy if exists "users can read own access key" on public.access_keys;
create policy "users can read own access key"
on public.access_keys for select
using (
  assigned_user_id = auth.uid()
  or lower(assigned_email) = lower((auth.jwt() ->> 'email'))
  or exists (
    select 1
    from public.business_license_users blu
    where upper(blu.license_key) = upper(access_keys.key_code)
      and lower(blu.email) = lower(auth.jwt() ->> 'email')
  )
);

create or replace function public.has_securo_access()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.access_keys ak
    where ak.used_at is not null
      and (
        ak.assigned_user_id = auth.uid()
        or lower(ak.assigned_email) = lower(auth.jwt() ->> 'email')
        or exists (
          select 1
          from public.business_license_users blu
          where upper(blu.license_key) = upper(ak.key_code)
            and lower(blu.email) = lower(auth.jwt() ->> 'email')
        )
      )
  );
$$;

create or replace function public.validate_key_session(input_email text, input_key text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.access_keys ak
    where lower(ak.assigned_email) = lower(input_email)
      and upper(ak.key_code) = upper(input_key)
      and ak.used_at is not null
  )
  or exists (
    select 1
    from public.access_keys ak
    join public.business_license_users blu
      on upper(blu.license_key) = upper(ak.key_code)
    where upper(ak.key_code) = upper(input_key)
      and ak.license_type = 'business'
      and ak.used_at is not null
      and (ak.expires_at is null or ak.expires_at > now())
      and lower(blu.email) = lower(input_email)
  );
$$;

drop policy if exists "pins owner read" on public.pins;
create policy "pins owner read"
on public.pins for select
using (
  owner_user_id = auth.uid()
  and public.has_securo_access()
);

drop policy if exists "pins owner insert" on public.pins;
create policy "pins owner insert"
on public.pins for insert
with check (
  owner_user_id = auth.uid()
  and public.has_securo_access()
);

drop policy if exists "reports owner read" on public.reports;
create policy "reports owner read"
on public.reports for select
using (
  owner_user_id = auth.uid()
  and public.has_securo_access()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles(id, email)
  values (new.id, new.email)
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

drop function if exists public.connect_pin(text);

create or replace function public.connect_pin(input_pin text)
returns table(ok boolean, error text, pin_id uuid, scan_profile text)
language plpgsql
security definer
set search_path = public
as $$
declare
  matched_pin public.pins;
begin
  select *
  into matched_pin
  from public.pins
  where pin_code = input_pin
    and status = 'queued'
    and expires_at > now()
  order by created_at desc
  limit 1;

  if matched_pin.id is null then
    return query select false, 'invalid_or_expired_pin', null::uuid, null::text;
    return;
  end if;

  update public.pins
  set status = 'scanning'
  where id = matched_pin.id;

  return query select true, null::text, matched_pin.id, coalesce(matched_pin.scan_profile, 'standard');
end;
$$;

create or replace function public.update_pin_scan_status(
  input_pin text,
  input_status text,
  input_diagnostics jsonb default '{}'::jsonb
)
returns table(ok boolean, error text)
language plpgsql
security definer
set search_path = public
as $$
declare
  matched_pin public.pins;
begin
  if input_status not in ('queued', 'scanning', 'completed', 'failed', 'timeout') then
    return query select false, 'invalid_status';
    return;
  end if;

  select *
  into matched_pin
  from public.pins
  where pin_code = input_pin
    and status in ('queued', 'scanning', 'completed', 'failed', 'timeout')
  order by created_at desc
  limit 1;

  if matched_pin.id is null then
    return query select false, 'invalid_or_expired_pin';
    return;
  end if;

  update public.pins
  set status = input_status,
      scan_stage = coalesce(input_diagnostics->>'stage', scan_stage),
      scan_progress = coalesce(nullif(input_diagnostics->>'progressPercent', '')::integer, scan_progress),
      files_scanned = coalesce(nullif(input_diagnostics->>'filesScanned', '')::integer, files_scanned),
      last_successful_operation = coalesce(input_diagnostics->>'lastSuccessfulOperation', last_successful_operation),
      diagnostics = coalesce(input_diagnostics, '{}'::jsonb),
      status_updated_at = now()
  where id = matched_pin.id;

  return query select true, null::text;
end;
$$;

create or replace function public.key_login(input_email text, input_key text)
returns table(ok boolean, error text)
language plpgsql
security definer
set search_path = public
as $$
declare
  matched_key public.access_keys;
  normalized_email text := lower(trim(input_email));
  current_seats integer := 0;
begin
  if normalized_email is null or normalized_email !~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    return query select false, 'invalid_email_or_key';
    return;
  end if;

  select *
  into matched_key
  from public.access_keys
  where upper(key_code) = upper(trim(input_key))
  limit 1
  for update;

  if matched_key.id is null then
    return query select false, 'invalid_email_or_key';
    return;
  end if;

  if matched_key.license_type = 'business' or upper(matched_key.key_code) like 'SEC-MVP-%' then
    update public.access_keys
    set license_type = 'business',
        max_emails = 20,
        used_at = coalesce(used_at, now())
    where id = matched_key.id;

    if matched_key.expires_at is not null and matched_key.expires_at <= now() then
      return query select false, 'license_expired';
      return;
    end if;

    if exists (
      select 1
      from public.business_license_users blu
      where upper(blu.license_key) = upper(matched_key.key_code)
        and lower(blu.email) = normalized_email
    ) then
      update public.business_license_users
      set last_seen_at = now()
      where upper(license_key) = upper(matched_key.key_code)
        and lower(email) = normalized_email;

      return query select true, null::text;
      return;
    end if;

    select count(*)::integer
    into current_seats
    from public.business_license_users blu
    where upper(blu.license_key) = upper(matched_key.key_code);

    if current_seats >= 20 then
      return query select false, 'business_slots_full';
      return;
    end if;

    insert into public.business_license_users(license_key, email)
    values (matched_key.key_code, normalized_email);

    return query select true, null::text;
    return;
  end if;

  if matched_key.used_at is not null then
    if lower(matched_key.assigned_email) = normalized_email then
      return query select true, null::text;
      return;
    end if;
    return query select false, 'key_already_assigned';
    return;
  end if;

  update public.access_keys
  set assigned_email = normalized_email,
      used_at = now()
  where id = matched_key.id;

  return query select true, null::text;
end;
$$;

drop function if exists public.create_pin_by_key(text, text, text, timestamptz);
drop function if exists public.create_pin_by_key(text, text, text, timestamptz, text);

create or replace function public.create_pin_by_key(
  input_email text,
  input_key text,
  input_pin text,
  input_expires_at timestamptz,
  input_scan_profile text default 'standard'
)
returns table(id uuid, pin_code text, owner_user_id uuid, owner_email text, status text, scan_profile text, created_at timestamptz, expires_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.validate_key_session(input_email, input_key) then
    return;
  end if;

  if coalesce(input_scan_profile, 'standard') not in ('quick', 'standard', 'deep') then
    input_scan_profile := 'standard';
  end if;

  return query
  insert into public.pins(pin_code, owner_email, status, scan_profile, expires_at)
  values (input_pin, lower(input_email), 'queued', input_scan_profile, input_expires_at)
  returning pins.id, pins.pin_code, pins.owner_user_id, pins.owner_email, pins.status, pins.scan_profile, pins.created_at, pins.expires_at;
end;
$$;

drop function if exists public.list_pins_by_key(text, text);

create or replace function public.list_pins_by_key(input_email text, input_key text)
returns table(id uuid, pin_code text, owner_user_id uuid, owner_email text, status text, scan_profile text, created_at timestamptz, expires_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select p.id, p.pin_code, p.owner_user_id, p.owner_email, p.status, p.scan_profile, p.created_at, p.expires_at
  from public.pins p
  where public.validate_key_session(input_email, input_key)
    and lower(p.owner_email) = lower(input_email)
  order by p.created_at desc
  limit 20;
$$;

create or replace function public.list_reports_by_key(input_email text, input_key text)
returns setof public.reports
language sql
stable
security definer
set search_path = public
as $$
  select r.*
  from public.reports r
  where public.validate_key_session(input_email, input_key)
    and lower(r.owner_email) = lower(input_email)
  order by r.uploaded_at desc;
$$;

create or replace function public.get_report_by_key(input_email text, input_key text, input_report_id uuid)
returns setof public.reports
language sql
stable
security definer
set search_path = public
as $$
  select r.*
  from public.reports r
  where public.validate_key_session(input_email, input_key)
    and lower(r.owner_email) = lower(input_email)
    and r.id = input_report_id
  limit 1;
$$;

create or replace function public.upload_report_by_pin(
  input_pin text,
  input_hostname text,
  input_risk_level text,
  input_evidence_score integer,
  input_report_json jsonb
)
returns table(ok boolean, error text, report_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
  matched_pin public.pins;
  created_report_id uuid;
begin
  if input_report_json is null
    or not (input_report_json ? 'scanTime')
    or not (input_report_json ? 'hostname')
    or not (input_report_json ? 'highestResult')
    or not (input_report_json ? 'confidence')
    or not (input_report_json ? 'evidenceSources')
    or not (input_report_json ? 'timeline')
    or not (input_report_json ? 'sessions')
    or not (input_report_json ? 'findings')
    or not (input_report_json ? 'limitations') then
    return query select false, 'invalid_report_schema', null::uuid;
    return;
  end if;

  select *
  into matched_pin
  from public.pins
  where pin_code = input_pin
    and status in ('queued', 'scanning')
    and (
      (status = 'queued' and expires_at > now())
      or status = 'scanning'
    )
  order by created_at desc
  limit 1;

  if matched_pin.id is null then
    return query select false, 'invalid_or_expired_pin', null::uuid;
    return;
  end if;

  insert into public.reports(
    pin_id,
    owner_user_id,
    owner_email,
    hostname,
    scan_time,
    risk_level,
    evidence_score,
    report_json
  )
  values (
    matched_pin.id,
    matched_pin.owner_user_id,
    matched_pin.owner_email,
    coalesce(nullif(input_hostname, ''), input_report_json->>'hostname'),
    coalesce((input_report_json->>'scanTime')::timestamptz, now()),
    coalesce(nullif(input_risk_level, ''), input_report_json->>'highestResult'),
    coalesce(input_evidence_score, 0),
    input_report_json
  )
  returning id into created_report_id;

  update public.pins
  set status = 'completed'
  where id = matched_pin.id;

  return query select true, null::text, created_report_id;
end;
$$;

grant execute on function public.connect_pin(text) to anon, authenticated;
grant execute on function public.update_pin_scan_status(text, text, jsonb) to anon, authenticated;
grant execute on function public.upload_report_by_pin(text, text, text, integer, jsonb) to anon, authenticated;
grant execute on function public.key_login(text, text) to anon, authenticated;
grant execute on function public.validate_key_session(text, text) to anon, authenticated;
grant execute on function public.create_pin_by_key(text, text, text, timestamptz, text) to anon, authenticated;
grant execute on function public.list_pins_by_key(text, text) to anon, authenticated;
grant execute on function public.list_reports_by_key(text, text) to anon, authenticated;
grant execute on function public.get_report_by_key(text, text, uuid) to anon, authenticated;

create or replace function public.is_securo_owner()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.allowed_users au
    where lower(au.email) = lower(auth.jwt() ->> 'email')
      and au.role = 'owner'
  );
$$;

create or replace function public.list_allowed_users()
returns table(id uuid, email text, role text, created_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select au.id, au.email, au.role, au.created_at
  from public.allowed_users au
  where public.is_securo_owner()
  order by au.created_at desc;
$$;

create or replace function public.upsert_allowed_user(input_email text, input_role text)
returns table(ok boolean, error text)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_securo_owner() then
    return query select false, 'owner_required';
    return;
  end if;

  if input_email is null or input_email !~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    return query select false, 'invalid_email';
    return;
  end if;

  if input_role not in ('owner', 'admin', 'moderator') then
    return query select false, 'invalid_role';
    return;
  end if;

  insert into public.allowed_users(email, role)
  values (lower(input_email), input_role)
  on conflict (email) do update
  set role = excluded.role;

  return query select true, null::text;
end;
$$;

create or replace function public.list_business_licenses()
returns table(
  key_code text,
  license_type text,
  max_emails integer,
  emails_used integer,
  created_at timestamptz,
  expires_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select
    ak.key_code,
    ak.license_type,
    ak.max_emails,
    count(blu.id)::integer as emails_used,
    ak.created_at,
    ak.expires_at
  from public.access_keys ak
  left join public.business_license_users blu
    on upper(blu.license_key) = upper(ak.key_code)
  where public.is_securo_owner()
    and ak.license_type = 'business'
  group by ak.key_code, ak.license_type, ak.max_emails, ak.created_at, ak.expires_at
  order by ak.created_at desc;
$$;

create or replace function public.list_business_license_users(input_license_key text)
returns table(license_key text, email text, activated_at timestamptz, last_seen_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select blu.license_key, blu.email, blu.activated_at, blu.last_seen_at
  from public.business_license_users blu
  where public.is_securo_owner()
    and upper(blu.license_key) = upper(input_license_key)
  order by blu.activated_at desc;
$$;

create or replace function public.revoke_business_license_user(input_license_key text, input_email text)
returns table(ok boolean, error text)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_securo_owner() then
    return query select false, 'owner_required';
    return;
  end if;

  delete from public.business_license_users
  where upper(license_key) = upper(input_license_key)
    and lower(email) = lower(input_email);

  return query select true, null::text;
end;
$$;

grant execute on function public.is_securo_owner() to authenticated;
grant execute on function public.has_securo_access() to authenticated;
grant execute on function public.list_allowed_users() to authenticated;
grant execute on function public.upsert_allowed_user(text, text) to authenticated;
grant execute on function public.list_business_licenses() to authenticated;
grant execute on function public.list_business_license_users(text) to authenticated;
grant execute on function public.revoke_business_license_user(text, text) to authenticated;

create or replace function public.activate_access_key(input_key text)
returns table(ok boolean, error text)
language plpgsql
security definer
set search_path = public
as $$
declare
  matched_key public.access_keys;
  current_email text := lower(auth.jwt() ->> 'email');
  current_user_id uuid := auth.uid();
  current_seats integer := 0;
begin
  if current_user_id is null or current_email is null or current_email = '' then
    return query select false, 'unauthorized';
    return;
  end if;

  select *
  into matched_key
  from public.access_keys
  where upper(key_code) = upper(input_key)
  limit 1
  for update;

  if matched_key.id is null then
    return query select false, 'invalid_or_used_key';
    return;
  end if;

  if matched_key.license_type = 'business' or upper(matched_key.key_code) like 'SEC-MVP-%' then
    update public.access_keys
    set license_type = 'business',
        max_emails = 20,
        used_at = coalesce(used_at, now())
    where id = matched_key.id;

    if matched_key.expires_at is not null and matched_key.expires_at <= now() then
      return query select false, 'license_expired';
      return;
    end if;

    if exists (
      select 1
      from public.business_license_users blu
      where upper(blu.license_key) = upper(matched_key.key_code)
        and lower(blu.email) = current_email
    ) then
      update public.business_license_users
      set last_seen_at = now()
      where upper(license_key) = upper(matched_key.key_code)
        and lower(email) = current_email;

      return query select true, null::text;
      return;
    end if;

    select count(*)::integer
    into current_seats
    from public.business_license_users blu
    where upper(blu.license_key) = upper(matched_key.key_code);

    if current_seats >= 20 then
      return query select false, 'business_slots_full';
      return;
    end if;

    insert into public.business_license_users(license_key, email)
    values (matched_key.key_code, current_email);

    return query select true, null::text;
    return;
  end if;

  if matched_key.used_at is not null then
    if matched_key.assigned_user_id = current_user_id or lower(matched_key.assigned_email) = current_email then
      return query select true, null::text;
      return;
    end if;
    return query select false, 'invalid_or_used_key';
    return;
  end if;

  update public.access_keys
  set assigned_email = current_email,
      assigned_user_id = current_user_id,
      used_at = now()
  where id = matched_key.id;

  return query select true, null::text;
end;
$$;

grant execute on function public.activate_access_key(text) to authenticated;

insert into public.access_keys(key_code, license_type, max_emails, assigned_email, assigned_user_id, used_at)
values ('SEC-MVP-V7K2-M9Q4-X3P8', 'business', 20, null, null, null)
on conflict (key_code) do update
set license_type = 'business',
    max_emails = 20;
