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

create table if not exists public.pins (
  id uuid primary key default gen_random_uuid(),
  pin_code text not null,
  owner_user_id uuid references auth.users(id) on delete cascade,
  owner_email text,
  status text not null default 'pending' check (status in ('pending', 'connected', 'completed')),
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
alter table public.reports add column if not exists owner_email text;

create index if not exists pins_owner_status_idx on public.pins(owner_user_id, status, created_at desc);
create index if not exists pins_pin_code_status_idx on public.pins(pin_code, status, expires_at);
create index if not exists reports_owner_uploaded_idx on public.reports(owner_user_id, uploaded_at desc);
create index if not exists pins_owner_email_idx on public.pins(lower(owner_email), created_at desc);
create index if not exists reports_owner_email_idx on public.reports(lower(owner_email), uploaded_at desc);
create index if not exists reports_report_json_gin_idx on public.reports using gin(report_json);
create index if not exists access_keys_assigned_user_idx on public.access_keys(assigned_user_id);
create index if not exists access_keys_assigned_email_idx on public.access_keys(lower(assigned_email));

alter table public.profiles enable row level security;
alter table public.allowed_users enable row level security;
alter table public.access_keys enable row level security;
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

create or replace function public.connect_pin(input_pin text)
returns table(ok boolean, error text, pin_id uuid)
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
    and status = 'pending'
    and expires_at > now()
  order by created_at desc
  limit 1;

  if matched_pin.id is null then
    return query select false, 'invalid_or_expired_pin', null::uuid;
    return;
  end if;

  update public.pins
  set status = 'connected'
  where id = matched_pin.id;

  return query select true, null::text, matched_pin.id;
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

create or replace function public.create_pin_by_key(
  input_email text,
  input_key text,
  input_pin text,
  input_expires_at timestamptz
)
returns table(id uuid, pin_code text, owner_user_id uuid, owner_email text, status text, created_at timestamptz, expires_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.validate_key_session(input_email, input_key) then
    return;
  end if;

  return query
  insert into public.pins(pin_code, owner_email, status, expires_at)
  values (input_pin, lower(input_email), 'pending', input_expires_at)
  returning pins.id, pins.pin_code, pins.owner_user_id, pins.owner_email, pins.status, pins.created_at, pins.expires_at;
end;
$$;

create or replace function public.list_pins_by_key(input_email text, input_key text)
returns table(id uuid, pin_code text, owner_user_id uuid, owner_email text, status text, created_at timestamptz, expires_at timestamptz)
language sql
stable
security definer
set search_path = public
as $$
  select p.id, p.pin_code, p.owner_user_id, p.owner_email, p.status, p.created_at, p.expires_at
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
    and status in ('pending', 'connected')
    and expires_at > now()
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
grant execute on function public.upload_report_by_pin(text, text, text, integer, jsonb) to anon, authenticated;
grant execute on function public.key_login(text, text) to anon, authenticated;
grant execute on function public.validate_key_session(text, text) to anon, authenticated;
grant execute on function public.create_pin_by_key(text, text, text, timestamptz) to anon, authenticated;
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

grant execute on function public.is_securo_owner() to authenticated;
grant execute on function public.has_securo_access() to authenticated;
grant execute on function public.list_allowed_users() to authenticated;
grant execute on function public.upsert_allowed_user(text, text) to authenticated;

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
