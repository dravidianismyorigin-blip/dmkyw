-- DMK Youth Wing: Supabase setup. Run once in Supabase > SQL Editor.

create extension if not exists pgcrypto with schema extensions;

-- Members. Aadhaar is NEVER stored in plain text: only an HMAC hash + last 4 digits.
create table if not exists public.yw_members (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  district      text not null,
  contact       text not null,
  aadhaar_hash  text not null unique,          -- unique = no duplicate joiners
  aadhaar_last4 char(4) not null,
  wants_kit     boolean not null default false,
  kit_size      text,
  kit_address   text,
  kit_pincode   text,
  created_at    timestamptz not null default now()
);

-- Secret pepper used for hashing (stays in the database, unreadable from the browser).
create table if not exists public.yw_private (key text primary key, value text not null);
insert into public.yw_private (key, value)
  values ('pepper', encode(extensions.gen_random_bytes(32), 'hex'))
  on conflict (key) do nothing;

-- Lock both tables: with RLS on and no policies, the public (anon) key cannot read or write them directly.
alter table public.yw_members enable row level security;
alter table public.yw_private enable row level security;

-- The only door the website uses.
create or replace function public.join_youth_wing(
  p_name text, p_district text, p_contact text, p_aadhaar text,
  p_wants_kit boolean default false, p_kit_size text default null,
  p_kit_address text default null, p_kit_pincode text default null)
returns json
language plpgsql security definer
set search_path = public, extensions
as $$
declare v_hash text; v_id uuid;
begin
  if p_aadhaar !~ '^[2-9][0-9]{11}$'
     or length(trim(coalesce(p_name,''))) < 2
     or length(trim(coalesce(p_district,''))) < 3
     or length(trim(coalesce(p_contact,''))) < 5 then
    return json_build_object('status', 'invalid');
  end if;

  v_hash := encode(hmac(p_aadhaar, (select value from yw_private where key = 'pepper'), 'sha256'), 'hex');

  insert into yw_members (name, district, contact, aadhaar_hash, aadhaar_last4,
                          wants_kit, kit_size, kit_address, kit_pincode)
  values (trim(p_name), trim(p_district), trim(p_contact), v_hash, right(p_aadhaar, 4),
          coalesce(p_wants_kit, false),
          case when p_wants_kit then p_kit_size end,
          case when p_wants_kit then p_kit_address end,
          case when p_wants_kit then p_kit_pincode end)
  on conflict (aadhaar_hash) do nothing
  returning id into v_id;

  if v_id is null then
    return json_build_object('status', 'duplicate');
  end if;
  return json_build_object('status', 'joined');
end $$;

revoke all on function public.join_youth_wing(text,text,text,text,boolean,text,text,text) from public;
grant execute on function public.join_youth_wing(text,text,text,text,boolean,text,text,text) to anon, authenticated;
