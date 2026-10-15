-- DMK Youth Wing: switch duplicate check from Aadhaar to Voter ID (EPIC).
-- Run ONCE in Supabase > SQL Editor, after supabase_setup.sql.
-- Existing members are kept. Old Aadhaar columns become optional (no new Aadhaar is ever collected).

alter table public.yw_members alter column aadhaar_hash  drop not null;
alter table public.yw_members alter column aadhaar_last4 drop not null;
alter table public.yw_members add column if not exists voter_hash  text unique;
alter table public.yw_members add column if not exists voter_last4 char(4);

-- Replace the join function: same name, Voter ID instead of Aadhaar.
drop function if exists public.join_youth_wing(text,text,text,text,boolean,text,text,text);

create or replace function public.join_youth_wing(
  p_name text, p_district text, p_contact text, p_voter_id text,
  p_wants_kit boolean default false, p_kit_size text default null,
  p_kit_address text default null, p_kit_pincode text default null)
returns json
language plpgsql security definer
set search_path = public, extensions
as $$
declare v_epic text; v_hash text; v_id uuid;
begin
  v_epic := upper(regexp_replace(coalesce(p_voter_id,''), '[^A-Za-z0-9]', '', 'g'));
  if v_epic !~ '^[A-Z]{3}[0-9]{7}$'
     or length(trim(coalesce(p_name,''))) < 2
     or length(trim(coalesce(p_district,''))) < 3
     or length(trim(coalesce(p_contact,''))) < 5 then
    return json_build_object('status', 'invalid');
  end if;

  v_hash := encode(hmac(v_epic, (select value from yw_private where key = 'pepper'), 'sha256'), 'hex');

  insert into yw_members (name, district, contact, voter_hash, voter_last4,
                          wants_kit, kit_size, kit_address, kit_pincode)
  values (trim(p_name), trim(p_district), trim(p_contact), v_hash, right(v_epic, 4),
          coalesce(p_wants_kit, false),
          case when p_wants_kit then p_kit_size end,
          case when p_wants_kit then p_kit_address end,
          case when p_wants_kit then p_kit_pincode end)
  on conflict (voter_hash) do nothing
  returning id into v_id;

  if v_id is null then
    return json_build_object('status', 'duplicate');
  end if;
  return json_build_object('status', 'joined');
end $$;

revoke all on function public.join_youth_wing(text,text,text,text,boolean,text,text,text) from public;
grant execute on function public.join_youth_wing(text,text,text,text,boolean,text,text,text) to anon, authenticated;
