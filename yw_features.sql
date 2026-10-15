-- =====================================================================
-- DMK Youth Wing: "Youth Wing" tab features (YW).
-- Run ORDER in Supabase > SQL Editor:
--   1. supabase_setup.sql      (already run)
--   2. supabase_voter_id.sql   (Exception B: Voter ID columns)
--   3. this file               (new yw_ tables, RLS, RPCs, samples, Exception A)
-- Existing tables are NOT altered here (only read / referenced).
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Admins (fill later: insert into yw_admins(user_id,email) select id,email from auth.users where email in (...); ----------
create table if not exists public.yw_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email   text not null,
  added_at timestamptz not null default now()
);
alter table public.yw_admins enable row level security;

create or replace function public.yw_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from yw_admins where user_id = auth.uid());
$$;
create or replace function public.yw_am_admin() returns boolean
language sql stable security definer set search_path = public as $$ select yw_is_admin(); $$;
grant execute on function public.yw_am_admin() to authenticated;

-- ---------- Rate limiting ----------
create table if not exists public.yw_rate_log (k text not null, at timestamptz not null default now());
create index if not exists yw_rate_log_k on public.yw_rate_log (k, at);
alter table public.yw_rate_log enable row level security;

create or replace function public.yw_rate_ok(p_scope text, p_max int, p_window interval)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare v_ip text; v_k text;
begin
  v_ip := coalesce(split_part(current_setting('request.headers', true)::json->>'x-forwarded-for', ',', 1), 'na');
  v_k  := p_scope || ':' || encode(digest(v_ip, 'sha256'), 'hex');
  delete from yw_rate_log where at < now() - interval '1 day';
  if (select count(*) from yw_rate_log where k = v_k and at > now() - p_window) >= p_max then return false; end if;
  insert into yw_rate_log(k) values (v_k);
  return true;
end $$;
revoke all on function public.yw_rate_ok(text,int,interval) from public, anon, authenticated;

-- ---------- Exception A: Member IDs ----------
create sequence if not exists public.yw_member_seq start 1;
create table if not exists public.yw_member_ids (
  member_id  text primary key default ('YW-' || lpad(nextval('public.yw_member_seq')::text, 6, '0')),
  member_ref uuid unique references public.yw_members(id) on delete set null,
  contact    text,
  first_name text not null,
  district   text not null,
  is_sample  boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.yw_member_ids enable row level security;

-- One-time backfill for existing members (oldest first). Safe to re-run.
insert into public.yw_member_ids (member_ref, contact, first_name, district, created_at)
select m.id, m.contact, split_part(trim(m.name), ' ', 1), m.district, m.created_at
from public.yw_members m
where not exists (select 1 from public.yw_member_ids x where x.member_ref = m.id)
order by m.created_at;

-- Join function: same name/signature/return as supabase_voter_id.sql, plus member_id in the JSON.
create or replace function public.join_youth_wing(
  p_name text, p_district text, p_contact text, p_voter_id text,
  p_wants_kit boolean default false, p_kit_size text default null,
  p_kit_address text default null, p_kit_pincode text default null)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_epic text; v_hash text; v_id uuid; v_mid text;
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
  if v_id is null then return json_build_object('status', 'duplicate'); end if;
  insert into yw_member_ids (member_ref, contact, first_name, district)
  values (v_id, trim(p_contact), split_part(trim(p_name), ' ', 1), trim(p_district))
  returning member_id into v_mid;
  return json_build_object('status', 'joined', 'member_id', v_mid);
end $$;
revoke all on function public.join_youth_wing(text,text,text,text,boolean,text,text,text) from public;
grant execute on function public.join_youth_wing(text,text,text,text,boolean,text,text,text) to anon, authenticated;

-- ---------- Points table ----------
create table if not exists public.yw_activity_types (
  id int primary key, name text not null unique, points int not null check (points >= 0), sort int not null default 0
);
alter table public.yw_activity_types enable row level security;
insert into public.yw_activity_types (id, name, points, sort) values
 (1,'Books reading / review',1,1),
 (2,'Blood donation camp',5,2),
 (3,'School / children related camp',5,3),
 (4,'Book donation to libraries',5,4),
 (5,'E-Sevai type free camp for public',5,5)
on conflict (id) do nothing;

-- ---------- Feeds ----------
create table if not exists public.yw_feeds (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(title) between 3 and 140),
  description text not null check (length(description) between 3 and 2000),
  photos text[] not null default '{}' check (coalesce(array_length(photos,1),0) <= 4),
  district text not null,
  activity_type_id int not null references public.yw_activity_types(id),
  activity_date date not null,
  consent boolean not null check (consent),
  status text not null default 'published' check (status in ('published','unpublished')),
  is_sample boolean not null default false,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);
alter table public.yw_feeds enable row level security;

create table if not exists public.yw_feed_credits (
  id bigserial primary key,
  feed_id uuid not null references public.yw_feeds(id) on delete cascade,
  member_id text not null references public.yw_member_ids(member_id) on delete cascade,
  points int not null check (points >= 0),
  credit_date date not null,
  reversed boolean not null default false,
  created_at timestamptz not null default now(),
  unique (feed_id, member_id)
);
alter table public.yw_feed_credits enable row level security;

-- Max 3 point-earning feeds per member per day.
create or replace function public.yw_credit_cap() returns trigger language plpgsql as $$
begin
  if new.points > 0 and not new.reversed and (
     select count(*) from public.yw_feed_credits
     where member_id = new.member_id and credit_date = new.credit_date and not reversed and points > 0
       and id <> coalesce(new.id, -1)) >= 3 then
    raise exception 'daily_cap: % already has 3 point-earning feeds on %', new.member_id, new.credit_date;
  end if;
  return new;
end $$;
drop trigger if exists yw_credit_cap on public.yw_feed_credits;
create trigger yw_credit_cap before insert or update on public.yw_feed_credits
for each row execute function public.yw_credit_cap();

-- Public view: published feeds only, first names only, no contact data.
create or replace view public.yw_feed_public as
select f.id, f.title, f.description, f.photos, f.district, f.activity_date, f.is_sample, f.created_at,
       a.id as activity_id, a.name as activity, a.points,
       (select string_agg(m.first_name, ', ' order by m.first_name)
          from public.yw_feed_credits c join public.yw_member_ids m on m.member_id = c.member_id
         where c.feed_id = f.id and not c.reversed) as members
from public.yw_feeds f join public.yw_activity_types a on a.id = f.activity_type_id
where f.status = 'published';
grant select on public.yw_feed_public to anon, authenticated;

-- Admin: publish a feed and credit members in one step.
create or replace function public.yw_admin_publish_feed(
  p_title text, p_description text, p_photos text[], p_district text, p_activity int,
  p_date date, p_members text[], p_consent boolean)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_pts int; v_m text;
begin
  if not yw_is_admin() then raise exception 'not_admin'; end if;
  if not coalesce(p_consent,false) then raise exception 'consent_required'; end if;
  select points into v_pts from yw_activity_types where id = p_activity;
  if v_pts is null then raise exception 'bad_activity'; end if;
  insert into yw_feeds (title, description, photos, district, activity_type_id, activity_date, consent)
  values (trim(p_title), trim(p_description), coalesce(p_photos,'{}'), p_district, p_activity, p_date, true)
  returning id into v_id;
  foreach v_m in array coalesce(p_members,'{}') loop
    v_m := upper(trim(v_m));
    if v_m = '' then continue; end if;
    if not exists (select 1 from yw_member_ids where member_id = v_m) then raise exception 'unknown_member: %', v_m; end if;
    insert into yw_feed_credits (feed_id, member_id, points, credit_date) values (v_id, v_m, v_pts, p_date);
  end loop;
  return v_id;
end $$;
grant execute on function public.yw_admin_publish_feed(text,text,text[],text,int,date,text[],boolean) to authenticated;

-- ---------- Leaderboard ----------
create or replace function public.yw_leaderboard(p_period text)
returns table (first_name text, district text, points bigint)
language plpgsql stable security definer set search_path = public as $$
begin
  if p_period = 'district' then
    return query
      select null::text, m.district, sum(c.points)::bigint
      from yw_feed_credits c join yw_feeds f on f.id = c.feed_id and f.status = 'published'
      join yw_member_ids m on m.member_id = c.member_id
      where not c.reversed group by m.district order by 3 desc limit 38;
  else
    return query
      select m.first_name, m.district, sum(c.points)::bigint
      from yw_feed_credits c join yw_feeds f on f.id = c.feed_id and f.status = 'published'
      join yw_member_ids m on m.member_id = c.member_id
      where not c.reversed
        and (p_period = 'all'
          or (p_period = 'week'  and c.credit_date >= date_trunc('week',  current_date)::date)
          or (p_period = 'month' and c.credit_date >= date_trunc('month', current_date)::date))
      group by m.member_id, m.first_name, m.district
      having sum(c.points) > 0
      order by 3 desc, min(c.created_at) limit 10;
  end if;
end $$;
grant execute on function public.yw_leaderboard(text) to anon, authenticated;

-- Seva Star of the Week (admin override per week).
create table if not exists public.yw_seva_star (
  week_start date primary key,
  member_id text not null references public.yw_member_ids(member_id) on delete cascade,
  note text,
  confirmed_at timestamptz not null default now()
);
alter table public.yw_seva_star enable row level security;

create or replace function public.yw_seva_star_current()
returns table (first_name text, district text, points bigint, confirmed boolean, note text)
language plpgsql stable security definer set search_path = public as $$
declare v_wk date := date_trunc('week', current_date)::date;
begin
  if exists (select 1 from yw_seva_star where week_start = v_wk) then
    return query
      select m.first_name, m.district,
             coalesce((select sum(c.points) from yw_feed_credits c join yw_feeds f on f.id=c.feed_id and f.status='published'
                        where c.member_id = s.member_id and not c.reversed and c.credit_date >= v_wk),0)::bigint,
             true, s.note
      from yw_seva_star s join yw_member_ids m on m.member_id = s.member_id where s.week_start = v_wk;
  else
    return query select l.first_name, l.district, l.points, false, null::text from yw_leaderboard('week') l limit 1;
  end if;
end $$;
grant execute on function public.yw_seva_star_current() to anon, authenticated;

-- Member points lookup by Member ID.
create or replace function public.yw_member_points(p_member_id text)
returns json language plpgsql stable security definer set search_path = public as $$
declare r record; v_all bigint; v_wk bigint;
begin
  select * into r from yw_member_ids where member_id = upper(trim(p_member_id));
  if not found then return json_build_object('found', false); end if;
  select coalesce(sum(c.points),0),
         coalesce(sum(c.points) filter (where c.credit_date >= date_trunc('week', current_date)::date),0)
    into v_all, v_wk
  from yw_feed_credits c join yw_feeds f on f.id = c.feed_id and f.status = 'published'
  where c.member_id = r.member_id and not c.reversed;
  return json_build_object('found', true, 'member_id', r.member_id, 'first_name', r.first_name,
    'district', r.district, 'points', v_all, 'week', v_wk,
    'badge', case when v_all >= 50 then 'Gold' when v_all >= 25 then 'Silver' when v_all >= 10 then 'Bronze' end);
end $$;
grant execute on function public.yw_member_points(text) to anon, authenticated;

-- ---------- Settings (Speaker of the Month, contact email) ----------
create table if not exists public.yw_settings (key text primary key, value jsonb not null default '{}');
alter table public.yw_settings enable row level security;
insert into public.yw_settings (key, value) values
 ('speaker_month', '{"name":"To be announced","about":"Our Speaker of the Month will be featured here.","link":""}'),
 ('contact_email', '{"email":""}')
on conflict (key) do nothing;

-- ---------- Podcast ----------
create table if not exists public.yw_podcast_episodes (
  id uuid primary key default gen_random_uuid(),
  category text not null default 'general' check (category in ('book','general')),
  title text not null, speaker text, ep_date date,
  thumbnail text, youtube text, spotify text, instagram text,
  is_live boolean not null default false,
  is_sample boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.yw_podcast_episodes enable row level security;
insert into public.yw_podcast_episodes (category, title, speaker, ep_date, thumbnail, youtube, is_live)
select v.* from (values
 ('general','காலத்தின் நிறம் கருப்பு சிவப்பு நூல் வெளியீடு: திரு. பன்னீர் பெருமாள் அவர்களின் பேச்சுரை','திரு. பன்னீர் பெருமாள்',null::date,'https://i.ytimg.com/vi/FDePiJkDURg/hqdefault.jpg','https://youtu.be/FDePiJkDURg',false),
 ('general','காலத்தின் நிறம் கருப்பு சிவப்பு நூல் வெளியீடு: வழக்கறிஞர் திருமதி அ. அருள்மொழி அவர்களின் பேச்சுரை','திருமதி அ. அருள்மொழி',null::date,'https://i.ytimg.com/vi/7RSsijRK430/hqdefault.jpg','https://youtu.be/7RSsijRK430',false),
 ('general','காலத்தின் நிறம் கருப்பு சிவப்பு: எழுத்தாளர் வே. மதிமாறன் அவர்களின் கட்டுரை','வே. மதிமாறன்',null::date,'https://i.ytimg.com/vi/g8KoNBzhNo8/hqdefault.jpg','https://youtu.be/g8KoNBzhNo8',false),
 ('general','Live: திமுக75 அறிவுத்திருவிழாவில் காலத்தின் நிறம் கருப்பு சிவப்பு நூல் வெளியீடு, சிறப்புரை','',null::date,'https://i.ytimg.com/vi/ZvC-hpSpK2c/hqdefault.jpg','https://www.youtube.com/live/ZvC-hpSpK2c',true)
) as v(category,title,speaker,ep_date,thumbnail,youtube,is_live)
where not exists (select 1 from public.yw_podcast_episodes e where e.youtube = v.youtube);

create table if not exists public.yw_speaker_applications (
  id bigserial primary key, name text not null, phone text not null, district text not null,
  college text, sample_link text, created_at timestamptz not null default now()
);
alter table public.yw_speaker_applications enable row level security;

-- ---------- Books ----------
create table if not exists public.yw_books (
  id uuid primary key default gen_random_uuid(),
  title text not null, author text not null, why text,
  level text not null default 'Beginner' check (level in ('Beginner','Deeper')),
  category text not null default 'General', cover text, amazon_url text,
  episode_id uuid references public.yw_podcast_episodes(id) on delete set null,
  is_sample boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.yw_books enable row level security;

create table if not exists public.yw_book_suggestions (
  id bigserial primary key, title text not null, author text, why text, name text,
  created_at timestamptz not null default now()
);
alter table public.yw_book_suggestions enable row level security;

-- ---------- Complaints ----------
create table if not exists public.yw_complaints (
  id bigserial primary key,
  ticket text not null unique,
  category text not null check (category in ('Party','Local issue','Event','Other')),
  district text not null, description text not null, photo text,
  name text, phone text, anonymous boolean not null default false,
  status text not null default 'New' check (status in ('New','In review','Resolved')),
  reply text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
alter table public.yw_complaints enable row level security;

-- ---------- Ideas ----------
create table if not exists public.yw_ideas (
  id uuid primary key default gen_random_uuid(),
  title text not null, description text not null,
  category text not null check (category in ('Event','Social service','Content','Digital','Other')),
  name text not null, district text not null,
  status text not null default 'Pending' check (status in ('Pending','Approved','Under review','Accepted','Done','Rejected')),
  is_sample boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.yw_ideas enable row level security;

create table if not exists public.yw_idea_votes (
  idea_id uuid not null references public.yw_ideas(id) on delete cascade,
  phone_hash text not null,
  created_at timestamptz not null default now(),
  primary key (idea_id, phone_hash)
);
alter table public.yw_idea_votes enable row level security;

create or replace view public.yw_ideas_public as
select i.id, i.title, i.description, i.category, split_part(i.name,' ',1) as first_name, i.district,
       i.status, i.is_sample, i.created_at,
       (select count(*) from public.yw_idea_votes v where v.idea_id = i.id) as supports
from public.yw_ideas i
where i.status in ('Approved','Under review','Accepted','Done');
grant select on public.yw_ideas_public to anon, authenticated;

-- ---------- Public form RPCs (validated + rate-limited) ----------
create or replace function public.yw_apply_speaker(p_name text, p_phone text, p_district text, p_college text, p_link text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(trim(coalesce(p_name,''))) < 2 or regexp_replace(coalesce(p_phone,''),'\D','','g') !~ '^(91)?[6-9][0-9]{9}$'
     or length(trim(coalesce(p_district,''))) < 3 then return json_build_object('status','invalid'); end if;
  if not yw_rate_ok('speaker', 3, interval '1 hour') then return json_build_object('status','limited'); end if;
  insert into yw_speaker_applications (name, phone, district, college, sample_link)
  values (left(trim(p_name),80), regexp_replace(p_phone,'\D','','g'), left(trim(p_district),40),
          left(nullif(trim(p_college),''),120), left(nullif(trim(p_link),''),300));
  return json_build_object('status','ok');
end $$;

create or replace function public.yw_suggest_book(p_title text, p_author text, p_why text, p_name text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(trim(coalesce(p_title,''))) < 2 then return json_build_object('status','invalid'); end if;
  if not yw_rate_ok('book', 5, interval '1 hour') then return json_build_object('status','limited'); end if;
  insert into yw_book_suggestions (title, author, why, name)
  values (left(trim(p_title),160), left(nullif(trim(p_author),''),120), left(nullif(trim(p_why),''),400), left(nullif(trim(p_name),''),80));
  return json_build_object('status','ok');
end $$;

create or replace function public.yw_submit_complaint(p_category text, p_district text, p_description text,
  p_photo text, p_name text, p_phone text, p_anonymous boolean)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_t text; v_anon boolean := coalesce(p_anonymous,false);
begin
  if p_category not in ('Party','Local issue','Event','Other') or length(trim(coalesce(p_district,''))) < 3
     or length(trim(coalesce(p_description,''))) < 10 then return json_build_object('status','invalid'); end if;
  if not v_anon and (length(trim(coalesce(p_name,''))) < 2 or regexp_replace(coalesce(p_phone,''),'\D','','g') !~ '^(91)?[6-9][0-9]{9}$') then
    return json_build_object('status','invalid'); end if;
  if not yw_rate_ok('complaint', 3, interval '1 hour') then return json_build_object('status','limited'); end if;
  loop
    v_t := 'YW-C-' || upper(substr(encode(gen_random_bytes(4),'hex'),1,6));
    exit when not exists (select 1 from yw_complaints where ticket = v_t);
  end loop;
  insert into yw_complaints (ticket, category, district, description, photo, name, phone, anonymous)
  values (v_t, p_category, left(trim(p_district),40), left(trim(p_description),2000),
          case when p_photo ~ '^[a-z0-9/_.-]{5,120}$' then p_photo end,
          case when v_anon then null else left(trim(p_name),80) end,
          case when v_anon then null else regexp_replace(p_phone,'\D','','g') end, v_anon);
  return json_build_object('status','ok','ticket',v_t);
end $$;

create or replace function public.yw_complaint_status(p_ticket text)
returns json language plpgsql stable security definer set search_path = public as $$
declare r record;
begin
  select status, reply, updated_at into r from yw_complaints where ticket = upper(trim(p_ticket));
  if not found then return json_build_object('found',false); end if;
  return json_build_object('found',true,'status',r.status,'reply',r.reply,'updated_at',r.updated_at);
end $$;

create or replace function public.yw_submit_idea(p_title text, p_description text, p_category text, p_name text, p_district text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(trim(coalesce(p_title,''))) < 3 or length(trim(coalesce(p_description,''))) < 10
     or p_category not in ('Event','Social service','Content','Digital','Other')
     or length(trim(coalesce(p_name,''))) < 2 or length(trim(coalesce(p_district,''))) < 3 then
    return json_build_object('status','invalid'); end if;
  if not yw_rate_ok('idea', 3, interval '1 hour') then return json_build_object('status','limited'); end if;
  insert into yw_ideas (title, description, category, name, district)
  values (left(trim(p_title),140), left(trim(p_description),2000), p_category, left(trim(p_name),80), left(trim(p_district),40));
  return json_build_object('status','ok');
end $$;

create or replace function public.yw_support_idea(p_idea uuid, p_phone text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_p text := regexp_replace(coalesce(p_phone,''),'\D','','g'); v_h text; n int;
begin
  v_p := right(v_p, 10);
  if v_p !~ '^[6-9][0-9]{9}$' then return json_build_object('status','invalid'); end if;
  if not exists (select 1 from yw_ideas where id = p_idea and status in ('Approved','Under review','Accepted','Done')) then
    return json_build_object('status','invalid'); end if;
  if not yw_rate_ok('vote', 30, interval '1 hour') then return json_build_object('status','limited'); end if;
  v_h := encode(hmac(v_p, (select value from yw_private where key='pepper'), 'sha256'), 'hex');
  insert into yw_idea_votes (idea_id, phone_hash) values (p_idea, v_h) on conflict do nothing;
  get diagnostics n = row_count;
  return json_build_object('status', case when n = 1 then 'ok' else 'duplicate' end,
                           'supports', (select count(*) from yw_idea_votes where idea_id = p_idea));
end $$;

grant execute on function public.yw_apply_speaker(text,text,text,text,text) to anon, authenticated;
grant execute on function public.yw_suggest_book(text,text,text,text) to anon, authenticated;
grant execute on function public.yw_submit_complaint(text,text,text,text,text,text,boolean) to anon, authenticated;
grant execute on function public.yw_complaint_status(text) to anon, authenticated;
grant execute on function public.yw_submit_idea(text,text,text,text,text) to anon, authenticated;
grant execute on function public.yw_support_idea(uuid,text) to anon, authenticated;

-- Admin: delete only sample rows.
create or replace function public.yw_admin_delete_samples() returns json
language plpgsql security definer set search_path = public as $$
declare a int; b int; c int; d int;
begin
  if not yw_is_admin() then raise exception 'not_admin'; end if;
  delete from yw_feeds where is_sample; get diagnostics a = row_count;
  delete from yw_member_ids where is_sample; get diagnostics b = row_count;
  delete from yw_books where is_sample; get diagnostics c = row_count;
  delete from yw_ideas where is_sample; get diagnostics d = row_count;
  delete from yw_podcast_episodes where is_sample;
  return json_build_object('feeds',a,'members',b,'books',c,'ideas',d);
end $$;
grant execute on function public.yw_admin_delete_samples() to authenticated;

-- ---------- RLS policies ----------
-- Public read of non-sensitive public tables.
drop policy if exists yw_pub_read on public.yw_activity_types;   create policy yw_pub_read on public.yw_activity_types   for select to anon, authenticated using (true);
drop policy if exists yw_pub_read on public.yw_podcast_episodes; create policy yw_pub_read on public.yw_podcast_episodes for select to anon, authenticated using (true);
drop policy if exists yw_pub_read on public.yw_books;            create policy yw_pub_read on public.yw_books            for select to anon, authenticated using (true);
drop policy if exists yw_pub_read on public.yw_settings;         create policy yw_pub_read on public.yw_settings         for select to anon, authenticated using (true);

-- Admins: full access to every yw_ table (only once added to yw_admins).
do $$ declare t text; begin
  foreach t in array array['yw_activity_types','yw_feeds','yw_feed_credits','yw_member_ids','yw_seva_star','yw_settings',
    'yw_podcast_episodes','yw_speaker_applications','yw_books','yw_book_suggestions','yw_complaints','yw_ideas','yw_idea_votes'] loop
    execute format('drop policy if exists yw_admin_all on public.%I', t);
    execute format('create policy yw_admin_all on public.%I for all to authenticated using (public.yw_is_admin()) with check (public.yw_is_admin())', t);
  end loop;
end $$;
drop policy if exists yw_admin_read on public.yw_admins;
create policy yw_admin_read on public.yw_admins for select to authenticated using (public.yw_is_admin());

-- ---------- Storage buckets (2 MB, images only) ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
 ('yw-feeds', 'yw-feeds', true, 2097152, array['image/webp','image/jpeg','image/png']),
 ('yw-complaints', 'yw-complaints', false, 2097152, array['image/webp','image/jpeg','image/png'])
on conflict (id) do nothing;
drop policy if exists yw_feeds_admin on storage.objects;
create policy yw_feeds_admin on storage.objects for all to authenticated
  using (bucket_id in ('yw-feeds','yw-complaints') and public.yw_is_admin())
  with check (bucket_id in ('yw-feeds','yw-complaints') and public.yw_is_admin());
drop policy if exists yw_complaint_upload on storage.objects;
create policy yw_complaint_upload on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'yw-complaints' and (storage.foldername(name))[1] = 'c');

-- ---------- Sample data (is_sample = true) ----------
insert into public.yw_member_ids (first_name, district, is_sample)
select v.n, v.d, true from (values ('Karthik','Salem'),('Priya','Madurai'),('Arun','Coimbatore'),
  ('Meena','Tiruchirappalli'),('Vignesh','Chennai'),('Divya','Erode'),('Sanjay','Vellore'),('Keerthana','Thanjavur')) v(n,d)
where not exists (select 1 from public.yw_member_ids where is_sample);

do $$
declare r record; v_id uuid;
begin
  if exists (select 1 from public.yw_feeds where is_sample) then return; end if;
  for r in select * from (values
    ('Blood donation camp at Government College','Our Salem team organised a blood donation camp with the college NSS unit. 64 students and staff donated blood, and the district blood bank collected every unit.','Salem',2,current_date-2,'Karthik'),
    ('120 books donated to the town library','Members collected 120 books from homes across Madurai: stories, science and Tamil literature. The town library has opened a new shelf for young readers.','Madurai',4,current_date-5,'Priya'),
    ('Painting and games day for school children','A full day of painting, quiz and outdoor games for 80 children of a panchayat union school. Every child went home with a drawing kit.','Coimbatore',3,current_date-8,'Arun'),
    ('Free e-Sevai help camp for villagers','Volunteers helped villagers apply for certificates, pensions and scheme benefits online, free of cost. Over 150 applications were filed in a single day.','Tiruchirappalli',5,current_date-11,'Meena'),
    ('Review: "Pavalar Kavithaigal"','A short review of the poetry collection, with three poems that speak to young people today. The full review was shared in our district reading circle.','Chennai',1,current_date-14,'Vignesh'),
    ('Second blood donation camp this month','Our Erode team held its second blood donation camp this month at the community hall. 48 donors came forward, many for the first time.','Erode',2,current_date-13,'Divya'),
    ('Pension and certificate help desk','A Sunday help desk at the panchayat office for senior citizens. Volunteers filed 90 pension and income certificate applications online.','Vellore',5,current_date-15,'Sanjay'),
    ('Notebooks and story books for a village school','Members donated 200 notebooks and 60 story books to a primary school, and spent the afternoon reading stories with the children.','Thanjavur',3,current_date-18,'Keerthana')
  ) t(title,descr,dist,act,dt,who) loop
    insert into public.yw_feeds (title, description, district, activity_type_id, activity_date, consent, is_sample)
    values (r.title, r.descr, r.dist, r.act, r.dt, true, true) returning id into v_id;
    insert into public.yw_feed_credits (feed_id, member_id, points, credit_date)
    select v_id, m.member_id, (select points from public.yw_activity_types where id = r.act), r.dt
    from public.yw_member_ids m where m.is_sample and m.first_name = r.who limit 1;
  end loop;
end $$;

insert into public.yw_books (title, author, why, level, category, amazon_url, is_sample)
select v.* , true from (values
 ('Annihilation of Caste','B. R. Ambedkar','The clearest argument for social justice you will ever read.','Deeper','Social justice','https://www.amazon.in/s?k=Annihilation+of+Caste+Ambedkar'),
 ('Why I Am an Atheist','Bhagat Singh','A short, fearless essay on reason by a 23-year-old revolutionary.','Beginner','Rationalism','https://www.amazon.in/s?k=Why+I+Am+an+Atheist+Bhagat+Singh'),
 ('The Dravidian Years','S. Narayan','How Tamil Nadu''s politics shaped its development story.','Deeper','History','https://www.amazon.in/s?k=The+Dravidian+Years+S+Narayan'),
 ('The Discovery of India','Jawaharlal Nehru','A sweeping look at India''s past, written from a prison cell.','Beginner','History','https://www.amazon.in/s?k=The+Discovery+of+India+Nehru')
) v(title,author,why,level,category,amazon_url)
where not exists (select 1 from public.yw_books where is_sample);

insert into public.yw_ideas (title, description, category, name, district, status, is_sample)
select v.*, true from (values
 ('Weekend reading circles in every district','A one-hour reading circle every Sunday at the district office, open to all students. One book a month, one speaker a month.','Event','Sanjay','Vellore','Accepted'),
 ('Exam help desk for Class 12 students','Volunteers run a free help desk before board exams for doubts, revision schedules and counselling referrals.','Social service','Keerthana','Thanjavur','Under review'),
 ('Short videos on our history','60-second explainer videos on key moments of our movement, made by members, for Instagram and YouTube Shorts.','Content','Rahul','Tirunelveli','Approved')
) v(title,description,category,name,district,status)
where not exists (select 1 from public.yw_ideas where is_sample);

-- ---------- Old Aadhaar rows (NOT deleted) - run to review and decide ----------
-- select id, name, district, aadhaar_last4, created_at from public.yw_members where aadhaar_hash is not null order by created_at;
