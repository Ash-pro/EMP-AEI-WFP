-- =====================================================================
--  AEI–WFP · نظام الإشعارات
--  يُشغَّل مرة واحدة في Supabase → SQL Editor (قابل لإعادة التشغيل بأمان)
--
--  • جدول aei_notif: إشعار لكل مستخدم مع حالة القراءة
--  • تُنشأ الإشعارات تلقائياً بـ Triggers من: المهام، الطلبات العامة (إجازة،
--    تسجيل، تعديل، استقالة، أصول)، تغيير حالة الإجازة، وسجل التعديلات
--  • المدير الأعلى يستلم كل الإشعارات، ولا يُشعَر أحد بعمليته هو
--  • لا يعدّل أي بيانات موجودة، وأي خطأ في الإشعارات لا يوقف العملية الأصلية
-- =====================================================================
begin;

create table if not exists public.aei_notif (
  id        bigint generated always as identity primary key,
  username  text not null references public.aei_users(username) on update cascade on delete cascade,
  kind      text not null,              -- task | leave | reg | upd | res | ast | log
  title     text not null,
  body      text not null default '',
  tab       text,                       -- تبويب لوحة التحكم الذي يفتحه الإشعار
  ref       text,                       -- معرّف العنصر (رقم المهمة مثلاً)
  actor     text,                       -- اسم مستخدم منفّذ العملية (null للنماذج العامة)
  at        timestamptz not null default now(),
  read_at   timestamptz
);
create index if not exists aei_notif_user_idx on public.aei_notif(username, at desc);
create index if not exists aei_notif_unread_idx on public.aei_notif(username) where read_at is null;
alter table public.aei_notif enable row level security;
revoke all on public.aei_notif from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- منفّذ العملية: يُسجَّل لكل طلب عند التحقق من الجلسة، لتعرفه الـ Triggers
-- ---------------------------------------------------------------------
create or replace function public.aei_who(p text) returns text
language plpgsql security definer set search_path = public, extensions as $fn$
declare u text; k text;
begin
  if p is null or left(p,2) <> 'u_' or length(p) < 40 then return null; end if;
  k := encode(digest(p,'sha256'),'hex');
  select s.username into u from aei_sess s join aei_users x on x.username = s.username
   where s.th = k and x.active and s.last_at > now() - interval '7 days';
  if u is not null then
    update aei_sess set last_at = now() where th = k and last_at < now() - interval '5 minutes';
    perform set_config('aei.actor', u, true);
  end if;
  return u;
end $fn$;

-- إرسال إشعار: للمستلمين المحددين + كل مدير أعلى، باستثناء منفّذ العملية
-- sti: صياغة بديلة لنسخة المدير الأعلى عندما لا يكون هو المعني بالإشعار
drop function if exists public.aei_notify(text[], text, text, text, text, text, text);
create or replace function public.aei_notify(rcp text[], k text, ti text, bo text, tb text, rf text, act text, sti text default null)
returns void language sql security definer set search_path = public, extensions as $fn$
  insert into aei_notif(username, kind, title, body, tab, ref, actor)
  select u.username, k, left(case when u.username = any(coalesce(rcp, '{}'::text[])) then ti else coalesce(sti, ti) end, 200),
         left(coalesce(bo, ''), 400), tb, rf, act
  from aei_users u
  where u.active and u.username is distinct from act
    and (u.username = any(coalesce(rcp, '{}'::text[])) or u.super);
$fn$;

create or replace function public.aei_admins() returns text[]
language sql stable security definer set search_path = public, extensions as $fn$
  select coalesce(array_agg(username), '{}') from aei_users where active and role = 'admin';
$fn$;

-- الحسابات المرتبطة باسم مشرف معيّن (مقارنة مرنة للأحرف العربية)
create or replace function public.aei_sup_users(nm text) returns text[]
language sql stable security definer set search_path = public, extensions as $fn$
  select coalesce(array_agg(username), '{}') from aei_users
  where active and sup_name is not null and coalesce(nm, '') <> '' and public.aei_nrm(sup_name) = public.aei_nrm(nm);
$fn$;

-- ---------------------------------------------------------------------
-- Trigger: أحداث المهام
-- ---------------------------------------------------------------------
create or replace function public.aei_tg_task_notif() returns trigger
language plpgsql security definer set search_path = public, extensions as $fn$
declare t aei_tasks; au text; an text; bn text; asg text[]; cr text; ti text; nt text; rf text;
begin
  begin
    select * into t from aei_tasks where id = new.task_id;
    if not found then return new; end if;
    ti := t.title; cr := t.created_by; rf := t.id::text;
    bn := coalesce(nullif(new.by_name, ''), new.by_user, '');
    nt := left(btrim(coalesce(new.note, '')), 160);
    if new.asg_id is not null then
      select username into au from aei_task_asg where id = new.asg_id;
      select coalesce(nullif(name, ''), username) into an from aei_users where username = au;
    end if;
    select coalesce(array_agg(username), '{}') into asg from aei_task_asg where task_id = t.id;
    case new.type
      when 'assigned' then
        perform aei_notify(array[au], 'task', 'مهمة جديدة مسندة إليك',
          ti || case when t.due is not null then ' · الاستحقاق ' || to_char(t.due, 'DD/MM/YYYY') else '' end, 'tasks', rf, new.by_user,
          'أُسندت مهمة إلى ' || coalesce(an, au));
      when 'edited' then
        perform aei_notify(asg, 'task', 'عُدّلت بيانات مهمة مسندة إليك', ti, 'tasks', rf, new.by_user, 'عُدّلت بيانات مهمة');
      when 'unassigned' then
        perform aei_notify('{}', 'task', 'أُزيل إسناد مهمة عن ' || nt, ti, 'tasks', rf, new.by_user);
      when 'received' then
        perform aei_notify(array[cr], 'task', coalesce(an, bn) || ' استلم المهمة', ti, 'tasks', rf, new.by_user);
      when 'progress' then
        if new.p_to = 100 then
          perform aei_notify(case when cr is null or cr = au then aei_admins() else array[cr] end, 'task',
            coalesce(an, bn) || ' أرسل المهمة للاعتماد', ti || case when nt <> '' then ' — ' || nt else '' end, 'tasks', rf, new.by_user);
        else
          perform aei_notify(array[cr], 'task', coalesce(an, bn) || ' حدّث الإنجاز إلى ' || new.p_to || '%',
            ti || case when nt <> '' then ' — ' || nt else '' end, 'tasks', rf, new.by_user);
        end if;
      when 'reply' then
        if au = new.by_user then
          perform aei_notify(case when cr is null or cr = au then aei_admins() else array[cr] end, 'task', 'رد جديد من ' || bn, ti || ' — ' || nt, 'tasks', rf, new.by_user);
        else
          perform aei_notify(array[au], 'task', 'رد من ' || bn || ' على مهمتك', ti || ' — ' || nt, 'tasks', rf, new.by_user, 'رد ' || bn || ' على مهمة ' || coalesce(an, au));
        end if;
      when 'approved' then
        perform aei_notify(array[au], 'task', 'اعتُمد إنجاز مهمتك', ti, 'tasks', rf, new.by_user, 'اعتُمد إنجاز ' || coalesce(an, au));
      when 'returned' then
        perform aei_notify(array[au], 'task', 'أُرجعت المهمة إليك للاستكمال',
          ti || case when nt <> '' then ' — السبب: ' || nt else '' end, 'tasks', rf, new.by_user, 'أُرجعت المهمة إلى ' || coalesce(an, au));
      when 'cancelled' then
        perform aei_notify(asg, 'task', 'أُلغيت مهمة', ti, 'tasks', rf, new.by_user);
      when 'reopened' then
        perform aei_notify(asg, 'task', 'أُعيد فتح مهمة', ti, 'tasks', rf, new.by_user);
      else null;
    end case;
  exception when others then null;   -- الإشعار لا يوقف العملية الأصلية أبداً
  end;
  return new;
end $fn$;

drop trigger if exists aei_task_notif on public.aei_task_upd;
create trigger aei_task_notif after insert on public.aei_task_upd for each row execute function public.aei_tg_task_notif();

-- ---------------------------------------------------------------------
-- Trigger: الطلبات العامة وسجل التعديلات وحالة الإجازات
-- ---------------------------------------------------------------------
create or replace function public.aei_tg_docs_notif() returns trigger
language plpgsql security definer set search_path = public, extensions as $fn$
declare d jsonb := new.data; act text := nullif(current_setting('aei.actor', true), '');
  nm text := coalesce(new.data->>'name', ''); ts bigint; tx text;
begin
  begin
    -- لا إشعارات عند استعادة نسخة احتياطية قديمة
    ts := case when coalesce(d->>'ts', '') ~ '^\d{1,15}$' then (d->>'ts')::bigint end;
    if ts is not null and ts < (extract(epoch from now()) * 1000)::bigint - 2 * 86400000 then return new; end if;

    if tg_op = 'INSERT' then
      if new.coll = 'leave' then
        perform aei_notify(aei_admins() || aei_sup_users(d->>'sup'), 'leave', 'طلب إجازة جديد',
          nm || coalesce(' · ' || nullif(d->>'type', ''), '') || coalesce(' · من ' || nullif(d->>'start', ''), '') || coalesce(' إلى ' || nullif(d->>'end', ''), ''),
          'leave', new.id, act);
      elsif new.coll = 'reg' then
        perform aei_notify(aei_admins() || aei_sup_users(d->>'sup'), 'reg', 'طلب تسجيل موظف جديد',
          nm || coalesce(' · ' || nullif(d->>'point', ''), ''), 'reg', new.id, act);
      elsif new.coll = 'upd' then
        perform aei_notify(aei_admins(), 'upd', 'طلب تعديل بيانات موظف', nm || coalesce(' · ' || nullif(d->>'point', ''), ''), 'upd', new.id, act);
      elsif new.coll = 'resreq' then
        perform aei_notify(aei_admins() || aei_sup_users(d->>'psup'), 'res', 'طلب استقالة جديد',
          nm || coalesce(' · ' || nullif(d->>'point', ''), ''), 'res', new.id, act);
      elsif new.coll = 'aev' and coalesce(d->>'status', '') = 'جديد' and act is null then
        perform aei_notify(aei_admins(), 'ast', coalesce(nullif(d->>'type', ''), 'حركة') || ' أصول من نقطة ' || coalesce(d->>'pt', ''),
          concat_ws(' · ', nullif(coalesce(d->>'itemName', d->>'item'), ''), nullif(d->>'by', '')), 'ast', new.id, act);
      elsif new.coll = 'acat' and coalesce(d->>'status', '') = 'جديد' and act is null then
        perform aei_notify(aei_admins(), 'ast', 'اقتراح أصل جديد من نقطة ' || coalesce(d->>'pt', ''), nm, 'ast', new.id, act);
      elsif new.coll = 'log' then
        if coalesce(d->>'type', '') like '%مهمة%' then return new; end if;   -- المهام لها إشعاراتها الخاصة
        tx := concat_ws(' · ', nullif(nm, ''), nullif(left(coalesce(d->>'text', ''), 200), ''));
        perform aei_notify('{}', 'log', coalesce(nullif(d->>'type', ''), 'نشاط') || coalesce(' — ' || nullif(d->>'by', ''), ''), tx, 'log', new.id,
          coalesce(act, (select username from aei_users where name = d->>'by' limit 1)));
      end if;
    elsif tg_op = 'UPDATE' and new.coll = 'leave'
      and coalesce(old.data->>'status', '') is distinct from coalesce(d->>'status', '') then
      perform aei_notify(aei_sup_users(d->>'sup'), 'leave', 'تحديث طلب إجازة: ' || coalesce(d->>'status', ''), nm, 'leave', new.id, act);
    end if;
  exception when others then null;
  end;
  return new;
end $fn$;

drop trigger if exists aei_docs_notif on public.aei_docs;
create trigger aei_docs_notif after insert or update on public.aei_docs for each row execute function public.aei_tg_docs_notif();

-- ---------------------------------------------------------------------
-- دوال الواجهة
-- ---------------------------------------------------------------------
-- القائمة: f = 'all' | 'unread' | نوع أو أكثر مفصولة بفاصلة (task أو leave,reg) ، before = آخر id للصفحة التالية
create or replace function public.aei_notif_list(p text, f text default 'all', lim int default 30, before bigint default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $fn$
declare me text := public.aei_who(p); n int := least(greatest(coalesce(lim, 30), 1), 100);
begin
  if me is null then raise exception 'انتهت الجلسة. سجّل الدخول من جديد'; end if;
  delete from aei_notif where username = me and at < now() - interval '120 days';
  return jsonb_build_object(
    'unread', (select count(*) from aei_notif where username = me and read_at is null),
    'items', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'title', title, 'body', body, 'tab', tab, 'ref', ref,
        'actor', actor, 'at', (extract(epoch from at) * 1000)::bigint, 'read', read_at is not null) order by id desc)
      from (select * from aei_notif where username = me
              and (before is null or id < before)
              and (coalesce(f, 'all') = 'all' or (f = 'unread' and read_at is null) or kind = any(string_to_array(f, ',')))
            order by id desc limit n) q), '[]'::jsonb));
end $fn$;

create or replace function public.aei_notif_count(p text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare me text := public.aei_who(p);
begin
  if me is null then return jsonb_build_object('unread', 0, 'last', 0); end if;
  return (select jsonb_build_object('unread', count(*) filter (where read_at is null), 'last', coalesce(max(id), 0))
          from aei_notif where username = me);
end $fn$;

-- تعليم كمقروء: ids = null يعني الكل
create or replace function public.aei_notif_read(p text, ids bigint[] default null) returns int
language plpgsql security definer set search_path = public, extensions as $fn$
declare me text := public.aei_who(p); n int;
begin
  if me is null then raise exception 'انتهت الجلسة. سجّل الدخول من جديد'; end if;
  update aei_notif set read_at = now() where username = me and read_at is null and (ids is null or id = any(ids));
  get diagnostics n = row_count; return n;
end $fn$;

revoke all on function public.aei_notify(text[], text, text, text, text, text, text, text), public.aei_admins(), public.aei_sup_users(text),
  public.aei_tg_task_notif(), public.aei_tg_docs_notif() from public, anon, authenticated;
revoke all on function public.aei_notif_list(text, text, int, bigint), public.aei_notif_count(text), public.aei_notif_read(text, bigint[]) from public;
grant execute on function public.aei_notif_list(text, text, int, bigint), public.aei_notif_count(text), public.aei_notif_read(text, bigint[]) to anon, authenticated;

commit;
notify pgrst, 'reload schema';
