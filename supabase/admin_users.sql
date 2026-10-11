-- دخول الإدارة باسم مستخدم وكلمة مرور + مدير أعلى + توقيع سجل التعديلات باسم المنفّذ.
-- آمن لإعادة التشغيل. لا يحتوي أي كلمة مرور: الحسابات تُنشأ من «مدراء النظام» داخل الموقع.
-- رمز العرض (للمشرفين) يبقى كما هو. رمز المدير القديم يبقى فعّالاً إلى أن يُحذف صفّه من aei_pins.

create table if not exists public.aei_users(
  username text primary key, name text not null default '', hash text not null,
  super boolean not null default false, active boolean not null default true,
  fails int not null default 0, locked_until timestamptz, last_login timestamptz,
  created_at timestamptz not null default now());
create table if not exists public.aei_sess(
  th text primary key,
  username text not null references public.aei_users(username) on delete cascade on update cascade,
  created_at timestamptz not null default now(), last_at timestamptz not null default now());
alter table public.aei_users enable row level security;
alter table public.aei_sess enable row level security;
revoke all on public.aei_users, public.aei_sess from anon, authenticated;

-- من صاحب الجلسة؟ (null إن لم تكن جلسة مستخدم صالحة)
create or replace function public.aei_who(p text) returns text
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare u text; k text;
begin
  if p is null or left(p,2) <> 'u_' or length(p) < 40 then return null; end if;
  k := encode(digest(p,'sha256'),'hex');
  select s.username into u from aei_sess s join aei_users x on x.username = s.username
   where s.th = k and x.active and s.last_at > now() - interval '7 days';
  if u is not null then update aei_sess set last_at = now() where th = k and last_at < now() - interval '5 minutes'; end if;
  return u;
end $fn$;

create or replace function public.aei_role(p text) returns text
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare r text;
begin
  if p is null or length(p)<4 then return null; end if;
  if left(p,2) = 'u_' then
    if public.aei_who(p) is not null then return 'admin'; end if;
    return null;
  end if;
  if (select count(*) from aei_fail where at>now()-interval '10 minutes')>=30 then perform pg_sleep(2); end if;
  select role into r from aei_pins where hash=crypt(p,hash) order by role limit 1;
  if r is null then insert into aei_fail default values; perform pg_sleep(1); end if;
  return r;
end $fn$;

-- المدير الأعلى: حساب super، أو رمز المدير القديم ما دام موجوداً
create or replace function public.aei_is_super(p text) returns boolean
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare u text;
begin
  if p is not null and left(p,2) = 'u_' then
    u := public.aei_who(p);
    return u is not null and coalesce((select super from aei_users where username = u), false);
  end if;
  return public.aei_role(p) is not distinct from 'admin';
end $fn$;

create or replace function public.aei_super(p text) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin if not public.aei_is_super(p) then raise exception 'هذه الصلاحية للمدير الأعلى فقط'; end if; end $fn$;

create or replace function public.aei_actor(p text) returns text
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare u text; r text;
begin
  u := public.aei_who(p);
  if u is not null then return coalesce(nullif((select name from aei_users where username = u),''), u); end if;
  r := public.aei_role(p);
  return case r when 'admin' then 'رمز المدير' when 'view' then 'رمز العرض' else '—' end;
end $fn$;

create or replace function public.aei_log(by_ text, type_ text, name_ text, text_ text) returns void
language sql security definer set search_path to 'public','extensions' as $fn$
  insert into aei_docs(coll,id,data) values('log',
    to_char(clock_timestamp(),'YYYYMMDDHH24MISSUS')||substr(md5(random()::text),1,4),
    jsonb_build_object('ts',(extract(epoch from clock_timestamp())*1000)::bigint,'type',type_,'empId','','name',name_,'text',text_,'by',by_));
$fn$;

create or replace function public.aei_user_login(u text, pw text) returns jsonb
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare x aei_users; t text; un text := lower(btrim(coalesce(u,'')));
  bad jsonb := jsonb_build_object('ok',false,'msg','اسم المستخدم أو كلمة المرور غير صحيحة');
begin
  if (select count(*) from aei_fail where at>now()-interval '10 minutes')>=30 then perform pg_sleep(2); end if;
  select * into x from aei_users where username = un;
  if not found or not x.active then insert into aei_fail default values; perform pg_sleep(1); return bad; end if;
  if x.locked_until is not null and x.locked_until > now() then
    return jsonb_build_object('ok',false,'msg','الحساب مقفل مؤقتاً بسبب محاولات خاطئة متكررة. حاول بعد '||ceil(extract(epoch from x.locked_until-now())/60)::int||' دقيقة.');
  end if;
  if pw is null or x.hash <> crypt(pw, x.hash) then
    update aei_users set fails = case when fails+1 >= 5 then 0 else fails+1 end,
      locked_until = case when fails+1 >= 5 then now()+interval '10 minutes' else null end where username = un;
    insert into aei_fail default values; perform pg_sleep(1); return bad;
  end if;
  t := 'u_'||encode(gen_random_bytes(24),'hex');
  delete from aei_sess where last_at < now() - interval '7 days';
  insert into aei_sess(th,username) values(encode(digest(t,'sha256'),'hex'), un);
  update aei_users set fails=0, locked_until=null, last_login=now() where username = un;
  return jsonb_build_object('ok',true,'token',t,'role','admin','user',un,'name',coalesce(nullif(x.name,''),un),'super',x.super);
end $fn$;

create or replace function public.aei_me(p text) returns jsonb
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare u text; r text;
begin
  u := public.aei_who(p);
  if u is not null then
    return (select jsonb_build_object('role','admin','user',username,'name',coalesce(nullif(name,''),username),'super',super) from aei_users where username = u);
  end if;
  r := public.aei_role(p);
  if r is null then return null; end if;
  return jsonb_build_object('role',r,'user',null,'name',null,'super',r='admin');
end $fn$;

create or replace function public.aei_logout(p text) returns void
language sql security definer set search_path to 'public','extensions' as $fn$
  delete from aei_sess where p is not null and th = encode(digest(p,'sha256'),'hex');
$fn$;

create or replace function public.aei_users_list(p text) returns jsonb
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin perform public.aei_super(p);
  return coalesce((select jsonb_agg(jsonb_build_object('username',username,'name',name,'super',super,'active',active,
    'last_login',(extract(epoch from last_login)*1000)::bigint,'locked',locked_until is not null and locked_until>now()) order by super desc, username) from aei_users),'[]'::jsonb);
end $fn$;

-- d: {name, pw?, super, active} · n=true للإضافة
create or replace function public.aei_user_save(p text, u text, d jsonb, n boolean default false) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare un text := lower(btrim(coalesce(u,''))); me text; pw text := d->>'pw'; ex boolean;
  nm text := btrim(coalesce(d->>'name','')); sp boolean := coalesce((d->>'super')::boolean,false); ac boolean := coalesce((d->>'active')::boolean,true);
begin perform public.aei_super(p); me := public.aei_who(p);
  if un !~ '^[a-z0-9_.-]{3,30}$' then raise exception 'اسم المستخدم: 3 إلى 30 خانة من أحرف إنجليزية صغيرة وأرقام'; end if;
  if pw is not null and pw <> '' and length(pw) < 6 then raise exception 'كلمة المرور يجب أن تكون 6 خانات على الأقل'; end if;
  ex := exists(select 1 from aei_users where username = un);
  if n and ex then raise exception 'اسم المستخدم موجود مسبقاً'; end if;
  if un = me and (not ac or not sp) then raise exception 'لا يمكنك تعطيل حسابك أو إزالة صلاحيتك بنفسك'; end if;
  if ex then
    update aei_users set name = nm, super = sp, active = ac, fails = 0, locked_until = null,
      hash = case when coalesce(pw,'') <> '' then crypt(pw, gen_salt('bf')) else hash end where username = un;
    if not ac or (coalesce(pw,'') <> '' and un is distinct from me) then delete from aei_sess where username = un; end if;
  else
    if coalesce(pw,'') = '' then raise exception 'أدخل كلمة المرور'; end if;
    insert into aei_users(username,name,hash,super,active) values(un,nm,crypt(pw,gen_salt('bf')),sp,ac);
  end if;
  if not exists(select 1 from aei_users where super and active) then raise exception 'يجب أن يبقى مدير أعلى واحد مفعّل على الأقل'; end if;
  perform public.aei_log(public.aei_actor(p), case when ex then 'تعديل حساب مدير' else 'إضافة حساب مدير' end, un,
    'الاسم: '||nm||' | الصلاحية: '||case when sp then 'مدير أعلى' else 'مدير' end||' | الحالة: '||case when ac then 'مفعّل' else 'معطّل' end
    ||case when ex and coalesce(pw,'') <> '' then ' | تغيير كلمة المرور' else '' end);
end $fn$;

create or replace function public.aei_user_delete(p text, u text) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare un text := lower(btrim(coalesce(u,'')));
begin perform public.aei_super(p);
  if un = public.aei_who(p) then raise exception 'لا يمكنك حذف حسابك'; end if;
  delete from aei_users where username = un;
  if not found then raise exception 'الحساب غير موجود'; end if;
  if not exists(select 1 from aei_users where super and active) then raise exception 'يجب أن يبقى مدير أعلى واحد مفعّل على الأقل'; end if;
  perform public.aei_log(public.aei_actor(p), 'حذف حساب مدير', un, '');
end $fn$;

create or replace function public.aei_user_pw(p text, o text, n text) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare me text := public.aei_who(p);
begin
  if me is null then raise exception 'انتهت الجلسة. سجّل الدخول من جديد'; end if;
  if n is null or length(n) < 6 then raise exception 'كلمة المرور الجديدة يجب أن تكون 6 خانات على الأقل'; end if;
  if not exists(select 1 from aei_users where username = me and hash = crypt(coalesce(o,''), hash)) then
    perform pg_sleep(1); raise exception 'كلمة المرور الحالية غير صحيحة'; end if;
  update aei_users set hash = crypt(n, gen_salt('bf')) where username = me;
  delete from aei_sess where username = me and th <> encode(digest(p,'sha256'),'hex');
  perform public.aei_log(public.aei_actor(p), 'تغيير كلمة المرور', me, '');
end $fn$;

-- سجل التعديلات: يُوقَّع باسم المنفّذ من الخادم، ولا يقرؤه أو يعدّله أو يحذفه إلا المدير الأعلى
create or replace function public.aei_list(p text, c text) returns jsonb
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare r text:=public.aei_role(p);
begin
  if r is null then raise exception 'رمز الدخول غير صحيح'; end if;
  if r='view' and c not in ('emp','leave','snap','point','plan') then return '[]'::jsonb; end if;
  if c='log' and not public.aei_is_super(p) then return '[]'::jsonb; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id',id,'data',data)) from aei_docs where coll=c),'[]'::jsonb);
end $fn$;

create or replace function public.aei_set(p text, c text, i text, d jsonb) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin perform public.aei_admin(p); perform public.aei_snap();
  if c='snap' then raise exception 'الأرشيف للقراءة فقط'; end if;
  if c='log' then
    if not public.aei_is_super(p) then
      if exists(select 1 from aei_docs where coll='log' and id=i) then raise exception 'سجل التعديلات للقراءة فقط'; end if;
      d := d || jsonb_build_object('by', public.aei_actor(p));
    elsif coalesce(d->>'by','') = '' then d := d || jsonb_build_object('by', public.aei_actor(p));
    end if;
  end if;
  insert into aei_docs(coll,id,data) values(c,i,d) on conflict(coll,id) do update set data=excluded.data, updated_at=now(); end $fn$;

create or replace function public.aei_update(p text, c text, i text, d jsonb) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin perform public.aei_admin(p); perform public.aei_snap();
  if c='snap' then raise exception 'الأرشيف للقراءة فقط'; end if;
  if c='log' and not public.aei_is_super(p) then raise exception 'سجل التعديلات للقراءة فقط'; end if;
  update aei_docs set data=data||d, updated_at=now() where coll=c and id=i;
  if not found then raise exception 'السجل غير موجود'; end if; end $fn$;

create or replace function public.aei_delete(p text, c text, i text) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin perform public.aei_admin(p); perform public.aei_snap();
  if c='snap' then raise exception 'الأرشيف للقراءة فقط'; end if;
  if c='log' and not public.aei_is_super(p) then raise exception 'سجل التعديلات للقراءة فقط'; end if;
  delete from aei_docs where coll=c and id=i; end $fn$;

create or replace function public.aei_focal(p text, i text, v boolean) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare r text:=public.aei_role(p); e jsonb;
begin
  if r is null then raise exception 'رمز الدخول غير صحيح'; end if;
  perform public.aei_snap();
  update aei_docs set data=data||jsonb_build_object('focal',v), updated_at=now() where coll='emp' and id=i returning data into e;
  if not found then raise exception 'السجل غير موجود'; end if;
  insert into aei_docs(coll,id,data) values('log',
    to_char(clock_timestamp(),'YYYYMMDDHH24MISSUS')||substr(md5(random()::text),1,4),
    jsonb_build_object('ts',(extract(epoch from clock_timestamp())*1000)::bigint,
      'type',case when v then 'تعيين فوكال' else 'إلغاء فوكال' end,'empId',i,'name',e->>'name',
      'text',coalesce(e->>'point','')||case when r='view' then ' (برمز العرض)' else '' end,'by',public.aei_actor(p)));
end $fn$;

create or replace function public.aei_set_pin(p text, r text, n text) returns void
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin perform public.aei_admin(p); perform public.aei_super(p);
  if r not in ('admin','view') or n is null or length(n)<6 then raise exception 'رمز غير صالح'; end if;
  if r='admin' and public.aei_who(p) is not null then raise exception 'دخول الإدارة أصبح باسم مستخدم وكلمة مرور'; end if;
  if left(n,2)='u_' then raise exception 'رمز غير صالح'; end if;
  if exists(select 1 from aei_pins where role<>r and hash=crypt(n,hash)) then raise exception 'الرمزان يجب أن يكونا مختلفين'; end if;
  insert into aei_pins(role,hash) values(r,crypt(n,gen_salt('bf'))) on conflict(role) do update set hash=excluded.hash;
  perform public.aei_log(public.aei_actor(p), 'تغيير رمز دخول', case when r='view' then 'رمز العرض' else 'رمز المدير' end, '');
end $fn$;

revoke all on function public.aei_who(text), public.aei_is_super(text), public.aei_super(text), public.aei_actor(text), public.aei_log(text,text,text,text) from public, anon, authenticated;
revoke all on function public.aei_user_login(text,text), public.aei_me(text), public.aei_logout(text), public.aei_users_list(text), public.aei_user_save(text,text,jsonb,boolean), public.aei_user_delete(text,text), public.aei_user_pw(text,text,text) from public;
grant execute on function public.aei_user_login(text,text), public.aei_me(text), public.aei_logout(text), public.aei_users_list(text), public.aei_user_save(text,text,jsonb,boolean), public.aei_user_delete(text,text), public.aei_user_pw(text,text,text) to anon, authenticated;
notify pgrst, 'reload schema';
