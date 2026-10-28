-- تعديل رقم هوية موظف (للمدير الأعلى فقط) — آمن لإعادة التشغيل.
-- ينقل سجل الموظف إلى الرقم الجديد، ويحدّث كل ما يشير إليه: الإجازات، طلبات التعديل والاستقالة والتسجيل، سجل التعديلات، وبيانات البديل في الاستقالات.
-- الأرشيف الشهري (snap) لا يُعدَّل لأنه صورة تاريخية لما كانت عليه البيانات.

create or replace function public.aei_id_ok(n text) returns boolean language sql immutable as $fn$
  select n ~ '^\d{9}$' and (select sum((d/10)+(d%10)) from (select substr(n,i,1)::int*(case when i%2=1 then 1 else 2 end) d from generate_series(1,9) i) t)%10=0
$fn$;

create or replace function public.aei_emp_rekey(o text, n text, by_ text, why text) returns jsonb
language plpgsql security definer set search_path to 'public','extensions' as $fn$
declare src text; nm text; x text;
begin
  o := regexp_replace(coalesce(o,''),'\D','','g'); n := regexp_replace(coalesce(n,''),'\D','','g');
  if not public.aei_id_ok(n) then raise exception 'رقم الهوية الجديد غير صحيح (9 أرقام ورقم تحقق صحيح)'; end if;
  if o = n then raise exception 'الرقم الجديد مطابق للرقم الحالي'; end if;
  if length(btrim(coalesce(why,''))) < 3 then raise exception 'اكتب سبب التعديل'; end if;
  if exists(select 1 from aei_docs where coll='emp' and id=o) then src := 'emp';
  elsif exists(select 1 from aei_docs where coll='resigned' and id=o) then src := 'resigned';
  else raise exception 'لا يوجد موظف بالرقم الحالي %', o; end if;
  select data->>'name' into x from aei_docs where coll in ('emp','resigned') and id=n limit 1;
  if x is not null then raise exception 'الرقم الجديد مسجّل لموظف آخر: %', x; end if;
  select data->>'name' into nm from aei_docs where coll=src and id=o;
  insert into aei_docs(coll,id,data) select coll, n, data from aei_docs where coll=src and id=o;
  delete from aei_docs where coll=src and id=o;
  update aei_docs set data=jsonb_set(data,'{id}',to_jsonb(n)), updated_at=now() where coll in ('leave','upd','resreq','reg') and data->>'id'=o;
  update aei_docs set data=jsonb_set(data,'{empId}',to_jsonb(n)) where coll='log' and data->>'empId'=o;
  update aei_docs set data=jsonb_set(data,'{repId}',to_jsonb(n)), updated_at=now() where coll in ('emp','resigned') and data->>'repId'=o;
  delete from aei_docs where coll='try' and id in (o,n);
  insert into aei_docs(coll,id,data) values('log', to_char(clock_timestamp(),'YYYYMMDDHH24MISSUS')||substr(md5(random()::text),1,4),
    jsonb_build_object('ts',(extract(epoch from clock_timestamp())*1000)::bigint,'type','تعديل رقم الهوية','empId',n,'name',nm,
      'text','رقم الهوية: '||o||' ← '||n||' | السبب: '||btrim(why),'by',coalesce(by_,'—')));
  return jsonb_build_object('ok',true,'id',n,'name',nm,'coll',src);
end $fn$;
revoke all on function public.aei_emp_rekey(text,text,text,text) from public, anon, authenticated;

create or replace function public.aei_change_id(p text, o text, n text, why text) returns jsonb
language plpgsql security definer set search_path to 'public','extensions' as $fn$
begin
  perform public.aei_super(p);
  perform public.aei_snap();
  return public.aei_emp_rekey(o, n, public.aei_actor(p), why);
end $fn$;
grant execute on function public.aei_change_id(text,text,text,text) to anon, authenticated;

-- تصحيح هوية: احمد حسن سليم الشوبكي (شغّل هذا السطر مرة واحدة فقط، أو استخدم زر «تعديل رقم الهوية» في الموقع بدلاً منه)
-- select public.aei_emp_rekey('942106352','403278906','ashraf','تصحيح رقم هوية خاطئ');
