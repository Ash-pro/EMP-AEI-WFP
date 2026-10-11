-- روابط العرض العامة (قراءة فقط) لتبويبات: التوزيع حسب النقاط / بيانات النقاط / حسب المشرفين
-- يُشغَّل مرة واحدة من Supabase → SQL Editor. آمن لإعادة التشغيل.
-- الرموز تُحفظ في المستند meta/share (تُنشأ وتُوقف من لوحة الإدارة عبر aei_set المحمية بالرمز).
-- الدالة لا تُرجع إلا حقول العرض: لا رقم هوية، لا أيبان، لا تاريخ ميلاد، لا بيانات مؤهل أو راتب.
do $mig$
declare dc text; cc text; ic text;
begin
  select column_name into dc from information_schema.columns
   where table_schema='public' and table_name='aei_docs' and data_type='jsonb' order by ordinal_position limit 1;
  select column_name into ic from information_schema.columns
   where table_schema='public' and table_name='aei_docs' and column_name in ('id','i','doc_id','key')
   order by array_position(array['id','i','doc_id','key'], column_name::text) limit 1;
  select column_name into cc from information_schema.columns
   where table_schema='public' and table_name='aei_docs' and column_name in ('c','coll','col','collection','kind')
   order by array_position(array['c','coll','col','collection','kind'], column_name::text) limit 1;
  if dc is null or ic is null or cc is null then
    raise exception 'aei_docs: أعمدة غير متوقعة (%)', (select string_agg(column_name||' '||data_type, ', ')
      from information_schema.columns where table_schema='public' and table_name='aei_docs');
  end if;
  execute format($f$
    create or replace function public.aei_share_public(k text, t text) returns jsonb
    language plpgsql stable security definer set search_path = public, pg_temp as $fn$
    declare lnk jsonb;
    begin
      if k is null or k not in ('points','pts','sups') or t is null or length(t) < 16 then return null; end if;
      select x.%1$I -> k into lnk from public.aei_docs x where x.%2$I = 'meta' and x.%3$I::text = 'share';
      if lnk is null or coalesce(lnk->>'token','') <> t or coalesce(lnk->>'on','true') = 'false' then return null; end if;
      return jsonb_build_object(
        'emp', coalesce((select jsonb_agg(jsonb_build_object(
            'name', e.d->>'name', 'point', e.d->>'point', 'track', e.d->>'track', 'cat', e.d->>'cat',
            'psup', e.d->>'psup', 'sup', e.d->>'sup', 'region', e.d->>'region', 'area', e.d->>'area',
            'focal', coalesce(e.d->>'focal','false') = 'true',
            'mobile', case when k = 'sups' or (k = 'pts' and (e.d->>'focal' = 'true' or e.d->>'track' = 'أمن'))
                           then coalesce(e.d->>'mobile','') else '' end) order by e.d->>'name')
          from (select x.%1$I as d from public.aei_docs x where x.%2$I = 'emp') e), '[]'::jsonb),
        'point', coalesce((select jsonb_object_agg(x.%3$I::text, x.%1$I) from public.aei_docs x where x.%2$I = 'point'), '{}'::jsonb));
    end $fn$
  $f$, dc, cc, ic);
  revoke all on function public.aei_share_public(text, text) from public;
  grant execute on function public.aei_share_public(text, text) to anon, authenticated;
end $mig$;
notify pgrst, 'reload schema';
