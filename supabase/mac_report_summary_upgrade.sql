drop function if exists public.list_report_summaries_by_key(text, text, integer);

create or replace function public.list_report_summaries_by_key(input_email text, input_key text, input_days integer default 7)
returns table(
  id uuid,
  pin_id uuid,
  owner_user_id uuid,
  owner_email text,
  uploaded_at timestamptz,
  hostname text,
  scan_time timestamptz,
  risk_level text,
  evidence_score integer,
  report_json jsonb
)
language sql
stable
security definer
set search_path = public
as $$
  with authorized as (
    select public.validate_key_session(input_email, input_key) as ok
  ),
  filtered_reports as (
    select r.*
    from public.reports r, authorized a
    where a.ok
      and lower(r.owner_email) = lower(input_email)
      and r.uploaded_at >= now() - make_interval(days => greatest(3, least(coalesce(input_days, 7), 30)))
    order by r.uploaded_at desc
    limit 100
  )
  select
    r.id,
    r.pin_id,
    r.owner_user_id,
    r.owner_email,
    r.uploaded_at,
    r.hostname,
    r.scan_time,
    r.risk_level,
    r.evidence_score,
    jsonb_build_object(
      'scanTime', r.scan_time::text,
      'hostname', r.hostname,
      'platform', coalesce(r.report_json -> 'platform', to_jsonb('windows'::text)),
      'platformVersion', coalesce(r.report_json -> 'platformVersion', 'null'::jsonb),
      'scannerVersion', coalesce(r.report_json -> 'scannerVersion', 'null'::jsonb),
      'scanProfile', coalesce(r.report_json -> 'scanProfile', 'null'::jsonb),
      'highestResult', coalesce(r.report_json -> 'highestResult', to_jsonb(r.risk_level)),
      'confidence', coalesce(r.report_json -> 'confidence', to_jsonb(''::text)),
      'evidenceSources', coalesce(r.report_json -> 'evidenceSources', '{}'::jsonb),
      'timeline', '[]'::jsonb,
      'sessions', case
        when jsonb_typeof(r.report_json -> 'sessions') = 'array'
          and jsonb_array_length(r.report_json -> 'sessions') > 0
        then jsonb_build_array((r.report_json -> 'sessions') -> 0)
        else '[]'::jsonb
      end,
      'findings', '[]'::jsonb,
      'limitations', '[]'::jsonb,
      '_summary', jsonb_build_object(
        'findingCount', case when jsonb_typeof(r.report_json -> 'findings') = 'array' then jsonb_array_length(r.report_json -> 'findings') else 0 end,
        'confirmedCount', jsonb_array_length(jsonb_path_query_array(coalesce(r.report_json -> 'findings', '[]'::jsonb), '$[*] ? (@.confidenceLevel == "Confirmed" || @.classification == "Confirmed" || @.classification == "Confirmed Exploit")')),
        'likelyCount', jsonb_array_length(jsonb_path_query_array(coalesce(r.report_json -> 'findings', '[]'::jsonb), '$[*] ? (@.confidenceLevel == "Likely" || @.classification == "Likely")')),
        'possibleCount', jsonb_array_length(jsonb_path_query_array(coalesce(r.report_json -> 'findings', '[]'::jsonb), '$[*] ? (@.confidenceLevel == "Possible" || @.classification == "Possible")')),
        'sessionCount', case when jsonb_typeof(r.report_json -> 'sessions') = 'array' then jsonb_array_length(r.report_json -> 'sessions') else 0 end,
        'robloxLogCount', case when jsonb_typeof(r.report_json -> 'robloxLogs') = 'array' then jsonb_array_length(r.report_json -> 'robloxLogs') else 0 end,
        'summaryOnly', true
      )
    ) as report_json
  from filtered_reports r
  order by r.uploaded_at desc;
$$;

grant execute on function public.list_report_summaries_by_key(text, text, integer) to anon, authenticated;
