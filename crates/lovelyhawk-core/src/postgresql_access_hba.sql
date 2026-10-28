-- Only this public projection leaves PostgreSQL. The complete view fingerprint
-- stays private in core, including any authentication options or verifier data.
WITH raw AS MATERIALIZED (
  SELECT * FROM pg_catalog.pg_hba_file_rules ORDER BY rule_number NULLS LAST, file_name, line_number LIMIT 513
), data AS (
  SELECT count(*) > 512 AS too_many,
    coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'ruleNumber', r.rule_number, 'fileName', r.file_name, 'lineNumber', r.line_number,
      'connectionType', r.type, 'databases', r.database, 'users', r.user_name,
      'address', r.address, 'netmask', r.netmask, 'method', r.auth_method,
      'optionNames', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.split_part(opt, '=', 1) ORDER BY ord)
        FROM pg_catalog.unnest(r.options) WITH ORDINALITY AS options(opt, ord)), '[]'::jsonb),
      'hasIssue', r.error IS NOT NULL) ORDER BY rule_number NULLS LAST, file_name, line_number), '[]'::jsonb) AS public_rows,
    coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(r) ORDER BY rule_number NULLS LAST, file_name, line_number), '[]'::jsonb) AS private_rows
  FROM raw r
), bounded AS (
  SELECT *, too_many OR pg_catalog.octet_length(public_rows::text) > 393216 AS overflow FROM data
)
SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
  'overflow', overflow,
  'rows', CASE WHEN overflow THEN '[]'::jsonb ELSE public_rows END,
  'fingerprint', CASE WHEN overflow THEN NULL ELSE pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(private_rows::text, 'UTF8')), 'hex') END
)::text, 'UTF8'), 'hex') FROM bounded
