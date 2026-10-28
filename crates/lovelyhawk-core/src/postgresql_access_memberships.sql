-- Only this public projection leaves PostgreSQL. The complete view fingerprint
-- stays private in core, including any authentication options or verifier data.
WITH raw AS MATERIALIZED (
  SELECT * FROM pg_catalog.pg_auth_members ORDER BY oid LIMIT 2049
), data AS (
  SELECT count(*) > 2048 AS too_many,
    coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'oid', r.oid::bigint, 'roleOid', r.roleid::bigint, 'memberOid', r.member::bigint,
      'grantorOid', r.grantor::bigint, 'adminOption', r.admin_option,
      'inheritOption', r.inherit_option, 'setOption', r.set_option) ORDER BY oid), '[]'::jsonb) AS public_rows,
    coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(r) ORDER BY oid), '[]'::jsonb) AS private_rows
  FROM raw r
), bounded AS (
  SELECT *, too_many OR pg_catalog.octet_length(public_rows::text) > 393216 AS overflow FROM data
)
SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
  'overflow', overflow,
  'rows', CASE WHEN overflow THEN '[]'::jsonb ELSE public_rows END,
  'fingerprint', CASE WHEN overflow THEN NULL ELSE pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(private_rows::text, 'UTF8')), 'hex') END
)::text, 'UTF8'), 'hex') FROM bounded
