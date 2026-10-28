-- Closed public object/ACL projection; private routine settings are only hashed.
WITH raw AS MATERIALIZED (
  SELECT d.oid, NULL::name AS name, d.defaclrole AS owner_oid, nullif(d.defaclnamespace,0) AS namespace_oid, 0 AS sub_id, d.defaclacl AS acl, d.defaclobjtype AS acl_type, pg_catalog.jsonb_build_object('kind','default','objectType',d.defaclobjtype) AS detail, NULL::text[] AS private_settings FROM pg_catalog.pg_default_acl d
  ORDER BY oid, sub_id LIMIT 513
), projected AS (
  SELECT oid, sub_id, private_settings, pg_catalog.jsonb_build_object(
    'oid', oid::bigint, 'subId', sub_id, 'name', name,
    'ownerOid', owner_oid::bigint, 'namespaceOid', namespace_oid::bigint,
    'detail', detail, 'aclSource', CASE WHEN namespace_oid IS NULL THEN 'future-global' ELSE 'future-schema' END,
    'acl', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'grantorOid', grantor::bigint, 'granteeOid', grantee::bigint,
      'privileges', privileges, 'grantOptions', grant_options
    ) ORDER BY grantor,grantee) FROM (
      SELECT grantor,grantee,pg_catalog.array_agg(privilege_type ORDER BY privilege_type) AS privileges,
        coalesce(pg_catalog.array_agg(privilege_type ORDER BY privilege_type) FILTER (WHERE is_grantable),'{}'::text[]) AS grant_options
      FROM pg_catalog.aclexplode(acl) GROUP BY grantor,grantee
    ) grants),'[]'::jsonb)
  ) AS public_row FROM raw
), data AS (
  SELECT pg_catalog.count(*)>512 AS too_many,
    coalesce(pg_catalog.jsonb_agg(public_row ORDER BY oid,sub_id),'[]'::jsonb) AS public_rows,
    coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('row',public_row,'privateSettings',private_settings) ORDER BY oid,sub_id),'[]'::jsonb) AS private_rows
  FROM projected
), bounded AS (
  SELECT *, too_many OR pg_catalog.octet_length(public_rows::text)>393216 AS overflow FROM data
)
SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
  'overflow',overflow,'omittedDefaults',0,
  'rows',CASE WHEN overflow THEN '[]'::jsonb ELSE public_rows END,
  'fingerprint',CASE WHEN overflow THEN NULL ELSE pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(private_rows::text,'UTF8')),'hex') END
)::text,'UTF8'),'hex') FROM bounded
