-- Closed public object/ACL projection; private routine settings are only hashed.
WITH raw AS MATERIALIZED (
  SELECT t.oid, t.typname AS name, CASE WHEN t.typelem<>0 AND t.typsubscript='pg_catalog.array_subscript_handler(internal)'::regprocedure THEN e.typowner ELSE t.typowner END AS owner_oid, t.typnamespace AS namespace_oid, 0 AS sub_id, CASE WHEN t.typelem<>0 AND t.typsubscript='pg_catalog.array_subscript_handler(internal)'::regprocedure THEN e.typacl ELSE t.typacl END AS acl, 'T'::"char" AS acl_type, pg_catalog.jsonb_build_object('kind','type','typeKind',t.typtype,'objectOwnerOid',t.typowner::bigint,'aclTypeOid',CASE WHEN t.typelem<>0 AND t.typsubscript='pg_catalog.array_subscript_handler(internal)'::regprocedure THEN e.oid::bigint ELSE t.oid::bigint END,'aclTypeName',CASE WHEN t.typelem<>0 AND t.typsubscript='pg_catalog.array_subscript_handler(internal)'::regprocedure THEN e.typname ELSE t.typname END) AS detail, NULL::text[] AS private_settings FROM pg_catalog.pg_type t LEFT JOIN pg_catalog.pg_type e ON e.oid=t.typelem AND t.typelem<>0 AND t.typsubscript='pg_catalog.array_subscript_handler(internal)'::regprocedure WHERE t.oid>=16384 OR t.typacl IS NOT NULL OR e.typacl IS NOT NULL
  ORDER BY oid, sub_id LIMIT 2049
), projected AS (
  SELECT oid, sub_id, private_settings, pg_catalog.jsonb_build_object(
    'oid', oid::bigint, 'subId', sub_id, 'name', name,
    'ownerOid', owner_oid::bigint, 'namespaceOid', namespace_oid::bigint,
    'detail', detail, 'aclSource', CASE WHEN acl IS NULL THEN 'builtin-default' ELSE 'explicit' END,
    'acl', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'grantorOid', grantor::bigint, 'granteeOid', grantee::bigint,
      'privileges', privileges, 'grantOptions', grant_options
    ) ORDER BY grantor,grantee) FROM (
      SELECT grantor,grantee,pg_catalog.array_agg(privilege_type ORDER BY privilege_type) AS privileges,
        coalesce(pg_catalog.array_agg(privilege_type ORDER BY privilege_type) FILTER (WHERE is_grantable),'{}'::text[]) AS grant_options
      FROM pg_catalog.aclexplode(coalesce(acl, pg_catalog.acldefault(acl_type, coalesce(owner_oid,10)))) GROUP BY grantor,grantee
    ) grants),'[]'::jsonb)
  ) AS public_row FROM raw
), data AS (
  SELECT pg_catalog.count(*)>2048 AS too_many,
    coalesce(pg_catalog.jsonb_agg(public_row ORDER BY oid,sub_id),'[]'::jsonb) AS public_rows,
    coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('row',public_row,'privateSettings',private_settings) ORDER BY oid,sub_id),'[]'::jsonb) AS private_rows
  FROM projected
), bounded AS (
  SELECT *, too_many OR pg_catalog.octet_length(public_rows::text)>393216 AS overflow FROM data
)
SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
  'overflow',overflow,'omittedDefaults',(SELECT pg_catalog.count(*) FROM pg_catalog.pg_type t LEFT JOIN pg_catalog.pg_type e ON e.oid=t.typelem AND t.typelem<>0 AND t.typsubscript='pg_catalog.array_subscript_handler(internal)'::regprocedure WHERE t.oid<16384 AND t.typacl IS NULL AND e.typacl IS NULL),
  'rows',CASE WHEN overflow THEN '[]'::jsonb ELSE public_rows END,
  'fingerprint',CASE WHEN overflow THEN NULL ELSE pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(private_rows::text,'UTF8')),'hex') END
)::text,'UTF8'),'hex') FROM bounded
