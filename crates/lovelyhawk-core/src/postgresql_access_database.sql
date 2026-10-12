SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.json_build_object(
  'oid', d.oid::bigint, 'name', d.datname, 'ownerOid', d.datdba::bigint
)::text, 'UTF8'), 'hex')
FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()
