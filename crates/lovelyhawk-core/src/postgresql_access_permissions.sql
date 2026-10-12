SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.json_build_object(
  'hba', pg_catalog.has_table_privilege('pg_catalog.pg_hba_file_rules', 'SELECT') AND pg_catalog.has_function_privilege('pg_catalog.pg_hba_file_rules()', 'EXECUTE'),
  'ident', pg_catalog.has_table_privilege('pg_catalog.pg_ident_file_mappings', 'SELECT') AND pg_catalog.has_function_privilege('pg_catalog.pg_ident_file_mappings()', 'EXECUTE'),
  'roles', pg_catalog.has_table_privilege('pg_catalog.pg_roles', 'SELECT') OR pg_catalog.has_table_privilege('pg_catalog.pg_authid', 'SELECT'),
  'memberships', pg_catalog.has_table_privilege('pg_catalog.pg_auth_members', 'SELECT'),
  'database', pg_catalog.has_table_privilege('pg_catalog.pg_database', 'SELECT'),
  'passwords', pg_catalog.has_table_privilege('pg_catalog.pg_authid', 'SELECT')
)::text, 'UTF8'), 'hex')
