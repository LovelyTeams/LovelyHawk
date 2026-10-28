SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
  'database', pg_catalog.has_table_privilege('pg_catalog.pg_database','SELECT'),
  'schemas', pg_catalog.has_table_privilege('pg_catalog.pg_namespace','SELECT'),
  'relations', pg_catalog.has_table_privilege('pg_catalog.pg_class','SELECT'),
  'columns', pg_catalog.has_table_privilege('pg_catalog.pg_class','SELECT') AND pg_catalog.has_table_privilege('pg_catalog.pg_attribute','SELECT'),
  'routines', pg_catalog.has_table_privilege('pg_catalog.pg_proc','SELECT'),
  'types', pg_catalog.has_table_privilege('pg_catalog.pg_type','SELECT'),
  'languages', pg_catalog.has_table_privilege('pg_catalog.pg_language','SELECT'),
  'tablespaces', pg_catalog.has_table_privilege('pg_catalog.pg_tablespace','SELECT'),
  'foreign-wrappers', pg_catalog.has_table_privilege('pg_catalog.pg_foreign_data_wrapper','SELECT'),
  'foreign-servers', pg_catalog.has_table_privilege('pg_catalog.pg_foreign_server','SELECT'),
  'large-objects', pg_catalog.has_table_privilege('pg_catalog.pg_largeobject_metadata','SELECT'),
  'parameters', pg_catalog.has_table_privilege('pg_catalog.pg_parameter_acl','SELECT'),
  'defaults', pg_catalog.has_table_privilege('pg_catalog.pg_default_acl','SELECT'),
  'functions', pg_catalog.has_function_privilege('pg_catalog.aclexplode(aclitem[])','EXECUTE') AND pg_catalog.has_function_privilege('pg_catalog.acldefault("char",oid)','EXECUTE')
)::text,'UTF8'),'hex')
