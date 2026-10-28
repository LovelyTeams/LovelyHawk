-- Closed PostgreSQL 16-18 observation. No user SQL, file contents or HBA options.
SELECT pg_catalog.encode(pg_catalog.convert_to(pg_catalog.json_build_object(
  'observedAt', pg_catalog.to_char(pg_catalog.clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'databaseName', pg_catalog.current_database(),
  'databaseOid', (SELECT oid::pg_catalog.int8 FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()),
  'sessionUser', session_user,
  'effectiveUser', current_user,
  'backendPid', pg_catalog.pg_backend_pid(),
  'serverAddress', pg_catalog.host(pg_catalog.inet_server_addr()),
  'serverPort', pg_catalog.inet_server_port(),
  'clientAddress', pg_catalog.host(pg_catalog.inet_client_addr()),
  'clientPort', pg_catalog.inet_client_port(),
  'serverStartedAt', pg_catalog.to_char(pg_catalog.pg_postmaster_start_time() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'configurationLoadedAt', pg_catalog.to_char(pg_catalog.pg_conf_load_time() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'inRecovery', pg_catalog.pg_is_in_recovery(),
  'clusterIdentifierReadable', pg_catalog.has_function_privilege('pg_catalog.pg_control_system()', 'EXECUTE'),
  'clusterIdentifier', NULL,
  'settingsReadable', pg_catalog.current_setting('is_superuser') = 'on' OR pg_catalog.pg_has_role(current_user, 'pg_read_all_settings', 'USAGE'),
  'paths', (SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name', names.name, 'path', settings.setting) ORDER BY names.position)
    FROM (VALUES (1, 'config_file'), (2, 'data_directory'), (3, 'hba_file'), (4, 'ident_file')) AS names(position, name)
    LEFT JOIN pg_catalog.pg_settings AS settings ON settings.name = names.name),
  'origins', (SELECT pg_catalog.json_agg(pg_catalog.json_build_object(
    'name', names.name, 'source', settings.source, 'sourceFile', settings.sourcefile,
    'sourceLine', settings.sourceline, 'pendingRestart', settings.pending_restart) ORDER BY names.position)
    FROM (VALUES (1, 'ssl'), (2, 'logging_collector'), (3, 'log_connections'), (4, 'log_disconnections'),
      (5, 'password_encryption'), (6, 'log_statement'), (7, 'listen_addresses'), (8, 'ssl_min_protocol_version'),
      (9, 'ssl_max_protocol_version'), (10, 'default_transaction_read_only')) AS names(position, name)
    LEFT JOIN pg_catalog.pg_settings AS settings ON settings.name = names.name)
)::text, 'UTF8'), 'hex')
