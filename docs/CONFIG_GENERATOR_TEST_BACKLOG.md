# Config-generator 测试迁移待办

原 GPUI `config_generator.rs`(受保护脏基线) 的 90 个遗留测试 ID 中，39 个已有通过的 Electron/core 替代，51 个仍待补齐。
GPUI crate 已于 2026-08-25 移除；脏基线源码归档在 `docs/legacy/config-generator-baseline.rs.txt`
(SHA-256 `7d66302eb9d58a09b09cc95f7b074057357d11c1f1f158ec37a6de56d37ac19e`)，编写替代测试时以它为行为参照。
本文件取代原 `docs/ELECTRON_CONFIG_TEST_MIGRATION.json` 与 `scripts/electron-config-test-ledger-gate.ps1`；
规则不变：Pending / 计划中 / 仅存在的测试不算完成，替代测试必须实际运行并通过。

## 待补齐 (51)

### backend (2)

- [ ] `database_assignment_schema_revision_and_dirty_version_mismatch_fail_closed`
  - 说明: Adjacent typed backend behavior exists, but no exact replacement test covers this legacy lifecycle/revision contract. It remains Pending rather than inheriting the full backend run.
- [ ] `preview_is_bounded_and_never_interprets_text`
  - 计划替代: `config_api::tests::previews_are_globally_bounded_and_copy_requires_current_revision`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::previews_are_globally_bounded_and_copy_requires_current_revision -- --exact`
  - 计划替代: `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "preview_is_bounded_and_never_interprets_text"`
  - 计划替代: `configuration process-boundary validators > validates opaque draft metadata without accepting leaked full contents`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "validates opaque draft metadata without accepting leaked full contents"`
  - 计划替代: `electron-cdp::config-generator::preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron test:debug`
  - 说明: Backend and renderer exact tests now prove the 32 KiB UTF-8 boundary, aggregate metadata consistency, explicit truncation state and React text-only hostile rendering. The mapping remains Pending because its recorded process-level Electron CDP hostile-preview check has not been implemented; no unit result is relabeled as CDP evidence.

### cdp (12)

- [ ] `goal_catalog_reference_viewport_keeps_three_columns_visible_and_non_overlapping`
  - 计划替代: `electron-cdp::config-generator::goal_catalog_reference_viewport_keeps_three_columns_visible_and_non_overlapping`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `apache_catalog_renders_inline_editor_and_preview_in_the_three_column_workspace`
  - 计划替代: `apache_config::tests::apache_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact`
    运行: `cargo test --locked --package lovelyres-core apache_config::tests::apache_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact -- --exact`
  - 计划替代: `config_api::tests::apache_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::apache_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed -- --exact`
  - 计划替代: `configuration process-boundary validators > apache_catalog_inline_editor_and_preview_contract_is_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "apache_catalog_inline_editor_and_preview_contract_is_closed"`
  - 计划替代: `config generator request lifecycle > apache_catalog_inline_editor_and_preview_dom_prerequisites_are_typed`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "apache_catalog_inline_editor_and_preview_dom_prerequisites_are_typed"`
  - 计划替代: `electron-cdp::config-generator::apache_catalog_renders_inline_editor_and_preview_in_the_three_column_workspace`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial replacement evidence is now exact across the four applicable configuration layers. Core owns the finite ClientBodyLimit identity and exact directive bytes. The sidecar projects one bounded catalog row and applies add/remove only through current revisions, rejecting stale or hostile input without echo or mutation. The strict shared contract accepts only catalog, typed input and bounded draft shapes and denies renderer-supplied DOM, geometry, markup, preview, copy, revision or raw-content authority. The production React page now renders a stable Apache feature-row selector followed in DOM order by a finite inline editor that contains only escaped catalog metadata; the real checkbox emits typed ClientBodyLimit intent, invalidates stale preview and rebuilds strict current input. These unit tests do not establish the legacy 1200x800 geometry: the final packaged Electron page still needs a named webContents.debugger/CDP plus capturePage assertion for the actual three-column workspace, visible preview and exact editor.origin.y == row.bottom adjacency without overlap or clipping. That Electron-native probe was NOT_RUN, so the CDP replacement and this mapping remain Pending.
- [ ] `mysql_catalog_renders_inline_editor_and_preview_in_the_three_column_workspace`
  - 计划替代: `mysql_config::tests::mysql_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact`
    运行: `cargo test --locked --package lovelyres-core mysql_config::tests::mysql_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact -- --exact`
  - 计划替代: `config_api::tests::mysql_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::mysql_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed -- --exact`
  - 计划替代: `configuration process-boundary validators > mysql_catalog_inline_editor_and_preview_contract_is_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "mysql_catalog_inline_editor_and_preview_contract_is_closed"`
  - 计划替代: `config generator request lifecycle > mysql_catalog_inline_editor_and_preview_dom_prerequisites_are_typed`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "mysql_catalog_inline_editor_and_preview_dom_prerequisites_are_typed"`
  - 计划替代: `electron-cdp::config-generator::mysql_catalog_renders_inline_editor_and_preview_in_the_three_column_workspace`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial replacement evidence is now exact across all four applicable configuration layers. Core owns the finite MaxConnections identity, its single max_connections key, typed 1 through 100000 range and byte-exact add/remove output. The sidecar projects one bounded catalog row and applies 400/500/removal only through current revisions, rejecting stale or hostile input without echo or mutation. The strict shared contract accepts only finite catalog, typed input and bounded draft shapes and denies renderer-supplied input handlers, DOM, geometry, markup, preview, copy, revision or raw-content authority. The production React page wires the selected MySQL MaxConnections row to a finite inline numeric input; its real checkbox and input emit only typed reducer intents, invalidate stale preview and rebuild strict current input, while previews remain escaped plain text. These unit tests do not establish the legacy 1200x800 geometry: the final packaged Electron page still needs a named webContents.debugger/CDP plus capturePage assertion for the actual three-column workspace, visible preview and exact editor.origin.y == row.bottom adjacency without overlap or clipping. That Electron-native probe is NOT_RUN by instruction, so the CDP replacement and this mapping remain Pending.
- [ ] `postgresql_and_mariadb_catalogs_render_versions_search_and_inline_editors`
  - 计划替代: `config generator stable DOM contract > provides deterministic mode and version test ids`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-state.test.ts -t "provides deterministic mode and version test ids"`
  - 计划替代: `postgresql_config::tests::postgresql_and_mariadb_catalog_versions_search_and_inline_editor_prerequisites_are_typed`
    运行: `cargo test --locked --package lovelyres-core postgresql_config::tests::postgresql_and_mariadb_catalog_versions_search_and_inline_editor_prerequisites_are_typed -- --exact`
  - 计划替代: `config_api::tests::postgresql_and_mariadb_catalog_versions_search_and_inline_editor_prerequisites_are_current`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::postgresql_and_mariadb_catalog_versions_search_and_inline_editor_prerequisites_are_current -- --exact`
  - 计划替代: `configuration process-boundary validators > postgresql_and_mariadb_catalog_versions_search_and_inline_editor_contract_is_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "postgresql_and_mariadb_catalog_versions_search_and_inline_editor_contract_is_closed"`
  - 计划替代: `config generator request lifecycle > postgresql_and_mariadb_catalog_versions_search_and_inline_editor_dom_prerequisites_are_typed`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "postgresql_and_mariadb_catalog_versions_search_and_inline_editor_dom_prerequisites_are_typed"`
  - 计划替代: `electron-cdp::config-generator::postgresql_and_mariadb_catalogs_render_versions_search_and_inline_editors`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial replacement evidence is now exact across all four applicable configuration layers while preserving the legacy Failed outcome. Core owns the reviewed PostgreSQL 14 through 18 and MariaDB 10.11/11.4/11.8/12.3 version sets, exact lock-wait and retention search aliases, typed numeric ranges, MariaDB BinaryLogging dependency and byte-exact generated directives. The sidecar projects only those bounded catalog identities and applies current typed inline values through revision-bound drafts, rejecting stale or hostile input without echo or mutation. The strict shared contract accepts finite catalog/input/draft shapes and denies renderer-supplied handlers, search results, DOM, geometry, markup, preview, copy, revision or raw-content authority. The production React page uses deterministic version IDs, tokenized alias search, filters unrelated feature rows and wires the selected PostgreSQL lock-wait and MariaDB retention rows to finite numeric editors that emit only typed reducer intents; current preview state remains revision-bound and hostile preview text stays escaped. These unit tests do not establish the legacy 1200x800 geometry: the final packaged Electron page still needs a named webContents.debugger/CDP plus capturePage assertion for actual selector visibility, quick-preview visibility and exact editor.origin.y == row.bottom adjacency without overlap or clipping. That Electron-native probe is NOT_RUN by instruction, so the CDP replacement and this mapping remain Pending.
- [ ] `redis_catalog_renders_editor_directly_below_the_selected_row`
  - 计划替代: `redis_config::tests::redis_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact`
    运行: `cargo test --locked --package lovelyres-core redis_config::tests::redis_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact -- --exact`
  - 计划替代: `config_api::tests::redis_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::redis_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed -- --exact`
  - 计划替代: `configuration process-boundary validators > redis_catalog_inline_editor_and_preview_contract_is_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "redis_catalog_inline_editor_and_preview_contract_is_closed"`
  - 计划替代: `config generator request lifecycle > redis_catalog_inline_editor_and_preview_dom_prerequisites_are_typed`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "redis_catalog_inline_editor_and_preview_dom_prerequisites_are_typed"`
  - 计划替代: `electron-cdp::config-generator::redis_catalog_renders_editor_directly_below_the_selected_row`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial replacement evidence is now exact across all four applicable configuration layers while preserving the legacy Passed outcome. Core owns the SlowLog catalog identity, reviewed metadata, typed threshold and queue-length ranges and byte-exact selected/removal output without inventing defaults. The sidecar projects the nine reviewed Redis choices and bounded SlowLog row, applies both inline values only through current revision-bound drafts, keeps current copy bytes equal to preview and rejects stale or hostile values without echo or mutation. The strict shared contract accepts finite catalog/input shapes but denies catalog- or renderer-supplied handlers, inline editor, search, DOM bounds, markup, preview, copy, revision or raw-content authority. The production React page now wires only the selected Redis SlowLog row to two finite numeric inputs; they emit typed reducer intents, preserve current input/revision semantics, render the editor as the row's next DOM sibling and keep hostile preview text escaped. CSS provides the reviewed full-width zero-gap inline-layout prerequisite. These unit tests do not establish the legacy 1200x800 geometry: the final packaged Electron page still needs a named webContents.debugger/CDP plus capturePage assertion that the Redis configuration table, SlowLog row/editor and quick preview are visible and that editor.getBoundingClientRect().top exactly equals row.getBoundingClientRect().bottom without overlap or clipping. That Electron-native probe is NOT_RUN by instruction, so the CDP replacement and this mapping remain Pending.
- [ ] `tomcat_catalog_renders_editor_directly_below_the_selected_row`
  - 计划替代: `electron-cdp::config-generator::tomcat_catalog_renders_editor_directly_below_the_selected_row`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `nginx_quick_preview_scrolls_independently_through_long_output`
  - 计划替代: `electron-cdp::config-generator::nginx_quick_preview_scrolls_independently_through_long_output`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `redis_quick_preview_scrolls_to_the_last_generated_directive`
  - 计划替代: `electron-cdp::config-generator::redis_quick_preview_scrolls_to_the_last_generated_directive`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `mariadb_quick_preview_scrolls_independently_through_all_fifteen_features`
  - 计划替代: `electron-cdp::config-generator::mariadb_quick_preview_scrolls_independently_through_all_fifteen_features`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `tomcat_three_artifact_preview_scrolls_independently_to_the_last_file`
  - 计划替代: `electron-cdp::config-generator::tomcat_three_artifact_preview_scrolls_independently_to_the_last_file`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `visual_workspace_layout_keeps_small_windows_scrollable_and_panels_bounded`
  - 计划替代: `electron-cdp::config-generator::visual_workspace_layout_keeps_small_windows_scrollable_and_panels_bounded`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.
- [ ] `short_viewport_scrolls_page_from_header_to_full_preview`
  - 计划替代: `electron-cdp::config-generator::short_viewport_scrolls_page_from_header_to_full_preview`
    运行: `pnpm --dir electron test:debug`
  - 说明: This is a GPUI geometry, viewport, scrolling, or inline-layout assertion. It requires a named final-candidate Electron CDP assertion and capture; none has passing evidence yet.

### core (21)

- [ ] `visual_search_is_bounded_ascii_case_insensitive_and_keeps_only_parent_chains`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `visual_search_uses_reviewed_schema_meaning_but_never_defaults_or_row_values`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `schema_value_domains_are_detailed_and_reviewed_literals_are_searchable`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `schema_catalog_covers_parameters_absent_from_the_document_without_mutation`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `search_never_indexes_sensitive_text_from_any_visual_document_source`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `configuration_explanations_use_fail_closed_meaning_levels_without_values`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `model_starts_with_independent_quick_and_competition_documents`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `schema_selection_rejects_cross_artifact_and_resets_when_artifact_changes`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `partial_schema_is_metadata_only_and_preserves_local_draft_permission`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `schema_metadata_lookup_is_path_qualified_and_redacts_before_ui_copy`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `documented_defaults_show_for_five_goldendb_matches_without_changing_document`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `documented_defaults_render_empty_text_but_hide_invalid_sensitive_metadata`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `readable_generated_json_pg_auto_yaml_and_xml_enter_the_selector`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `mysql_auto_cnf_is_selectable_byte_exact_non_secret_and_fully_read_only`
  - 计划替代: `database_config::tests::mysql_auto_cnf_core_fixture_is_byte_exact_structured_and_non_secret`
    运行: `cargo test --locked --package lovelyres-core database_config::tests::mysql_auto_cnf_core_fixture_is_byte_exact_structured_and_non_secret -- --exact`
  - 计划替代: `database_config::tests::mysql_and_mariadb_p0_c_inventory_rows_are_typed_and_read_only`
    运行: `cargo test --locked --package lovelyres-core database_config::tests::mysql_and_mariadb_p0_c_inventory_rows_are_typed_and_read_only -- --exact`
  - 计划替代: `database_config_schema::tests::newly_visible_artifacts_do_not_inherit_unrelated_schemas`
    运行: `cargo test --locked --package lovelyres-core database_config_schema::tests::newly_visible_artifacts_do_not_inherit_unrelated_schemas -- --exact`
  - 计划替代: `config_api::tests::catalog_exposes_mysql_auto_cnf_metadata_without_a_content_capability`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::catalog_exposes_mysql_auto_cnf_metadata_without_a_content_capability -- --exact`
  - 计划替代: `configuration process-boundary validators > accepts auto.cnf selector metadata and rejects injected content capabilities`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "accepts auto.cnf selector metadata and rejects injected content capabilities"`
  - 计划替代: `config generator read-only artifact boundary > selects auto.cnf while preview copy save and mutation remain unavailable`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-read-only.test.tsx -t "selects auto.cnf while preview copy save and mutation remain unavailable"`
  - 计划替代: `config generator read-only artifact content > loads auto.cnf bytes through a bounded capability and copies or saves without mutation`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-read-only.test.tsx -t "loads auto.cnf bytes through a bounded capability and copies or saves without mutation"`
  - 说明: Core exact evidence covers artifact identity, schema isolation, fixture byte preservation and the non-secret control. Electron now proves the real catalog-v2 auto.cnf selector, fixed filename metadata, generated/read-only notice, strict rejection of injected content/capability/path fields and absence of every preview/copy/save/edit/apply/deploy action. The mapping remains Pending because it still lacks an authorized artifact-bound byte ingress, core-owned secret scan, bounded read-only draft handle and native create-only save payload; the fixture is not presented as real target data.
- [ ] `readable_read_only_documents_preserve_bytes_and_reject_every_mutation`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `tidb_auxiliary_toml_catalog_is_byte_exact_read_only_and_schema_isolated`
  - 计划替代: `database_config::tests::tidb_auxiliary_toml_core_fixtures_are_byte_exact_structured_and_non_secret`
    运行: `cargo test --locked --package lovelyres-core database_config::tests::tidb_auxiliary_toml_core_fixtures_are_byte_exact_structured_and_non_secret -- --exact`
  - 计划替代: `database_config::tests::tidb_auxiliary_toml_artifacts_preserve_official_roles_and_fail_closed`
    运行: `cargo test --locked --package lovelyres-core database_config::tests::tidb_auxiliary_toml_artifacts_preserve_official_roles_and_fail_closed -- --exact`
  - 计划替代: `database_config_schema::tests::tidb_auxiliary_components_do_not_inherit_tidb_server_8_5_7_schema`
    运行: `cargo test --locked --package lovelyres-core database_config_schema::tests::tidb_auxiliary_components_do_not_inherit_tidb_server_8_5_7_schema -- --exact`
  - 计划替代: `config generator read-only artifact boundary > binds TiDB auxiliary selection, filename, notice and mutation denial to each component`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-read-only.test.tsx -t "binds TiDB auxiliary selection, filename, notice and mutation denial to each component"`
  - 说明: Core exact evidence now covers every auxiliary component identity, representative TOML bytes, secret control and schema isolation. The mapping remains Pending because the low-level line parser is intentionally editable and Electron has not yet proved the artifact policy enforces selector/selection/save filename/read-only notice and complete mutation denial.
- [ ] `gbase_8a_cluster_common_json_keeps_component_identity_and_read_only_boundaries`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `yashandb_23_5_yasdb_ini_is_selectable_byte_exact_and_fully_read_only`
  - 计划替代: `database_config::tests::yashandb_23_5_yasdb_ini_core_fixture_is_byte_exact_structured_and_non_secret`
    运行: `cargo test --locked --package lovelyres-core database_config::tests::yashandb_23_5_yasdb_ini_core_fixture_is_byte_exact_structured_and_non_secret -- --exact`
  - 计划替代: `database_config::tests::yashan_23_5_keeps_text_source_and_vendor_owned_binary_state_separate`
    运行: `cargo test --locked --package lovelyres-core database_config::tests::yashan_23_5_keeps_text_source_and_vendor_owned_binary_state_separate -- --exact`
  - 计划替代: `database_config_schema::tests::yashandb_yasdb_ini_has_one_exact_fixed_production_schema`
    运行: `cargo test --locked --package lovelyres-core database_config_schema::tests::yashandb_yasdb_ini_has_one_exact_fixed_production_schema -- --exact`
  - 计划替代: `database_config_schema_domestic::tests::yashandb_schema_requires_the_exact_build_and_document_family`
    运行: `cargo test --locked --package lovelyres-core database_config_schema_domestic::tests::yashandb_schema_requires_the_exact_build_and_document_family -- --exact`
  - 计划替代: `config generator read-only artifact boundary > binds yasdb.ini selection, save filename, notice and mutation denial to the exact Yashan build`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-read-only.test.tsx -t "binds yasdb.ini selection, save filename, notice and mutation denial to the exact Yashan build"`
  - 说明: Core exact evidence now covers yasdb.ini identity, CRLF byte preservation, secret control and the one exact 23.5.4.100 production schema family. The mapping remains Pending because Electron has not yet proved artifact-bound selection, suggested filename/save output, read-only notice and parser mutation enforcement.
- [ ] `sequoia_quick_deploy_cross_role_imports_are_whole_sensitive_opaque_and_keep_catalog_name`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `sequoia_quick_deploy_sensitive_and_local_opaque_rows_block_copy_but_keep_safe_sibling`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.
- [ ] `sequoia_quick_deploy_opaque_rows_redact_and_all_mutation_starter_deploy_paths_stay_closed`
  - 说明: No exact UI-independent replacement test has been identified for this GPUI-owned visual/schema behavior. The full core run is not treated as blanket evidence.

### renderer (16)

- [ ] `apache_quick_configurations_stack_remove_reset_and_open_visual`
  - 计划替代: `apache_config::tests::apache_stack_remove_reset_and_structured_visual_prerequisite_are_byte_exact`
    运行: `cargo test --locked --package lovelyres-core apache_config::tests::apache_stack_remove_reset_and_structured_visual_prerequisite_are_byte_exact -- --exact`
  - 计划替代: `config_api::tests::apache_stack_remove_reset_revisions_are_consistent_and_fail_closed`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::apache_stack_remove_reset_revisions_are_consistent_and_fail_closed -- --exact`
  - 计划替代: `configuration process-boundary validators > apache_stack_remove_reset_transitions_are_closed_and_reject_visual_injection`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "apache_stack_remove_reset_transitions_are_closed_and_reject_visual_injection"`
  - 计划替代: `config generator request lifecycle > apache_stack_remove_reset_and_preview_state_are_isolated`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "apache_stack_remove_reset_and_preview_state_are_isolated"`
  - 计划替代: `config generator request lifecycle > lifecycle_rejects_late_save_completions`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "lifecycle_rejects_late_save_completions"`
  - 计划替代: `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "wires unmount cleanup and every async action through the request lane"`
  - 计划替代: `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "preview_is_bounded_and_never_interprets_text"`
  - 计划替代: `electron-config-visual-wiring::apache_quick_configuration_opens_byte_exact_structured_visual_document`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial evidence is now exact: core proves typed stack/remove/reset plus a byte-exact ApacheVisualDocument parsing prerequisite; the sidecar proves revision-scoped preview/copy consistency and hostile/stale fail-closed behavior; the shared contract rejects unsafe dependency combinations and visual-capability injection; and the production renderer proves real checkbox intents, dependency cascade, cross-product isolation, reset wiring and stale-preview rejection. Existing exact lifecycle and hostile-text tests cover late/unmount rejection and escaped plain-text rendering. The mapping remains Pending because Electron still lacks an ApacheVisualDocument capability from the sidecar through the typed aggregate into a renderer structured visual editor, and therefore lacks the legacy byte-exact open-visual action. The current escaped <pre> preview is intentionally not treated as structured visual parity; the separate geometry CDP mapping also remains Pending.
- [ ] `mysql_quick_configurations_stack_remove_reset_preview_save_and_open_visual`
  - 计划替代: `mysql_config::tests::mysql_quick_stack_remove_reset_save_and_structured_visual_prerequisite_are_byte_exact`
    运行: `cargo test --locked --package lovelyres-core mysql_config::tests::mysql_quick_stack_remove_reset_save_and_structured_visual_prerequisite_are_byte_exact -- --exact`
  - 计划替代: `config_api::tests::mysql_quick_stack_remove_reset_preview_and_save_prerequisites_fail_closed`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::mysql_quick_stack_remove_reset_preview_and_save_prerequisites_fail_closed -- --exact`
  - 计划替代: `configuration process-boundary validators > mysql_quick_stack_remove_reset_save_transitions_are_closed_and_dependency_safe`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "mysql_quick_stack_remove_reset_save_transitions_are_closed_and_dependency_safe"`
  - 计划替代: `config generator request lifecycle > mysql_quick_stack_remove_reset_preview_and_save_prerequisites_are_isolated`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "mysql_quick_stack_remove_reset_preview_and_save_prerequisites_are_isolated"`
  - 计划替代: `config generator request lifecycle > lifecycle_rejects_late_save_completions`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "lifecycle_rejects_late_save_completions"`
  - 计划替代: `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "wires unmount cleanup and every async action through the request lane"`
  - 计划替代: `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "preview_is_bounded_and_never_interprets_text"`
  - 计划替代: `electron-config-native-save::mysql_quick_configuration_exports_current_revision_byte_exact_create_only`
    运行: `pnpm --dir electron test:debug`
  - 计划替代: `electron-config-visual-wiring::mysql_quick_configuration_opens_byte_exact_structured_visual_document`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial evidence is now exact: core proves typed MySQL stack/remove/reset, dependency safety, byte-exact create-new save and a structured MySqlOption parser prerequisite; the sidecar proves revision-scoped preview/copy/export bytes plus stale, dependency and hostile-input failure; the shared contract closes all complete transition shapes and rejects save/path/visual/content capability injection; and the production renderer proves real checkbox intents, dependency cascade, cross-product isolation, reset wiring, current-artifact export inputs and late-export rejection. Existing lifecycle and hostile-text tests cover late/unmount failure and escaped plain-text rendering. Production source audit found the renderer-to-validated-IPC-to-current-sidecar-artifact route and native fs.open wx create-only save, but this legacy scenario still lacks an executed byte-exact native-dialog integration test. More importantly, Electron has no mysql-option-file visual capability from the sidecar through the typed aggregate into a renderer structured visual editor, so the byte-exact open-visual action is absent. The escaped <pre> preview is intentionally not treated as structured visual parity; both missing production acceptance tests and the separate geometry CDP mapping remain Pending.
- [ ] `postgresql_and_mariadb_quick_interactions_are_isolated_and_save_create_new`
  - 计划替代: `postgresql_config::tests::postgresql_quick_version_stack_remove_reset_and_save_prerequisite_is_byte_exact`
    运行: `cargo test --locked --package lovelyres-core postgresql_config::tests::postgresql_quick_version_stack_remove_reset_and_save_prerequisite_is_byte_exact -- --exact`
  - 计划替代: `mariadb_config::tests::mariadb_quick_dependency_stack_remove_reset_save_and_visual_prerequisite_are_byte_exact`
    运行: `cargo test --locked --package lovelyres-core mariadb_config::tests::mariadb_quick_dependency_stack_remove_reset_save_and_visual_prerequisite_are_byte_exact -- --exact`
  - 计划替代: `config_api::tests::postgresql_and_mariadb_quick_interactions_are_isolated_and_save_prerequisites_are_current`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::postgresql_and_mariadb_quick_interactions_are_isolated_and_save_prerequisites_are_current -- --exact`
  - 计划替代: `configuration process-boundary validators > postgresql_and_mariadb_quick_transitions_are_isolated_dependency_safe_and_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "postgresql_and_mariadb_quick_transitions_are_isolated_dependency_safe_and_closed"`
  - 计划替代: `config generator request lifecycle > postgresql_and_mariadb_quick_interactions_are_isolated_and_save_prerequisites_are_current`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "postgresql_and_mariadb_quick_interactions_are_isolated_and_save_prerequisites_are_current"`
  - 计划替代: `config generator request lifecycle > lifecycle_rejects_late_save_completions`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "lifecycle_rejects_late_save_completions"`
  - 计划替代: `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "wires unmount cleanup and every async action through the request lane"`
  - 计划替代: `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "preview_is_bounded_and_never_interprets_text"`
  - 计划替代: `electron-config-native-save::postgresql_and_mariadb_export_current_revision_byte_exact_create_only`
    运行: `pnpm --dir electron test:debug`
  - 计划替代: `electron-config-visual-wiring::mariadb_quick_configuration_opens_byte_exact_structured_visual_document`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial evidence is now exact across both products. PostgreSQL core proves version-aware capacity and logging, independent removal, reset and create-new save; MariaDB core proves binlog dependency stack/cascade prerequisites, the 10.11 transition, reset, create-new save and a structured visual-parser prerequisite. The sidecar proves deterministic cross-product reconstruction, current-revision preview/copy/export bytes and stale/hostile/dependency failure. The strict contract rejects PostgreSQL 14/15 reserved_connections drift, MariaDB dependency violations, combined-state injection and renderer-supplied save/path/visual/content capabilities. The production renderer proves real checkbox intents, version normalization, dependency cascade, per-product switch/reset isolation, stale-preview rejection and current-artifact export arguments; existing exact lifecycle and hostile-text tests cover late/unmount failure and escaped rendering. Production source audit confirms the validated IPC and native fs.open wx create-only route, but this legacy scenario still lacks an executed byte-exact native-dialog acceptance test. Electron also lacks a MariaDB LineConfigVisualDocument capability from the sidecar through the typed aggregate into a renderer structured visual editor. The escaped <pre> preview is not structured visual parity; both production acceptance points and the separate geometry CDP mapping remain Pending.
- [ ] `redis_quick_configurations_stack_remove_reset_and_save_without_overwrite`
  - 计划替代: `redis_config::tests::redis_quick_stack_remove_reset_and_save_prerequisite_is_byte_exact`
    运行: `cargo test --locked --package lovelyres-core redis_config::tests::redis_quick_stack_remove_reset_and_save_prerequisite_is_byte_exact -- --exact`
  - 计划替代: `config_api::tests::redis_quick_stack_remove_reset_preview_and_save_prerequisites_are_current`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::redis_quick_stack_remove_reset_preview_and_save_prerequisites_are_current -- --exact`
  - 计划替代: `configuration process-boundary validators > redis_quick_stack_remove_reset_save_transitions_are_dependency_safe_and_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "redis_quick_stack_remove_reset_save_transitions_are_dependency_safe_and_closed"`
  - 计划替代: `config generator request lifecycle > redis_quick_stack_remove_reset_and_save_prerequisites_are_current`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "redis_quick_stack_remove_reset_and_save_prerequisites_are_current"`
  - 计划替代: `config generator request lifecycle > lifecycle_rejects_late_save_completions`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "lifecycle_rejects_late_save_completions"`
  - 计划替代: `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "wires unmount cleanup and every async action through the request lane"`
  - 计划替代: `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "preview_is_bounded_and_never_interprets_text"`
  - 计划替代: `electron-config-native-save::redis_quick_configuration_exports_current_revision_byte_exact_without_overwrite`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial evidence is now exact across the four applicable configuration layers. Core proves the Redis 8.10 stack, independent timeout removal, mandatory bounded memory, at-least-one AOF/RDB persistence, byte-exact reset and create-new save prerequisite. The sidecar proves deterministic current-revision preview/copy/export bytes, stale capability rejection and no mutation after invalid or hostile revisions. The strict contract requires memory plus one persistence mode and rejects renderer-supplied mutation, save, path, visual, raw-content, markup, copy and revision capabilities. The production renderer invokes real typed checkbox intents, refuses mandatory-memory and last-persistence removal without revision or preview drift, resets catalog defaults, rejects stale previews and wires copy/export to the current opaque handle, revision and artifact key; existing exact lifecycle and hostile-preview tests cover late/unmount failure and escaped text. Production source audit confirms the validated IPC obtains sidecar-owned current bytes and saveConfigArtifact uses a native dialog followed by fs.promises.open with wx, write, sync and close. However no mapping-specific executable test has driven that native-dialog/filesystem route to assert Redis byte equality and a second create failure, so save-without-overwrite acceptance remains Pending/NOT_RUN and this mapping cannot be Passed. The legacy Redis visual attempt intentionally remained in Quick mode with an unsupported error; Electron does not invent a structured Redis visual editor or treat its plain-text preview as visual parity.
- [ ] `tomcat_quick_bundle_stacks_excludes_removes_resets_copies_and_saves_without_overwrite`
  - 计划替代: `tomcat_config::tests::tomcat_quick_bundle_stack_exclude_remove_reset_and_save_prerequisite_is_byte_exact`
    运行: `cargo test --locked --package lovelyres-core tomcat_config::tests::tomcat_quick_bundle_stack_exclude_remove_reset_and_save_prerequisite_is_byte_exact -- --exact`
  - 计划替代: `config_api::tests::tomcat_quick_bundle_stack_exclude_remove_reset_copy_and_save_prerequisites_are_current`
    运行: `cargo test --locked --package lovelyres-electron-backend config_api::tests::tomcat_quick_bundle_stack_exclude_remove_reset_copy_and_save_prerequisites_are_current -- --exact`
  - 计划替代: `configuration process-boundary validators > tomcat_quick_bundle_transitions_and_three_artifact_boundaries_are_closed`
    运行: `pnpm --dir electron exec vitest run src/shared/config-contract.test.ts -t "tomcat_quick_bundle_transitions_and_three_artifact_boundaries_are_closed"`
  - 计划替代: `config generator request lifecycle > tomcat_quick_bundle_stack_exclude_remove_reset_copy_and_save_prerequisites_are_current`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "tomcat_quick_bundle_stack_exclude_remove_reset_copy_and_save_prerequisites_are_current"`
  - 计划替代: `config generator request lifecycle > lifecycle_rejects_late_save_completions`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "lifecycle_rejects_late_save_completions"`
  - 计划替代: `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "wires unmount cleanup and every async action through the request lane"`
  - 计划替代: `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-page.test.tsx -t "preview_is_bounded_and_never_interprets_text"`
  - 计划替代: `electron-config-copy::tomcat_bundle_copy_preserves_fixed_artifact_boundaries_byte_exact`
    运行: `pnpm --dir electron test:debug`
  - 计划替代: `electron-config-native-save::tomcat_bundle_exports_three_fixed_artifacts_byte_exact_without_overwrite`
    运行: `pnpm --dir electron test:debug`
  - 说明: Partial evidence is now exact across all four applicable configuration layers. Core proves the Tomcat 11 baseline, the fully typed Tomcat 10.1 stack, safe-method versus deny-all exclusion, owning-artifact-only removal, byte-exact reset and create-new three-file directory prerequisite. The sidecar proves fixed ordered server.xml/context.xml/web.xml identities and relative paths, current-revision copy/export bytes, cross-artifact isolation, stale rejection and no mutation after conflicting or hostile revisions. The strict contract requires the exact three-artifact order, unique keys/paths and XML media type, rejects conflicting method policies and denies renderer-supplied action/copy/save/path/artifact/visual/raw-content capabilities. The production renderer invokes real checkbox handlers, normalizes mutual exclusion, removes independent features, resets the selected Tomcat version/values, rejects stale previews and wires fixed artifact tabs, copy-all and current-artifact export through the current opaque handle and revision; existing exact lifecycle and hostile-preview tests cover late/unmount failure and escaped XML text. Two production gaps remain. First, main-process copy currently joins three raw XML strings with blank lines and drops the legacy BEGIN/END relative-path boundaries, so byte-exact bundle copy is NOT_RUN. Second, exportConfigArtifact saves only the selected artifact through the native dialog and fs.open wx route; it does not create the fixed three-artifact directory bundle atomically, and no mapping-specific native-dialog/filesystem test verifies all bytes plus a second-create failure. Both acceptance points remain Pending, so this mapping cannot be Passed. The legacy attempt to open a Tomcat visual editor intentionally stayed in Quick mode with an unsupported error; Electron does not invent a structured three-artifact editor or call plain-text tabs visual parity.
- [ ] `nginx_spa_fallback_swaps_with_static_404_and_removal_restores_baseline`
  - 计划替代: `electron-cdp::config-generator::nginx_spa_fallback_swaps_with_static_404_and_removal_restores_baseline`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `nginx_reset_restores_every_checked_in_default`
  - 计划替代: `electron-cdp::config-generator::nginx_reset_restores_every_checked_in_default`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `nginx_403_goal_is_discoverable_and_drives_the_typed_preview`
  - 计划替代: `electron-cdp::config-generator::nginx_403_goal_is_discoverable_and_drives_the_typed_preview`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `nginx_import_result_replaces_a_stale_apache_visual_document`
  - 计划替代: `electron-cdp::config-generator::nginx_import_result_replaces_a_stale_apache_visual_document`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `unified_goal_search_opens_database_guidance_and_explains_unavailable_products`
  - 计划替代: `config generator reducer > switches product and unique search subject atomically`
    运行: `pnpm --dir electron exec vitest run src/renderer/config-generator-state.test.ts -t "switches product and unique search subject atomically"`
  - 计划替代: `electron-cdp::config-generator::unified_goal_search_opens_database_guidance_and_explains_unavailable_products`
    运行: `pnpm --dir electron test:debug`
  - 说明: The failing stale selectedSubject behavior is replaced by the atomic reducer test. Final Electron CDP evidence for cross-product search and the visible result is still pending, so this mapping cannot be Passed.
- [ ] `database_assignment_previews_then_atomically_confirms_a_typed_local_draft`
  - 计划替代: `electron-cdp::config-generator::database_assignment_previews_then_atomically_confirms_a_typed_local_draft`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `database_assignment_ambiguity_rejection_and_failed_stage_never_mutate_the_document`
  - 计划替代: `electron-cdp::config-generator::database_assignment_ambiguity_rejection_and_failed_stage_never_mutate_the_document`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `config_preview_colors_are_readable_on_every_current_theme`
  - 计划替代: `electron-cdp::config-generator::config_preview_colors_are_readable_on_every_current_theme`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `nginx_403_goal_generates_and_reloads_as_an_exact_visual_tree`
  - 计划替代: `electron-cdp::config-generator::nginx_403_goal_generates_and_reloads_as_an_exact_visual_tree`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `hidden_and_stale_search_selections_fail_closed`
  - 计划替代: `electron-cdp::config-generator::hidden_and_stale_search_selections_fail_closed`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.
- [ ] `quick_result_can_become_a_structured_visual_document`
  - 计划替代: `electron-cdp::config-generator::quick_result_can_become_a_structured_visual_document`
    运行: `pnpm --dir electron test:debug`
  - 说明: This interaction or visual-state behavior lacks an exact Electron component test plus final CDP evidence. The existing renderer run is not treated as blanket coverage.

## 已完成 (39)

- [x] `database_bundle_parameter_labels_disambiguate_every_mariadb_container` → `database_config_schema::tests::mariadb_container_parameter_labels_are_unique_and_root_free`
- [x] `goal_catalog_product_search_and_subject_inference_are_bounded_and_exact` → `configuration_goal::tests::product_label_search_and_unique_subject_inference_are_bounded_and_exact`
- [x] `nginx_configuration_catalog_has_a_useful_baseline_and_searchable_rows` → `nginx_config::tests::feature_metadata_is_complete_unique_and_has_exact_defaults`, `nginx_config::tests::feature_support_matrix_is_explicit_for_every_site_kind`, `config_api::tests::catalog_covers_nine_unique_products_and_every_typed_feature`, `config generator reducer > uses catalog defaults only when supported by the default choice`
- [x] `apache_configuration_catalog_has_a_useful_baseline_and_searchable_rows` → `apache_config::tests::feature_metadata_is_complete_unique_and_has_exact_defaults`, `apache_config::tests::feature_support_and_module_matrices_are_explicit`, `config_api::tests::catalog_covers_nine_unique_products_and_every_typed_feature`, `config generator reducer > uses catalog defaults only when supported by the default choice`
- [x] `mysql_configuration_catalog_has_an_immutable_searchable_baseline` → `mysql_config::tests::feature_catalog_is_complete_unique_and_closed`, `mysql_config::tests::baseline_is_exact_immutable_and_deterministic`, `config_api::tests::catalog_covers_nine_unique_products_and_every_typed_feature`
- [x] `postgresql_and_mariadb_quick_catalogs_are_closed_searchable_and_typed` → `postgresql_config::tests::supported_versions_and_feature_metadata_are_closed_and_explained`, `postgresql_config::tests::every_optional_feature_emits_only_its_closed_directives`, `mariadb_config::tests::supported_lts_series_are_explicit_and_eol_or_rolling_series_are_rejected`, `mariadb_config::tests::feature_catalog_is_closed_unique_explained_and_version_aware`, `mariadb_config::tests::all_features_render_the_closed_reviewed_values`, `config_api::tests::canonical_feature_mapping_covers_all_137_keys_and_rejects_aliases_and_duplicates`
- [x] `redis_configuration_catalog_and_latest_empty_instance_baseline_are_searchable` → `redis_config::tests::version_lines_and_feature_metadata_are_closed_and_unique`, `redis_config::tests::baseline_is_explicitly_for_empty_instances_and_has_bounded_dual_persistence`, `config_api::tests::catalog_covers_nine_unique_products_and_every_typed_feature`
- [x] `tomcat_configuration_catalog_and_default_three_artifact_baseline_are_searchable` → `tomcat_config::tests::feature_and_deferred_catalogs_are_complete_unique_and_searchable`, `tomcat_config::tests::every_baseline_is_a_three_artifact_bounded_closed_bundle`, `config_api::tests::tomcat_is_a_three_artifact_bundle_with_fixed_safe_paths`
- [x] `goal_catalog_middleware_groups_cover_the_registered_products_exactly_once` → `config_api::tests::catalog_covers_nine_unique_products_and_every_typed_feature`, `config_api::tests::canonical_feature_mapping_covers_all_137_keys_and_rejects_aliases_and_duplicates`
- [x] `quick_configuration_source_does_not_restore_the_removed_legacy_filter_badges` → `config generator stable DOM contract > does not restore the removed legacy content or product filter badges`
- [x] `nginx_quick_configurations_stack_and_remove_independently` → `config generator legacy isolation migration > nginx_quick_configurations_stack_and_remove_independently`, `nginx_config::tests::additive_features_are_order_independent_and_keep_the_baseline`, `nginx_config::tests::disabling_one_feature_preserves_the_other_feature_and_baseline`
- [x] `nginx_remove_button_click_removes_feature_and_updates_preview_and_row_state` → `nginx_config::tests::nginx_feature_removal_updates_typed_model_and_generated_preview`, `config_api::tests::nginx_feature_removal_revises_preview_and_invalidates_stale_capabilities`, `configuration process-boundary validators > nginx_feature_remove_intent_is_closed_and_rejects_hostile_payload_fields`, `config generator request lifecycle > nginx_remove_button_click_removes_feature_and_updates_preview_and_row_state`, `config generator request lifecycle > lifecycle_rejects_late_save_completions`, `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`, `config generator hostile preview > preview_is_bounded_and_never_interprets_text`
- [x] `quick_configuration_search_and_product_switches_never_leak_another_preview` → `config generator legacy isolation migration > quick_configuration_search_and_product_switches_never_leak_another_preview`, `config_api::tests::previews_are_globally_bounded_and_copy_requires_current_revision`
- [x] `reset_only_restores_the_selected_product_family` → `config generator legacy isolation migration > reset_only_restores_the_selected_product_family`
- [x] `redis_reset_is_isolated_from_mysql_and_web_state` → `config generator legacy isolation migration > redis_reset_is_isolated_from_mysql_and_web_state`
- [x] `tomcat_reset_is_isolated_and_other_product_resets_preserve_tomcat_state` → `config generator legacy isolation migration > tomcat_reset_is_isolated_and_other_product_resets_preserve_tomcat_state`
- [x] `database_assignment_writer_preserves_product_tokens_and_equals_inside_the_value` → `configuration_goal::tests::database_assignment_writer_preserves_product_tokens_and_equals_inside_the_value`
- [x] `nginx_goal_search_recognizes_403_intent_and_extracts_only_typed_paths` → `configuration_goal::tests::nginx_goal_search_recognizes_403_intent_and_extracts_only_typed_paths`, `nginx_visual::tests::safe_nginx_row_search_never_indexes_arguments_or_preview_text`
- [x] `form_translation_generates_both_closed_templates` → `nginx_config::tests::static_template_is_exact_and_deterministic`, `nginx_config::tests::reverse_proxy_template_has_only_fixed_security_directives`, `config_api::tests::default_quick_inputs_generate_all_nine_products_through_core`
- [x] `form_translation_rejects_nginx_directive_injection` → `nginx_config::tests::exact_dns_name_is_normalized_and_hostile_forms_are_rejected`, `nginx_config::tests::static_root_has_both_posix_and_nginx_token_boundaries`, `config_api::tests::serde_and_core_reject_unknown_fields_injection_and_unsupported_combinations`
- [x] `schemas_never_change_vendor_or_generated_local_draft_permission` → `database_config_schema::tests::schemas_never_change_vendor_or_generated_local_draft_permission`, `config_api::tests::schema_metadata_never_changes_typed_catalog_local_draft_authority`, `configuration process-boundary validators > schemas_never_change_vendor_or_generated_local_draft_permission`, `config generator read-only artifact boundary > schemas_never_change_vendor_or_generated_local_draft_permission`
- [x] `apache_competition_skeleton_is_available_through_visual_facade` → `apache_visual::tests::checked_in_competition_skeleton_remains_structured`
- [x] `supported_database_starters_remain_structured` → `database_config::tests::supported_database_starters_are_core_owned_and_structured`
- [x] `compatible_and_domestic_starters_do_not_guess_upstream_defaults` → `database_config::tests::compatible_and_domestic_starters_do_not_guess_upstream_defaults`, `config_api::tests::compatible_and_domestic_starters_do_not_guess_upstream_defaults`, `configuration process-boundary validators > compatible_and_domestic_starters_do_not_guess_upstream_defaults`, `config generator read-only artifact boundary > compatible_and_domestic_starters_do_not_guess_upstream_defaults`
- [x] `local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts` → `database_config::tests::local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts`, `config_api::tests::local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts`, `configuration process-boundary validators > local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts`, `config generator read-only artifact boundary > local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts`
- [x] `unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries` → `database_config::tests::unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries`, `config_api::tests::unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries`, `configuration process-boundary validators > unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries`, `config generator read-only artifact boundary > unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries`
- [x] `dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor` → `database_config::tests::dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor`, `config_api::tests::dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor`, `configuration process-boundary validators > dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor`, `config generator read-only artifact boundary > dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor`
- [x] `dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates` → `database_config::tests::dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates`, `config_api::tests::dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates`, `configuration process-boundary validators > dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates`, `config generator read-only artifact boundary > dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates`
- [x] `gbase_8s_known_text_grammars_remain_byte_exact_visual_and_read_only` → `database_config::tests::gbase_8s_known_text_grammars_are_readable_byte_exact_and_read_only`
- [x] `gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy` → `database_config::tests::gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy`, `config_api::tests::gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy`, `configuration process-boundary validators > gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy`, `config generator read-only artifact boundary > gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy`
- [x] `gbase_8a_generated_json_authkey_is_redacted_and_blocks_whole_document_copy` → `database_config::tests::gbase_8a_gnode_and_gcluster_artifacts_keep_distinct_component_identity`, `structured_config_visual::tests::authkey_keys_assignments_and_comments_are_redacted_without_broad_auth_matches`
- [x] `yashandb_23_5_4_100_schema_is_exact_read_only_metadata_and_never_serialized` → `database_config_schema_domestic::tests::yashandb_schema_requires_the_exact_build_and_document_family`, `database_config_schema_domestic::tests::yashandb_schema_metadata_is_exact_and_never_implies_file_mutation`, `database_config_schema_domestic::tests::yashandb_23_5_4_100_schema_is_exact_read_only_metadata_and_never_serialized`, `config_api::tests::catalog_projects_yashandb_exact_schema_as_read_only_metadata_only`, `configuration process-boundary validators > keeps YashanDB exact schema identity in bounded notice-only metadata`, `config generator read-only artifact boundary > renders YashanDB 23.5.4.100 schema as notice-only metadata without mutation or save authority`
- [x] `yashandb_23_5_vendor_binary_artifacts_never_enter_or_read_as_text` → `database_config::tests::yashan_23_5_keeps_text_source_and_vendor_owned_binary_state_separate`
- [x] `gcware_catalog_document_is_nested_byte_exact_and_never_deployable` → `structured_config_visual::tests::gcware_nested_document_is_byte_exact_and_read_only`, `database_config::tests::gbase_gcware_conf_is_structured_but_never_a_local_draft`
- [x] `sequoia_quick_deploy_catalog_artifacts_are_selectable_read_only_and_byte_exact` → `database_config::tests::sequoiadb_quick_deploy_tables_are_unique_read_only_inputs`, `structured_config_visual::tests::sequoia_quick_deploy_dialects_are_byte_exact_read_only_and_redacted`
- [x] `read_only_status_distinguishes_generated_and_vendor_schema_artifacts` → `database_config::tests::read_only_status_distinguishes_generated_and_vendor_schema_artifacts`, `config_api::tests::catalog_projects_finite_read_only_reasons_without_mutation_authority`, `config generator database artifact status > read_only_status_distinguishes_generated_and_vendor_schema_artifacts`, `configuration process-boundary validators > accepts only finite read-only artifact reasons without mutation fields`
- [x] `sensitive_structured_documents_remain_non_copyable_and_redacted` → `structured_config_visual::tests::sensitive_json_blocks_whole_text_copy_and_redacts_rows_and_debug`
- [x] `foreign_document_node_ids_fail_closed_without_mutation` → `nginx_visual::tests::foreign_document_node_ids_fail_closed_without_mutation`, `apache_visual::tests::foreign_document_node_ids_fail_closed_without_mutation`, `line_config_visual::tests::foreign_document_node_ids_fail_closed_without_mutation`
- [x] `lifecycle_rejects_late_save_completions` → `config generator request lifecycle > lifecycle_rejects_late_save_completions`, `config generator request lifecycle > wires unmount cleanup and every async action through the request lane`
