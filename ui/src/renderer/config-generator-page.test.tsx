import { readFileSync } from "node:fs";

import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  ConfigCatalog,
  ConfigDraft,
  ConfigDraftArtifact,
  ConfigReadOnlyArtifactStatus,
} from "../shared/config-contract";
import { isConfigGenerateInput } from "../shared/config-contract";
import {
  ConfigArtifactPreview,
  ConfigFeatureCatalogEntry,
  ConfigFeatureToggle,
  ConfigReadOnlyStatusPanel,
  MariaDbBinaryLogRetentionInlineEditor,
  MariaDbBinaryLogRetentionInput,
  MySqlMaxConnectionsInlineEditor,
  MySqlMaxConnectionsInput,
  NginxForbiddenPathInlineEditor,
  PostgreSqlLockWaitInlineEditor,
  PostgreSqlLockWaitInput,
  RedisSlowLogInlineEditor,
  RedisSlowLogValueInput,
} from "./ConfigGeneratorPage";
import {
  DEFAULT_CONFIG_VALUES,
  ConfigRequestLifecycle,
  buildConfigGenerateInput,
  configEditorReducer,
  createConfigEditorState,
  forbiddenGoalActions,
  forbiddenGoalFromQuery,
  getConfigChoiceTestId,
  isConfigPreviewCurrent,
  releaseLateConfigDraft,
  searchConfigCatalog,
  selectConfigReadOnlyArtifactStatus,
  selectVisibleConfigFeatures,
  type ConfigEditorAction,
} from "./config-generator-state";

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept;
    reject = decline;
  });
  return { promise, resolve, reject };
}

function draft(handle: string, revision: number): ConfigDraft {
  return {
    handle,
    revision,
    product: "nginx",
    choice: "reverse-proxy",
    suggestedName: "nginx-site.conf",
    totalBytes: 4,
    copyAllowed: true,
    artifacts: [{
      key: "site",
      relativePath: "nginx-site.conf",
      mediaType: "text/plain",
      byteLength: 4,
      preview: "safe",
      previewTruncated: false,
      copyAllowed: true,
    }],
    notices: [],
  };
}

describe("config generator request lifecycle", () => {
  it("nginx_remove_button_click_removes_feature_and_updates_preview_and_row_state", () => {
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [{
        key: "nginx",
        title: "Nginx",
        family: "web-server",
        choiceKind: "mode",
        defaultChoice: "reverse-proxy",
        choices: [{
          key: "reverse-proxy",
          label: "反向代理",
          detail: "测试闭合目录",
          isDefault: true,
        }],
        features: [{
          key: "security-headers",
          title: "安全响应头",
          summary: "固定安全响应头",
          scope: "server",
          defaultEnabled: true,
          aliases: ["security headers"],
          supportedChoices: ["reverse-proxy"],
        }],
        artifacts: [{ key: "site", relativePath: "nginx-site.conf", title: "站点配置" }],
        scopeNotice: "仅生成本地草稿。",
      }],
      readOnlyArtifacts: [],
    };
    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    editor = configEditorReducer(editor, {
      type: "set-feature",
      product: "nginx",
      featureKey: "security-headers",
      enabled: true,
    });
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "nginx",
      inputRevision: editor.inputRevisions.nginx,
    });
    expect(editor.selectedSubject).toEqual({
      product: "nginx",
      featureKey: "security-headers",
    });
    expect(isConfigPreviewCurrent(editor, "nginx")).toBe(true);

    const staleRevision = editor.inputRevisions.nginx;
    const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
    const enabledToggle = ConfigFeatureToggle({
      product: "nginx",
      featureKey: "security-headers",
      checked: true,
      disabled: false,
      onIntent: (intent) => intents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { checked: boolean } }): void;
    }>;
    enabledToggle.props.onChange({ currentTarget: { checked: false } });

    expect(intents).toEqual([{
      type: "set-feature",
      product: "nginx",
      featureKey: "security-headers",
      enabled: false,
    }]);
    const removeIntent = intents[0];
    if (removeIntent === undefined) throw new Error("remove intent must be emitted");
    editor = configEditorReducer(editor, removeIntent);

    expect(editor.enabledFeatures.nginx).toEqual([]);
    expect(editor.selectedSubject).toBeNull();
    expect(editor.inputRevisions.nginx).toBe(staleRevision + 1);
    expect(editor.preview).toBeNull();
    expect(isConfigPreviewCurrent(editor, "nginx")).toBe(false);
    expect(buildConfigGenerateInput(editor)?.features).toEqual([]);

    const afterStalePreview = configEditorReducer(editor, {
      type: "preview-generated",
      product: "nginx",
      inputRevision: staleRevision,
    });
    expect(afterStalePreview).toBe(editor);
    expect(isConfigPreviewCurrent(afterStalePreview, "nginx")).toBe(false);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "nginx",
      inputRevision: editor.inputRevisions.nginx,
    });
    expect(isConfigPreviewCurrent(editor, "nginx")).toBe(true);
    const uncheckedRowState = renderToStaticMarkup(
      <ConfigFeatureToggle
        product="nginx"
        featureKey="security-headers"
        checked={false}
        disabled={false}
        onIntent={() => undefined}
      />,
    );
    expect(uncheckedRowState).toContain("type=\"checkbox\"");
    expect(uncheckedRowState).toContain(
      "data-testid=\"config-feature-nginx-security-headers\"",
    );
    expect(uncheckedRowState).not.toContain("checked=\"\"");
  });

  it("apache_stack_remove_reset_and_preview_state_are_isolated", () => {
    const apacheProduct = {
      key: "apache",
      title: "Apache HTTP Server",
      family: "web-server",
      choiceKind: "mode",
      defaultChoice: "reverse-proxy",
      choices: [{
        key: "reverse-proxy",
        label: "反向代理",
        detail: "测试闭合目录",
        isDefault: true,
      }],
      features: [
        {
          key: "security-headers",
          title: "安全响应头",
          summary: "固定安全响应头",
          scope: "virtual-host",
          defaultEnabled: true,
          aliases: ["security headers"],
          supportedChoices: ["reverse-proxy"],
        },
        {
          key: "reduce-version-disclosure",
          title: "减少版本暴露",
          summary: "固定版本边界",
          scope: "global",
          defaultEnabled: true,
          aliases: ["server tokens"],
          supportedChoices: ["reverse-proxy"],
        },
        {
          key: "disable-trace",
          title: "禁用 TRACE",
          summary: "固定 TRACE 边界",
          scope: "virtual-host",
          defaultEnabled: true,
          aliases: ["trace"],
          supportedChoices: ["reverse-proxy"],
        },
        {
          key: "restrict-request-methods",
          title: "限制请求方法",
          summary: "只允许 GET 和 HEAD",
          scope: "location",
          defaultEnabled: false,
          aliases: ["require method"],
          supportedChoices: ["reverse-proxy"],
        },
        {
          key: "client-body-limit",
          title: "限制请求体",
          summary: "固定请求体边界",
          scope: "virtual-host",
          defaultEnabled: false,
          aliases: ["limit request body"],
          supportedChoices: ["reverse-proxy"],
        },
      ],
      artifacts: [{ key: "site", relativePath: "apache-site.conf", title: "站点配置" }],
      scopeNotice: "仅生成本地草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [
        apacheProduct,
        {
          key: "nginx",
          title: "Nginx",
          family: "web-server",
          choiceKind: "mode",
          defaultChoice: "reverse-proxy",
          choices: [{
            key: "reverse-proxy",
            label: "反向代理",
            detail: "隔离哨兵",
            isDefault: true,
          }],
          features: [{
            key: "nginx-sentinel",
            title: "Nginx 隔离哨兵",
            summary: "不得被 Apache reset 修改",
            scope: "test",
            defaultEnabled: true,
            aliases: ["sentinel"],
            supportedChoices: ["reverse-proxy"],
          }],
          artifacts: [{ key: "site", relativePath: "nginx-site.conf", title: "站点配置" }],
          scopeNotice: "隔离测试。",
        },
      ],
      readOnlyArtifacts: [],
    };
    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    const defaults = [
      "security-headers",
      "reduce-version-disclosure",
      "disable-trace",
    ];
    expect(editor.enabledFeatures.apache).toEqual(defaults);
    expect(editor.enabledFeatures.nginx).toEqual(["nginx-sentinel"]);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: editor.inputRevisions.apache,
    });
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(true);

    function clickFeature(featureKey: string, enabled: boolean) {
      const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
      const toggle = ConfigFeatureToggle({
        product: "apache",
        featureKey,
        checked: editor.enabledFeatures.apache.includes(featureKey),
        disabled: false,
        onIntent: (intent) => intents.push(intent),
      }) as ReactElement<{
        onChange(event: { currentTarget: { checked: boolean } }): void;
      }>;
      toggle.props.onChange({ currentTarget: { checked: enabled } });
      expect(intents).toEqual([{
        type: "set-feature",
        product: "apache",
        featureKey,
        enabled,
      }]);
      const intent = intents[0];
      if (intent === undefined) throw new Error("Apache feature intent must be emitted");
      editor = configEditorReducer(editor, intent);
    }

    clickFeature("restrict-request-methods", true);
    clickFeature("client-body-limit", true);
    expect(editor.enabledFeatures.apache).toEqual([
      ...defaults,
      "restrict-request-methods",
      "client-body-limit",
    ]);
    expect(editor.enabledFeatures.nginx).toEqual(["nginx-sentinel"]);
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(false);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: editor.inputRevisions.apache,
    });
    clickFeature("restrict-request-methods", true);
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(true);
    expect(editor.selectedSubject?.featureKey).toBe("restrict-request-methods");
    const staleStackRevision = editor.inputRevisions.apache;
    clickFeature("disable-trace", false);
    expect(editor.enabledFeatures.apache).toEqual([
      "security-headers",
      "reduce-version-disclosure",
      "client-body-limit",
    ]);
    expect(editor.selectedSubject).toBeNull();
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(false);
    const afterStalePreview = configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: staleStackRevision,
    });
    expect(afterStalePreview).toBe(editor);

    clickFeature("restrict-request-methods", true);
    expect(editor.enabledFeatures.apache).toContain("disable-trace");
    expect(editor.enabledFeatures.apache).toContain("restrict-request-methods");
    clickFeature("restrict-request-methods", false);
    expect(editor.enabledFeatures.apache).toContain("disable-trace");
    expect(editor.enabledFeatures.apache).not.toContain("restrict-request-methods");
    expect(editor.enabledFeatures.apache).toContain("client-body-limit");

    editor = configEditorReducer(editor, {
      type: "set-value",
      product: "apache",
      key: "serverName",
      value: "changed.example.com",
    });
    const staleResetRevision = editor.inputRevisions.apache;
    editor = configEditorReducer(editor, { type: "reset-product", product: apacheProduct });
    expect(editor.enabledFeatures.apache).toEqual(defaults);
    expect(editor.enabledFeatures.nginx).toEqual(["nginx-sentinel"]);
    expect(editor.values.apache).toEqual(DEFAULT_CONFIG_VALUES.apache);
    expect(editor.choices.apache).toBe("reverse-proxy");
    expect(editor.selectedSubject).toBeNull();
    expect(editor.preview).toBeNull();
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: staleResetRevision,
    })).toBe(editor);

    const resetInput = buildConfigGenerateInput(editor);
    expect(resetInput?.product).toBe("apache");
    expect(resetInput?.features).toEqual(defaults);
    expect(isConfigGenerateInput(resetInput)).toBe(true);
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain(
      "dispatch({ type: \"reset-product\", product: selectedProduct });",
    );
    expect(source).toContain("data-testid={`config-reset-${selectedProduct.key}`}");

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: editor.inputRevisions.apache,
    });
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(true);
    const rowStates = renderToStaticMarkup(<>
      <ConfigFeatureToggle
        product="apache"
        featureKey="disable-trace"
        checked
        disabled={false}
        onIntent={() => undefined}
      />
      <ConfigFeatureToggle
        product="apache"
        featureKey="restrict-request-methods"
        checked={false}
        disabled={false}
        onIntent={() => undefined}
      />
    </>);
    expect(rowStates).toContain("data-testid=\"config-feature-apache-disable-trace\" checked=\"\"");
    expect(rowStates).toContain("data-testid=\"config-feature-apache-restrict-request-methods\"");
  });

  it("apache_catalog_inline_editor_and_preview_dom_prerequisites_are_typed", () => {
    const apacheProduct = {
      key: "apache",
      title: "Apache HTTP Server",
      family: "web",
      choiceKind: "mode",
      defaultChoice: "reverse-proxy",
      choices: [
        {
          key: "static",
          label: "静态站点",
          detail: "本地审阅片段",
          isDefault: false,
        },
        {
          key: "reverse-proxy",
          label: "反向代理",
          detail: "本地审阅片段",
          isDefault: true,
        },
      ],
      features: [{
        key: "client-body-limit",
        title: "限制请求体大小",
        summary: "将客户端请求体上限固定为 10 MiB。",
        scope: "虚拟主机",
        defaultEnabled: false,
        aliases: ["请求体", "上传大小", "LimitRequestBody", "10 MiB"],
        supportedChoices: ["static", "reverse-proxy"],
      }],
      artifacts: [{ key: "site", relativePath: "apache-site.conf", title: "站点配置片段" }],
      scopeNotice: "仅生成本地草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [apacheProduct],
      readOnlyArtifacts: [],
    };
    const feature = apacheProduct.features[0];
    if (feature === undefined) throw new Error("ClientBodyLimit fixture must exist");

    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: editor.inputRevisions.apache,
    });
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(true);
    editor = configEditorReducer(editor, {
      type: "select-search-result",
      subject: { product: "apache", featureKey: "client-body-limit" },
    });
    expect(editor.selectedSubject).toEqual({
      product: "apache",
      featureKey: "client-body-limit",
    });

    const selectedMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="apache"
        feature={feature}
        checked={false}
        supported
        selected
        onIntent={() => undefined}
      />,
    );
    const rowSelector = "data-testid=\"config-feature-row-apache-client-body-limit\"";
    const editorSelector =
      "data-testid=\"config-feature-inline-editor-apache-client-body-limit\"";
    expect(selectedMarkup).toContain(rowSelector);
    expect(selectedMarkup).toContain(editorSelector);
    expect(selectedMarkup.indexOf(editorSelector)).toBeGreaterThan(
      selectedMarkup.indexOf(rowSelector),
    );
    expect(selectedMarkup).toContain("配置：限制请求体大小");
    expect(selectedMarkup).toContain("尚未添加");
    expect(selectedMarkup).toContain("固定使用已审查模板，无额外自由文本参数。");

    const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
    const toggle = ConfigFeatureToggle({
      product: "apache",
      featureKey: "client-body-limit",
      checked: false,
      disabled: false,
      onIntent: (intent) => intents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { checked: boolean } }): void;
    }>;
    const staleRevision = editor.inputRevisions.apache;
    toggle.props.onChange({ currentTarget: { checked: true } });
    expect(intents).toEqual([{
      type: "set-feature",
      product: "apache",
      featureKey: "client-body-limit",
      enabled: true,
    }]);
    const intent = intents[0];
    if (intent === undefined) throw new Error("ClientBodyLimit intent must exist");
    editor = configEditorReducer(editor, intent);
    expect(editor.enabledFeatures.apache).toEqual(["client-body-limit"]);
    expect(editor.selectedSubject?.featureKey).toBe("client-body-limit");
    expect(editor.inputRevisions.apache).toBe(staleRevision + 1);
    expect(editor.preview).toBeNull();
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(false);
    const input = buildConfigGenerateInput(editor);
    expect(input).toMatchObject({
      product: "apache",
      choice: "reverse-proxy",
      features: ["client-body-limit"],
    });
    expect(isConfigGenerateInput(input)).toBe(true);

    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: staleRevision,
    })).toBe(editor);
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "apache",
      inputRevision: editor.inputRevisions.apache,
    });
    expect(isConfigPreviewCurrent(editor, "apache")).toBe(true);

    const preview = "<VirtualHost *:80>\n    LimitRequestBody 10485760\n</VirtualHost>\n";
    const previewMarkup = renderToStaticMarkup(
      <ConfigArtifactPreview artifact={{
        key: "site",
        relativePath: "apache-site.conf",
        mediaType: "text/plain",
        byteLength: new TextEncoder().encode(preview).byteLength,
        preview,
        previewTruncated: false,
        copyAllowed: true,
      }} />,
    );
    expect(previewMarkup).toContain("LimitRequestBody 10485760");
    expect(previewMarkup).toContain("&lt;VirtualHost *:80&gt;");
    expect(previewMarkup).not.toContain("<VirtualHost");

    const hostileFeatureMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="apache"
        feature={{
          ...feature,
          summary: "<img src=x onerror=globalThis.apacheInlineExecuted=true>",
        }}
        checked
        supported
        selected
        onIntent={() => undefined}
      />,
    );
    expect(hostileFeatureMarkup).toContain("&lt;img");
    expect(hostileFeatureMarkup).not.toContain("<img");
  });

  it("mysql_catalog_inline_editor_and_preview_dom_prerequisites_are_typed", () => {
    const mysqlProduct = {
      key: "mysql",
      title: "MySQL",
      family: "database",
      choiceKind: "version",
      defaultChoice: "8.4.0",
      choices: [{
        key: "8.4.0",
        label: "MySQL 8.4.x",
        detail: "闭合模型只接受 8.4 系列。",
        isDefault: true,
      }],
      features: [{
        key: "max-connections",
        title: "限制最大连接数",
        summary: "设置服务器可同时接受的客户端连接数量上限。",
        scope: "连接",
        defaultEnabled: false,
        aliases: ["max_connections", "最大连接", "并发连接"],
        supportedChoices: ["8.4.0"],
      }],
      artifacts: [{ key: "main", relativePath: "my.cnf", title: "mysqld option file" }],
      scopeNotice: "仅生成本地草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [mysqlProduct],
      readOnlyArtifacts: [],
    };
    const feature = mysqlProduct.features[0];
    if (feature === undefined) throw new Error("MaxConnections fixture must exist");

    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: editor.inputRevisions.mysql,
    });
    expect(isConfigPreviewCurrent(editor, "mysql")).toBe(true);
    editor = configEditorReducer(editor, {
      type: "select-search-result",
      subject: { product: "mysql", featureKey: "max-connections" },
    });
    expect(editor.selectedSubject).toEqual({
      product: "mysql",
      featureKey: "max-connections",
    });

    const featureIntents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
    const toggle = ConfigFeatureToggle({
      product: "mysql",
      featureKey: "max-connections",
      checked: false,
      disabled: false,
      onIntent: (intent) => featureIntents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { checked: boolean } }): void;
    }>;
    const staleRevision = editor.inputRevisions.mysql;
    toggle.props.onChange({ currentTarget: { checked: true } });
    const featureIntent = featureIntents[0];
    if (featureIntent === undefined) throw new Error("MaxConnections feature intent must exist");
    editor = configEditorReducer(editor, featureIntent);

    const valueIntents: Array<Extract<ConfigEditorAction, { type: "set-value" }>> = [];
    const inputElement = MySqlMaxConnectionsInput({
      value: editor.values.mysql.maxConnections,
      enabled: true,
      onIntent: (intent) => valueIntents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { value: string } }): void;
    }>;
    inputElement.props.onChange({ currentTarget: { value: "400" } });
    expect(valueIntents).toEqual([{
      type: "set-value",
      product: "mysql",
      key: "maxConnections",
      value: "400",
    }]);
    const valueIntent = valueIntents[0];
    if (valueIntent === undefined) throw new Error("MaxConnections value intent must exist");
    editor = configEditorReducer(editor, valueIntent);

    expect(editor.enabledFeatures.mysql).toEqual(["max-connections"]);
    expect(editor.values.mysql.maxConnections).toBe("400");
    expect(editor.inputRevisions.mysql).toBe(staleRevision + 2);
    expect(editor.preview).toBeNull();
    expect(isConfigPreviewCurrent(editor, "mysql")).toBe(false);
    const generateInput = buildConfigGenerateInput(editor);
    expect(generateInput).toMatchObject({
      product: "mysql",
      choice: "8.4.0",
      features: ["max-connections"],
      values: { maxConnections: "400" },
    });
    expect(isConfigGenerateInput(generateInput)).toBe(true);

    const inlineEditor = (
      <MySqlMaxConnectionsInlineEditor
        value={editor.values.mysql.maxConnections}
        enabled
        onIntent={() => undefined}
      />
    );
    const selectedMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="mysql"
        feature={feature}
        checked
        supported
        selected
        inlineEditor={inlineEditor}
        onIntent={() => undefined}
      />,
    );
    const rowSelector = "data-testid=\"config-feature-row-mysql-max-connections\"";
    const editorSelector =
      "data-testid=\"config-feature-inline-editor-mysql-max-connections\"";
    expect(selectedMarkup).toContain(rowSelector);
    expect(selectedMarkup).toContain(editorSelector);
    expect(selectedMarkup.indexOf(editorSelector)).toBeGreaterThan(
      selectedMarkup.indexOf(rowSelector),
    );
    expect(selectedMarkup).toContain(
      "data-testid=\"config-inline-value-mysql-maxConnections\"",
    );
    expect(selectedMarkup).toContain("value=\"400\"");
    expect(selectedMarkup).toContain("允许范围 1 - 100000；生成 max_connections。");
    expect(renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="mysql"
        feature={feature}
        checked
        supported
        selected={false}
        inlineEditor={inlineEditor}
        onIntent={() => undefined}
      />,
    )).not.toContain(editorSelector);

    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: staleRevision,
    })).toBe(editor);
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: editor.inputRevisions.mysql,
    });
    expect(isConfigPreviewCurrent(editor, "mysql")).toBe(true);

    const preview = "[mysqld]\nmax_connections = 400\n<script>run()</script>";
    const previewMarkup = renderToStaticMarkup(
      <ConfigArtifactPreview artifact={{
        key: "main",
        relativePath: "my.cnf",
        mediaType: "text/plain",
        byteLength: new TextEncoder().encode(preview).byteLength,
        preview,
        previewTruncated: false,
        copyAllowed: true,
      }} />,
    );
    expect(previewMarkup).toContain("max_connections = 400");
    expect(previewMarkup).toContain("&lt;script&gt;run()&lt;/script&gt;");
    expect(previewMarkup).not.toContain("<script>");

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain(
      'selectedProduct.key === "mysql" && feature.key === "max-connections"',
    );
    expect(source).toContain("<MySqlMaxConnectionsInlineEditor");
  });

  it("postgresql_and_mariadb_catalog_versions_search_and_inline_editor_dom_prerequisites_are_typed", () => {
    const feature = (
      key: string,
      title: string,
      aliases: string[],
      supportedChoices: string[],
    ) => ({
      key,
      title,
      summary: `${title} reviewed summary`,
      scope: "database",
      defaultEnabled: false,
      aliases,
      supportedChoices,
    });
    const postgresqlVersions = ["14", "15", "16", "17", "18"];
    const postgresqlProduct = {
      key: "postgresql",
      title: "PostgreSQL",
      family: "database",
      choiceKind: "version",
      defaultChoice: "18",
      choices: postgresqlVersions.map((key) => ({
        key,
        label: key,
        detail: "reviewed major",
        isDefault: key === "18",
      })),
      features: [
        feature(
          "lock-wait-logging",
          "按明确阈值记录锁等待",
          ["log_lock_waits", "锁等待", "deadlock_timeout"],
          postgresqlVersions,
        ),
        feature(
          "connection-capacity",
          "设置连接容量与应急保留槽",
          ["max_connections"],
          postgresqlVersions,
        ),
      ],
      artifacts: [{ key: "main", relativePath: "postgresql.conf", title: "PostgreSQL fragment" }],
      scopeNotice: "仅生成新建空集群片段。",
    } satisfies ConfigCatalog["products"][number];
    const mariadbVersions = ["10.11", "11.4", "11.8", "12.3"];
    const mariadbProduct = {
      key: "mariadb",
      title: "MariaDB",
      family: "database",
      choiceKind: "version",
      defaultChoice: "12.3",
      choices: mariadbVersions.map((key) => ({
        key,
        label: key,
        detail: "reviewed LTS",
        isDefault: key === "12.3",
      })),
      features: [
        feature(
          "binary-logging",
          "启用传统文件式二进制日志",
          ["log_bin", "复制日志"],
          mariadbVersions,
        ),
        feature(
          "binary-log-retention",
          "设置二进制日志保留时间",
          ["binlog_expire_logs_seconds", "日志保留", "自动清理"],
          mariadbVersions,
        ),
        feature(
          "maximum-packet-size",
          "限制最大协议包",
          ["max_allowed_packet"],
          mariadbVersions,
        ),
      ],
      artifacts: [{ key: "main", relativePath: "my.cnf", title: "MariaDB fragment" }],
      scopeNotice: "仅生成新建空实例片段。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [postgresqlProduct, mariadbProduct],
      readOnlyArtifacts: [],
    };

    const getPostgreSqlChoiceTestId = getConfigChoiceTestId(postgresqlProduct);
    expect(postgresqlProduct.choices.map((choice) => getPostgreSqlChoiceTestId(choice.key))).toEqual([
      "config-version-postgresql-14",
      "config-version-postgresql-15",
      "config-version-postgresql-16",
      "config-version-postgresql-17",
      "config-version-postgresql-18",
    ]);
    const getMariaDbChoiceTestId = getConfigChoiceTestId(mariadbProduct);
    expect(mariadbProduct.choices.map((choice) => getMariaDbChoiceTestId(choice.key))).toEqual([
      "config-version-mariadb-10-11",
      "config-version-mariadb-11-4",
      "config-version-mariadb-11-8",
      "config-version-mariadb-12-3",
    ]);

    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    editor = configEditorReducer(editor, {
      type: "set-query",
      query: "锁等待 deadlock_timeout",
    });
    const postgresqlResults = searchConfigCatalog(catalog, editor.query);
    expect(postgresqlResults.map((result) => result.id)).toEqual([
      "postgresql:lock-wait-logging",
    ]);
    expect(
      selectVisibleConfigFeatures(postgresqlProduct, postgresqlResults, editor.query)
        .map((item) => item.key),
    ).toEqual(["lock-wait-logging"]);
    editor = configEditorReducer(editor, {
      type: "select-search-result",
      subject: { product: "postgresql", featureKey: "lock-wait-logging" },
    });
    const postgresqlStaleRevision = editor.inputRevisions.postgresql;
    editor = configEditorReducer(editor, {
      type: "set-feature",
      product: "postgresql",
      featureKey: "lock-wait-logging",
      enabled: true,
    });
    const postgresqlValueIntents: Array<Extract<ConfigEditorAction, { type: "set-value" }>> = [];
    const postgresqlInput = PostgreSqlLockWaitInput({
      value: editor.values.postgresql.lockWaitThreshold,
      enabled: true,
      onIntent: (intent) => postgresqlValueIntents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { value: string } }): void;
    }>;
    postgresqlInput.props.onChange({ currentTarget: { value: "1500" } });
    expect(postgresqlValueIntents).toEqual([{
      type: "set-value",
      product: "postgresql",
      key: "lockWaitThreshold",
      value: "1500",
    }]);
    const postgresqlValueIntent = postgresqlValueIntents[0];
    if (postgresqlValueIntent === undefined) throw new Error("PostgreSQL value intent required");
    editor = configEditorReducer(editor, postgresqlValueIntent);
    expect(editor.inputRevisions.postgresql).toBe(postgresqlStaleRevision + 2);
    expect(buildConfigGenerateInput(editor)).toMatchObject({
      product: "postgresql",
      choice: "18",
      features: ["lock-wait-logging"],
      values: { lockWaitThreshold: "1500" },
    });
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const postgresqlFeature = postgresqlProduct.features[0];
    if (postgresqlFeature === undefined) throw new Error("PostgreSQL lock feature required");
    const postgresqlMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="postgresql"
        feature={postgresqlFeature}
        checked
        supported
        selected
        inlineEditor={(
          <PostgreSqlLockWaitInlineEditor
            value="1500"
            enabled
            onIntent={() => undefined}
          />
        )}
        onIntent={() => undefined}
      />,
    );
    expect(postgresqlMarkup.indexOf(
      "data-testid=\"config-feature-inline-editor-postgresql-lock-wait-logging\"",
    )).toBeGreaterThan(postgresqlMarkup.indexOf(
      "data-testid=\"config-feature-row-postgresql-lock-wait-logging\"",
    ));
    expect(postgresqlMarkup).toContain(
      "data-testid=\"config-inline-value-postgresql-lockWaitThreshold\"",
    );
    expect(postgresqlMarkup).toContain("value=\"1500\"");

    editor = configEditorReducer(editor, { type: "select-product", product: "mariadb" });
    editor = configEditorReducer(editor, { type: "set-query", query: "日志保留" });
    const mariadbResults = searchConfigCatalog(catalog, editor.query);
    expect(mariadbResults.map((result) => result.id)).toEqual([
      "mariadb:binary-log-retention",
    ]);
    expect(
      selectVisibleConfigFeatures(mariadbProduct, mariadbResults, editor.query)
        .map((item) => item.key),
    ).toEqual(["binary-log-retention"]);
    editor = configEditorReducer(editor, {
      type: "select-search-result",
      subject: { product: "mariadb", featureKey: "binary-log-retention" },
    });
    const mariadbStaleRevision = editor.inputRevisions.mariadb;
    editor = configEditorReducer(editor, {
      type: "set-feature",
      product: "mariadb",
      featureKey: "binary-log-retention",
      enabled: true,
    });
    expect(editor.enabledFeatures.mariadb).toEqual([
      "binary-logging",
      "binary-log-retention",
    ]);
    const mariadbValueIntents: Array<Extract<ConfigEditorAction, { type: "set-value" }>> = [];
    const mariadbInput = MariaDbBinaryLogRetentionInput({
      value: editor.values.mariadb.binlogRetention,
      enabled: true,
      onIntent: (intent) => mariadbValueIntents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { value: string } }): void;
    }>;
    mariadbInput.props.onChange({ currentTarget: { value: "86400" } });
    expect(mariadbValueIntents).toEqual([{
      type: "set-value",
      product: "mariadb",
      key: "binlogRetention",
      value: "86400",
    }]);
    const mariadbValueIntent = mariadbValueIntents[0];
    if (mariadbValueIntent === undefined) throw new Error("MariaDB value intent required");
    editor = configEditorReducer(editor, mariadbValueIntent);
    expect(editor.inputRevisions.mariadb).toBe(mariadbStaleRevision + 2);
    expect(buildConfigGenerateInput(editor)).toMatchObject({
      product: "mariadb",
      choice: "12.3",
      features: ["binary-logging", "binary-log-retention"],
      values: { binlogRetention: "86400" },
    });
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const mariadbFeature = mariadbProduct.features[1];
    if (mariadbFeature === undefined) throw new Error("MariaDB retention feature required");
    const mariadbMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="mariadb"
        feature={mariadbFeature}
        checked
        supported
        selected
        inlineEditor={(
          <MariaDbBinaryLogRetentionInlineEditor
            value="86400"
            enabled
            onIntent={() => undefined}
          />
        )}
        onIntent={() => undefined}
      />,
    );
    expect(mariadbMarkup.indexOf(
      "data-testid=\"config-feature-inline-editor-mariadb-binary-log-retention\"",
    )).toBeGreaterThan(mariadbMarkup.indexOf(
      "data-testid=\"config-feature-row-mariadb-binary-log-retention\"",
    ));
    expect(mariadbMarkup).toContain(
      "data-testid=\"config-inline-value-mariadb-binlogRetention\"",
    );
    expect(mariadbMarkup).toContain("value=\"86400\"");

    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "mariadb",
      inputRevision: mariadbStaleRevision,
    })).toBe(editor);
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "mariadb",
      inputRevision: editor.inputRevisions.mariadb,
    });
    expect(isConfigPreviewCurrent(editor, "mariadb")).toBe(true);

    const hostilePreview = renderToStaticMarkup(
      <ConfigArtifactPreview artifact={{
        key: "main",
        relativePath: "my.cnf",
        mediaType: "text/plain",
        byteLength: 35,
        preview: "<script>run()</script>\nretention=86400",
        previewTruncated: false,
        copyAllowed: true,
      }} />,
    );
    expect(hostilePreview).toContain("&lt;script&gt;run()&lt;/script&gt;");
    expect(hostilePreview).not.toContain("<script>");

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("visibleSelectedFeatures.map((feature) =>");
    expect(source).toContain("<PostgreSqlLockWaitInlineEditor");
    expect(source).toContain("<MariaDbBinaryLogRetentionInlineEditor");
  });

  it("redis_catalog_inline_editor_and_preview_dom_prerequisites_are_typed", () => {
    const feature = (key: string, title: string, aliases: string[], defaultEnabled: boolean) => ({
      key,
      title,
      summary: `${title} reviewed Redis feature`,
      scope: "可观测性",
      defaultEnabled,
      aliases,
      supportedChoices: ["8.10"],
    });
    const redisProduct = {
      key: "redis",
      title: "Redis",
      family: "cache",
      choiceKind: "version",
      defaultChoice: "8.10",
      choices: [{
        key: "8.10",
        label: "8.10",
        detail: "reviewed Redis version",
        isDefault: true,
      }],
      features: [
        feature("memory-limit", "设置最大内存", ["maxmemory"], true),
        feature("aof-persistence", "启用 AOF 持久化", ["appendonly"], true),
        feature("slow-log", "记录慢命令", ["slowlog", "慢命令", "慢日志"], true),
        feature("latency-monitor", "启用延迟事件监控", ["LATENCY"], false),
      ],
      artifacts: [{ key: "main", relativePath: "redis.conf", title: "Redis configuration" }],
      scopeNotice: "仅生成全新空实例的本地审阅草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [redisProduct],
      readOnlyArtifacts: [],
    };

    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    expect(editor.enabledFeatures.redis).toEqual([
      "memory-limit",
      "aof-persistence",
      "slow-log",
    ]);
    editor = configEditorReducer(editor, { type: "set-query", query: "slowlog 慢命令" });
    const searchResults = searchConfigCatalog(catalog, editor.query);
    expect(searchResults.map((result) => result.id)).toEqual(["redis:slow-log"]);
    expect(
      selectVisibleConfigFeatures(redisProduct, searchResults, editor.query)
        .map((item) => item.key),
    ).toEqual(["slow-log"]);
    const revisionBeforeSelection = editor.inputRevisions.redis;
    editor = configEditorReducer(editor, {
      type: "select-search-result",
      subject: { product: "redis", featureKey: "slow-log" },
    });
    expect(editor.inputRevisions.redis).toBe(revisionBeforeSelection);
    expect(editor.selectedSubject).toEqual({ product: "redis", featureKey: "slow-log" });

    const valueIntents: Array<Extract<ConfigEditorAction, { type: "set-value" }>> = [];
    const thresholdInput = RedisSlowLogValueInput({
      valueKey: "slowlogThreshold",
      value: editor.values.redis.slowlogThreshold,
      enabled: true,
      onIntent: (intent) => valueIntents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { value: string } }): void;
    }>;
    thresholdInput.props.onChange({ currentTarget: { value: "25000" } });
    const lengthInput = RedisSlowLogValueInput({
      valueKey: "slowlogLength",
      value: editor.values.redis.slowlogLength,
      enabled: true,
      onIntent: (intent) => valueIntents.push(intent),
    }) as ReactElement<{
      onChange(event: { currentTarget: { value: string } }): void;
    }>;
    lengthInput.props.onChange({ currentTarget: { value: "256" } });
    expect(valueIntents).toEqual([
      {
        type: "set-value",
        product: "redis",
        key: "slowlogThreshold",
        value: "25000",
      },
      {
        type: "set-value",
        product: "redis",
        key: "slowlogLength",
        value: "256",
      },
    ]);
    for (const intent of valueIntents) editor = configEditorReducer(editor, intent);
    expect(editor.inputRevisions.redis).toBe(revisionBeforeSelection + 2);
    expect(buildConfigGenerateInput(editor)).toMatchObject({
      product: "redis",
      choice: "8.10",
      features: ["memory-limit", "aof-persistence", "slow-log"],
      values: { slowlogThreshold: "25000", slowlogLength: "256" },
    });
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const slowLogFeature = redisProduct.features.find((item) => item.key === "slow-log");
    if (slowLogFeature === undefined) throw new Error("Redis slow-log feature required");
    const inlineEditor = (
      <RedisSlowLogInlineEditor
        threshold="25000"
        length="256"
        enabled
        onIntent={() => undefined}
      />
    );
    const selectedMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="redis"
        feature={slowLogFeature}
        checked
        supported
        selected
        inlineEditor={inlineEditor}
        onIntent={() => undefined}
      />,
    );
    expect(selectedMarkup.indexOf(
      "data-testid=\"config-feature-inline-editor-redis-slow-log\"",
    )).toBeGreaterThan(selectedMarkup.indexOf(
      "data-testid=\"config-feature-row-redis-slow-log\"",
    ));
    expect(selectedMarkup).toContain(
      "data-testid=\"config-inline-value-redis-slowlogThreshold\"",
    );
    expect(selectedMarkup).toContain("value=\"25000\"");
    expect(selectedMarkup).toContain(
      "data-testid=\"config-inline-value-redis-slowlogLength\"",
    );
    expect(selectedMarkup).toContain("value=\"256\"");
    const unselectedMarkup = renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="redis"
        feature={slowLogFeature}
        checked
        supported
        selected={false}
        inlineEditor={inlineEditor}
        onIntent={() => undefined}
      />,
    );
    expect(unselectedMarkup).not.toContain("config-feature-inline-editor-redis-slow-log");

    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: revisionBeforeSelection,
    })).toBe(editor);
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: editor.inputRevisions.redis,
    });
    expect(isConfigPreviewCurrent(editor, "redis")).toBe(true);

    const hostilePreview = renderToStaticMarkup(
      <ConfigArtifactPreview artifact={{
        key: "main",
        relativePath: "redis.conf",
        mediaType: "text/plain",
        byteLength: 72,
        preview: "<script>globalThis.redisInlineExecuted=true</script>\nslowlog-max-len 256",
        previewTruncated: false,
        copyAllowed: true,
      }} />,
    );
    expect(hostilePreview).toContain(
      "&lt;script&gt;globalThis.redisInlineExecuted=true&lt;/script&gt;",
    );
    expect(hostilePreview).not.toContain("<script>");

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain('selectedProduct.key === "redis" &&');
    expect(source).toContain('feature.key === "slow-log"');
    expect(source).toContain("<RedisSlowLogInlineEditor");
    const css = readFileSync(new URL("./config-generator.css", import.meta.url), "utf8");
    expect(css).toContain(".config-feature-list > label.inline-editor-anchor");
    expect(css).toContain("margin-top: -6px;");
    // The page fills a wide window like the other configuration modes; a
    // fixed cap once left a blank strip on its right.
    const page = css.match(/\.config-generator-page \{[^}]*\}/u)?.[0] ?? "";
    expect(page).not.toContain("max-width");
    expect(css).toMatch(/\.config-feature-list \{[^}]*repeat\(auto-fill, minmax\(260px, 1fr\)\)/u);
  });

  it("mysql_quick_stack_remove_reset_preview_and_save_prerequisites_are_isolated", async () => {
    const mysqlProduct = {
      key: "mysql",
      title: "MySQL",
      family: "database",
      choiceKind: "version",
      defaultChoice: "8.4.0",
      choices: [{
        key: "8.4.0",
        label: "MySQL 8.4.0",
        detail: "闭合的 MySQL 8.4 option-file 生成器",
        isDefault: true,
      }],
      features: [
        {
          key: "max-connections",
          title: "最大连接数",
          summary: "设置 max_connections",
          scope: "mysqld",
          defaultEnabled: false,
          aliases: ["max_connections"],
          supportedChoices: ["8.4.0"],
        },
        {
          key: "slow-query-log",
          title: "慢查询日志",
          summary: "启用慢查询日志",
          scope: "mysqld",
          defaultEnabled: false,
          aliases: ["slow_query_log"],
          supportedChoices: ["8.4.0"],
        },
        {
          key: "binary-logging",
          title: "二进制日志",
          summary: "启用二进制日志标识",
          scope: "mysqld",
          defaultEnabled: false,
          aliases: ["log_bin"],
          supportedChoices: ["8.4.0"],
        },
        {
          key: "binary-log-retention",
          title: "二进制日志保留",
          summary: "设置二进制日志保留时间",
          scope: "mysqld",
          defaultEnabled: false,
          aliases: ["binlog retention"],
          supportedChoices: ["8.4.0"],
        },
      ],
      artifacts: [{ key: "main", relativePath: "my.cnf", title: "mysqld option file" }],
      scopeNotice: "仅生成本地审阅草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [
        mysqlProduct,
        {
          key: "nginx",
          title: "Nginx",
          family: "web-server",
          choiceKind: "mode",
          defaultChoice: "reverse-proxy",
          choices: [{
            key: "reverse-proxy",
            label: "反向代理",
            detail: "隔离哨兵",
            isDefault: true,
          }],
          features: [{
            key: "nginx-sentinel",
            title: "Nginx 隔离哨兵",
            summary: "不得被 MySQL reset 修改",
            scope: "test",
            defaultEnabled: true,
            aliases: ["sentinel"],
            supportedChoices: ["reverse-proxy"],
          }],
          artifacts: [{ key: "site", relativePath: "nginx-site.conf", title: "站点配置" }],
          scopeNotice: "隔离测试。",
        },
      ],
      readOnlyArtifacts: [],
    };
    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    expect(editor.enabledFeatures.mysql).toEqual([]);
    expect(editor.enabledFeatures.nginx).toEqual(["nginx-sentinel"]);
    expect(editor.values.mysql.maxConnections).toBe("151");

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: editor.inputRevisions.mysql,
    });
    expect(isConfigPreviewCurrent(editor, "mysql")).toBe(true);
    editor = configEditorReducer(editor, {
      type: "set-value",
      product: "mysql",
      key: "maxConnections",
      value: "400",
    });

    function clickFeature(featureKey: string, enabled: boolean) {
      const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
      const toggle = ConfigFeatureToggle({
        product: "mysql",
        featureKey,
        checked: editor.enabledFeatures.mysql.includes(featureKey),
        disabled: false,
        onIntent: (intent) => intents.push(intent),
      }) as ReactElement<{
        onChange(event: { currentTarget: { checked: boolean } }): void;
      }>;
      toggle.props.onChange({ currentTarget: { checked: enabled } });
      expect(intents).toEqual([{
        type: "set-feature",
        product: "mysql",
        featureKey,
        enabled,
      }]);
      const intent = intents[0];
      if (intent === undefined) throw new Error("MySQL feature intent must be emitted");
      editor = configEditorReducer(editor, intent);
    }

    clickFeature("max-connections", true);
    clickFeature("slow-query-log", true);
    clickFeature("binary-log-retention", true);
    expect(editor.enabledFeatures.mysql).toEqual([
      "max-connections",
      "slow-query-log",
      "binary-logging",
      "binary-log-retention",
    ]);
    expect(editor.enabledFeatures.nginx).toEqual(["nginx-sentinel"]);
    const stackedInput = buildConfigGenerateInput(editor);
    if (stackedInput?.product !== "mysql") {
      throw new Error("stacked MySQL input must retain its discriminant");
    }
    expect(stackedInput.values.maxConnections).toBe("400");
    expect(isConfigGenerateInput(stackedInput)).toBe(true);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: editor.inputRevisions.mysql,
    });
    const staleStackRevision = editor.inputRevisions.mysql;
    clickFeature("max-connections", false);
    expect(editor.enabledFeatures.mysql).toEqual([
      "slow-query-log",
      "binary-logging",
      "binary-log-retention",
    ]);
    expect(editor.selectedSubject).toEqual({
      product: "mysql",
      featureKey: "binary-log-retention",
    });
    expect(isConfigPreviewCurrent(editor, "mysql")).toBe(false);
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: staleStackRevision,
    })).toBe(editor);
    const remainingRowStates = renderToStaticMarkup(<>
      <ConfigFeatureToggle
        product="mysql"
        featureKey="max-connections"
        checked={editor.enabledFeatures.mysql.includes("max-connections")}
        disabled={false}
        onIntent={() => undefined}
      />
      <ConfigFeatureToggle
        product="mysql"
        featureKey="slow-query-log"
        checked={editor.enabledFeatures.mysql.includes("slow-query-log")}
        disabled={false}
        onIntent={() => undefined}
      />
    </>);
    expect(remainingRowStates).toContain("data-testid=\"config-feature-mysql-max-connections\"");
    expect(remainingRowStates).not.toContain(
      "data-testid=\"config-feature-mysql-max-connections\" checked=\"\"",
    );
    expect(remainingRowStates).toContain(
      "data-testid=\"config-feature-mysql-slow-query-log\" checked=\"\"",
    );

    clickFeature("binary-logging", false);
    expect(editor.enabledFeatures.mysql).toEqual(["slow-query-log"]);
    expect(editor.selectedSubject).toBeNull();
    clickFeature("binary-log-retention", true);
    expect(editor.enabledFeatures.mysql).toEqual([
      "slow-query-log",
      "binary-logging",
      "binary-log-retention",
    ]);

    const staleResetRevision = editor.inputRevisions.mysql;
    editor = configEditorReducer(editor, { type: "reset-product", product: mysqlProduct });
    expect(editor.enabledFeatures.mysql).toEqual([]);
    expect(editor.enabledFeatures.nginx).toEqual(["nginx-sentinel"]);
    expect(editor.values.mysql).toEqual(DEFAULT_CONFIG_VALUES.mysql);
    expect(editor.values.mysql.maxConnections).toBe("151");
    expect(editor.choices.mysql).toBe("8.4.0");
    expect(editor.preview).toBeNull();
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "mysql",
      inputRevision: staleResetRevision,
    })).toBe(editor);
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain(
      "dispatch({ type: \"reset-product\", product: selectedProduct });",
    );
    expect(source).toContain("work: () => configApi.exportConfigArtifact(");
    expect(source).toContain("currentDraft.handle,");
    expect(source).toContain("currentDraft.revision,");
    expect(source).toContain("currentArtifact.key,");
    expect(source).toContain("onClick={() => void exportArtifact()}");

    const lifecycle = new ConfigRequestLifecycle();
    const pendingExport = deferred<{ saved: boolean; fileName: string | null }>();
    const acceptLateExport = vi.fn();
    lifecycle.activate();
    const runningExport = lifecycle.run({
      work: () => pendingExport.promise,
      onSuccess: acceptLateExport,
      onError: vi.fn(),
      onFinally: vi.fn(),
    });
    lifecycle.deactivate();
    pendingExport.resolve({ saved: true, fileName: "mysql-quick.cnf" });
    await expect(runningExport).resolves.toBe("stale");
    expect(acceptLateExport).not.toHaveBeenCalled();
  });

  it("postgresql_and_mariadb_quick_interactions_are_isolated_and_save_prerequisites_are_current", () => {
    const choice = (key: string, isDefault = false) => ({
      key,
      label: key,
      detail: "闭合版本测试",
      isDefault,
    });
    const feature = (key: string, supportedChoices: string[]) => ({
      key,
      title: key,
      summary: `${key} 闭合测试特性`,
      scope: "database",
      defaultEnabled: false,
      aliases: [key],
      supportedChoices,
    });
    const postgresqlProduct = {
      key: "postgresql",
      title: "PostgreSQL",
      family: "database",
      choiceKind: "version",
      defaultChoice: "18",
      choices: [choice("15"), choice("18", true)],
      features: [
        feature("connection-capacity", ["15", "18"]),
        feature("connection-lifecycle-logging", ["15", "18"]),
      ],
      artifacts: [{ key: "main", relativePath: "postgresql.conf", title: "server configuration" }],
      scopeNotice: "仅生成本地审阅草稿。",
    } satisfies ConfigCatalog["products"][number];
    const mariadbProduct = {
      key: "mariadb",
      title: "MariaDB",
      family: "database",
      choiceKind: "version",
      defaultChoice: "12.3",
      choices: [choice("10.11"), choice("12.3", true)],
      features: [
        feature("slow-query-log", ["10.11", "12.3"]),
        feature("binary-logging", ["10.11", "12.3"]),
        feature("binary-log-retention", ["10.11", "12.3"]),
        feature("binary-log-durability", ["10.11", "12.3"]),
      ],
      artifacts: [{ key: "main", relativePath: "mariadb.cnf", title: "server option file" }],
      scopeNotice: "仅生成本地审阅草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [postgresqlProduct, mariadbProduct],
      readOnlyArtifacts: [],
    };
    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });

    function setValue(product: "postgresql" | "mariadb", key: string, value: string) {
      editor = configEditorReducer(editor, { type: "set-value", product, key, value });
    }

    function clickFeature(
      product: "postgresql" | "mariadb",
      featureKey: string,
      enabled: boolean,
    ) {
      const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
      const toggle = ConfigFeatureToggle({
        product,
        featureKey,
        checked: editor.enabledFeatures[product].includes(featureKey),
        disabled: false,
        onIntent: (intent) => intents.push(intent),
      }) as ReactElement<{
        onChange(event: { currentTarget: { checked: boolean } }): void;
      }>;
      toggle.props.onChange({ currentTarget: { checked: enabled } });
      expect(intents).toEqual([{ type: "set-feature", product, featureKey, enabled }]);
      const intent = intents[0];
      if (intent === undefined) throw new Error("database feature intent must be emitted");
      editor = configEditorReducer(editor, intent);
    }

    setValue("postgresql", "maxConnections", "240");
    setValue("postgresql", "reservedConnections", "2");
    clickFeature("postgresql", "connection-capacity", true);
    clickFeature("postgresql", "connection-lifecycle-logging", true);
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "postgresql",
      inputRevision: editor.inputRevisions.postgresql,
    });
    expect(isConfigPreviewCurrent(editor, "postgresql")).toBe(true);
    const stalePostgreSql18Revision = editor.inputRevisions.postgresql;

    editor = configEditorReducer(editor, {
      type: "set-choice",
      product: "postgresql",
      choice: "15",
      supportedFeatureKeys: postgresqlProduct.features.map((item) => item.key),
    });
    expect(editor.choices.postgresql).toBe("15");
    expect(editor.values.postgresql.reservedConnections).toBe("0");
    expect(editor.values.postgresql.maxConnections).toBe("240");
    expect(editor.enabledFeatures.postgresql).toEqual([
      "connection-capacity",
      "connection-lifecycle-logging",
    ]);
    expect(isConfigPreviewCurrent(editor, "postgresql")).toBe(false);
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "postgresql",
      inputRevision: stalePostgreSql18Revision,
    })).toBe(editor);
    const postgresql15Input = buildConfigGenerateInput(editor);
    if (postgresql15Input?.product !== "postgresql") {
      throw new Error("PostgreSQL input must retain its discriminant");
    }
    expect(postgresql15Input.values.reservedConnections).toBe("0");
    expect(isConfigGenerateInput(postgresql15Input)).toBe(true);

    clickFeature("postgresql", "connection-capacity", false);
    expect(editor.enabledFeatures.postgresql).toEqual(["connection-lifecycle-logging"]);
    editor = configEditorReducer(editor, { type: "select-product", product: "mariadb" });
    expect(editor.enabledFeatures.postgresql).toEqual(["connection-lifecycle-logging"]);
    expect(editor.choices.postgresql).toBe("15");

    setValue("mariadb", "serverId", "42");
    setValue("mariadb", "binlogRetention", "86400");
    clickFeature("mariadb", "binary-log-retention", true);
    clickFeature("mariadb", "binary-log-durability", true);
    expect(editor.enabledFeatures.mariadb).toEqual([
      "binary-logging",
      "binary-log-retention",
      "binary-log-durability",
    ]);
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "mariadb",
      inputRevision: editor.inputRevisions.mariadb,
    });
    const staleMariaDbStackRevision = editor.inputRevisions.mariadb;
    clickFeature("mariadb", "binary-logging", false);
    expect(editor.enabledFeatures.mariadb).toEqual([]);
    expect(editor.selectedSubject).toBeNull();
    expect(isConfigPreviewCurrent(editor, "mariadb")).toBe(false);
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "mariadb",
      inputRevision: staleMariaDbStackRevision,
    })).toBe(editor);

    editor = configEditorReducer(editor, {
      type: "set-choice",
      product: "mariadb",
      choice: "10.11",
      supportedFeatureKeys: mariadbProduct.features.map((item) => item.key),
    });
    clickFeature("mariadb", "slow-query-log", true);
    expect(editor.choices.mariadb).toBe("10.11");
    expect(editor.enabledFeatures.mariadb).toEqual(["slow-query-log"]);

    editor = configEditorReducer(editor, { type: "select-product", product: "postgresql" });
    editor = configEditorReducer(editor, {
      type: "reset-product",
      product: postgresqlProduct,
    });
    expect(editor.choices.postgresql).toBe("18");
    expect(editor.enabledFeatures.postgresql).toEqual([]);
    expect(editor.values.postgresql).toEqual(DEFAULT_CONFIG_VALUES.postgresql);
    expect(editor.choices.mariadb).toBe("10.11");
    expect(editor.enabledFeatures.mariadb).toEqual(["slow-query-log"]);
    expect(editor.values.mariadb.serverId).toBe("42");
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    editor = configEditorReducer(editor, { type: "select-product", product: "mariadb" });
    const mariadb10Input = buildConfigGenerateInput(editor);
    expect(mariadb10Input?.product).toBe("mariadb");
    expect(isConfigGenerateInput(mariadb10Input)).toBe(true);
    editor = configEditorReducer(editor, { type: "reset-product", product: mariadbProduct });
    expect(editor.choices.mariadb).toBe("12.3");
    expect(editor.enabledFeatures.mariadb).toEqual([]);
    expect(editor.values.mariadb).toEqual(DEFAULT_CONFIG_VALUES.mariadb);
    expect(editor.choices.postgresql).toBe("18");
    expect(editor.enabledFeatures.postgresql).toEqual([]);

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("dispatch(choiceAction(selectedProduct,");
    // The mode change carries the features the new choice supports (choiceAction, tested on its own).
    expect(readFileSync(new URL("./config-generator-state.ts", import.meta.url), "utf8"))
      .toContain("supportedFeatureKeys: product.features");
    expect(source).toContain(
      "dispatch({ type: \"reset-product\", product: selectedProduct });",
    );
    expect(source).toContain("work: () => configApi.exportConfigArtifact(");
    expect(source).toContain("currentDraft.handle,");
    expect(source).toContain("currentDraft.revision,");
    expect(source).toContain("currentArtifact.key,");
  });

  it("redis_quick_stack_remove_reset_and_save_prerequisites_are_current", () => {
    const feature = (key: string, defaultEnabled: boolean) => ({
      key,
      title: key,
      summary: `${key} 闭合 Redis 测试特性`,
      scope: "redis",
      defaultEnabled,
      aliases: [key],
      supportedChoices: ["8.10"],
    });
    const redisProduct = {
      key: "redis",
      title: "Redis",
      family: "cache",
      choiceKind: "version",
      defaultChoice: "8.10",
      choices: [{
        key: "8.10",
        label: "8.10",
        detail: "闭合的 Redis 新空实例配置",
        isDefault: true,
      }],
      features: [
        feature("max-clients", true),
        feature("idle-client-timeout", false),
        feature("tcp-keepalive", true),
        feature("memory-limit", true),
        feature("eviction-policy", false),
        feature("aof-persistence", true),
        feature("rdb-persistence", true),
        feature("slow-log", true),
        feature("latency-monitor", false),
      ],
      artifacts: [{ key: "main", relativePath: "redis.conf", title: "Redis configuration" }],
      scopeNotice: "仅生成全新空实例的本地审阅草稿。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [redisProduct],
      readOnlyArtifacts: [],
    };
    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    const defaults = [
      "max-clients",
      "tcp-keepalive",
      "memory-limit",
      "aof-persistence",
      "rdb-persistence",
      "slow-log",
    ];
    expect(editor.enabledFeatures.redis).toEqual(defaults);

    function setValue(key: string, value: string) {
      editor = configEditorReducer(editor, { type: "set-value", product: "redis", key, value });
    }

    function clickFeature(featureKey: string, enabled: boolean) {
      const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
      const toggle = ConfigFeatureToggle({
        product: "redis",
        featureKey,
        checked: editor.enabledFeatures.redis.includes(featureKey),
        disabled: false,
        onIntent: (intent) => intents.push(intent),
      }) as ReactElement<{
        onChange(event: { currentTarget: { checked: boolean } }): void;
      }>;
      toggle.props.onChange({ currentTarget: { checked: enabled } });
      expect(intents).toEqual([{
        type: "set-feature",
        product: "redis",
        featureKey,
        enabled,
      }]);
      const intent = intents[0];
      if (intent === undefined) throw new Error("Redis feature intent must be emitted");
      editor = configEditorReducer(editor, intent);
    }

    setValue("idleTimeout", "600");
    setValue("latencyThreshold", "50");
    setValue("evictionPolicy", "allkeys-lru");
    clickFeature("idle-client-timeout", true);
    clickFeature("latency-monitor", true);
    clickFeature("eviction-policy", true);
    expect(editor.enabledFeatures.redis).toEqual([
      ...defaults,
      "idle-client-timeout",
      "latency-monitor",
      "eviction-policy",
    ]);
    const stackedInput = buildConfigGenerateInput(editor);
    if (stackedInput?.product !== "redis") {
      throw new Error("Redis input must retain its discriminant");
    }
    expect(stackedInput.values.idleTimeout).toBe("600");
    expect(stackedInput.values.latencyThreshold).toBe("50");
    expect(stackedInput.values.evictionPolicy).toBe("allkeys-lru");
    expect(isConfigGenerateInput(stackedInput)).toBe(true);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: editor.inputRevisions.redis,
    });
    const staleStackRevision = editor.inputRevisions.redis;
    clickFeature("idle-client-timeout", false);
    expect(editor.enabledFeatures.redis).not.toContain("idle-client-timeout");
    expect(editor.enabledFeatures.redis).toContain("latency-monitor");
    expect(editor.enabledFeatures.redis).toContain("eviction-policy");
    expect(isConfigPreviewCurrent(editor, "redis")).toBe(false);
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: staleStackRevision,
    })).toBe(editor);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: editor.inputRevisions.redis,
    });
    const mandatoryMemoryRevision = editor.inputRevisions.redis;
    clickFeature("memory-limit", false);
    expect(editor.enabledFeatures.redis).toContain("memory-limit");
    expect(editor.inputRevisions.redis).toBe(mandatoryMemoryRevision);
    expect(isConfigPreviewCurrent(editor, "redis")).toBe(true);

    clickFeature("aof-persistence", false);
    expect(editor.enabledFeatures.redis).not.toContain("aof-persistence");
    expect(editor.enabledFeatures.redis).toContain("rdb-persistence");
    expect(isConfigPreviewCurrent(editor, "redis")).toBe(false);
    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: editor.inputRevisions.redis,
    });
    const lastPersistenceRevision = editor.inputRevisions.redis;
    clickFeature("rdb-persistence", false);
    expect(editor.enabledFeatures.redis).toContain("rdb-persistence");
    expect(editor.inputRevisions.redis).toBe(lastPersistenceRevision);
    expect(isConfigPreviewCurrent(editor, "redis")).toBe(true);
    const persistenceRow = renderToStaticMarkup(
      <ConfigFeatureToggle
        product="redis"
        featureKey="rdb-persistence"
        checked={editor.enabledFeatures.redis.includes("rdb-persistence")}
        disabled={false}
        onIntent={() => undefined}
      />,
    );
    expect(persistenceRow).toContain(
      "data-testid=\"config-feature-redis-rdb-persistence\" checked=\"\"",
    );

    setValue("maxmemoryMib", "1024");
    const staleResetRevision = editor.inputRevisions.redis;
    editor = configEditorReducer(editor, { type: "reset-product", product: redisProduct });
    expect(editor.enabledFeatures.redis).toEqual(defaults);
    expect(editor.values.redis).toEqual(DEFAULT_CONFIG_VALUES.redis);
    expect(editor.choices.redis).toBe("8.10");
    expect(editor.selectedSubject).toBeNull();
    expect(editor.preview).toBeNull();
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "redis",
      inputRevision: staleResetRevision,
    })).toBe(editor);
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain(
      "dispatch({ type: \"reset-product\", product: selectedProduct });",
    );
    expect(source).toContain(
      "work: () => configApi.copyConfig(currentDraft.handle, currentDraft.revision)",
    );
    expect(source).toContain("work: () => configApi.exportConfigArtifact(");
    expect(source).toContain("currentDraft.handle,");
    expect(source).toContain("currentDraft.revision,");
    expect(source).toContain("currentArtifact.key,");
    expect(source).toContain("onClick={() => void exportArtifact()}");
  });

  it("tomcat_quick_bundle_stack_exclude_remove_reset_copy_and_save_prerequisites_are_current", () => {
    const feature = (key: string, defaultEnabled: boolean) => ({
      key,
      title: key,
      summary: `${key} 闭合 Tomcat 测试特性`,
      scope: "tomcat",
      defaultEnabled,
      aliases: [key],
      supportedChoices: ["10.1", "11.0"],
    });
    const tomcatProduct = {
      key: "tomcat",
      title: "Tomcat",
      family: "application-server",
      choiceKind: "version",
      defaultChoice: "11.0",
      choices: [
        { key: "10.1", label: "10.1", detail: "Servlet 6.0", isDefault: false },
        { key: "11.0", label: "11.0", detail: "Servlet 6.1", isDefault: true },
      ],
      features: [
        feature("connector-limits", true),
        feature("response-compression", false),
        feature("host-auto-deploy", false),
        feature("host-unpack-wars", false),
        feature("allow-cross-context", false),
        feature("http-only-session-cookies", true),
        feature("header-security-filter", true),
        feature("allow-safe-methods-only", false),
        feature("deny-all-requests", false),
      ],
      artifacts: [
        { key: "server.xml", relativePath: "conf/server.xml", title: "Connector" },
        {
          key: "context.xml",
          relativePath: "webapps/ROOT/META-INF/context.xml",
          title: "Context",
        },
        {
          key: "web.xml",
          relativePath: "webapps/ROOT/WEB-INF/web.xml",
          title: "Deployment descriptor",
        },
      ],
      scopeNotice: "仅生成全新空环境的三工件本地审阅 bundle。",
    } satisfies ConfigCatalog["products"][number];
    const catalog: ConfigCatalog = {
      schema: "lovelyres-config-catalog/v2",
      products: [tomcatProduct],
      readOnlyArtifacts: [],
    };
    let editor = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog,
    });
    const defaults = [
      "connector-limits",
      "http-only-session-cookies",
      "header-security-filter",
    ];
    expect(editor.enabledFeatures.tomcat).toEqual(defaults);

    function setValue(key: string, value: string) {
      editor = configEditorReducer(editor, { type: "set-value", product: "tomcat", key, value });
    }

    function clickFeature(featureKey: string, enabled: boolean) {
      const intents: Array<Extract<ConfigEditorAction, { type: "set-feature" }>> = [];
      const toggle = ConfigFeatureToggle({
        product: "tomcat",
        featureKey,
        checked: editor.enabledFeatures.tomcat.includes(featureKey),
        disabled: false,
        onIntent: (intent) => intents.push(intent),
      }) as ReactElement<{
        onChange(event: { currentTarget: { checked: boolean } }): void;
      }>;
      toggle.props.onChange({ currentTarget: { checked: enabled } });
      expect(intents).toEqual([{
        type: "set-feature",
        product: "tomcat",
        featureKey,
        enabled,
      }]);
      const intent = intents[0];
      if (intent === undefined) throw new Error("Tomcat feature intent must be emitted");
      editor = configEditorReducer(editor, intent);
    }

    editor = configEditorReducer(editor, {
      type: "set-choice",
      product: "tomcat",
      choice: "10.1",
      supportedFeatureKeys: tomcatProduct.features.map((item) => item.key),
    });
    for (const [key, value] of [
      ["connectorAddress", "ipv6-loopback"],
      ["applicationName", "Operations ROOT"],
      ["port", "8181"],
      ["connectionTimeout", "25000"],
      ["maxThreads", "320"],
      ["acceptCount", "400"],
      ["maxConnections", "12000"],
      ["maxPostSize", "3000000"],
      ["maxSwallowSize", "4000000"],
      ["compressionMinSize", "1024"],
    ] as const) {
      setValue(key, value);
    }
    clickFeature("response-compression", true);
    clickFeature("host-auto-deploy", true);
    clickFeature("allow-safe-methods-only", true);
    expect(editor.enabledFeatures.tomcat).toEqual([
      ...defaults,
      "response-compression",
      "host-auto-deploy",
      "allow-safe-methods-only",
    ]);
    const stackedInput = buildConfigGenerateInput(editor);
    if (stackedInput?.product !== "tomcat") {
      throw new Error("Tomcat input must retain its discriminant");
    }
    expect(stackedInput.choice).toBe("10.1");
    expect(stackedInput.values.connectorAddress).toBe("ipv6-loopback");
    expect(stackedInput.values.applicationName).toBe("Operations ROOT");
    expect(isConfigGenerateInput(stackedInput)).toBe(true);

    editor = configEditorReducer(editor, {
      type: "preview-generated",
      product: "tomcat",
      inputRevision: editor.inputRevisions.tomcat,
    });
    const staleStackRevision = editor.inputRevisions.tomcat;
    clickFeature("deny-all-requests", true);
    expect(editor.enabledFeatures.tomcat).not.toContain("allow-safe-methods-only");
    expect(editor.enabledFeatures.tomcat).toContain("deny-all-requests");
    expect(editor.enabledFeatures.tomcat).toContain("response-compression");
    expect(editor.enabledFeatures.tomcat).toContain("host-auto-deploy");
    expect(isConfigPreviewCurrent(editor, "tomcat")).toBe(false);
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "tomcat",
      inputRevision: staleStackRevision,
    })).toBe(editor);
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const policyRows = renderToStaticMarkup(<>
      <ConfigFeatureToggle
        product="tomcat"
        featureKey="allow-safe-methods-only"
        checked={editor.enabledFeatures.tomcat.includes("allow-safe-methods-only")}
        disabled={false}
        onIntent={() => undefined}
      />
      <ConfigFeatureToggle
        product="tomcat"
        featureKey="deny-all-requests"
        checked={editor.enabledFeatures.tomcat.includes("deny-all-requests")}
        disabled={false}
        onIntent={() => undefined}
      />
    </>);
    expect(policyRows).not.toContain(
      "data-testid=\"config-feature-tomcat-allow-safe-methods-only\" checked=\"\"",
    );
    expect(policyRows).toContain(
      "data-testid=\"config-feature-tomcat-deny-all-requests\" checked=\"\"",
    );

    clickFeature("deny-all-requests", false);
    expect(editor.enabledFeatures.tomcat).not.toContain("deny-all-requests");
    clickFeature("response-compression", false);
    expect(editor.enabledFeatures.tomcat).not.toContain("response-compression");
    expect(editor.enabledFeatures.tomcat).toContain("host-auto-deploy");

    const staleResetRevision = editor.inputRevisions.tomcat;
    editor = configEditorReducer(editor, { type: "reset-product", product: tomcatProduct });
    expect(editor.enabledFeatures.tomcat).toEqual(defaults);
    expect(editor.values.tomcat).toEqual(DEFAULT_CONFIG_VALUES.tomcat);
    expect(editor.choices.tomcat).toBe("11.0");
    expect(editor.selectedSubject).toBeNull();
    expect(editor.preview).toBeNull();
    expect(configEditorReducer(editor, {
      type: "preview-generated",
      product: "tomcat",
      inputRevision: staleResetRevision,
    })).toBe(editor);
    expect(isConfigGenerateInput(buildConfigGenerateInput(editor))).toBe(true);

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("visibleDraft.artifacts.map((artifact) => (");
    expect(source).toContain("onClick={() => setActiveArtifactKey(artifact.key)}");
    expect(source).toContain("aria-selected={activeArtifact.key === artifact.key}");
    expect(source).toContain("<ConfigArtifactPreview artifact={activeArtifact} />");
    expect(source).toContain(
      "work: () => configApi.copyConfig(currentDraft.handle, currentDraft.revision)",
    );
    expect(source).toContain("复制全部");
    expect(source).toContain("work: () => configApi.exportConfigArtifact(");
    expect(source).toContain("currentDraft.handle,");
    expect(source).toContain("currentDraft.revision,");
    expect(source).toContain("currentArtifact.key,");
    expect(source).toContain("导出当前文件…");
  });

  it("lifecycle_rejects_late_save_completions", async () => {
    for (const operation of ["generate", "revise"] as const) {
      const lifecycle = new ConfigRequestLifecycle();
      const pending = deferred<ConfigDraft>();
      const setDraft = vi.fn();
      const setNotice = vi.fn();
      const finish = vi.fn();
      const close = vi.fn(async () => ({ closed: true as const }));
      lifecycle.activate();

      const running = lifecycle.run({
        work: () => pending.promise,
        onSuccess: setDraft,
        onError: setNotice,
        onFinally: finish,
        onStaleSuccess: (lateDraft) => releaseLateConfigDraft(lateDraft, close),
      });
      lifecycle.deactivate();
      pending.resolve(draft(`late-${operation}`, operation === "generate" ? 1 : 2));

      await expect(running).resolves.toBe("stale");
      expect(setDraft).not.toHaveBeenCalled();
      expect(setNotice).not.toHaveBeenCalled();
      expect(finish).not.toHaveBeenCalled();
      expect(close).toHaveBeenCalledOnce();
      expect(close).toHaveBeenCalledWith(
        `late-${operation}`,
        operation === "generate" ? 1 : 2,
      );
    }
  });

  it("keeps only the newest request and releases the stale draft once", async () => {
    const lifecycle = new ConfigRequestLifecycle();
    const first = deferred<ConfigDraft>();
    const second = deferred<ConfigDraft>();
    const applied: string[] = [];
    const notices: unknown[] = [];
    const close = vi.fn(async () => ({ closed: true as const }));
    lifecycle.activate();

    const firstRun = lifecycle.run({
      work: () => first.promise,
      onSuccess: (value) => {
        applied.push(value.handle);
      },
      onError: (error) => notices.push(error),
      onFinally: vi.fn(),
      onStaleSuccess: (lateDraft) => releaseLateConfigDraft(lateDraft, close),
    });
    const secondRun = lifecycle.run({
      work: () => second.promise,
      onSuccess: (value) => {
        applied.push(value.handle);
      },
      onError: (error) => notices.push(error),
      onFinally: vi.fn(),
      onStaleSuccess: (lateDraft) => releaseLateConfigDraft(lateDraft, close),
    });
    first.resolve(draft("stale-request", 1));
    second.resolve(draft("current-request", 1));

    await expect(firstRun).resolves.toBe("stale");
    await expect(secondRun).resolves.toBe("completed");
    expect(applied).toEqual(["current-request"]);
    expect(notices).toEqual([]);
    expect(close).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledWith("stale-request", 1);
  });

  it("rejects late copy, export, and close completions without hiding current errors", async () => {
    for (const operation of ["copy", "export", "close"] as const) {
      const lifecycle = new ConfigRequestLifecycle();
      const pending = deferred<{ operation: typeof operation }>();
      const setNotice = vi.fn();
      const finish = vi.fn();
      lifecycle.activate();
      const running = lifecycle.run({
        work: () => pending.promise,
        onSuccess: setNotice,
        onError: setNotice,
        onFinally: finish,
      });
      lifecycle.deactivate();
      pending.resolve({ operation });
      await expect(running).resolves.toBe("stale");
      expect(setNotice).not.toHaveBeenCalled();
      expect(finish).not.toHaveBeenCalled();
    }

    const lifecycle = new ConfigRequestLifecycle();
    const failure = new Error("current operation failed");
    const setNotice = vi.fn();
    const finish = vi.fn();
    lifecycle.activate();
    await expect(lifecycle.run({
      work: () => Promise.reject(failure),
      onSuccess: vi.fn(),
      onError: setNotice,
      onFinally: finish,
    })).resolves.toBe("failed");
    expect(setNotice).toHaveBeenCalledOnce();
    expect(setNotice).toHaveBeenCalledWith(failure);
    expect(finish).toHaveBeenCalledOnce();
  });

  it("wires unmount cleanup and every async action through the request lane", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("return () => requestLifecycle.deactivate()");
    // generate, copy, export one file, export every file, close
    expect(source.match(/requestLifecycle\.run\(/gu)).toHaveLength(5);
    expect(source).toContain("releaseLateConfigDraft(");
  });
});

describe("config generator Nginx 403 goal", () => {
  it("nginx_403_goal_is_discoverable_and_drives_the_typed_preview", () => {
    const feature = {
      key: "forbidden-path-403",
      title: "禁止指定路径（HTTP 403）",
      summary: "拒绝访问指定路径及其可选子路径，返回 HTTP 403。",
      scope: "站点/Location",
      defaultEnabled: false,
      aliases: ["403", "禁止路径", "拒绝访问", "return 403"],
      supportedChoices: ["reverse-proxy", "static"],
    };
    const nginx = {
      key: "nginx" as const,
      title: "Nginx",
      family: "web",
      choiceKind: "mode" as const,
      defaultChoice: "reverse-proxy",
      choices: [
        { key: "reverse-proxy", label: "反向代理", detail: "", isDefault: true },
        { key: "static", label: "静态站点", detail: "", isDefault: false },
      ],
      features: [feature],
      artifacts: [{ key: "site", relativePath: "nginx-site.conf", title: "站点配置" }],
      scopeNotice: "",
    };
    const catalog: ConfigCatalog = { schema: "lovelyres-config-catalog/v2", products: [nginx], readOnlyArtifacts: [] };
    let editor = configEditorReducer(createConfigEditorState(), { type: "catalog-loaded", catalog });

    // The sentence names no catalogue entry word for word, yet the goal is offered.
    editor = configEditorReducer(editor, { type: "set-query", query: "让 /admin/tools 从外部访问返回 403" });
    expect(searchConfigCatalog(catalog, editor.query)).toEqual([]);
    const goal = forbiddenGoalFromQuery(editor.query);
    expect(goal).toEqual({ path: "/admin/tools" });
    for (const action of forbiddenGoalActions(goal!.path)) editor = configEditorReducer(editor, action);
    expect(selectVisibleConfigFeatures(nginx, [], editor.query).map((entry) => entry.key)).toEqual(["forbidden-path-403"]);

    const generateInput = buildConfigGenerateInput(editor);
    expect(generateInput).toMatchObject({
      product: "nginx",
      choice: "reverse-proxy",
      features: ["forbidden-path-403"],
      values: { forbiddenPath: "/admin/tools", forbiddenScope: "path-and-descendants" },
    });
    expect(isConfigGenerateInput(generateInput)).toBe(true);

    const entry = (path: string, selected = true) => renderToStaticMarkup(
      <ConfigFeatureCatalogEntry
        product="nginx"
        feature={feature}
        checked
        supported
        selected={selected}
        inlineEditor={(
          <NginxForbiddenPathInlineEditor
            path={path}
            scope={editor.values.nginx.forbiddenScope}
            enabled
            onIntent={() => undefined}
          />
        )}
        onIntent={() => undefined}
      />,
    );
    const markup = entry(editor.values.nginx.forbiddenPath);
    const rowSelector = "data-testid=\"config-feature-row-nginx-forbidden-path-403\"";
    const editorSelector = "data-testid=\"config-feature-inline-editor-nginx-forbidden-path-403\"";
    expect(markup.indexOf(editorSelector)).toBeGreaterThan(markup.indexOf(rowSelector));
    expect(markup.indexOf(rowSelector)).toBeGreaterThanOrEqual(0);
    expect(markup).toContain("value=\"/admin/tools\"");
    expect(markup).toContain("aria-invalid=\"false\"");
    expect(markup).not.toContain("生成时会被拒绝");
    expect(entry("/admin; return 200")).toContain("aria-invalid=\"true\"");
    expect(entry("/admin; return 200")).toContain("生成时会被拒绝");
    expect(entry("/admin/tools", false)).not.toContain(editorSelector);

    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("const forbiddenGoal = useMemo(() => forbiddenGoalFromQuery(editor.query), [editor.query]);");
    expect(source).toContain("data-testid=\"config-forbidden-goal-apply\" onClick={() => applyForbiddenGoal(forbiddenGoal.path)}");
    expect(source).toContain("for (const action of forbiddenGoalActions(path)) dispatch(action);");
    expect(source).toContain('selectedProduct.key === "nginx" && feature.key === "forbidden-path-403"');
    // The goal shows even when no catalogue entry matches the sentence.
    expect(source.indexOf("data-testid=\"config-forbidden-goal\"")).toBeLessThan(source.indexOf("searchResults.length === 0 ? ("));
  });
});

describe("config generator hostile preview", () => {
  it("preview_is_bounded_and_never_interprets_text", () => {
    const preview = [
      "<script>globalThis.configPreviewExecuted = true</script>",
      "<img src=x onerror=\"globalThis.configPreviewExecuted = true\">",
      "<button onclick=\"globalThis.configPreviewExecuted = true\">边界🙂e\u0301</button>",
    ].join("\n");
    const artifact: ConfigDraftArtifact = {
      key: "hostile",
      relativePath: "hostile.conf",
      mediaType: "text/plain",
      byteLength: new TextEncoder().encode(preview).byteLength + 1,
      preview,
      previewTruncated: true,
      copyAllowed: false,
    };

    const html = renderToStaticMarkup(<ConfigArtifactPreview artifact={artifact} />);
    expect(html).toContain("data-config-preview-truncated=\"true\"");
    expect(html).toContain("预览已截断");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img src=x onerror=");
    expect(html).toContain("边界🙂e\u0301");
    expect(html).not.toMatch(/<script\b|<img\b|<button\b/iu);

    const complete = renderToStaticMarkup(
      <ConfigArtifactPreview artifact={{ ...artifact, byteLength: 4, preview: "safe", previewTruncated: false }} />,
    );
    expect(complete).toContain("data-config-preview-truncated=\"false\"");
    expect(complete).not.toContain("预览已截断");
  });
});

describe("config generator database artifact status", () => {
  it("read_only_status_distinguishes_generated_and_vendor_schema_artifacts", () => {
    const statuses: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "mysql-persisted-variables",
        productKey: "mysql",
        productTitle: "MySQL",
        title: "mysqld-auto.cnf",
        authority: "read-only",
        reason: "generated-artifact",
        notice: "只读展示：该工件由服务器或厂商工具生成；所有结构修改均已禁用。",
      },
      {
        artifactKey: "opengauss-om-cluster-xml",
        productKey: "opengauss",
        productTitle: "openGauss",
        title: "cluster.xml",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：该工件要求匹配产品/版本的厂商 schema。",
      },
    ];

    const generated = selectConfigReadOnlyArtifactStatus(
      statuses,
      "mysql-persisted-variables",
    );
    expect(generated?.reason).toBe("generated-artifact");
    const generatedHtml = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={statuses}
        selectedArtifactKey={generated?.artifactKey ?? null}
        onSelect={vi.fn()}
      />,
    );
    expect(generatedHtml).toContain("data-config-read-only-reason=\"generated-artifact\"");
    expect(generatedHtml).toContain("data-config-mutation-authority=\"read-only\"");
    expect(generatedHtml).toContain("只读展示");
    expect(generatedHtml).toContain("生成");
    expect(generatedHtml).not.toContain("<button");

    const vendor = selectConfigReadOnlyArtifactStatus(
      statuses,
      "opengauss-om-cluster-xml",
    );
    expect(vendor?.reason).toBe("vendor-schema-required");
    const vendorHtml = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={statuses}
        selectedArtifactKey={vendor?.artifactKey ?? null}
        onSelect={vi.fn()}
      />,
    );
    expect(vendorHtml).toContain("data-config-read-only-reason=\"vendor-schema-required\"");
    expect(vendorHtml).toContain("schema");
    expect(vendorHtml).toContain("版本");
    expect(vendorHtml).not.toContain("<button");
    expect(selectConfigReadOnlyArtifactStatus(statuses, "foreign-artifact")).toBeNull();
  });
});
