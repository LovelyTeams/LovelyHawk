import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isConfigGenerateInput,
  type ConfigCatalog,
  type ConfigFeature,
  type ConfigProduct,
  type ConfigProductKey,
} from "../shared/config-contract";
import {
  CONFIG_VALUE_FIELDS,
  DEFAULT_CONFIG_VALUES,
  buildConfigGenerateInput,
  configEditorReducer,
  createConfigEditorState,
  getConfigChoiceTestId,
  isConfigPreviewCurrent,
  searchConfigCatalog,
  type ConfigEditorState,
} from "./config-generator-state";

function product(
  key: ConfigProductKey,
  title: string,
  choiceKind: "mode" | "version" = "version",
): ConfigProduct {
  return {
    key,
    title,
    family: "test",
    choiceKind,
    defaultChoice: choiceKind === "mode" ? "reverse-proxy" : "1.0",
    choices: [{
      key: choiceKind === "mode" ? "reverse-proxy" : "1.0",
      label: "默认",
      detail: "本地测试目录",
      isDefault: true,
    }],
    features: [{
      key: `${key}-only`,
      title: `${title} 独有特性`,
      summary: `仅属于 ${title} 的本地条目`,
      scope: "test",
      defaultEnabled: true,
      aliases: [`${key}-alias`],
      supportedChoices: [choiceKind === "mode" ? "reverse-proxy" : "1.0"],
    }],
    artifacts: [{ key: "main", relativePath: `${key}.conf`, title: "测试草稿" }],
    scopeNotice: "测试目录不执行远程操作。",
  };
}

const atomicCatalog: ConfigCatalog = {
  schema: "lovelyres-config-catalog/v2",
  products: [product("mongodb", "MongoDB"), product("postgresql", "PostgreSQL")],
  readOnlyArtifacts: [],
};

function optionalFeature(product: ConfigProduct, key: string, title: string): ConfigFeature {
  return {
    key,
    title,
    summary: `${title} 的闭合测试条目`,
    scope: "test",
    defaultEnabled: false,
    aliases: [key],
    supportedChoices: [product.defaultChoice],
  };
}

const migrationProducts = {
  nginx: product("nginx", "Nginx", "mode"),
  apache: product("apache", "Apache", "mode"),
  mysql: product("mysql", "MySQL"),
  redis: product("redis", "Redis"),
  tomcat: product("tomcat", "Tomcat"),
} satisfies Record<"nginx" | "apache" | "mysql" | "redis" | "tomcat", ConfigProduct>;

migrationProducts.nginx.features.push(
  optionalFeature(migrationProducts.nginx, "restrict-request-methods", "限制请求方法"),
  optionalFeature(migrationProducts.nginx, "static-asset-caching", "静态资源缓存"),
);
migrationProducts.apache.features.push(
  optionalFeature(migrationProducts.apache, "disable-trace", "禁用 TRACE"),
);
migrationProducts.mysql.features.push(
  optionalFeature(migrationProducts.mysql, "max-connections", "最大连接数"),
);
migrationProducts.redis.features.push(
  optionalFeature(migrationProducts.redis, "max-clients", "最大客户端"),
);
migrationProducts.tomcat.features.push(
  optionalFeature(migrationProducts.tomcat, "host-auto-deploy", "Host 自动部署"),
);

const migrationCatalog: ConfigCatalog = {
  schema: "lovelyres-config-catalog/v2",
  products: [
    migrationProducts.nginx,
    migrationProducts.apache,
    migrationProducts.mysql,
    migrationProducts.redis,
    migrationProducts.tomcat,
  ],
  readOnlyArtifacts: [],
};

const configPageSource = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");

function migrationState(): ConfigEditorState {
  return configEditorReducer(createConfigEditorState(), {
    type: "catalog-loaded",
    catalog: migrationCatalog,
  });
}

function selectProduct(state: ConfigEditorState, productKey: ConfigProductKey): ConfigEditorState {
  return configEditorReducer(state, { type: "select-product", product: productKey });
}

function setValue(
  state: ConfigEditorState,
  productKey: ConfigProductKey,
  key: string,
  value: string,
): ConfigEditorState {
  return configEditorReducer(state, { type: "set-value", product: productKey, key, value });
}

function setFeature(
  state: ConfigEditorState,
  productKey: ConfigProductKey,
  featureKey: string,
  enabled = true,
): ConfigEditorState {
  return configEditorReducer(state, {
    type: "set-feature",
    product: productKey,
    featureKey,
    enabled,
  });
}

function resetProduct(
  state: ConfigEditorState,
  productKey: keyof typeof migrationProducts,
): ConfigEditorState {
  return configEditorReducer(state, {
    type: "reset-product",
    product: migrationProducts[productKey],
  });
}

function markPreviewCurrent(
  state: ConfigEditorState,
  productKey: ConfigProductKey,
): ConfigEditorState {
  return configEditorReducer(state, {
    type: "preview-generated",
    product: productKey,
    inputRevision: state.inputRevisions[productKey],
  });
}

describe("config generator reducer", () => {
  it("switches product and unique search subject atomically", () => {
    let state = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog: atomicCatalog,
    });
    state = configEditorReducer(state, {
      type: "select-search-result",
      subject: { product: "mongodb", featureKey: "mongodb-only" },
    });

    const [result] = searchConfigCatalog(atomicCatalog, "postgresql-only");
    expect(result).toBeDefined();
    if (result === undefined) throw new Error("fixture must contain the PostgreSQL result");
    const next = configEditorReducer(state, {
      type: "select-search-result",
      subject: { product: result.product, featureKey: result.featureKey },
    });

    expect(next.selectedProduct).toBe("postgresql");
    expect(next.selectedSubject).toEqual({
      product: "postgresql",
      featureKey: "postgresql-only",
    });
    expect(next.selectedSubject).not.toEqual({
      product: "postgresql",
      featureKey: "mongodb-only",
    });
    expect(state.selectedProduct).toBe("mongodb");
  });

  it("clears an old subject when a product is selected directly", () => {
    const selected = configEditorReducer(createConfigEditorState(), {
      type: "select-search-result",
      subject: { product: "mongodb", featureKey: "mongodb-only" },
    });
    const next = configEditorReducer(selected, {
      type: "select-product",
      product: "redis",
    });

    expect(next.selectedProduct).toBe("redis");
    expect(next.selectedSubject).toBeNull();
  });

  it("uses catalog defaults only when supported by the default choice", () => {
    const nginx = product("nginx", "Nginx", "mode");
    nginx.features.push({
      key: "static-only",
      title: "静态模式特性",
      summary: "反向代理模式不支持",
      scope: "site",
      defaultEnabled: true,
      aliases: [],
      supportedChoices: ["static"],
    });
    const state = configEditorReducer(createConfigEditorState(), {
      type: "catalog-loaded",
      catalog: {
        schema: "lovelyres-config-catalog/v2",
        products: [nginx],
        readOnlyArtifacts: [],
      },
    });

    expect(state.enabledFeatures.nginx).toEqual(["nginx-only"]);
  });
});

describe("config generator legacy isolation migration", () => {
  it("nginx_quick_configurations_stack_and_remove_independently", () => {
    let state = migrationState();
    state = markPreviewCurrent(state, "nginx");
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(true);

    state = setFeature(state, "nginx", "restrict-request-methods");
    state = setFeature(state, "nginx", "static-asset-caching");
    const stacked = buildConfigGenerateInput(state);
    expect(stacked?.product).toBe("nginx");
    expect(stacked?.features).toEqual([
      "nginx-only",
      "restrict-request-methods",
      "static-asset-caching",
    ]);
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(false);

    state = markPreviewCurrent(state, "nginx");
    state = setFeature(state, "nginx", "restrict-request-methods", false);
    const remaining = buildConfigGenerateInput(state);
    expect(remaining?.features).toEqual(["nginx-only", "static-asset-caching"]);
    expect(state.selectedSubject).toEqual({
      product: "nginx",
      featureKey: "static-asset-caching",
    });
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(false);
    expect(configPageSource).toContain("<ConfigFeatureCatalogEntry");
    expect(configPageSource).toContain(
      "data-testid={`config-feature-${product}-${feature.key}`}",
    );
  });

  it("quick_configuration_search_and_product_switches_never_leak_another_preview", () => {
    let state = markPreviewCurrent(migrationState(), "nginx");
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(true);

    state = selectProduct(state, "apache");
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(false);
    state = markPreviewCurrent(state, "apache");
    state = configEditorReducer(state, { type: "set-query", query: "nginx-alias" });
    expect(state.selectedProduct).toBe("apache");
    expect(searchConfigCatalog(migrationCatalog, state.query).map((result) => result.product))
      .toContain("nginx");
    expect(isConfigPreviewCurrent(state, "apache")).toBe(true);
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(false);

    for (const productKey of ["mysql", "redis", "tomcat"] as const) {
      state = selectProduct(state, productKey);
      expect(isConfigPreviewCurrent(state, "apache")).toBe(false);
      state = markPreviewCurrent(state, productKey);
      expect(isConfigPreviewCurrent(state, productKey)).toBe(true);
      expect(isConfigPreviewCurrent(state, "nginx")).toBe(false);
    }

    const staleTomcatRevision = state.inputRevisions.tomcat;
    state = configEditorReducer(state, {
      type: "select-search-result",
      subject: { product: "nginx", featureKey: "nginx-only" },
    });
    state = configEditorReducer(state, {
      type: "preview-generated",
      product: "tomcat",
      inputRevision: staleTomcatRevision,
    });
    expect(state.selectedProduct).toBe("nginx");
    expect(isConfigPreviewCurrent(state, "tomcat")).toBe(false);
    expect(isConfigPreviewCurrent(state, "nginx")).toBe(false);
    expect(configPageSource).toContain("isConfigPreviewCurrent(editor, draft.product)");
    expect(configPageSource).toContain("data-config-preview-product={visibleDraft?.product ?? \"none\"}");
  });

  it("reset_only_restores_the_selected_product_family", () => {
    let state = migrationState();
    state = setValue(state, "mysql", "maxConnections", "400");
    state = setFeature(state, "mysql", "max-connections");
    state = setValue(state, "apache", "serverName", "discarded.example");
    state = setFeature(state, "apache", "disable-trace");

    state = selectProduct(state, "apache");
    state = resetProduct(state, "apache");
    expect(state.values.apache.serverName).toBe(DEFAULT_CONFIG_VALUES.apache.serverName);
    expect(state.enabledFeatures.apache).toEqual(["apache-only"]);
    expect(state.values.mysql.maxConnections).toBe("400");
    expect(state.enabledFeatures.mysql).toContain("max-connections");

    state = setValue(state, "apache", "serverName", "kept.example");
    state = selectProduct(state, "mysql");
    state = markPreviewCurrent(state, "mysql");
    state = resetProduct(state, "mysql");
    expect(state.values.mysql.maxConnections).toBe(DEFAULT_CONFIG_VALUES.mysql.maxConnections);
    expect(state.enabledFeatures.mysql).toEqual(["mysql-only"]);
    expect(state.values.apache.serverName).toBe("kept.example");
    expect(isConfigPreviewCurrent(state, "mysql")).toBe(false);
    expect(configPageSource).toContain("onClick={() => dispatch({ type: \"reset-product\", product: selectedProduct })}");
    expect(configPageSource).toContain("data-testid={`config-reset-${selectedProduct.key}`}");
  });

  it("redis_reset_is_isolated_from_mysql_and_web_state", () => {
    let state = migrationState();
    state = setValue(state, "redis", "maxClients", "22000");
    state = setFeature(state, "redis", "max-clients");
    state = setValue(state, "mysql", "maxConnections", "400");
    state = setFeature(state, "mysql", "max-connections");
    state = setValue(state, "apache", "serverName", "kept.example");

    state = selectProduct(state, "redis");
    state = markPreviewCurrent(state, "redis");
    state = resetProduct(state, "redis");

    expect(state.values.redis.maxClients).toBe(DEFAULT_CONFIG_VALUES.redis.maxClients);
    expect(state.enabledFeatures.redis).toEqual(["redis-only"]);
    expect(isConfigPreviewCurrent(state, "redis")).toBe(false);
    expect(state.values.mysql.maxConnections).toBe("400");
    expect(state.enabledFeatures.mysql).toContain("max-connections");
    expect(state.values.apache.serverName).toBe("kept.example");
  });

  it("tomcat_reset_is_isolated_and_other_product_resets_preserve_tomcat_state", () => {
    let state = migrationState();
    state = setValue(state, "redis", "maxClients", "22000");
    state = setValue(state, "mysql", "maxConnections", "400");
    state = setValue(state, "apache", "serverName", "kept.example");
    state = setValue(state, "tomcat", "applicationName", "Changed ROOT");
    state = setFeature(state, "tomcat", "host-auto-deploy");

    state = selectProduct(state, "tomcat");
    state = resetProduct(state, "tomcat");
    expect(state.values.tomcat.applicationName).toBe(DEFAULT_CONFIG_VALUES.tomcat.applicationName);
    expect(state.enabledFeatures.tomcat).toEqual(["tomcat-only"]);
    expect(state.values.redis.maxClients).toBe("22000");
    expect(state.values.mysql.maxConnections).toBe("400");
    expect(state.values.apache.serverName).toBe("kept.example");

    state = setValue(state, "tomcat", "applicationName", "Preserved ROOT");
    state = setFeature(state, "tomcat", "host-auto-deploy");
    for (const productKey of ["redis", "mysql", "apache"] as const) {
      state = selectProduct(state, productKey);
      state = resetProduct(state, productKey);
      expect(state.values.tomcat.applicationName).toBe("Preserved ROOT");
      expect(state.enabledFeatures.tomcat).toContain("host-auto-deploy");
    }
  });
});

describe("config generator stable DOM contract", () => {
  it("does not restore the removed legacy content or product filter badges", () => {
    expect(configPageSource).not.toContain("内容：已审配置");
    expect(configPageSource).not.toContain("适用产品：Nginx");
  });

  it("provides deterministic mode and version test ids", () => {
    expect(getConfigChoiceTestId(product("nginx", "Nginx", "mode"))("reverse-proxy"))
      .toBe("config-mode-nginx-reverse-proxy");
    expect(getConfigChoiceTestId(product("postgresql", "PostgreSQL"))("18"))
      .toBe("config-version-postgresql-18");
    expect(getConfigChoiceTestId(product("mariadb", "MariaDB"))("12.3"))
      .toBe("config-version-mariadb-12-3");
  });

  it("defines exactly the values required by every closed product input", () => {
    const products = Object.keys(DEFAULT_CONFIG_VALUES) as ConfigProductKey[];
    for (const key of products) {
      const valueKeys = Object.keys(DEFAULT_CONFIG_VALUES[key]).sort();
      const fieldKeys = CONFIG_VALUE_FIELDS[key].map((field) => field.key).sort();
      expect(fieldKeys, `${key} field descriptors`).toEqual(valueKeys);

      let state = createConfigEditorState();
      state = {
        ...state,
        selectedProduct: key,
        choices: { [key]: key === "nginx" || key === "apache" ? "reverse-proxy" : "1.0" },
        enabledFeatures: {
          ...state.enabledFeatures,
          [key]: key === "redis" ? ["memory-limit", "rdb-persistence"] : [],
        },
      };
      const input = buildConfigGenerateInput(state);
      expect(input).not.toBeNull();
      expect(isConfigGenerateInput(input), `${key} closed input`).toBe(true);
    }
  });
});
