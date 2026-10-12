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
  choiceAction,
  configEditorReducer,
  configFeatureRemovalRefusal,
  createConfigEditorState,
  forbiddenGoalActions,
  forbiddenGoalFromQuery,
  getConfigChoiceTestId,
  isConfigPreviewCurrent,
  isNginxForbiddenPath,
  recipeActions,
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

  it("nginx_spa_fallback_swaps_with_static_404_and_removal_restores_baseline", () => {
    // A static site starts with its own 404 fallback; core refuses it together
    // with the SPA fallback, so the page must never send both.
    let state = setFeature(migrationState(), "nginx", "static-try-files");
    expect(state.enabledFeatures.nginx).toContain("static-try-files");

    state = setFeature(state, "nginx", "spa-fallback");
    expect(state.enabledFeatures.nginx).toContain("spa-fallback");
    expect(state.enabledFeatures.nginx).not.toContain("static-try-files");
    expect(state.selectedSubject).toEqual({ product: "nginx", featureKey: "spa-fallback" });

    state = setFeature(state, "nginx", "static-try-files");
    expect(state.enabledFeatures.nginx).toContain("static-try-files");
    expect(state.enabledFeatures.nginx).not.toContain("spa-fallback");

    // Turning the SPA fallback off again brings back the 404 it replaced.
    state = setFeature(state, "nginx", "spa-fallback");
    state = setFeature(state, "nginx", "spa-fallback", false);
    expect(state.enabledFeatures.nginx).toContain("static-try-files");
    expect(state.enabledFeatures.nginx).not.toContain("spa-fallback");

    // Turning off one that was never on changes nothing, and other features
    // ride through every swap untouched.
    const before = setFeature(state, "nginx", "restrict-request-methods");
    const after = setFeature(before, "nginx", "spa-fallback", false);
    expect(after.enabledFeatures.nginx).toEqual(before.enabledFeatures.nginx);
    expect(setFeature(after, "nginx", "spa-fallback").enabledFeatures.nginx).toContain("restrict-request-methods");
  });

  it("switching mode brings in the new mode's own defaults and keeps the operator's choices", () => {
    let state = setFeature(migrationState(), "nginx", "restrict-request-methods");
    state = configEditorReducer(state, {
      type: "set-choice",
      product: "nginx",
      choice: "static",
      supportedFeatureKeys: ["nginx-only", "restrict-request-methods", "static-try-files"],
      availableDefaultKeys: ["static-try-files"],
    });
    expect(state.enabledFeatures.nginx).toEqual(["nginx-only", "restrict-request-methods", "static-try-files"]);

    // Choosing the same mode again adds nothing the operator turned off.
    state = setFeature(state, "nginx", "static-try-files", false);
    const again = configEditorReducer(state, {
      type: "set-choice",
      product: "nginx",
      choice: "static",
      supportedFeatureKeys: ["nginx-only", "restrict-request-methods", "static-try-files"],
      availableDefaultKeys: ["static-try-files"],
    });
    expect(again.enabledFeatures.nginx).not.toContain("static-try-files");

    // A default the new mode does not support is never added.
    const unsupported = configEditorReducer(migrationState(), {
      type: "set-choice",
      product: "nginx",
      choice: "static",
      supportedFeatureKeys: ["nginx-only"],
      availableDefaultKeys: ["static-try-files"],
    });
    expect(unsupported.enabledFeatures.nginx).toEqual(["nginx-only"]);
  });

  it("builds a mode change and a reviewed recipe as the generator's own steps", () => {
    const feature = (key: string, supportedChoices: string[], defaultEnabled = false) =>
      ({ key, supportedChoices, defaultEnabled }) as unknown as ConfigProduct["features"][number];
    const nginx = {
      key: "nginx", defaultChoice: "reverse-proxy",
      choices: [{ key: "reverse-proxy" }, { key: "static" }],
      features: [feature("nginx-only", ["static", "reverse-proxy"], true), feature("static-try-files", ["static"], true),
        feature("proxy-only", ["reverse-proxy"])],
    } as unknown as ConfigProduct;
    expect(choiceAction(nginx, "reverse-proxy", "static")).toEqual({
      type: "set-choice", product: "nginx", choice: "static",
      supportedFeatureKeys: ["nginx-only", "static-try-files"], availableDefaultKeys: ["static-try-files"],
    });
    const catalog = { products: [nginx] } as unknown as ConfigCatalog;
    const state = migrationState();
    expect(recipeActions(catalog, state, "nginx.static-site", "Nginx 静态站点")).toEqual([
      { type: "set-query", query: "" },
      { type: "select-product", product: "nginx" },
      choiceAction(nginx, state.choices.nginx ?? "reverse-proxy", "static"),
    ]);
    // A path in the sentence is read by the same rules as the 403 card.
    expect(recipeActions(catalog, state, "apache.forbidden-path-403", "Apache 让 /admin 返回 403")).toEqual([
      { type: "set-query", query: "" },
      { type: "select-search-result", subject: { product: "apache", featureKey: "forbidden-path-403" } },
      { type: "set-feature", product: "apache", featureKey: "forbidden-path-403", enabled: true },
      { type: "set-value", product: "apache", key: "forbiddenPath", value: "/admin" },
    ]);
    expect(recipeActions(catalog, state, "apache.disable-trace", "Apache 禁用 TRACE").at(-1))
      .toEqual({ type: "set-feature", product: "apache", featureKey: "disable-trace", enabled: true });
    expect(recipeActions(catalog, state, "redis.unknown", "x")).toEqual([]);
  });

  it("nginx_403_goal_reads_the_typed_path_by_core_rules", () => {
    // The same sentences core's goal search reads (configuration_goal.rs).
    for (const [query, expected] of [
      ["让 /admin 从外部访问返回 403", "/admin"],
      ["禁止 /admin/tools，返回 403", "/admin/tools"],
      ["我现在要配 nginx 的 /admin 从外部访问全部返回 403", "/admin"],
      ["禁止 /admin 及子路径", "/admin"],
      ["拒绝访问：/ops/v1.2~beta", "/ops/v1.2~beta"],
    ] as const) {
      expect(forbiddenGoalFromQuery(query), query).toEqual({ path: expected });
    }
    // A 403 intent with nothing usable typed still offers the rule, without a path.
    for (const query of [
      "403",
      "禁止访问",
      "FORBIDDEN",
      "deny access",
      "返回 403 /admin; return 200",
      "403 /admin%2Fusers",
      "403 /admin{ return 200; }",
      "403 //admin",
      "403 /admin//users",
      "403 https://host/admin",
      "只禁止根路径 / 返回 403",
      "禁止访问 /管理",
      "403 /admin/",
      "403 /admin/../etc",
    ]) {
      expect(forbiddenGoalFromQuery(query), query).toEqual({ path: null });
    }
    // No refusal asked for, or not a goal query at all.
    for (const query of ["启用 gzip 压缩", "access_log", "location root", "admin", "", `403 /${"a".repeat(130)}`, "403\n/admin"]) {
      expect(forbiddenGoalFromQuery(query), JSON.stringify(query)).toBeNull();
    }
    expect(isNginxForbiddenPath(`/${"a".repeat(511)}`)).toBe(true);
    expect(isNginxForbiddenPath(`/${"a".repeat(512)}`)).toBe(false);
  });

  it("nginx_403_goal_selects_and_enables_the_rule_with_the_typed_path", () => {
    let state = configEditorReducer(selectProduct(migrationState(), "apache"), {
      type: "set-query",
      query: "让 /admin/tools 从外部访问返回 403",
    });
    state = setFeature(state, "apache", "disable-trace");
    const apacheBefore = { features: state.enabledFeatures.apache, values: state.values.apache };
    const goal = forbiddenGoalFromQuery(state.query);
    expect(goal).toEqual({ path: "/admin/tools" });
    for (const action of forbiddenGoalActions(goal!.path)) state = configEditorReducer(state, action);

    expect(state.query).toBe("");
    expect(state.selectedProduct).toBe("nginx");
    expect(state.selectedSubject).toEqual({ product: "nginx", featureKey: "forbidden-path-403" });
    expect(state.enabledFeatures.nginx).toContain("forbidden-path-403");
    expect(state.values.nginx.forbiddenPath).toBe("/admin/tools");
    expect(state.preview).toBeNull();
    expect({ features: state.enabledFeatures.apache, values: state.values.apache }).toEqual(apacheBefore);

    // Without a usable path the rule is still turned on, and the path the
    // operator already had is left alone rather than cleared.
    const edited = setValue(migrationState(), "nginx", "forbiddenPath", "/private");
    let untouched = edited;
    for (const action of forbiddenGoalActions(null)) untouched = configEditorReducer(untouched, action);
    expect(untouched.enabledFeatures.nginx).toContain("forbidden-path-403");
    expect(untouched.values.nginx.forbiddenPath).toBe("/private");
    // A path core would refuse never reaches the editor through the goal.
    expect(forbiddenGoalActions("/admin; return 200").some((action) => action.type === "set-value")).toBe(false);
  });

  it("redis_required_features_stay_and_say_why", () => {
    const both = ["memory-limit", "aof-persistence", "rdb-persistence", "slow-log"];
    expect(configFeatureRemovalRefusal("redis", both, "memory-limit")).toContain("内存上限");
    expect(configFeatureRemovalRefusal("redis", both, "aof-persistence")).toBeNull();
    expect(configFeatureRemovalRefusal("redis", both, "slow-log")).toBeNull();
    const rdbOnly = ["memory-limit", "rdb-persistence"];
    expect(configFeatureRemovalRefusal("redis", rdbOnly, "rdb-persistence")).toContain("至少要保留一种持久化方式");
    // Ticking a box is never refused here, nor a box that was not ticked.
    expect(configFeatureRemovalRefusal("redis", rdbOnly, "aof-persistence")).toBeNull();
    expect(configFeatureRemovalRefusal("mysql", ["memory-limit"], "memory-limit")).toBeNull();

    // The reducer refuses the same removals on its own, with no revision drift.
    let state = migrationState();
    state = configEditorReducer(state, { type: "select-product", product: "redis" });
    for (const key of ["memory-limit", "rdb-persistence"]) state = setFeature(state, "redis", key);
    const revision = state.inputRevisions.redis;
    for (const key of ["memory-limit", "rdb-persistence"]) {
      const after = setFeature(state, "redis", key, false);
      expect(after.enabledFeatures.redis).toEqual(state.enabledFeatures.redis);
      expect(after.inputRevisions.redis).toBe(revision);
    }
    expect(configPageSource).toContain("const refusal = configFeatureRemovalRefusal(action.product, editor.enabledFeatures[action.product], action.featureKey);");
    expect(configPageSource).toContain("onIntent={featureIntent}");
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
    expect(configPageSource).toContain("dispatch({ type: \"reset-product\", product: selectedProduct });");
    // A message about the values just reset is stale, so it goes with them.
    expect(configPageSource).toMatch(/type: "reset-product", product: selectedProduct \}\);[\s\S]{0,160}setNotice\(null\);/u);
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
