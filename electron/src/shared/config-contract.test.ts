import { describe, expect, it } from "vitest";

import {
  isConfigCatalog,
  isConfigDraft,
  isConfigGenerateInput,
  isInternalConfigArtifact,
  isInternalConfigCopy,
  type ConfigCatalog,
  type ConfigProductKey,
  type ConfigReadOnlyArtifactStatus,
} from "./config-contract";

const configProductKeys: readonly ConfigProductKey[] = [
  "nginx", "apache", "haproxy", "mysql", "postgresql", "mariadb", "mongodb", "redis", "tomcat",
];

function finiteCatalogFixture(): ConfigCatalog {
  return {
    schema: "lovelyres-config-catalog/v2",
    products: configProductKeys.map((key, productIndex) => ({
      key,
      title: key,
      family: "test",
      choiceKind: "version",
      defaultChoice: "current",
      choices: [{ key: "current", label: "Current", detail: "fixture", isDefault: true }],
      features: Array.from({ length: productIndex === 8 ? 17 : 15 }, (_, featureIndex) => ({
        key: `feature-${featureIndex}`,
        title: `Feature ${featureIndex}`,
        summary: "fixture",
        scope: "test",
        defaultEnabled: false,
        aliases: [`alias-${featureIndex}`],
        supportedChoices: ["current"],
      })),
      artifacts: [{ key: "main", relativePath: `${key}.conf`, title: "Main" }],
      scopeNotice: "Local fixture.",
    })),
    readOnlyArtifacts: [
      {
        artifactKey: "mysql-server-uuid",
        productKey: "mysql",
        productTitle: "MySQL",
        title: "auto.cnf",
        authority: "read-only",
        reason: "generated-artifact",
        notice: "只读展示：该工件由服务器生成。",
      },
      {
        artifactKey: "mysql-persisted-variables",
        productKey: "mysql",
        productTitle: "MySQL",
        title: "mysqld-auto.cnf",
        authority: "read-only",
        reason: "generated-artifact",
        notice: "只读展示：由服务器生成。",
      },
      {
        artifactKey: "opengauss-om-cluster-xml",
        productKey: "opengauss",
        productTitle: "openGauss",
        title: "opengauss-om-cluster-xml",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：需要匹配版本的厂商 schema。",
      },
      {
        artifactKey: "yashandb-yasdb-ini",
        productKey: "yashandb",
        productTitle: "崖山数据库",
        title: "yasdb.ini",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：仅公开 schema 元数据；精确 build 23.5.4.100；文档族 official-doc-family-23.5.4.100；完整性 Partial。该元数据只用于显示，绝不会写入目标内容、本地草稿或另存文件，也不授予修改权限。",
      },
    ],
  };
}

describe("configuration process-boundary validators", () => {
  it("nginx_feature_remove_intent_is_closed_and_rejects_hostile_payload_fields", () => {
    const before = {
      product: "nginx",
      choice: "reverse-proxy",
      features: ["security-headers"],
      values: {
        serverName: "api.example.com",
        listenPort: "80",
        staticRoot: "/var/www/html",
        upstream: "http://127.0.0.1:3000",
        forbiddenPath: "/admin",
        forbiddenScope: "path-and-descendants",
        allowedSource: "",
      },
    };
    const after = { ...before, features: [] };

    expect(isConfigGenerateInput(before)).toBe(true);
    expect(isConfigGenerateInput(after)).toBe(true);
    expect(before.features).toEqual(["security-headers"]);
    expect(after.features).toEqual([]);

    for (const [field, value] of [
      ["removeFeature", "security-headers"],
      ["action", { type: "remove", feature: "security-headers" }],
      ["onClick", "removeSecurityHeaders()"],
      ["rawText", "<script>globalThis.nginxRemoveExecuted=true</script>"],
      ["markup", "<button onclick=remove()>remove</button>"],
      ["contents", "add_header X-Credential NeverShow42;"],
      ["copyPayload", "credential=NeverShow42"],
      ["revision", 2],
    ] as const) {
      expect(isConfigGenerateInput({ ...after, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput({
      ...after,
      features: ["<script>globalThis.nginxRemoveExecuted=true</script>"],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...after,
      features: ["security-headers", "security-headers"],
    })).toBe(false);
  });

  it("apache_stack_remove_reset_transitions_are_closed_and_reject_visual_injection", () => {
    const values = {
      serverName: "api.example.com",
      listenPort: "80",
      staticRoot: "/var/www/html",
      upstream: "http://127.0.0.1:3000",
      forbiddenPath: "/admin",
      forbiddenScope: "path-and-descendants",
      allowedSource: "",
    };
    const input = (features: string[]) => ({
      product: "apache",
      choice: "reverse-proxy",
      features,
      values,
    });
    const baseline = input([
      "security-headers",
      "reduce-version-disclosure",
      "disable-trace",
    ]);
    const stacked = input([
      ...baseline.features,
      "restrict-request-methods",
      "client-body-limit",
    ]);
    const traceRemoved = input([
      "security-headers",
      "reduce-version-disclosure",
      "client-body-limit",
    ]);
    const reopened = input([
      ...traceRemoved.features,
      "disable-trace",
      "restrict-request-methods",
    ]);
    const methodRemoved = input([
      "security-headers",
      "reduce-version-disclosure",
      "disable-trace",
      "client-body-limit",
    ]);

    for (const transition of [baseline, stacked, traceRemoved, reopened, methodRemoved]) {
      expect(isConfigGenerateInput(transition)).toBe(true);
    }
    expect(isConfigGenerateInput(input(["restrict-request-methods"]))).toBe(false);

    for (const [field, value] of [
      ["removeFeature", "disable-trace"],
      ["reset", true],
      ["openVisual", true],
      ["visualDocument", { kind: "apache", rows: [] }],
      ["rawBytes", "<VirtualHost *:80>\n</VirtualHost>\n"],
      ["mode", "visual"],
      ["markup", "<button onclick=openVisual()>open</button>"],
      ["copyPayload", "password=NeverShow42"],
      ["revision", 5],
    ] as const) {
      expect(isConfigGenerateInput({ ...baseline, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput(input([
      "<script>globalThis.apacheStackExecuted=true</script>",
    ]))).toBe(false);
    expect(isConfigGenerateInput(input([
      "disable-trace",
      "disable-trace",
    ]))).toBe(false);
  });

  it("apache_catalog_inline_editor_and_preview_contract_is_closed", () => {
    const catalog = finiteCatalogFixture();
    const apache = catalog.products.find((product) => product.key === "apache");
    if (apache === undefined) throw new Error("Apache fixture product must exist");
    apache.features[0] = {
      key: "client-body-limit",
      title: "限制请求体大小",
      summary: "将客户端请求体上限固定为 10 MiB。",
      scope: "虚拟主机",
      defaultEnabled: false,
      aliases: ["请求体", "上传大小", "LimitRequestBody", "10 MiB"],
      supportedChoices: ["current"],
    };
    expect(isConfigCatalog(catalog)).toBe(true);

    const injectedCatalog = {
      ...catalog,
      products: catalog.products.map((product) => product.key !== "apache" ? product : {
        ...product,
        features: product.features.map((feature) => feature.key !== "client-body-limit" ? feature : {
          ...feature,
          rawContents: "<script>globalThis.apacheInlineExecuted=true</script>",
        }),
      }),
    };
    expect(isConfigCatalog(injectedCatalog)).toBe(false);

    const values = {
      serverName: "api.example.com",
      listenPort: "80",
      staticRoot: "/var/www/html",
      upstream: "http://127.0.0.1:3000",
      forbiddenPath: "/admin",
      forbiddenScope: "path-and-descendants",
      allowedSource: "",
    };
    const selected = {
      product: "apache",
      choice: "reverse-proxy",
      features: [
        "security-headers",
        "reduce-version-disclosure",
        "disable-trace",
        "client-body-limit",
      ],
      values,
    };
    expect(isConfigGenerateInput(selected)).toBe(true);

    for (const [field, value] of [
      ["inlineEditor", { feature: "client-body-limit" }],
      ["bounds", { x: 0, y: 48, width: 640, height: 120 }],
      ["markup", "<button onclick=copy()>copy</button>"],
      ["preview", "LimitRequestBody 10485760"],
      ["copyPayload", "credential=NeverShow42"],
      ["revision", 2],
    ] as const) {
      expect(isConfigGenerateInput({ ...selected, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput({
      ...selected,
      features: [...selected.features, "client-body-limit"],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...selected,
      features: ["<script>globalThis.apacheInlineExecuted=true</script>"],
    })).toBe(false);

    const preview = "<VirtualHost *:80>\n    LimitRequestBody 10485760\n</VirtualHost>\n";
    const byteLength = new TextEncoder().encode(preview).byteLength;
    const draft = {
      handle: "cfg-apache-inline-1",
      revision: 2,
      product: "apache",
      choice: "reverse-proxy",
      suggestedName: "apache-site.conf",
      totalBytes: byteLength,
      copyAllowed: true,
      artifacts: [{
        key: "site",
        relativePath: "apache-site.conf",
        mediaType: "text/plain",
        byteLength,
        preview,
        previewTruncated: false,
        copyAllowed: true,
      }],
      notices: [],
    };
    expect(isConfigDraft(draft)).toBe(true);
    expect(isConfigDraft({ ...draft, dom: "<pre>trusted</pre>" })).toBe(false);
    expect(isConfigDraft({
      ...draft,
      artifacts: [{ ...draft.artifacts[0], contents: preview }],
    })).toBe(false);
  });

  it("mysql_catalog_inline_editor_and_preview_contract_is_closed", () => {
    const catalog = finiteCatalogFixture();
    const mysql = catalog.products.find((product) => product.key === "mysql");
    if (mysql === undefined) throw new Error("MySQL fixture product must exist");
    mysql.features[0] = {
      key: "max-connections",
      title: "限制最大连接数",
      summary: "设置服务器可同时接受的客户端连接数量上限。",
      scope: "连接",
      defaultEnabled: false,
      aliases: ["max_connections", "最大连接", "并发连接"],
      supportedChoices: ["current"],
    };
    expect(isConfigCatalog(catalog)).toBe(true);

    const injectedCatalog = {
      ...catalog,
      products: catalog.products.map((product) => product.key !== "mysql" ? product : {
        ...product,
        features: product.features.map((feature) => feature.key !== "max-connections" ? feature : {
          ...feature,
          input: { type: "number", onChange: "run()" },
        }),
      }),
    };
    expect(isConfigCatalog(injectedCatalog)).toBe(false);

    const values = {
      remoteListener: "0.0.0.0",
      maxConnections: "400",
      connectTimeout: "10",
      maxConnectErrors: "100",
      waitTimeout: "28800",
      interactiveTimeout: "28800",
      longQueryTime: "10",
      logErrorVerbosity: "2",
      serverId: "1",
      binlogRetention: "2592000",
    };
    const selected = {
      product: "mysql",
      choice: "8.4.0",
      features: ["max-connections"],
      values,
    };
    expect(isConfigGenerateInput(selected)).toBe(true);

    for (const [field, value] of [
      ["inlineEditor", { feature: "max-connections", value: "400" }],
      ["bounds", { x: 0, y: 48, width: 640, height: 120 }],
      ["markup", "<input oninput=run()>"],
      ["preview", "max_connections = 400\n"],
      ["copyPayload", "credential=NeverShow42"],
      ["revision", 2],
    ] as const) {
      expect(isConfigGenerateInput({ ...selected, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput({
      ...selected,
      features: ["max-connections", "max-connections"],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...selected,
      features: ["<script>globalThis.mysqlInlineExecuted=true</script>"],
    })).toBe(false);

    const preview = "[mysqld]\nmax_connections = 400\n";
    const byteLength = new TextEncoder().encode(preview).byteLength;
    const draft = {
      handle: "cfg-mysql-inline-1",
      revision: 2,
      product: "mysql",
      choice: "8.4.0",
      suggestedName: "my.cnf",
      totalBytes: byteLength,
      copyAllowed: true,
      artifacts: [{
        key: "main",
        relativePath: "my.cnf",
        mediaType: "text/plain",
        byteLength,
        preview,
        previewTruncated: false,
        copyAllowed: true,
      }],
      notices: [],
    };
    expect(isConfigDraft(draft)).toBe(true);
    expect(isConfigDraft({ ...draft, editorValue: "400" })).toBe(false);
    expect(isConfigDraft({
      ...draft,
      artifacts: [{ ...draft.artifacts[0], contents: preview }],
    })).toBe(false);
  });

  it("mysql_quick_stack_remove_reset_save_transitions_are_closed_and_dependency_safe", () => {
    const defaultValues = {
      remoteListener: "0.0.0.0",
      maxConnections: "151",
      connectTimeout: "10",
      maxConnectErrors: "100",
      waitTimeout: "28800",
      interactiveTimeout: "28800",
      longQueryTime: "10",
      logErrorVerbosity: "2",
      serverId: "1",
      binlogRetention: "2592000",
    };
    const input = (features: string[], maxConnections = "151") => ({
      product: "mysql",
      choice: "8.4.0",
      features,
      values: { ...defaultValues, maxConnections },
    });
    const baseline = input([]);
    const stacked = input([
      "max-connections",
      "slow-query-log",
      "binary-logging",
      "binary-log-retention",
    ], "400");
    const maxConnectionsRemoved = input([
      "slow-query-log",
      "binary-logging",
      "binary-log-retention",
    ], "400");
    const reset = input([]);

    for (const transition of [baseline, stacked, maxConnectionsRemoved, reset]) {
      expect(isConfigGenerateInput(transition)).toBe(true);
    }
    expect(isConfigGenerateInput(input(["binary-log-retention"]))).toBe(false);

    for (const [field, value] of [
      ["removeFeature", "max-connections"],
      ["reset", true],
      ["save", { suggestedName: "mysql-quick.cnf" }],
      ["exportPath", "C:\\hostile\\mysql-quick.cnf"],
      ["openVisual", true],
      ["visualDocument", { dialect: "mysql-option-file", rows: [] }],
      ["rawBytes", "[mysqld]\npassword=NeverShow42\n"],
      ["markup", "<button onclick=openVisual()>open</button>"],
      ["copyPayload", "password=NeverShow42"],
      ["revision", 5],
    ] as const) {
      expect(isConfigGenerateInput({ ...baseline, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput(input([
      "<script>globalThis.mysqlStackExecuted=true</script>",
    ]))).toBe(false);
    expect(isConfigGenerateInput(input([
      "binary-logging",
      "binary-logging",
    ]))).toBe(false);
  });

  it("postgresql_and_mariadb_catalog_versions_search_and_inline_editor_contract_is_closed", () => {
    const catalog = finiteCatalogFixture();
    const postgresql = catalog.products.find((product) => product.key === "postgresql");
    const mariadb = catalog.products.find((product) => product.key === "mariadb");
    if (postgresql === undefined || mariadb === undefined) {
      throw new Error("PostgreSQL and MariaDB fixture products must exist");
    }

    const choices = (keys: readonly string[], defaultChoice: string) => keys.map((key) => ({
      key,
      label: key,
      detail: "finite reviewed version",
      isDefault: key === defaultChoice,
    }));
    const postgresqlVersions = ["14", "15", "16", "17", "18"];
    postgresql.defaultChoice = "18";
    postgresql.choices = choices(postgresqlVersions, "18");
    postgresql.features = postgresql.features.map((feature, index) => index === 0 ? {
      key: "lock-wait-logging",
      title: "按明确阈值记录锁等待",
      summary: "成组设置 deadlock_timeout 与 log_lock_waits。",
      scope: "日志/可观测性",
      defaultEnabled: false,
      aliases: ["log_lock_waits", "锁等待", "deadlock_timeout"],
      supportedChoices: postgresqlVersions,
    } : { ...feature, supportedChoices: postgresqlVersions });

    const mariadbVersions = ["10.11", "11.4", "11.8", "12.3"];
    mariadb.defaultChoice = "12.3";
    mariadb.choices = choices(mariadbVersions, "12.3");
    mariadb.features = mariadb.features.map((feature, index) => index === 0 ? {
      key: "binary-log-retention",
      title: "设置二进制日志保留时间",
      summary: "使用非零 binlog_expire_logs_seconds。",
      scope: "二进制日志",
      defaultEnabled: false,
      aliases: ["binlog_expire_logs_seconds", "日志保留", "自动清理"],
      supportedChoices: mariadbVersions,
    } : { ...feature, supportedChoices: mariadbVersions });
    expect(isConfigCatalog(catalog)).toBe(true);

    const injectedCatalog = {
      ...catalog,
      products: catalog.products.map((product) => product.key !== "postgresql" ? product : {
        ...product,
        choices: product.choices.map((choice) => choice.key !== "18" ? choice : {
          ...choice,
          onSelect: "openVersion()",
        }),
      }),
    };
    expect(isConfigCatalog(injectedCatalog)).toBe(false);

    const postgresqlValues = {
      port: "5432",
      maxConnections: "100",
      superuserReservedConnections: "3",
      reservedConnections: "0",
      authenticationTimeout: "60",
      idleInTransactionTimeout: "300",
      idleSessionTimeout: "1800",
      temporaryFileLimit: "1024",
      lockWaitThreshold: "1500",
      autovacuumLogThreshold: "1000",
      temporaryFileLogThreshold: "10240",
      walCompression: "pglz",
    };
    const postgresqlInput = (choice: string) => ({
      product: "postgresql",
      choice,
      features: ["lock-wait-logging"],
      values: postgresqlValues,
    });
    for (const version of postgresqlVersions) {
      expect(isConfigGenerateInput(postgresqlInput(version))).toBe(true);
    }

    const mariadbValues = {
      port: "3306",
      maxConnections: "200",
      connectTimeout: "10",
      waitTimeout: "600",
      interactiveTimeout: "600",
      maxConnectErrors: "100",
      maxAllowedPacket: "64",
      slowQueryTime: "2",
      serverId: "42",
      binlogRetention: "86400",
      innodbLockWaitTimeout: "50",
      characterProfile: "unicode-case-insensitive",
    };
    const mariadbInput = (choice: string) => ({
      product: "mariadb",
      choice,
      features: ["binary-logging", "binary-log-retention"],
      values: mariadbValues,
    });
    for (const version of mariadbVersions) {
      expect(isConfigGenerateInput(mariadbInput(version))).toBe(true);
    }
    expect(isConfigGenerateInput({
      ...mariadbInput("12.3"),
      features: ["binary-log-retention"],
    })).toBe(false);

    for (const [field, value] of [
      ["inlineEditor", { product: "postgresql", value: "1500" }],
      ["searchResults", ["lock-wait-logging"]],
      ["bounds", { x: 0, y: 48, width: 640, height: 120 }],
      ["markup", "<input oninput=run()>"],
      ["preview", "deadlock_timeout = 1500ms"],
      ["copyPayload", "credential=NeverShow42"],
      ["revision", 3],
    ] as const) {
      expect(isConfigGenerateInput({ ...postgresqlInput("18"), [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput({
      ...postgresqlInput("18"),
      features: ["lock-wait-logging", "lock-wait-logging"],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...mariadbInput("12.3"),
      features: ["<script>globalThis.databaseInlineExecuted=true</script>"],
    })).toBe(false);
  });

  it("postgresql_and_mariadb_quick_transitions_are_isolated_dependency_safe_and_closed", () => {
    const postgresqlValues = {
      port: "5432",
      maxConnections: "100",
      superuserReservedConnections: "3",
      reservedConnections: "0",
      authenticationTimeout: "60",
      idleInTransactionTimeout: "300",
      idleSessionTimeout: "1800",
      temporaryFileLimit: "1024",
      lockWaitThreshold: "1000",
      autovacuumLogThreshold: "1000",
      temporaryFileLogThreshold: "10240",
      walCompression: "pglz",
    };
    const postgresql = (
      choice: string,
      features: string[],
      maxConnections = "100",
      reservedConnections = "0",
    ) => ({
      product: "postgresql",
      choice,
      features,
      values: { ...postgresqlValues, maxConnections, reservedConnections },
    });
    const postgresql18 = postgresql(
      "18",
      ["connection-capacity", "connection-lifecycle-logging"],
      "240",
      "2",
    );
    const postgresql15 = postgresql(
      "15",
      ["connection-capacity", "connection-lifecycle-logging"],
      "240",
      "0",
    );
    const postgresqlRemaining = postgresql("15", ["connection-lifecycle-logging"], "240");
    expect(isConfigGenerateInput(postgresql18)).toBe(true);
    expect(isConfigGenerateInput(postgresql15)).toBe(true);
    expect(isConfigGenerateInput(postgresqlRemaining)).toBe(true);
    expect(isConfigGenerateInput(postgresql("15", ["connection-capacity"], "240", "2")))
      .toBe(false);

    const mariadbValues = {
      port: "3306",
      maxConnections: "200",
      connectTimeout: "10",
      waitTimeout: "600",
      interactiveTimeout: "600",
      maxConnectErrors: "100",
      maxAllowedPacket: "64",
      slowQueryTime: "2",
      serverId: "1",
      binlogRetention: "604800",
      innodbLockWaitTimeout: "50",
      characterProfile: "unicode-case-insensitive",
    };
    const mariadb = (
      choice: string,
      features: string[],
      serverId = "1",
      binlogRetention = "604800",
    ) => ({
      product: "mariadb",
      choice,
      features,
      values: { ...mariadbValues, serverId, binlogRetention },
    });
    const mariadbStacked = mariadb("12.3", [
      "binary-logging",
      "binary-log-retention",
      "binary-log-durability",
    ], "42", "86400");
    const mariadbWithoutBinlog = mariadb("12.3", []);
    const mariadb10 = mariadb("10.11", ["slow-query-log"]);
    for (const transition of [mariadbStacked, mariadbWithoutBinlog, mariadb10]) {
      expect(isConfigGenerateInput(transition)).toBe(true);
    }
    expect(isConfigGenerateInput(mariadb("12.3", ["binary-log-retention"]))).toBe(false);
    expect(isConfigGenerateInput(mariadb("12.3", ["binary-log-durability"]))).toBe(false);

    expect(postgresql18.product).toBe("postgresql");
    expect(mariadbStacked.product).toBe("mariadb");
    expect(postgresql18.values).not.toHaveProperty("serverId");
    expect(mariadbStacked.values).not.toHaveProperty("reservedConnections");
    for (const [field, value] of [
      ["stateByProduct", { postgresql: postgresql18, mariadb: mariadbStacked }],
      ["save", true],
      ["exportPath", "C:\\hostile\\database.conf"],
      ["openVisual", true],
      ["visualDocument", { dialect: "mysql-option-file", rows: [] }],
      ["rawBytes", "password=NeverShow42"],
      ["markup", "<button onclick=save()>save</button>"],
      ["copyPayload", "password=NeverShow42"],
      ["revision", 8],
    ] as const) {
      expect(isConfigGenerateInput({ ...mariadb10, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput(mariadb("10.11", [
      "<script>globalThis.databaseIsolationExecuted=true</script>",
    ]))).toBe(false);
  });

  it("redis_quick_stack_remove_reset_save_transitions_are_dependency_safe_and_closed", () => {
    const values = {
      bindProfile: "dual-stack-loopback",
      dataDirectory: "/var/lib/redis",
      port: "6379",
      maxClients: "10000",
      idleTimeout: "300",
      tcpKeepalive: "300",
      maxmemoryMib: "512",
      evictionPolicy: "noeviction",
      appendFsync: "everysec",
      slowlogThreshold: "10000",
      slowlogLength: "128",
      latencyThreshold: "100",
    };
    const input = (features: string[], overrides: Partial<typeof values> = {}) => ({
      product: "redis",
      choice: "8.10",
      features,
      values: { ...values, ...overrides },
    });
    const baselineFeatures = [
      "max-clients",
      "tcp-keepalive",
      "memory-limit",
      "aof-persistence",
      "rdb-persistence",
      "slow-log",
    ];
    const stackedFeatures = [
      "max-clients",
      "idle-client-timeout",
      "tcp-keepalive",
      "memory-limit",
      "eviction-policy",
      "aof-persistence",
      "rdb-persistence",
      "slow-log",
      "latency-monitor",
    ];
    const stacked = input(stackedFeatures, {
      idleTimeout: "600",
      evictionPolicy: "allkeys-lru",
      latencyThreshold: "50",
    });
    const idleRemoved = input(
      stackedFeatures.filter((feature) => feature !== "idle-client-timeout"),
      { idleTimeout: "600", evictionPolicy: "allkeys-lru", latencyThreshold: "50" },
    );
    const rdbOnly = input(
      idleRemoved.features.filter((feature) => feature !== "aof-persistence"),
      { idleTimeout: "600", evictionPolicy: "allkeys-lru", latencyThreshold: "50" },
    );
    for (const transition of [input(baselineFeatures), stacked, idleRemoved, rdbOnly]) {
      expect(isConfigGenerateInput(transition)).toBe(true);
    }
    expect(isConfigGenerateInput(input(
      stackedFeatures.filter((feature) => feature !== "memory-limit"),
    ))).toBe(false);
    expect(isConfigGenerateInput(input(
      baselineFeatures.filter(
        (feature) => feature !== "aof-persistence" && feature !== "rdb-persistence",
      ),
    ))).toBe(false);

    for (const [field, value] of [
      ["removeFeature", "memory-limit"],
      ["reset", true],
      ["save", { suggestedName: "redis-new-empty-instance.conf" }],
      ["exportPath", "C:\\hostile\\redis.conf"],
      ["openVisual", true],
      ["rawBytes", "requirepass NeverShow42\n"],
      ["contents", "<script>globalThis.redisStackExecuted=true</script>"],
      ["markup", "<button onclick=save()>save</button>"],
      ["copyPayload", "password=NeverShow42"],
      ["revision", 9],
    ] as const) {
      expect(isConfigGenerateInput({ ...stacked, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput(input([
      ...baselineFeatures,
      "<script>globalThis.redisStackExecuted=true</script>",
    ]))).toBe(false);
    expect(isConfigGenerateInput(input([
      ...baselineFeatures,
      "memory-limit",
    ]))).toBe(false);
  });

  it("redis_catalog_inline_editor_and_preview_contract_is_closed", () => {
    const catalog = finiteCatalogFixture();
    const redis = catalog.products.find((product) => product.key === "redis");
    if (redis === undefined) throw new Error("Redis fixture product must exist");
    redis.defaultChoice = "8.10";
    redis.choices = ["6.2", "7.2", "7.4", "8.0", "8.2", "8.4", "8.6", "8.8", "8.10"]
      .map((key) => ({
        key,
        label: key,
        detail: "reviewed Redis version",
        isDefault: key === "8.10",
      }));
    const supportedChoices = redis.choices.map((choice) => choice.key);
    redis.features = redis.features.map((feature, index) => index === 0 ? {
      key: "slow-log",
      title: "记录慢命令",
      summary: "用类型化微秒阈值和有界队列记录慢命令。",
      scope: "可观测性",
      defaultEnabled: true,
      aliases: ["slowlog", "慢命令", "慢日志"],
      supportedChoices,
    } : { ...feature, supportedChoices });
    expect(isConfigCatalog(catalog)).toBe(true);

    const slowLogFeature = redis.features[0];
    if (slowLogFeature === undefined) throw new Error("Redis slow-log feature must exist");
    for (const [field, value] of [
      ["input", { type: "number" }],
      ["onChange", "revise"],
      ["inlineEditor", { threshold: "25000", length: "256" }],
      ["bounds", { top: 1, bottom: 2 }],
      ["rawContents", "requirepass NeverShow42"],
    ] as const) {
      expect(isConfigCatalog({
        ...catalog,
        products: catalog.products.map((product) => product.key === "redis"
          ? {
              ...product,
              features: product.features.map((feature) => feature.key === "slow-log"
                ? { ...slowLogFeature, [field]: value }
                : feature),
            }
          : product),
      })).toBe(false);
    }

    const values = {
      bindProfile: "dual-stack-loopback",
      dataDirectory: "/var/lib/redis",
      port: "6379",
      maxClients: "10000",
      idleTimeout: "300",
      tcpKeepalive: "300",
      maxmemoryMib: "512",
      evictionPolicy: "noeviction",
      appendFsync: "everysec",
      slowlogThreshold: "25000",
      slowlogLength: "256",
      latencyThreshold: "100",
    };
    const input = {
      product: "redis",
      choice: "8.10",
      features: [
        "max-clients",
        "tcp-keepalive",
        "memory-limit",
        "aof-persistence",
        "rdb-persistence",
        "slow-log",
      ],
      values,
    };
    expect(isConfigGenerateInput(input)).toBe(true);
    for (const [field, value] of [
      ["inlineEditor", true],
      ["searchResults", ["redis:slow-log"]],
      ["bounds", { rowBottom: 120, editorTop: 120 }],
      ["markup", "<input oninput=revise()>"],
      ["preview", "slowlog-log-slower-than 25000"],
      ["copyPayload", "password=NeverShow42"],
      ["revision", 9],
    ] as const) {
      expect(isConfigGenerateInput({ ...input, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput({
      ...input,
      features: [...input.features, "slow-log"],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...input,
      features: [
        ...input.features.filter((feature) => feature !== "slow-log"),
        "<script>globalThis.redisInlineExecuted=true</script>",
      ],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...input,
      values: { ...values, slowlogThreshold: "1".repeat(4_097) },
    })).toBe(false);
  });

  it("tomcat_catalog_inline_editor_and_preview_contract_is_closed", () => {
    const catalog = finiteCatalogFixture();
    const tomcat = catalog.products.find((product) => product.key === "tomcat");
    if (tomcat === undefined) throw new Error("Tomcat fixture product must exist");
    const versions = ["9.0", "10.1", "11.0"];
    tomcat.defaultChoice = "11.0";
    tomcat.choices = versions.map((key) => ({
      key,
      label: key,
      detail: "reviewed Tomcat version",
      isDefault: key === "11.0",
    }));
    tomcat.features = tomcat.features.map((feature, index) => index === 0 ? {
      key: "connector-limits",
      title: "限制 Connector 容量、参数转换与中止上传吞咽量",
      summary: "五个参数保持一个原子特性。",
      scope: "Connector / server.xml",
      defaultEnabled: true,
      aliases: [
        "maxThreads",
        "acceptCount",
        "maxConnections",
        "maxPostSize",
        "maxSwallowSize",
      ],
      supportedChoices: versions,
    } : { ...feature, supportedChoices: versions });
    expect(isConfigCatalog(catalog)).toBe(true);

    const connectorLimits = tomcat.features[0];
    if (connectorLimits === undefined) throw new Error("Tomcat connector limits must exist");
    for (const [field, value] of [
      ["inputs", ["maxThreads", "acceptCount"]],
      ["onChange", "revise"],
      ["inlineEditor", { owner: "renderer" }],
      ["bounds", { rowBottom: 100, editorTop: 100 }],
      ["rawContents", "<Server password=\"NeverShow42\" />"],
    ] as const) {
      expect(isConfigCatalog({
        ...catalog,
        products: catalog.products.map((product) => product.key === "tomcat"
          ? {
              ...product,
              features: product.features.map((feature) => feature.key === "connector-limits"
                ? { ...connectorLimits, [field]: value }
                : feature),
            }
          : product),
      })).toBe(false);
    }

    const values = {
      connectorAddress: "ipv4-loopback",
      applicationName: "LovelyRes ROOT application",
      port: "8080",
      connectionTimeout: "20000",
      maxThreads: "320",
      acceptCount: "400",
      maxConnections: "12000",
      maxPostSize: "3000000",
      maxSwallowSize: "4000000",
      compressionMinSize: "2048",
    };
    const input = {
      product: "tomcat",
      choice: "11.0",
      features: [
        "connector-limits",
        "http-only-session-cookies",
        "header-security-filter",
      ],
      values,
    };
    expect(isConfigGenerateInput(input)).toBe(true);
    for (const [field, value] of [
      ["inlineEditor", true],
      ["searchResults", ["tomcat:connector-limits"]],
      ["bounds", { rowBottom: 100, editorTop: 100 }],
      ["markup", "<input oninput=revise()>"],
      ["preview", "maxThreads=320"],
      ["copyPayload", "password=NeverShow42"],
      ["revision", 12],
    ] as const) {
      expect(isConfigGenerateInput({ ...input, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput({
      ...input,
      features: [...input.features, "connector-limits"],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...input,
      features: [
        ...input.features.filter((feature) => feature !== "connector-limits"),
        "<script>globalThis.tomcatInlineExecuted=true</script>",
      ],
    })).toBe(false);
    expect(isConfigGenerateInput({
      ...input,
      values: { ...values, maxThreads: "1".repeat(4_097) },
    })).toBe(false);
  });

  it("tomcat_quick_bundle_transitions_and_three_artifact_boundaries_are_closed", () => {
    const values = {
      connectorAddress: "ipv4-loopback",
      applicationName: "LovelyRes ROOT application",
      port: "8080",
      connectionTimeout: "20000",
      maxThreads: "200",
      acceptCount: "100",
      maxConnections: "8192",
      maxPostSize: "2097152",
      maxSwallowSize: "2097152",
      compressionMinSize: "2048",
    };
    const input = (choice: string, features: string[], overrides: Partial<typeof values> = {}) => ({
      product: "tomcat",
      choice,
      features,
      values: { ...values, ...overrides },
    });
    const defaults = [
      "connector-limits",
      "http-only-session-cookies",
      "header-security-filter",
    ];
    const stackedFeatures = [
      "connector-limits",
      "response-compression",
      "host-auto-deploy",
      "http-only-session-cookies",
      "header-security-filter",
      "allow-safe-methods-only",
    ];
    const tunedValues = {
      connectorAddress: "ipv6-loopback",
      applicationName: "Operations ROOT",
      port: "8181",
      connectionTimeout: "25000",
      maxThreads: "320",
      acceptCount: "400",
      maxConnections: "12000",
      maxPostSize: "3000000",
      maxSwallowSize: "4000000",
      compressionMinSize: "1024",
    };
    const stacked = input("10.1", stackedFeatures, tunedValues);
    const denyAll = input("10.1", [
      ...stackedFeatures.filter((feature) => feature !== "allow-safe-methods-only"),
      "deny-all-requests",
    ], tunedValues);
    const denyRemoved = input("10.1", denyAll.features.filter(
      (feature) => feature !== "deny-all-requests",
    ), tunedValues);
    const compressionRemoved = input("10.1", denyRemoved.features.filter(
      (feature) => feature !== "response-compression",
    ), tunedValues);
    for (const transition of [
      input("11.0", defaults),
      stacked,
      denyAll,
      denyRemoved,
      compressionRemoved,
    ]) {
      expect(isConfigGenerateInput(transition)).toBe(true);
    }
    expect(isConfigGenerateInput(input("10.1", [
      ...stackedFeatures,
      "deny-all-requests",
    ], tunedValues))).toBe(false);

    for (const [field, value] of [
      ["removeFeature", "deny-all-requests"],
      ["reset", true],
      ["copyPayload", "===== BEGIN conf/server.xml ====="],
      ["save", { directoryName: "lovelyres-tomcat-new-empty-review-bundle" }],
      ["exportPath", "C:\\hostile\\tomcat-bundle"],
      ["artifactKey", "server.xml"],
      ["activeArtifactKey", "web.xml"],
      ["artifacts", [{ key: "server.xml", contents: "<Server />" }]],
      ["openVisual", true],
      ["rawBytes", "<Server password=\"NeverShow42\" />"],
      ["markup", "<button onclick=save()>save</button>"],
      ["revision", 12],
    ] as const) {
      expect(isConfigGenerateInput({ ...stacked, [field]: value })).toBe(false);
    }
    expect(isConfigGenerateInput(input("11.0", [
      ...defaults,
      "<script>globalThis.tomcatBundleExecuted=true</script>",
    ]))).toBe(false);
    expect(isConfigGenerateInput(input("11.0", [...defaults, "connector-limits"]))).toBe(false);

    const contents = {
      "server.xml": "<Server />\n",
      "context.xml": "<Context />\n",
      "web.xml": "<web-app />\n",
    } as const;
    const artifacts = [
      {
        key: "server.xml",
        relativePath: "conf/server.xml",
        mediaType: "application/xml",
        byteLength: contents["server.xml"].length,
        preview: contents["server.xml"],
        previewTruncated: false,
        copyAllowed: true,
      },
      {
        key: "context.xml",
        relativePath: "webapps/ROOT/META-INF/context.xml",
        mediaType: "application/xml",
        byteLength: contents["context.xml"].length,
        preview: contents["context.xml"],
        previewTruncated: false,
        copyAllowed: true,
      },
      {
        key: "web.xml",
        relativePath: "webapps/ROOT/WEB-INF/web.xml",
        mediaType: "application/xml",
        byteLength: contents["web.xml"].length,
        preview: contents["web.xml"],
        previewTruncated: false,
        copyAllowed: true,
      },
    ];
    const draft = {
      handle: "tomcat-draft-1",
      revision: 1,
      product: "tomcat",
      choice: "11.0",
      suggestedName: "lovelyres-tomcat-new-empty-review-bundle",
      totalBytes: artifacts.reduce((total, artifact) => total + artifact.byteLength, 0),
      copyAllowed: true,
      artifacts,
      notices: ["Local review bundle only."],
    };
    expect(isConfigDraft(draft)).toBe(true);
    expect(isConfigDraft({ ...draft, artifacts: [...artifacts].reverse() })).toBe(false);
    expect(isConfigDraft({
      ...draft,
      artifacts: artifacts.map((artifact, index) =>
        index === 1 ? { ...artifact, key: "server.xml" } : artifact),
    })).toBe(false);
    expect(isConfigDraft({
      ...draft,
      artifacts: artifacts.map((artifact, index) =>
        index === 2 ? { ...artifact, relativePath: "conf/web.xml" } : artifact),
    })).toBe(false);

    const copy = {
      revision: 1,
      artifacts: artifacts.map((artifact) => ({
        key: artifact.key,
        contents: contents[artifact.key as keyof typeof contents],
      })),
    };
    expect(isInternalConfigCopy(copy)).toBe(true);
    expect(isInternalConfigCopy({ ...copy, artifacts: [...copy.artifacts].reverse() })).toBe(false);
    expect(isInternalConfigCopy({
      ...copy,
      artifacts: copy.artifacts.map((artifact, index) =>
        index === 2 ? { ...artifact, key: "server.xml" } : artifact),
    })).toBe(false);
  });

  it("keeps YashanDB exact schema identity in bounded notice-only metadata", () => {
    const catalog = finiteCatalogFixture();
    const yashan = catalog.readOnlyArtifacts.find(
      (artifact) => artifact.artifactKey === "yashandb-yasdb-ini",
    );
    expect(yashan).toMatchObject({
      productKey: "yashandb",
      title: "yasdb.ini",
      authority: "read-only",
      reason: "vendor-schema-required",
    });
    expect(yashan?.notice).toContain("23.5.4.100");
    expect(yashan?.notice).toContain("official-doc-family-23.5.4.100");
    expect(yashan?.notice).toContain("Partial");
    expect(yashan?.notice).not.toContain("当前仅允许预览");
    expect(isConfigCatalog(catalog)).toBe(true);
    expect(isConfigGenerateInput({ product: "yashandb" })).toBe(false);
    if (yashan === undefined) throw new Error("fixture must include YashanDB schema metadata");

    for (const [field, value] of [
      ["schema", { parameters: ["RUN_LOG_LEVEL"] }],
      ["parameters", ["RUN_LOG_LEVEL"]],
      ["documentedDefaults", { RUN_LOG_LEVEL: "INFO" }],
      ["contents", "RUN_LOG_LEVEL=INFO"],
      ["draft", { contents: "RUN_LOG_LEVEL=INFO" }],
      ["savePayload", "RUN_LOG_LEVEL=INFO"],
      ["mutationAllowed", false],
      ["path", "C:\\private\\yasdb.ini"],
    ] as const) {
      expect(isConfigCatalog({
        ...catalog,
        readOnlyArtifacts: catalog.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === yashan.artifactKey
            ? { ...artifact, [field]: value }
            : artifact,
        ),
      })).toBe(false);
    }

    for (const patch of [
      { authority: "editable" },
      { reason: "schema-metadata" },
      { notice: "x".repeat(8_193) },
      { notice: yashan.notice.replace("23.5.4.100", "23.5.4.99") },
      { notice: yashan.notice.replace("official-doc-family-23.5.4.100", "enterprise") },
    ]) {
      expect(isConfigCatalog({
        ...catalog,
        readOnlyArtifacts: catalog.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === yashan.artifactKey
            ? { ...artifact, ...patch }
            : artifact,
        ),
      })).toBe(false);
    }
  });

  it("accepts auto.cnf selector metadata and rejects injected content capabilities", () => {
    const catalog = finiteCatalogFixture();
    const autoCnf = catalog.readOnlyArtifacts.find(
      (artifact) => artifact.artifactKey === "mysql-server-uuid",
    );
    expect(autoCnf).toMatchObject({
      productKey: "mysql",
      title: "auto.cnf",
      authority: "read-only",
      reason: "generated-artifact",
    });
    expect(isConfigCatalog(catalog)).toBe(true);
    if (autoCnf === undefined) throw new Error("fixture must include auto.cnf");

    for (const [field, value] of [
      ["contents", "[auto]\nserver-uuid=untrusted\n"],
      ["preview", "[auto]\n"],
      ["handle", "read-only-draft"],
      ["revision", 1],
      ["copyAllowed", true],
      ["saveAllowed", true],
      ["mutationAllowed", false],
      ["path", "C:\\private\\auto.cnf"],
    ] as const) {
      expect(isConfigCatalog({
        ...catalog,
        readOnlyArtifacts: catalog.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === autoCnf.artifactKey
            ? { ...artifact, [field]: value }
            : artifact,
        ),
      })).toBe(false);
    }
  });

  it("accepts only finite read-only artifact reasons without mutation fields", () => {
    const catalog = finiteCatalogFixture();
    expect(isConfigCatalog(catalog)).toBe(true);
    expect(isConfigCatalog({ ...catalog, schema: "lovelyres-config-catalog/v1" })).toBe(false);
    expect(isConfigCatalog({ schema: catalog.schema, products: catalog.products })).toBe(false);
    expect(isConfigCatalog({
      ...catalog,
      readOnlyArtifacts: [
        { ...catalog.readOnlyArtifacts[0], reason: "arbitrary-reason" },
        catalog.readOnlyArtifacts[1],
      ],
    })).toBe(false);
    expect(isConfigCatalog({
      ...catalog,
      readOnlyArtifacts: catalog.readOnlyArtifacts.map((artifact) => ({
        ...artifact,
        mutationAllowed: false,
      })),
    })).toBe(false);
    expect(isConfigCatalog({
      ...catalog,
      readOnlyArtifacts: [catalog.readOnlyArtifacts[0], catalog.readOnlyArtifacts[0]],
    })).toBe(false);
    expect(isConfigCatalog({
      ...catalog,
      readOnlyArtifacts: Array.from({ length: 257 }, (_, index) => ({
        ...catalog.readOnlyArtifacts[index % 2],
        artifactKey: `artifact-${index}`,
      })),
    })).toBe(false);
  });

  it("schemas_never_change_vendor_or_generated_local_draft_permission", () => {
    const catalog = finiteCatalogFixture();
    for (const [artifactKey, completeness] of [
      ["opengauss-om-cluster-xml", "Partial"],
      ["mysql-persisted-variables", "Complete"],
    ] as const) {
      const withSchemaNotice: ConfigCatalog = {
        ...catalog,
        readOnlyArtifacts: catalog.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === artifactKey
            ? { ...artifact, notice: `${artifact.notice} Schema completeness: ${completeness}.` }
            : artifact,
        ),
      };
      expect(isConfigCatalog(withSchemaNotice)).toBe(true);
      expect(
        withSchemaNotice.readOnlyArtifacts.find((artifact) => artifact.artifactKey === artifactKey),
      ).toMatchObject({ authority: "read-only" });

      for (const schemaAttempt of [
        { authority: "lossless-local-draft" },
        { schemaAuthority: "lossless-local-draft" },
        { schemaCompleteness: completeness },
        { localDraftAllowed: true },
        { mutationAllowed: true },
      ]) {
        expect(isConfigCatalog({
          ...withSchemaNotice,
          readOnlyArtifacts: withSchemaNotice.readOnlyArtifacts.map((artifact) =>
            artifact.artifactKey === artifactKey
              ? { ...artifact, ...schemaAttempt }
              : artifact,
          ),
        })).toBe(false);
      }
    }
  });

  it("compatible_and_domestic_starters_do_not_guess_upstream_defaults", () => {
    const catalog = finiteCatalogFixture();
    expect(isConfigCatalog(catalog)).toBe(true);

    for (const [field, value] of [
      ["databaseStarters", [
        { artifactKey: "kingbase-es-main", contents: "port = 5432" },
        { artifactKey: "gbase-8c-main", contents: "password_encryption = 'scram-sha-256'" },
        { artifactKey: "tidb-server-toml", contents: "port = 3306" },
      ]],
      ["starterContents", { "kingbase-es-main": "port = 5432" }],
      ["upstreamDefaults", { postgresql: 5432, mysql: 3306 }],
    ] as const) {
      expect(isConfigCatalog({ ...catalog, [field]: value })).toBe(false);
    }

    for (const product of ["kingbase-es", "gbase-8c", "tidb"] as const) {
      expect(isConfigGenerateInput({
        product,
        choice: "upstream-compatible",
        features: [],
        values: {},
      })).toBe(false);
    }

    for (const [field, value] of [
      ["starterContents", "port = 5432"],
      ["upstreamDefaults", { port: 5432 }],
      ["inheritsDefaultsFrom", "postgresql"],
    ] as const) {
      expect(isConfigCatalog({
        ...catalog,
        products: catalog.products.map((product) =>
          product.key === "postgresql" ? { ...product, [field]: value } : product,
        ),
      })).toBe(false);
    }
  });

  it("local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts", () => {
    const catalog = finiteCatalogFixture();
    const unparsedMetadata: ConfigReadOnlyArtifactStatus = {
      artifactKey: "kingbase-es-repmgr",
      productKey: "kingbase-es",
      productTitle: "KingbaseES",
      title: "repmgr.conf",
      authority: "read-only",
      reason: "vendor-schema-required",
      notice: "只读元数据：未提供经过审查的本地可视解析器。",
    };
    const withUnparsedMetadata: ConfigCatalog = {
      ...catalog,
      readOnlyArtifacts: [...catalog.readOnlyArtifacts, unparsedMetadata],
    };
    expect(isConfigCatalog(withUnparsedMetadata)).toBe(true);

    for (const [field, value] of [
      ["contents", "AUTHKEY=NeverExpose"],
      ["preview", "AUTHKEY=NeverExpose"],
      ["draft", { handle: "draft-1", revision: 1 }],
      ["handle", "draft-1"],
      ["copyAllowed", true],
      ["saveAllowed", true],
      ["mutationAllowed", true],
      ["localVisualSelectable", true],
    ] as const) {
      expect(isConfigCatalog({
        ...withUnparsedMetadata,
        readOnlyArtifacts: withUnparsedMetadata.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === unparsedMetadata.artifactKey
            ? { ...artifact, [field]: value }
            : artifact,
        ),
      })).toBe(false);
    }

    for (const product of [
      "tdsql-mysql-managed",
      "tdsql-postgresql-managed",
      "polardb-managed-mysql",
      "polardb-managed-postgresql",
      "polardb-managed-oracle",
    ] as const) {
      expect(isConfigGenerateInput({
        product,
        choice: "local-visual",
        features: [],
        values: {},
      })).toBe(false);
    }

    expect(isConfigCatalog({
      ...catalog,
      localVisualArtifacts: [
        "mysql-runtime-variables",
        "tdsql-mysql-managed-parameter-api",
        "oceanbase-observer-binary",
        "kingbase-es-repmgr",
      ],
    })).toBe(false);
  });

  it("unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries", () => {
    const catalog = finiteCatalogFixture();
    const hostileMarkup = "<script>globalThis.vendorTextExecuted=true</script>";
    const rejectedVendorText = `${hostileMarkup}\nAUTHKEY K9z7Q2\n`;
    const metadataOnly: ConfigReadOnlyArtifactStatus = {
      artifactKey: "kingbase-es-repmgr",
      productKey: "kingbase-es",
      productTitle: "KingbaseES",
      title: "repmgr.conf",
      authority: "read-only",
      reason: "vendor-schema-required",
      notice: hostileMarkup,
    };
    const boundedPlainTextCatalog: ConfigCatalog = {
      ...catalog,
      readOnlyArtifacts: [...catalog.readOnlyArtifacts, metadataOnly],
    };
    expect(isConfigCatalog(boundedPlainTextCatalog)).toBe(true);

    for (const [field, value] of [
      ["rawText", rejectedVendorText],
      ["contents", rejectedVendorText],
      ["rows", [{ name: "AUTHKEY", value: "K9z7Q2" }]],
      ["preview", rejectedVendorText],
      ["copyPayload", rejectedVendorText],
      ["exportPayload", rejectedVendorText],
      ["savePayload", rejectedVendorText],
      ["credential", "K9z7Q2"],
      ["authKey", "K9z7Q2"],
      ["handle", "unparsed-vendor-draft"],
      ["copyAllowed", true],
      ["saveAllowed", true],
      ["mutationAllowed", true],
    ] as const) {
      expect(isConfigCatalog({
        ...boundedPlainTextCatalog,
        readOnlyArtifacts: boundedPlainTextCatalog.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === metadataOnly.artifactKey
            ? { ...artifact, [field]: value }
            : artifact,
        ),
      })).toBe(false);
    }

    expect(isConfigCatalog({
      ...boundedPlainTextCatalog,
      visualRows: [{ artifactKey: metadataOnly.artifactKey, rawText: rejectedVendorText }],
    })).toBe(false);
    expect(isConfigCatalog({
      ...catalog,
      readOnlyArtifacts: [...catalog.readOnlyArtifacts, {
        ...metadataOnly,
        notice: hostileMarkup.repeat(600),
      }],
    })).toBe(false);
  });

  it("gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy", () => {
    const catalog = finiteCatalogFixture();
    const sentinel = "K9z7Q2";
    const source = `AUTHKEY ${sentinel}\n`;
    const metadataOnly: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "gbase-8s-onconfig",
        productKey: "gbase-8s",
        productTitle: "GBase 8s",
        title: "onconfig",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：匹配版本的厂商 schema 也不授予本地草稿权限。",
      },
      {
        artifactKey: "gbase-8s-sqlhosts",
        productKey: "gbase-8s",
        productTitle: "GBase 8s",
        title: "sqlhosts",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：目录响应不携带源文件内容。",
      },
    ];
    const metadataCatalog: ConfigCatalog = {
      ...catalog,
      readOnlyArtifacts: [...catalog.readOnlyArtifacts, ...metadataOnly],
    };
    expect(isConfigCatalog(metadataCatalog)).toBe(true);

    for (const artifactKey of ["gbase-8s-onconfig", "gbase-8s-sqlhosts"] as const) {
      for (const [field, value] of [
        ["AUTHKEY", sentinel],
        ["credential", sentinel],
        ["rawText", source],
        ["contents", source],
        ["rows", [{ name: "AUTHKEY", value: sentinel }]],
        ["preview", "[sensitive value redacted]"],
        ["draft", { handle: artifactKey, revision: 1 }],
        ["handle", artifactKey],
        ["copyPayload", source],
        ["exportPayload", source],
        ["savePayload", source],
        ["copyAllowed", true],
        ["saveAllowed", true],
        ["mutationAllowed", true],
      ] as const) {
        expect(isConfigCatalog({
          ...metadataCatalog,
          readOnlyArtifacts: metadataCatalog.readOnlyArtifacts.map((artifact) =>
            artifact.artifactKey === artifactKey
              ? { ...artifact, [field]: value }
              : artifact,
          ),
        })).toBe(false);
      }
    }

    expect(isConfigGenerateInput({
      product: "gbase-8s",
      choice: "onconfig",
      features: [],
      values: { AUTHKEY: sentinel },
    })).toBe(false);
    expect(isConfigDraft({
      handle: "gbase-8s-onconfig",
      revision: 1,
      product: "gbase-8s",
      choice: "onconfig",
      suggestedName: "onconfig",
      totalBytes: new TextEncoder().encode(source).byteLength,
      copyAllowed: false,
      artifacts: [{
        key: "main",
        relativePath: "onconfig",
        mediaType: "text/plain",
        byteLength: new TextEncoder().encode(source).byteLength,
        preview: "[sensitive value redacted]",
        previewTruncated: false,
        copyAllowed: false,
      }],
      notices: [],
    })).toBe(false);
    expect(isConfigCatalog({
      ...metadataCatalog,
      visualRows: [{ artifactKey: "gbase-8s-onconfig", name: "AUTHKEY", value: sentinel }],
    })).toBe(false);
  });

  it("dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor", () => {
    const catalog = finiteCatalogFixture();
    const dcrConfig = [
      "[GRP]",
      "DCR_GRP_NAME=CSS_GRP",
      "DCR_GRP_TYPE=CSS",
      "[CSS]",
      "DCR_EP_NAME=CSS0",
      "<script>globalThis.dcrExecuted=true</script>",
    ].join("\n");
    const dcrNode = [
      "DMDCR_PATH=/dmdata/dmdcr_cfg.ini",
      "DMDCR_DB_STARTUP_CMD=/opt/dmdbms/bin/dmserver path=/dmdata/DAMENG/dm.ini password=NeverShow42",
    ].join("\n");
    const metadataOnly: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "dm-dcr-config",
        productKey: "dm",
        productTitle: "达梦数据库",
        title: "dmdcr_cfg.ini",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "<script>DM DCR array metadata only</script>",
      },
      {
        artifactKey: "dm-dcr-node",
        productKey: "dm",
        productTitle: "达梦数据库",
        title: "dmdcr.ini",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "DM DCR startup command metadata only",
      },
    ];
    const metadataCatalog: ConfigCatalog = {
      ...catalog,
      readOnlyArtifacts: [...catalog.readOnlyArtifacts, ...metadataOnly],
    };
    expect(isConfigCatalog(metadataCatalog)).toBe(true);

    for (const [artifactKey, payload] of [
      ["dm-dcr-config", dcrConfig],
      ["dm-dcr-node", dcrNode],
    ] as const) {
      for (const [field, value] of [
        ["iniRows", [{ section: "GRP", key: "DCR_GRP_NAME", value: "CSS_GRP" }]],
        ["groups", [{ name: "CSS_GRP", members: ["CSS0"] }]],
        ["startupCommand", dcrNode],
        ["command", dcrNode],
        ["shell", dcrNode],
        ["rawText", payload],
        ["contents", payload],
        ["preview", payload],
        ["copyPayload", payload],
        ["savePayload", payload],
        ["exportPayload", payload],
        ["credential", "NeverShow42"],
        ["handle", artifactKey],
        ["copyAllowed", true],
        ["saveAllowed", true],
        ["mutationAllowed", true],
      ] as const) {
        expect(isConfigCatalog({
          ...metadataCatalog,
          readOnlyArtifacts: metadataCatalog.readOnlyArtifacts.map((artifact) =>
            artifact.artifactKey === artifactKey
              ? { ...artifact, [field]: value }
              : artifact,
          ),
        })).toBe(false);
      }
    }

    expect(isConfigGenerateInput({
      product: "dm",
      choice: "dcr",
      features: [],
      values: { DMDCR_DB_STARTUP_CMD: dcrNode },
    })).toBe(false);
    expect(isConfigDraft({
      handle: "dm-dcr-node",
      revision: 1,
      product: "dm",
      choice: "dcr",
      suggestedName: "dmdcr.ini",
      totalBytes: new TextEncoder().encode(dcrNode).byteLength,
      copyAllowed: true,
      artifacts: [{
        key: "main",
        relativePath: "dmdcr.ini",
        mediaType: "text/plain",
        byteLength: new TextEncoder().encode(dcrNode).byteLength,
        preview: dcrNode,
        previewTruncated: false,
        copyAllowed: true,
      }],
      notices: [],
    })).toBe(false);
    expect(isConfigCatalog({
      ...metadataCatalog,
      genericIniEditor: { artifactKey: "dm-dcr-node", contents: dcrNode },
    })).toBe(false);
  });

  it("dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates", () => {
    const catalog = finiteCatalogFixture();
    const secret = "NeverShow42";
    const hostileInput = "<script>globalThis.dmInitExecuted=true</script> password=EchoMe";
    const dmInitSource = [
      "[DAMENG]",
      `SYSDBA_PWD=${secret}`,
      "LOG_PATH=/var/log/dm/primary",
    ].join("\n");
    expect(isConfigCatalog(catalog)).toBe(true);

    expect(isConfigGenerateInput({
      product: "dm",
      choice: "dminit",
      features: [],
      values: { SYSDBA_PWD: hostileInput },
    })).toBe(false);
    expect(isConfigGenerateInput({
      product: "mysql",
      choice: "8.4.0",
      features: [],
      values: { SYSDBA_PWD: hostileInput },
    })).toBe(false);

    const safeMetadata: ConfigReadOnlyArtifactStatus = {
      artifactKey: "dm-init",
      productKey: "dm",
      productTitle: "达梦数据库",
      title: "dminit.ini",
      authority: "read-only",
      reason: "read-only-policy",
      notice: "固定只读元数据；目录不携带 dminit.ini 字节。",
    };
    const metadataCatalog: ConfigCatalog = {
      ...catalog,
      readOnlyArtifacts: [...catalog.readOnlyArtifacts, safeMetadata],
    };
    expect(isConfigCatalog(metadataCatalog)).toBe(true);

    for (const [field, value] of [
      ["SYSDBA_PWD", secret],
      ["password", secret],
      ["credential", hostileInput],
      ["rawText", dmInitSource],
      ["contents", dmInitSource],
      ["preview", "[sensitive value redacted]"],
      ["draft", { handle: "dm-init", revision: 1 }],
      ["handle", "dm-init"],
      ["copyPayload", dmInitSource],
      ["exportPayload", dmInitSource],
      ["savePayload", dmInitSource],
      ["copyAllowed", true],
      ["saveAllowed", true],
      ["mutationAllowed", true],
    ] as const) {
      expect(isConfigCatalog({
        ...metadataCatalog,
        readOnlyArtifacts: metadataCatalog.readOnlyArtifacts.map((artifact) =>
          artifact.artifactKey === safeMetadata.artifactKey
            ? { ...artifact, [field]: value }
            : artifact,
        ),
      })).toBe(false);
    }

    expect(isConfigDraft({
      handle: "dm-init",
      revision: 1,
      product: "dm",
      choice: "dminit",
      suggestedName: "dminit.ini",
      totalBytes: new TextEncoder().encode(dmInitSource).byteLength,
      copyAllowed: false,
      artifacts: [{
        key: "dm-init",
        relativePath: "dminit.ini",
        mediaType: "text/plain",
        byteLength: new TextEncoder().encode(dmInitSource).byteLength,
        preview: "[sensitive value redacted]",
        previewTruncated: false,
        copyAllowed: false,
      }],
      notices: [],
    })).toBe(false);
    expect(isConfigCatalog({
      ...catalog,
      dmInit: { contents: dmInitSource, credential: hostileInput },
    })).toBe(false);
  });

  it("accepts a closed Nginx request and rejects unknown or duplicate feature input", () => {
    const request = {
      product: "nginx",
      choice: "reverse-proxy",
      features: ["security-headers"],
      values: {
        serverName: "example.com",
        listenPort: "80",
        staticRoot: "/var/www/html",
        upstream: "http://127.0.0.1:3000",
        forbiddenPath: "/admin",
        forbiddenScope: "path-and-descendants",
        allowedSource: "",
      },
    };
    expect(isConfigGenerateInput(request)).toBe(true);
    expect(isConfigGenerateInput({ ...request, command: "nginx -t" })).toBe(false);
    expect(isConfigGenerateInput({ ...request, features: ["security-headers", "security-headers"] })).toBe(false);
    expect(isConfigGenerateInput({ ...request, values: { ...request.values, rawText: "evil" } })).toBe(false);
  });

  it("validates opaque draft metadata without accepting leaked full contents", () => {
    const draft = {
      handle: "draft-1",
      revision: 1,
      product: "nginx",
      choice: "reverse-proxy",
      suggestedName: "nginx-site.conf",
      totalBytes: 3,
      copyAllowed: true,
      artifacts: [{
        key: "main",
        relativePath: "nginx-site.conf",
        mediaType: "text/plain",
        byteLength: 3,
        preview: "abc",
        previewTruncated: false,
        copyAllowed: true,
      }],
      notices: ["local draft"],
    };
    expect(isConfigDraft(draft)).toBe(true);
    expect(isConfigDraft({
      ...draft,
      product: "mongodb",
      suggestedName: "mongod.conf",
      artifacts: [{ ...draft.artifacts[0], mediaType: "application/yaml" }],
    })).toBe(true);
    expect(isConfigDraft({
      ...draft,
      artifacts: [{ ...draft.artifacts[0], mediaType: "application/javascript" }],
    })).toBe(false);
    expect(isConfigDraft({ ...draft, contents: "must stay in Rust" })).toBe(false);
    expect(isConfigDraft({ ...draft, suggestedName: "../escape.conf" })).toBe(false);

    const exactPreviewLimit = `${"界".repeat(10_922)}ab`;
    const exactPreviewBytes = new TextEncoder().encode(exactPreviewLimit).byteLength;
    expect(exactPreviewBytes).toBe(32 * 1_024);
    expect(isConfigDraft({
      ...draft,
      totalBytes: exactPreviewBytes,
      artifacts: [{
        ...draft.artifacts[0],
        byteLength: exactPreviewBytes,
        preview: exactPreviewLimit,
      }],
    })).toBe(true);
    const oversizedPreview = `${exactPreviewLimit}界`;
    const oversizedPreviewBytes = new TextEncoder().encode(oversizedPreview).byteLength;
    expect(isConfigDraft({
      ...draft,
      totalBytes: oversizedPreviewBytes,
      artifacts: [{
        ...draft.artifacts[0],
        byteLength: oversizedPreviewBytes,
        preview: oversizedPreview,
      }],
    })).toBe(false);
    expect(isConfigDraft({
      ...draft,
      artifacts: [{ ...draft.artifacts[0], byteLength: draft.totalBytes + 1 }],
    })).toBe(false);
  });

  it("bounds internal copy/export responses and rejects path traversal", () => {
    expect(isInternalConfigCopy({ revision: 1, artifacts: [{ key: "main", contents: "safe" }] })).toBe(true);
    expect(isInternalConfigCopy({ revision: 1, artifacts: [{ key: "main", contents: "safe", path: "C:\\escape" }] })).toBe(false);
    expect(isInternalConfigArtifact({ suggestedName: "conf/server.xml", contents: "<Server />" })).toBe(true);
    expect(isInternalConfigArtifact({ suggestedName: "../server.xml", contents: "<Server />" })).toBe(false);
  });
});
