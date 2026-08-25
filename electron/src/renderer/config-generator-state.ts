import type {
  ApacheConfigValues,
  ConfigCatalog,
  ConfigDraft,
  ConfigFeature,
  ConfigGenerateInput,
  ConfigProduct,
  ConfigProductKey,
  ConfigReadOnlyArtifactStatus,
  HaProxyConfigValues,
  MariaDbConfigValues,
  MongoDbConfigValues,
  MySqlConfigValues,
  NginxConfigValues,
  PostgreSqlConfigValues,
  RedisConfigValues,
  TomcatConfigValues,
} from "../shared/config-contract";

export type ConfigRequestOutcome = "completed" | "failed" | "stale";

interface ConfigRequestCallbacks<T> {
  work(): Promise<T>;
  onSuccess(value: T): void | Promise<void>;
  onError(error: unknown): void;
  onFinally(): void;
  onStaleSuccess?(value: T): void | Promise<void>;
}

/**
 * One mounted config-generator request lane. A new request or lifecycle change
 * invalidates every older completion before it can update renderer state.
 */
export class ConfigRequestLifecycle {
  private active = false;
  private generation = 0;

  activate(): void {
    this.generation += 1;
    this.active = true;
  }

  deactivate(): void {
    this.generation += 1;
    this.active = false;
  }

  async run<T>(callbacks: ConfigRequestCallbacks<T>): Promise<ConfigRequestOutcome> {
    if (!this.active) return "stale";
    const generation = ++this.generation;
    const isCurrent = () => this.active && this.generation === generation;

    try {
      const value = await callbacks.work();
      if (!isCurrent()) {
        try {
          await callbacks.onStaleSuccess?.(value);
        } catch {
          // A stale capability release is best-effort and must not revive UI state.
        }
        return "stale";
      }
      await callbacks.onSuccess(value);
      return "completed";
    } catch (error) {
      if (!isCurrent()) return "stale";
      callbacks.onError(error);
      return "failed";
    } finally {
      if (isCurrent()) callbacks.onFinally();
    }
  }
}

export async function releaseLateConfigDraft(
  draft: ConfigDraft,
  closeDraft: (handle: string, revision: number) => Promise<unknown>,
): Promise<void> {
  try {
    await closeDraft(draft.handle, draft.revision);
  } catch {
    // The owning page is already inactive; this is cleanup, not a user-visible failure.
  }
}

export interface ConfigValuesByProduct {
  nginx: NginxConfigValues;
  apache: ApacheConfigValues;
  haproxy: HaProxyConfigValues;
  mysql: MySqlConfigValues;
  postgresql: PostgreSqlConfigValues;
  mariadb: MariaDbConfigValues;
  mongodb: MongoDbConfigValues;
  redis: RedisConfigValues;
  tomcat: TomcatConfigValues;
}

export interface ConfigValueField {
  key: string;
  label: string;
  description: string;
  inputMode?: "decimal" | "text";
  options?: ReadonlyArray<{ value: string; label: string }>;
}

const localHttpUpstream = "http:" + "//127.0.0.1:3000";

export const DEFAULT_CONFIG_VALUES: ConfigValuesByProduct = {
  nginx: {
    serverName: "example.com",
    listenPort: "80",
    staticRoot: "/var/www/html",
    upstream: localHttpUpstream,
    forbiddenPath: "/admin",
    forbiddenScope: "path-and-descendants",
    allowedSource: "",
  },
  apache: {
    serverName: "example.com",
    listenPort: "80",
    staticRoot: "/var/www/html",
    upstream: localHttpUpstream,
    forbiddenPath: "/admin",
    forbiddenScope: "path-and-descendants",
    allowedSource: "",
  },
  haproxy: {
    listenAddress: "127.0.0.1",
    listenPort: "80",
    upstream: "127.0.0.1:3000",
    forbiddenPath: "/admin",
    forbiddenScope: "path-and-descendants",
    allowedSource: "127.0.0.1",
  },
  mysql: {
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
  },
  postgresql: {
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
  },
  mariadb: {
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
  },
  mongodb: {
    port: "27017",
    maxConnections: "10000",
    slowOperationThreshold: "100",
    slowOperationSampleRate: "1.0",
    slowInProgressThreshold: "1000",
    logPath: "/var/log/mongodb/mongod.log",
    logRotationMode: "rename",
    wiredTigerCacheGib: "1",
    collectionCompressor: "snappy",
    journalCompressor: "zstd",
  },
  redis: {
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
  },
  tomcat: {
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
  },
};

const scopeOptions = [
  { value: "exact", label: "仅精确路径" },
  { value: "path-and-descendants", label: "路径及其子路径" },
] as const;

const numberField = (key: string, label: string, description: string): ConfigValueField => ({
  key,
  label,
  description,
  inputMode: "decimal",
});

export const CONFIG_VALUE_FIELDS: Record<ConfigProductKey, readonly ConfigValueField[]> = {
  nginx: [
    { key: "serverName", label: "Server name", description: "单个受校验的主机名。" },
    numberField("listenPort", "监听端口", "站点监听端口。"),
    { key: "staticRoot", label: "静态目录", description: "静态站点根目录。" },
    { key: "upstream", label: "上游地址", description: "反向代理使用的 HTTP 上游。" },
    { key: "forbiddenPath", label: "禁止路径", description: "命中后返回 403 的 URL 路径。" },
    { key: "forbiddenScope", label: "禁止范围", description: "精确匹配或包含后代路径。", options: scopeOptions },
    { key: "allowedSource", label: "允许来源", description: "可选的受信 CIDR；留空时由特性决定。" },
  ],
  apache: [
    { key: "serverName", label: "Server name", description: "单个受校验的主机名。" },
    numberField("listenPort", "监听端口", "VirtualHost 监听端口。"),
    { key: "staticRoot", label: "静态目录", description: "DocumentRoot 的绝对路径。" },
    { key: "upstream", label: "上游地址", description: "反向代理使用的 HTTP 上游。" },
    { key: "forbiddenPath", label: "禁止路径", description: "命中后返回 403 的 URL 路径。" },
    { key: "forbiddenScope", label: "禁止范围", description: "精确匹配或包含后代路径。", options: scopeOptions },
    { key: "allowedSource", label: "允许来源", description: "可选的受信 CIDR；留空时由特性决定。" },
  ],
  haproxy: [
    { key: "listenAddress", label: "监听地址", description: "前端绑定的 IP 地址。" },
    numberField("listenPort", "监听端口", "HTTP 前端监听端口。"),
    { key: "upstream", label: "上游地址", description: "后端服务器的 host:port。" },
    { key: "forbiddenPath", label: "禁止路径", description: "命中后拒绝的 URL 路径。" },
    { key: "forbiddenScope", label: "禁止范围", description: "精确匹配或包含后代路径。", options: scopeOptions },
    { key: "allowedSource", label: "允许来源", description: "受信来源 IP 或 CIDR。" },
  ],
  mysql: [
    { key: "remoteListener", label: "监听地址", description: "远程监听不替代账号 Host、TLS 或防火墙。" },
    numberField("maxConnections", "最大连接数", "mysqld 最大并发连接。"),
    numberField("connectTimeout", "连接超时（秒）", "握手等待上限。"),
    numberField("maxConnectErrors", "最大连接错误", "阻断主机前允许的连续错误数。"),
    numberField("waitTimeout", "空闲超时（秒）", "非交互会话空闲上限。"),
    numberField("interactiveTimeout", "交互超时（秒）", "交互会话空闲上限。"),
    numberField("longQueryTime", "慢查询阈值（秒）", "写入慢日志的时长阈值。"),
    { key: "logErrorVerbosity", label: "错误日志级别", description: "闭合的 mysqld 日志详细度。", options: [
      { value: "1", label: "1 · 错误" },
      { value: "2", label: "2 · 错误与警告" },
      { value: "3", label: "3 · 错误、警告与信息" },
    ] },
    numberField("serverId", "Server ID", "复制与 binlog 使用的服务器编号。"),
    numberField("binlogRetention", "Binlog 保留（秒）", "二进制日志保留时长。"),
  ],
  postgresql: [
    numberField("port", "端口", "PostgreSQL 监听端口。"),
    numberField("maxConnections", "最大连接数", "普通与预留连接的总容量。"),
    numberField("superuserReservedConnections", "超级用户预留", "为超级用户预留的连接数。"),
    numberField("reservedConnections", "角色预留", "为特权角色预留的连接数。"),
    numberField("authenticationTimeout", "认证超时（秒）", "完成客户端认证的时限。"),
    numberField("idleInTransactionTimeout", "事务内空闲（秒）", "终止事务内空闲会话的阈值。"),
    numberField("idleSessionTimeout", "会话空闲（秒）", "终止普通空闲会话的阈值。"),
    numberField("temporaryFileLimit", "临时文件上限（MiB）", "单进程临时文件限制。"),
    numberField("lockWaitThreshold", "锁等待日志（毫秒）", "记录锁等待的阈值。"),
    numberField("autovacuumLogThreshold", "Autovacuum 日志（毫秒）", "记录 autovacuum 的阈值。"),
    numberField("temporaryFileLogThreshold", "临时文件日志（KiB）", "记录临时文件的阈值。"),
    { key: "walCompression", label: "WAL 压缩", description: "目标构建能力未知时仅允许闭合的 pglz。", options: [
      { value: "pglz", label: "pglz" },
    ] },
  ],
  mariadb: [
    numberField("port", "端口", "MariaDB 监听端口。"),
    numberField("maxConnections", "最大连接数", "服务端并发连接上限。"),
    numberField("connectTimeout", "连接超时（秒）", "握手等待上限。"),
    numberField("waitTimeout", "空闲超时（秒）", "非交互会话空闲上限。"),
    numberField("interactiveTimeout", "交互超时（秒）", "交互会话空闲上限。"),
    numberField("maxConnectErrors", "最大连接错误", "阻断主机前允许的连续错误数。"),
    numberField("maxAllowedPacket", "最大包（MiB）", "协议包与部分中间结果的上限。"),
    numberField("slowQueryTime", "慢查询阈值（秒）", "写入慢日志的时长阈值。"),
    numberField("serverId", "Server ID", "复制与 binlog 使用的服务器编号。"),
    numberField("binlogRetention", "Binlog 保留（秒）", "二进制日志保留时长。"),
    numberField("innodbLockWaitTimeout", "InnoDB 锁等待（秒）", "事务等待行锁的上限。"),
    { key: "characterProfile", label: "字符集配置", description: "数据库默认字符集与排序规则组合。", options: [
      { value: "unicode-case-insensitive", label: "Unicode · 不区分大小写" },
      { value: "unicode-binary", label: "Unicode · 二进制排序" },
    ] },
  ],
  mongodb: [
    numberField("port", "端口", "mongod 监听端口。"),
    numberField("maxConnections", "最大连接数", "网络连接上限。"),
    numberField("slowOperationThreshold", "慢操作阈值（毫秒）", "Profiler 慢操作阈值。"),
    { key: "slowOperationSampleRate", label: "慢操作采样率", description: "0 到 1 的采样比例。", inputMode: "decimal" },
    numberField("slowInProgressThreshold", "进行中慢操作（毫秒）", "记录仍在执行的慢操作阈值。"),
    { key: "logPath", label: "日志路径", description: "mongod 日志的绝对路径。" },
    { key: "logRotationMode", label: "日志轮转", description: "本地日志轮转方式。", options: [
      { value: "rename", label: "rename" },
      { value: "reopen", label: "reopen" },
    ] },
    numberField("wiredTigerCacheGib", "WiredTiger 缓存（GiB）", "显式缓存容量。"),
    { key: "collectionCompressor", label: "集合压缩", description: "新集合使用的块压缩算法。", options: [
      { value: "snappy", label: "snappy" },
      { value: "zstd", label: "zstd" },
      { value: "zlib", label: "zlib" },
      { value: "none", label: "不压缩" },
    ] },
    { key: "journalCompressor", label: "Journal 压缩", description: "Journal 使用的压缩算法。", options: [
      { value: "snappy", label: "snappy" },
      { value: "zstd", label: "zstd" },
      { value: "zlib", label: "zlib" },
      { value: "none", label: "不压缩" },
    ] },
  ],
  redis: [
    { key: "bindProfile", label: "绑定配置", description: "闭合的本地接口绑定组合。", options: [
      { value: "ipv4-loopback", label: "仅 IPv4 回环" },
      { value: "dual-stack-loopback", label: "IPv4 + IPv6 回环" },
    ] },
    { key: "dataDirectory", label: "数据目录", description: "持久化文件所在绝对目录。" },
    numberField("port", "端口", "Redis 监听端口。"),
    numberField("maxClients", "最大客户端", "同时连接的客户端上限。"),
    numberField("idleTimeout", "空闲超时（秒）", "断开空闲客户端的阈值。"),
    numberField("tcpKeepalive", "TCP Keepalive（秒）", "连接保活探测间隔。"),
    numberField("maxmemoryMib", "内存上限（MiB）", "受管实例最大内存。"),
    { key: "evictionPolicy", label: "淘汰策略", description: "达到内存上限后的闭合策略。", options: [
      { value: "noeviction", label: "noeviction" },
      { value: "allkeys-lru", label: "allkeys-lru" },
      { value: "allkeys-lfu", label: "allkeys-lfu" },
      { value: "allkeys-random", label: "allkeys-random" },
      { value: "volatile-lru", label: "volatile-lru" },
      { value: "volatile-lfu", label: "volatile-lfu" },
      { value: "volatile-random", label: "volatile-random" },
      { value: "volatile-ttl", label: "volatile-ttl" },
    ] },
    { key: "appendFsync", label: "AOF fsync", description: "AOF 刷盘频率。", options: [
      { value: "always", label: "always" },
      { value: "everysec", label: "everysec" },
      { value: "no", label: "no" },
    ] },
    numberField("slowlogThreshold", "慢日志阈值（微秒）", "命令进入慢日志的耗时阈值。"),
    numberField("slowlogLength", "慢日志长度", "慢日志保留条目数。"),
    numberField("latencyThreshold", "延迟监控（毫秒）", "动态延迟监控阈值。"),
  ],
  tomcat: [
    { key: "connectorAddress", label: "Connector 地址", description: "闭合的回环监听地址。", options: [
      { value: "ipv4-loopback", label: "IPv4 回环" },
      { value: "ipv6-loopback", label: "IPv6 回环" },
    ] },
    { key: "applicationName", label: "应用名称", description: "写入本地配置注释的纯文本名称。" },
    numberField("port", "端口", "HTTP Connector 端口。"),
    numberField("connectionTimeout", "连接超时（毫秒）", "Connector 等待请求的时限。"),
    numberField("maxThreads", "最大线程", "Connector 工作线程上限。"),
    numberField("acceptCount", "接受队列", "工作线程饱和后的排队上限。"),
    numberField("maxConnections", "最大连接", "Connector 同时连接上限。"),
    numberField("maxPostSize", "POST 上限（字节）", "表单参数解析上限。"),
    numberField("maxSwallowSize", "吞弃上限（字节）", "中止上传后可吞弃的请求体上限。"),
    numberField("compressionMinSize", "压缩阈值（字节）", "启用响应压缩的最小长度。"),
  ],
};

export interface ConfigSearchSubject {
  product: ConfigProductKey;
  featureKey: string;
}

export interface ConfigSearchResult extends ConfigSearchSubject {
  id: string;
  productTitle: string;
  title: string;
  summary: string;
}

export interface ConfigEditorState {
  selectedProduct: ConfigProductKey | null;
  selectedSubject: ConfigSearchSubject | null;
  query: string;
  choices: Partial<Record<ConfigProductKey, string>>;
  enabledFeatures: Record<ConfigProductKey, string[]>;
  values: ConfigValuesByProduct;
  inputRevisions: Record<ConfigProductKey, number>;
  preview: { product: ConfigProductKey; inputRevision: number } | null;
}

export type ConfigEditorAction =
  | { type: "catalog-loaded"; catalog: ConfigCatalog }
  | { type: "select-product"; product: ConfigProductKey }
  | { type: "set-query"; query: string }
  | { type: "select-search-result"; subject: ConfigSearchSubject }
  | {
      type: "set-choice";
      product: ConfigProductKey;
      choice: string;
      supportedFeatureKeys: string[];
    }
  | { type: "set-feature"; product: ConfigProductKey; featureKey: string; enabled: boolean }
  | { type: "set-value"; product: ConfigProductKey; key: string; value: string }
  | { type: "reset-product"; product: ConfigProduct }
  | { type: "preview-generated"; product: ConfigProductKey; inputRevision: number }
  | { type: "clear-preview" };

function createProductRecord<T>(value: T): Record<ConfigProductKey, T> {
  return {
    nginx: value,
    apache: value,
    haproxy: value,
    mysql: value,
    postgresql: value,
    mariadb: value,
    mongodb: value,
    redis: value,
    tomcat: value,
  };
}

function defaultFeatureKeys(product: ConfigProduct): string[] {
  return product.features
    .filter(
      (feature) =>
        feature.defaultEnabled && feature.supportedChoices.includes(product.defaultChoice),
    )
    .map((feature) => feature.key);
}

function nextInputRevisions(
  state: ConfigEditorState,
  product: ConfigProductKey,
): Record<ConfigProductKey, number> {
  return {
    ...state.inputRevisions,
    [product]: state.inputRevisions[product] + 1,
  };
}

function previewAfterProductMutation(
  state: ConfigEditorState,
  product: ConfigProductKey,
): ConfigEditorState["preview"] {
  return state.preview?.product === product ? null : state.preview;
}

function cloneDefaultValues(): ConfigValuesByProduct {
  return {
    nginx: { ...DEFAULT_CONFIG_VALUES.nginx },
    apache: { ...DEFAULT_CONFIG_VALUES.apache },
    haproxy: { ...DEFAULT_CONFIG_VALUES.haproxy },
    mysql: { ...DEFAULT_CONFIG_VALUES.mysql },
    postgresql: { ...DEFAULT_CONFIG_VALUES.postgresql },
    mariadb: { ...DEFAULT_CONFIG_VALUES.mariadb },
    mongodb: { ...DEFAULT_CONFIG_VALUES.mongodb },
    redis: { ...DEFAULT_CONFIG_VALUES.redis },
    tomcat: { ...DEFAULT_CONFIG_VALUES.tomcat },
  };
}

export function createConfigEditorState(): ConfigEditorState {
  return {
    selectedProduct: null,
    selectedSubject: null,
    query: "",
    choices: {},
    enabledFeatures: {
      nginx: [],
      apache: [],
      haproxy: [],
      mysql: [],
      postgresql: [],
      mariadb: [],
      mongodb: [],
      redis: [],
      tomcat: [],
    },
    values: cloneDefaultValues(),
    inputRevisions: createProductRecord(0),
    preview: null,
  };
}

function featureKeysAfterToggle(
  product: ConfigProductKey,
  current: string[],
  featureKey: string,
  enabled: boolean,
): string[] {
  if (product === "apache" && featureKey === "restrict-request-methods" && enabled) {
    const next = [...current];
    if (!next.includes("disable-trace")) next.push("disable-trace");
    if (!next.includes(featureKey)) next.push(featureKey);
    return next;
  }
  if (product === "apache" && featureKey === "disable-trace" && !enabled) {
    return current.filter(
      (key) => key !== "disable-trace" && key !== "restrict-request-methods",
    );
  }
  if (product === "mysql" && featureKey === "binary-log-retention" && enabled) {
    const next = [...current];
    if (!next.includes("binary-logging")) next.push("binary-logging");
    if (!next.includes(featureKey)) next.push(featureKey);
    return next;
  }
  if (product === "mysql" && featureKey === "binary-logging" && !enabled) {
    return current.filter(
      (key) => key !== "binary-logging" && key !== "binary-log-retention",
    );
  }
  if (
    product === "mariadb" &&
    enabled &&
    (featureKey === "binary-log-retention" || featureKey === "binary-log-durability")
  ) {
    const next = [...current];
    if (!next.includes("binary-logging")) next.push("binary-logging");
    if (!next.includes(featureKey)) next.push(featureKey);
    return next;
  }
  if (product === "mariadb" && featureKey === "binary-logging" && !enabled) {
    return current.filter(
      (key) =>
        key !== "binary-logging" &&
        key !== "binary-log-retention" &&
        key !== "binary-log-durability",
    );
  }
  if (product === "redis" && featureKey === "memory-limit" && !enabled) {
    return current;
  }
  if (
    product === "redis" &&
    !enabled &&
    (featureKey === "aof-persistence" || featureKey === "rdb-persistence")
  ) {
    const otherPersistence =
      featureKey === "aof-persistence" ? "rdb-persistence" : "aof-persistence";
    return current.includes(otherPersistence)
      ? current.filter((key) => key !== featureKey)
      : current;
  }
  if (
    product === "tomcat" &&
    enabled &&
    (featureKey === "allow-safe-methods-only" || featureKey === "deny-all-requests")
  ) {
    const excluded =
      featureKey === "allow-safe-methods-only"
        ? "deny-all-requests"
        : "allow-safe-methods-only";
    const next = current.filter((key) => key !== excluded);
    return next.includes(featureKey) ? next : [...next, featureKey];
  }
  if (enabled) {
    return current.includes(featureKey) ? current : [...current, featureKey];
  }
  return current.filter((key) => key !== featureKey);
}

export function configEditorReducer(
  state: ConfigEditorState,
  action: ConfigEditorAction,
): ConfigEditorState {
  switch (action.type) {
    case "catalog-loaded": {
      const choices: Partial<Record<ConfigProductKey, string>> = {};
      const enabledFeatures = { ...state.enabledFeatures };
      for (const product of action.catalog.products) {
        choices[product.key] = product.defaultChoice;
        enabledFeatures[product.key] = defaultFeatureKeys(product);
      }
      return {
        ...state,
        selectedProduct: action.catalog.products[0]?.key ?? null,
        selectedSubject: null,
        choices,
        enabledFeatures,
        inputRevisions: createProductRecord(0),
        preview: null,
      };
    }
    case "select-product":
      return {
        ...state,
        selectedProduct: action.product,
        selectedSubject: null,
        preview: state.selectedProduct === action.product ? state.preview : null,
      };
    case "set-query":
      return { ...state, query: action.query };
    case "select-search-result":
      return {
        ...state,
        selectedProduct: action.subject.product,
        selectedSubject: { ...action.subject },
        preview: state.selectedProduct === action.subject.product ? state.preview : null,
      };
    case "set-choice": {
      const supported = new Set(action.supportedFeatureKeys);
      const nextFeatures = state.enabledFeatures[action.product].filter((key) => supported.has(key));
      const resetReservedConnections =
        action.product === "postgresql" &&
        (action.choice === "14" || action.choice === "15") &&
        state.values.postgresql.reservedConnections !== "0";
      const nextValues = resetReservedConnections
        ? {
            ...state.values,
            postgresql: { ...state.values.postgresql, reservedConnections: "0" },
          }
        : state.values;
      const inputsChanged =
        state.choices[action.product] !== action.choice ||
        nextFeatures.length !== state.enabledFeatures[action.product].length ||
        resetReservedConnections;
      const selectedSubject =
        state.selectedSubject?.product === action.product &&
        !supported.has(state.selectedSubject.featureKey)
          ? null
          : state.selectedSubject;
      return {
        ...state,
        selectedSubject,
        choices: { ...state.choices, [action.product]: action.choice },
        enabledFeatures: {
          ...state.enabledFeatures,
          [action.product]: nextFeatures,
        },
        values: nextValues,
        inputRevisions: inputsChanged
          ? nextInputRevisions(state, action.product)
          : state.inputRevisions,
        preview: inputsChanged
          ? previewAfterProductMutation(state, action.product)
          : state.preview,
      };
    }
    case "set-feature": {
      const current = state.enabledFeatures[action.product];
      const next = featureKeysAfterToggle(
        action.product,
        current,
        action.featureKey,
        action.enabled,
      );
      const membershipChanged =
        current.length !== next.length || current.some((key, index) => key !== next[index]);
      return {
        ...state,
        selectedSubject: action.enabled
          ? { product: action.product, featureKey: action.featureKey }
          : state.selectedSubject?.product === action.product &&
              !next.includes(state.selectedSubject.featureKey)
            ? null
            : state.selectedSubject,
        enabledFeatures: { ...state.enabledFeatures, [action.product]: next },
        inputRevisions: membershipChanged
          ? nextInputRevisions(state, action.product)
          : state.inputRevisions,
        preview: membershipChanged
          ? previewAfterProductMutation(state, action.product)
          : state.preview,
      };
    }
    case "set-value": {
      const current = state.values[action.product] as unknown as Record<string, string>;
      if (!(action.key in current)) return state;
      if (current[action.key] === action.value) return state;
      return {
        ...state,
        values: {
          ...state.values,
          [action.product]: { ...current, [action.key]: action.value },
        } as ConfigValuesByProduct,
        inputRevisions: nextInputRevisions(state, action.product),
        preview: previewAfterProductMutation(state, action.product),
      };
    }
    case "reset-product": {
      const product = action.product.key;
      const defaults = cloneDefaultValues();
      return {
        ...state,
        selectedSubject:
          state.selectedSubject?.product === product ? null : state.selectedSubject,
        choices: { ...state.choices, [product]: action.product.defaultChoice },
        enabledFeatures: {
          ...state.enabledFeatures,
          [product]: defaultFeatureKeys(action.product),
        },
        values: { ...state.values, [product]: defaults[product] } as ConfigValuesByProduct,
        inputRevisions: nextInputRevisions(state, product),
        preview: previewAfterProductMutation(state, product),
      };
    }
    case "preview-generated":
      if (
        state.selectedProduct !== action.product ||
        state.inputRevisions[action.product] !== action.inputRevision
      ) {
        return state;
      }
      return {
        ...state,
        preview: { product: action.product, inputRevision: action.inputRevision },
      };
    case "clear-preview":
      return state.preview === null ? state : { ...state, preview: null };
  }
}

export function isConfigPreviewCurrent(
  state: ConfigEditorState,
  draftProduct: ConfigProductKey | null | undefined,
): boolean {
  if (draftProduct === null || draftProduct === undefined) return false;
  return (
    state.selectedProduct === draftProduct &&
    state.preview?.product === draftProduct &&
    state.preview.inputRevision === state.inputRevisions[draftProduct]
  );
}

export function selectConfigReadOnlyArtifactStatus(
  statuses: readonly ConfigReadOnlyArtifactStatus[],
  selectedArtifactKey: string | null,
): ConfigReadOnlyArtifactStatus | null {
  if (selectedArtifactKey === null) return statuses[0] ?? null;
  return statuses.find((status) => status.artifactKey === selectedArtifactKey) ?? null;
}

export function searchConfigCatalog(catalog: ConfigCatalog, rawQuery: string): ConfigSearchResult[] {
  const query = rawQuery.trim().toLocaleLowerCase();
  if (query.length === 0) return [];
  const terms = query.split(/\s+/u);
  const matches: ConfigSearchResult[] = [];
  for (const product of catalog.products) {
    for (const feature of product.features) {
      const searchable = [
        product.title,
        product.family,
        feature.title,
        feature.summary,
        feature.scope,
        feature.key,
        ...feature.aliases,
      ]
        .join("\n")
        .toLocaleLowerCase();
      if (terms.every((term) => searchable.includes(term))) {
        matches.push({
          id: `${product.key}:${feature.key}`,
          product: product.key,
          featureKey: feature.key,
          productTitle: product.title,
          title: feature.title,
          summary: feature.summary,
        });
        if (matches.length === 50) return matches;
      }
    }
  }
  return matches;
}

export function selectVisibleConfigFeatures(
  product: ConfigProduct,
  searchResults: readonly ConfigSearchResult[],
  rawQuery: string,
): ConfigFeature[] {
  if (rawQuery.trim().length === 0) return product.features;
  const visibleKeys = new Set(
    searchResults
      .filter((result) => result.product === product.key)
      .map((result) => result.featureKey),
  );
  return product.features.filter((feature) => visibleKeys.has(feature.key));
}

function testIdToken(value: string): string {
  return value
    .toLocaleLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
}

export function getConfigChoiceTestId(product: ConfigProduct): (choiceKey: string) => string {
  return (choiceKey) =>
    `config-${product.choiceKind}-${product.key}-${testIdToken(choiceKey)}`;
}

export function buildConfigGenerateInput(state: ConfigEditorState): ConfigGenerateInput | null {
  const product = state.selectedProduct;
  if (product === null) return null;
  const choice = state.choices[product];
  if (choice === undefined) return null;
  const features = state.enabledFeatures[product];
  switch (product) {
    case "nginx":
      return { product, choice, features, values: state.values.nginx };
    case "apache":
      return { product, choice, features, values: state.values.apache };
    case "haproxy":
      return { product, choice, features, values: state.values.haproxy };
    case "mysql":
      return { product, choice, features, values: state.values.mysql };
    case "postgresql":
      return { product, choice, features, values: state.values.postgresql };
    case "mariadb":
      return { product, choice, features, values: state.values.mariadb };
    case "mongodb":
      return { product, choice, features, values: state.values.mongodb };
    case "redis":
      return { product, choice, features, values: state.values.redis };
    case "tomcat":
      return { product, choice, features, values: state.values.tomcat };
  }
}
