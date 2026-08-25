export type ConfigProductKey =
  | "nginx"
  | "apache"
  | "haproxy"
  | "mysql"
  | "postgresql"
  | "mariadb"
  | "mongodb"
  | "redis"
  | "tomcat";

export interface ConfigChoice {
  key: string;
  label: string;
  detail: string;
  isDefault: boolean;
}

export interface ConfigFeature {
  key: string;
  title: string;
  summary: string;
  scope: string;
  defaultEnabled: boolean;
  aliases: string[];
  supportedChoices: string[];
}

export interface ConfigArtifactDescriptor {
  key: string;
  relativePath: string;
  title: string;
}

export interface ConfigProduct {
  key: ConfigProductKey;
  title: string;
  family: string;
  choiceKind: "mode" | "version";
  defaultChoice: string;
  choices: ConfigChoice[];
  features: ConfigFeature[];
  artifacts: ConfigArtifactDescriptor[];
  scopeNotice: string;
}

export type ConfigReadOnlyReason =
  | "generated-artifact"
  | "vendor-schema-required"
  | "read-only-policy";

const YASHANDB_EXACT_SCHEMA_NOTICE = "只读展示：仅公开 schema 元数据；精确 build 23.5.4.100；文档族 official-doc-family-23.5.4.100；完整性 Partial。该元数据只用于显示，绝不会写入目标内容、本地草稿或另存文件，也不授予修改权限。";

export interface ConfigReadOnlyArtifactStatus {
  artifactKey: string;
  productKey: string;
  productTitle: string;
  title: string;
  authority: "read-only";
  reason: ConfigReadOnlyReason;
  notice: string;
}

export interface ConfigCatalog {
  schema: "lovelyres-config-catalog/v2";
  products: ConfigProduct[];
  readOnlyArtifacts: ConfigReadOnlyArtifactStatus[];
}

export interface NginxConfigValues {
  serverName: string;
  listenPort: string;
  staticRoot: string;
  upstream: string;
  forbiddenPath: string;
  forbiddenScope: string;
  allowedSource: string;
}

export interface ApacheConfigValues extends NginxConfigValues {}

export interface HaProxyConfigValues {
  listenAddress: string;
  listenPort: string;
  upstream: string;
  forbiddenPath: string;
  forbiddenScope: string;
  allowedSource: string;
}

export interface MySqlConfigValues {
  remoteListener: string;
  maxConnections: string;
  connectTimeout: string;
  maxConnectErrors: string;
  waitTimeout: string;
  interactiveTimeout: string;
  longQueryTime: string;
  logErrorVerbosity: string;
  serverId: string;
  binlogRetention: string;
}

export interface PostgreSqlConfigValues {
  port: string;
  maxConnections: string;
  superuserReservedConnections: string;
  reservedConnections: string;
  authenticationTimeout: string;
  idleInTransactionTimeout: string;
  idleSessionTimeout: string;
  temporaryFileLimit: string;
  lockWaitThreshold: string;
  autovacuumLogThreshold: string;
  temporaryFileLogThreshold: string;
  walCompression: string;
}

export interface MariaDbConfigValues {
  port: string;
  maxConnections: string;
  connectTimeout: string;
  waitTimeout: string;
  interactiveTimeout: string;
  maxConnectErrors: string;
  maxAllowedPacket: string;
  slowQueryTime: string;
  serverId: string;
  binlogRetention: string;
  innodbLockWaitTimeout: string;
  characterProfile: string;
}

export interface MongoDbConfigValues {
  port: string;
  maxConnections: string;
  slowOperationThreshold: string;
  slowOperationSampleRate: string;
  slowInProgressThreshold: string;
  logPath: string;
  logRotationMode: string;
  wiredTigerCacheGib: string;
  collectionCompressor: string;
  journalCompressor: string;
}

export interface RedisConfigValues {
  bindProfile: string;
  dataDirectory: string;
  port: string;
  maxClients: string;
  idleTimeout: string;
  tcpKeepalive: string;
  maxmemoryMib: string;
  evictionPolicy: string;
  appendFsync: string;
  slowlogThreshold: string;
  slowlogLength: string;
  latencyThreshold: string;
}

export interface TomcatConfigValues {
  connectorAddress: string;
  applicationName: string;
  port: string;
  connectionTimeout: string;
  maxThreads: string;
  acceptCount: string;
  maxConnections: string;
  maxPostSize: string;
  maxSwallowSize: string;
  compressionMinSize: string;
}

type ConfigGenerateBase<P extends ConfigProductKey, V> = {
  product: P;
  choice: string;
  features: string[];
  values: V;
};

export type ConfigGenerateInput =
  | ConfigGenerateBase<"nginx", NginxConfigValues>
  | ConfigGenerateBase<"apache", ApacheConfigValues>
  | ConfigGenerateBase<"haproxy", HaProxyConfigValues>
  | ConfigGenerateBase<"mysql", MySqlConfigValues>
  | ConfigGenerateBase<"postgresql", PostgreSqlConfigValues>
  | ConfigGenerateBase<"mariadb", MariaDbConfigValues>
  | ConfigGenerateBase<"mongodb", MongoDbConfigValues>
  | ConfigGenerateBase<"redis", RedisConfigValues>
  | ConfigGenerateBase<"tomcat", TomcatConfigValues>;

export interface ConfigDraftArtifact {
  key: string;
  relativePath: string;
  mediaType: "text/plain" | "application/xml" | "application/yaml";
  byteLength: number;
  preview: string;
  previewTruncated: boolean;
  copyAllowed: boolean;
}

export interface ConfigDraft {
  handle: string;
  revision: number;
  product: ConfigProductKey;
  choice: string;
  suggestedName: string;
  totalBytes: number;
  copyAllowed: boolean;
  artifacts: ConfigDraftArtifact[];
  notices: string[];
}

export interface ConfigClipboardResult {
  artifactCount: number;
  byteLength: number;
}

export interface ConfigExportResult {
  saved: boolean;
  fileName: string | null;
}

export interface ConfigClosedResult {
  closed: true;
}

export interface InternalConfigCopy {
  revision: number;
  artifacts: Array<{ key: string; contents: string }>;
}

export interface InternalConfigArtifact {
  suggestedName: string;
  contents: string;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const products: readonly ConfigProductKey[] = [
  "nginx", "apache", "haproxy", "mysql", "postgresql", "mariadb", "mongodb", "redis", "tomcat",
];

const valueKeys: Record<ConfigProductKey, readonly string[]> = {
  nginx: ["serverName", "listenPort", "staticRoot", "upstream", "forbiddenPath", "forbiddenScope", "allowedSource"],
  apache: ["serverName", "listenPort", "staticRoot", "upstream", "forbiddenPath", "forbiddenScope", "allowedSource"],
  haproxy: ["listenAddress", "listenPort", "upstream", "forbiddenPath", "forbiddenScope", "allowedSource"],
  mysql: ["remoteListener", "maxConnections", "connectTimeout", "maxConnectErrors", "waitTimeout", "interactiveTimeout", "longQueryTime", "logErrorVerbosity", "serverId", "binlogRetention"],
  postgresql: ["port", "maxConnections", "superuserReservedConnections", "reservedConnections", "authenticationTimeout", "idleInTransactionTimeout", "idleSessionTimeout", "temporaryFileLimit", "lockWaitThreshold", "autovacuumLogThreshold", "temporaryFileLogThreshold", "walCompression"],
  mariadb: ["port", "maxConnections", "connectTimeout", "waitTimeout", "interactiveTimeout", "maxConnectErrors", "maxAllowedPacket", "slowQueryTime", "serverId", "binlogRetention", "innodbLockWaitTimeout", "characterProfile"],
  mongodb: ["port", "maxConnections", "slowOperationThreshold", "slowOperationSampleRate", "slowInProgressThreshold", "logPath", "logRotationMode", "wiredTigerCacheGib", "collectionCompressor", "journalCompressor"],
  redis: ["bindProfile", "dataDirectory", "port", "maxClients", "idleTimeout", "tcpKeepalive", "maxmemoryMib", "evictionPolicy", "appendFsync", "slowlogThreshold", "slowlogLength", "latencyThreshold"],
  tomcat: ["connectorAddress", "applicationName", "port", "connectionTimeout", "maxThreads", "acceptCount", "maxConnections", "maxPostSize", "maxSwallowSize", "compressionMinSize"],
};

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function bounded(value: unknown, maximum: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) && encoder.encode(value).byteLength <= maximum;
}

function identifier(value: unknown): value is string {
  return bounded(value, 128) && /^[A-Za-z0-9._-]+$/u.test(value);
}

function safeInteger(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function relativePath(value: unknown): value is string {
  return (
    bounded(value, 512) &&
    !value.startsWith("/") &&
    !value.startsWith("\\") &&
    !value.includes("\\") &&
    value.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}

export function isConfigGenerateInput(value: unknown): value is ConfigGenerateInput {
  if (!isRecord(value) || !exact(value, ["product", "choice", "features", "values"])) return false;
  if (typeof value.product !== "string" || !products.includes(value.product as ConfigProductKey)) return false;
  if (!bounded(value.choice, 32)) return false;
  if (
    !Array.isArray(value.features) ||
    value.features.length > 32 ||
    !value.features.every(identifier) ||
    new Set(value.features).size !== value.features.length
  ) return false;
  const features = value.features as string[];
  if (
    value.product === "apache" &&
    features.includes("restrict-request-methods") &&
    !features.includes("disable-trace")
  ) return false;
  if (
    value.product === "mysql" &&
    features.includes("binary-log-retention") &&
    !features.includes("binary-logging")
  ) return false;
  if (
    value.product === "mariadb" &&
    (features.includes("binary-log-retention") ||
      features.includes("binary-log-durability")) &&
    !features.includes("binary-logging")
  ) return false;
  if (
    value.product === "redis" &&
    (!features.includes("memory-limit") ||
      (!features.includes("aof-persistence") && !features.includes("rdb-persistence")))
  ) return false;
  if (
    value.product === "tomcat" &&
    features.includes("allow-safe-methods-only") &&
    features.includes("deny-all-requests")
  ) return false;
  if (!isRecord(value.values)) return false;
  const values = value.values;
  const keys = valueKeys[value.product as ConfigProductKey];
  if (!exact(values, keys) || !keys.every((key) => bounded(values[key], 4_096, true))) return false;
  if (
    value.product === "postgresql" &&
    (value.choice === "14" || value.choice === "15") &&
    values.reservedConnections !== "0"
  ) return false;
  return true;
}

function isChoice(value: unknown): value is ConfigChoice {
  return isRecord(value) && exact(value, ["key", "label", "detail", "isDefault"]) && bounded(value.key, 64) && bounded(value.label, 256) && bounded(value.detail, 4_096, true) && typeof value.isDefault === "boolean";
}

function isFeature(value: unknown): value is ConfigFeature {
  return isRecord(value) && exact(value, ["key", "title", "summary", "scope", "defaultEnabled", "aliases", "supportedChoices"]) && identifier(value.key) && bounded(value.title, 512) && bounded(value.summary, 8_192) && bounded(value.scope, 128) && typeof value.defaultEnabled === "boolean" && Array.isArray(value.aliases) && value.aliases.length <= 32 && value.aliases.every((item) => bounded(item, 256)) && Array.isArray(value.supportedChoices) && value.supportedChoices.length > 0 && value.supportedChoices.length <= 16 && value.supportedChoices.every((item) => bounded(item, 64));
}

function isArtifactDescriptor(value: unknown): value is ConfigArtifactDescriptor {
  return isRecord(value) && exact(value, ["key", "relativePath", "title"]) && identifier(value.key) && relativePath(value.relativePath) && bounded(value.title, 512);
}

function isProduct(value: unknown): value is ConfigProduct {
  if (!isRecord(value) || !exact(value, ["key", "title", "family", "choiceKind", "defaultChoice", "choices", "features", "artifacts", "scopeNotice"])) return false;
  if (typeof value.key !== "string" || !products.includes(value.key as ConfigProductKey) || !bounded(value.title, 256) || !identifier(value.family) || (value.choiceKind !== "mode" && value.choiceKind !== "version") || !bounded(value.defaultChoice, 64) || !Array.isArray(value.choices) || value.choices.length === 0 || value.choices.length > 16 || !value.choices.every(isChoice) || !Array.isArray(value.features) || value.features.length > 32 || !value.features.every(isFeature) || !Array.isArray(value.artifacts) || value.artifacts.length === 0 || value.artifacts.length > 3 || !value.artifacts.every(isArtifactDescriptor) || !bounded(value.scopeNotice, 8_192)) return false;
  const choices = new Set(value.choices.map((choice) => choice.key));
  return choices.has(value.defaultChoice) && value.features.every((feature) => feature.supportedChoices.every((choice) => choices.has(choice)));
}

function isReadOnlyArtifactStatus(value: unknown): value is ConfigReadOnlyArtifactStatus {
  if (!(
    isRecord(value) &&
    exact(value, ["artifactKey", "productKey", "productTitle", "title", "authority", "reason", "notice"]) &&
    identifier(value.artifactKey) &&
    identifier(value.productKey) &&
    bounded(value.productTitle, 256) &&
    bounded(value.title, 512) &&
    value.authority === "read-only" &&
    (value.reason === "generated-artifact" ||
      value.reason === "vendor-schema-required" ||
      value.reason === "read-only-policy") &&
    bounded(value.notice, 8_192)
  )) return false;
  if (value.artifactKey !== "yashandb-yasdb-ini") return true;
  return (
    value.productKey === "yashandb" &&
    value.productTitle === "崖山数据库" &&
    value.title === "yasdb.ini" &&
    value.reason === "vendor-schema-required" &&
    value.notice === YASHANDB_EXACT_SCHEMA_NOTICE
  );
}

export function isConfigCatalog(value: unknown): value is ConfigCatalog {
  if (!isRecord(value) || !exact(value, ["schema", "products", "readOnlyArtifacts"]) || value.schema !== "lovelyres-config-catalog/v2" || !Array.isArray(value.products) || value.products.length !== 9 || !value.products.every(isProduct) || !Array.isArray(value.readOnlyArtifacts) || value.readOnlyArtifacts.length === 0 || value.readOnlyArtifacts.length > 256 || !value.readOnlyArtifacts.every(isReadOnlyArtifactStatus)) return false;
  const readOnlyReasons = new Set(value.readOnlyArtifacts.map((artifact) => artifact.reason));
  return new Set(value.products.map((product) => product.key)).size === 9 && value.products.reduce((count, product) => count + product.features.length, 0) === 137 && new Set(value.readOnlyArtifacts.map((artifact) => artifact.artifactKey)).size === value.readOnlyArtifacts.length && readOnlyReasons.has("generated-artifact") && readOnlyReasons.has("vendor-schema-required");
}

function isDraftArtifact(value: unknown): value is ConfigDraftArtifact {
  return isRecord(value) && exact(value, ["key", "relativePath", "mediaType", "byteLength", "preview", "previewTruncated", "copyAllowed"]) && identifier(value.key) && relativePath(value.relativePath) && (value.mediaType === "text/plain" || value.mediaType === "application/xml" || value.mediaType === "application/yaml") && safeInteger(value.byteLength, 512 * 1_024) && bounded(value.preview, 32 * 1_024, true) && typeof value.previewTruncated === "boolean" && typeof value.copyAllowed === "boolean";
}

export function isConfigDraft(value: unknown): value is ConfigDraft {
  if (!isRecord(value) || !exact(value, ["handle", "revision", "product", "choice", "suggestedName", "totalBytes", "copyAllowed", "artifacts", "notices"])) return false;
  if (!(identifier(value.handle) && safeInteger(value.revision, Number.MAX_SAFE_INTEGER) && value.revision > 0 && typeof value.product === "string" && products.includes(value.product as ConfigProductKey) && bounded(value.choice, 64) && relativePath(value.suggestedName) && safeInteger(value.totalBytes, 512 * 1_024) && typeof value.copyAllowed === "boolean" && Array.isArray(value.artifacts) && value.artifacts.length > 0 && value.artifacts.length <= 3 && value.artifacts.every(isDraftArtifact) && value.artifacts.reduce((total, item) => total + item.byteLength, 0) === value.totalBytes && Array.isArray(value.notices) && value.notices.length <= 16 && value.notices.every((notice) => bounded(notice, 8_192)))) return false;
  const artifacts = value.artifacts as ConfigDraftArtifact[];
  if (new Set(artifacts.map((artifact) => artifact.key)).size !== artifacts.length ||
      new Set(artifacts.map((artifact) => artifact.relativePath)).size !== artifacts.length) return false;
  if (value.product !== "tomcat") return true;
  const expected = [
    ["server.xml", "conf/server.xml"],
    ["context.xml", "webapps/ROOT/META-INF/context.xml"],
    ["web.xml", "webapps/ROOT/WEB-INF/web.xml"],
  ] as const;
  return artifacts.length === expected.length && artifacts.every((artifact, index) =>
    artifact.key === expected[index]?.[0] &&
    artifact.relativePath === expected[index]?.[1] &&
    artifact.mediaType === "application/xml"
  );
}

export function isInternalConfigCopy(value: unknown): value is InternalConfigCopy {
  if (!isRecord(value) || !exact(value, ["revision", "artifacts"]) || !safeInteger(value.revision, Number.MAX_SAFE_INTEGER) || !Array.isArray(value.artifacts) || value.artifacts.length === 0 || value.artifacts.length > 3) return false;
  let total = 0;
  const keys = new Set<string>();
  for (const item of value.artifacts) {
    if (!isRecord(item) || !exact(item, ["key", "contents"]) || !identifier(item.key) || !bounded(item.contents, 256 * 1_024, true)) return false;
    if (!keys.add(item.key)) return false;
    total += encoder.encode(item.contents).byteLength;
    if (total > 256 * 1_024) return false;
  }
  if (value.artifacts.length === 3 &&
      value.artifacts.some((item, index) => item.key !== ["server.xml", "context.xml", "web.xml"][index])) return false;
  return true;
}

export function isInternalConfigArtifact(value: unknown): value is InternalConfigArtifact {
  return isRecord(value) && exact(value, ["suggestedName", "contents"]) && relativePath(value.suggestedName) && bounded(value.contents, 512 * 1_024, true);
}

export function isConfigClosedResult(value: unknown): value is ConfigClosedResult {
  return isRecord(value) && exact(value, ["closed"]) && value.closed === true;
}

export function isConfigClipboardResult(value: unknown): value is ConfigClipboardResult {
  return isRecord(value) && exact(value, ["artifactCount", "byteLength"]) && safeInteger(value.artifactCount, 3) && value.artifactCount > 0 && safeInteger(value.byteLength, 256 * 1_024);
}

export function isConfigExportResult(value: unknown): value is ConfigExportResult {
  return isRecord(value) && exact(value, ["saved", "fileName"]) && typeof value.saved === "boolean" && (value.fileName === null || relativePath(value.fileName)) && (value.saved ? value.fileName !== null : value.fileName === null);
}
