import {
  Fragment,
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";

import type {
  ConfigCatalog,
  ConfigDraft,
  ConfigDraftArtifact,
  ConfigFeature,
  ConfigProductKey,
  ConfigReadOnlyArtifactStatus,
} from "../shared/config-contract";
import { isConfigCatalog, isConfigGenerateInput } from "../shared/config-contract";
import { isConfigVisualProduct } from "../shared/config-visual-contract";
import { ConfigArtifactNotes } from "./ConfigArtifactNotes";
import { ConfigGoalResults, type ConfigGoalOpenVisual } from "./ConfigGoalPanel";
import type { LovelyHawkApi } from "../shared/contract";
import {
  CONFIG_VALUE_FIELDS,
  ConfigRequestLifecycle,
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
  releaseLateConfigDraft,
  searchConfigCatalog,
  selectConfigReadOnlyArtifactStatus,
  selectVisibleConfigFeatures,
  type ConfigEditorAction,
  type ConfigSearchSubject,
} from "./config-generator-state";
import "./config-generator.css";

export type ConfigGeneratorApi = Pick<
  LovelyHawkApi,
  | "getConfigCatalog"
  | "generateConfig"
  | "reviseConfig"
  | "copyConfig"
  | "exportConfigArtifact"
  | "exportConfigBundle"
  | "closeConfigDraft"
  | "configVisual"
>;

interface ConfigGeneratorPageProps {
  api?: ConfigGeneratorApi;
  /** Set when the configuration workbench already carries the page title. */
  embedded?: boolean;
  /** The switch between checking a host and generating a configuration. */
  modeSwitch?: ReactNode;
  /** Opens the current Nginx draft as a tree in the visual editor. */
  onOpenVisual?: ((source: { handle: string; revision: number; artifactKey: string }) => Promise<void>) | undefined;
  /** Opens a database file the goal search found, or a value it wrote, in the visual editor. */
  onOpenVisualView?: ConfigGoalOpenVisual | undefined;
}

export interface ConfigGeneratorPageHandle {
  beforeDeactivate(): Promise<boolean>;
}

interface Notice {
  tone: "error" | "info";
  message: string;
}

export function ConfigArtifactPreview({ artifact }: { artifact: ConfigDraftArtifact }) {
  return (
    <>
      <div data-config-preview-truncated={artifact.previewTruncated ? "true" : "false"}>
        <span>{artifact.mediaType} · {artifact.byteLength} 字节</span>
        {artifact.previewTruncated ? <em>预览已截断</em> : null}
      </div>
      <pre data-testid="config-artifact-preview-text">{artifact.preview}</pre>
    </>
  );
}

type ConfigFeatureIntent = Extract<ConfigEditorAction, { type: "set-feature" }>;
type ConfigValueIntent = Extract<ConfigEditorAction, { type: "set-value" }>;

interface ConfigFeatureToggleProps {
  product: ConfigProductKey;
  featureKey: string;
  checked: boolean;
  disabled: boolean;
  "data-testid"?: string;
  onIntent(intent: ConfigFeatureIntent): void;
}

export function ConfigFeatureToggle({
  product,
  featureKey,
  checked,
  disabled,
  "data-testid": testId = `config-feature-${product}-${featureKey}`,
  onIntent,
}: ConfigFeatureToggleProps) {
  return (
    <input
      type="checkbox"
      checked={checked}
      disabled={disabled}
      data-testid={testId}
      onChange={(event) => onIntent({
        type: "set-feature",
        product,
        featureKey,
        enabled: event.currentTarget.checked,
      })}
    />
  );
}

interface MySqlMaxConnectionsInputProps {
  value: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function MySqlMaxConnectionsInput({
  value,
  enabled,
  onIntent,
}: MySqlMaxConnectionsInputProps) {
  return (
    <input
      id="config-inline-value-mysql-maxConnections"
      data-testid="config-inline-value-mysql-maxConnections"
      value={value}
      disabled={!enabled}
      inputMode="decimal"
      maxLength={6}
      spellCheck={false}
      onChange={(event) => onIntent({
        type: "set-value",
        product: "mysql",
        key: "maxConnections",
        value: event.currentTarget.value,
      })}
    />
  );
}

interface NginxForbiddenPathInlineEditorProps {
  path: string;
  scope: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

/**
 * The 403 rule's two values right under its row: which path, and whether
 * the paths under it are refused too. The same values as the product
 * parameters below, shown where the rule is being chosen.
 */
export function NginxForbiddenPathInlineEditor({ path, scope, enabled, onIntent }: NginxForbiddenPathInlineEditorProps) {
  const scopeOptions = CONFIG_VALUE_FIELDS.nginx.find((field) => field.key === "forbiddenScope")?.options ?? [];
  const pathRefused = enabled && !isNginxForbiddenPath(path);
  return (
    <section
      className="config-feature-inline-editor config-inline-numeric-editor config-inline-path-editor"
      data-testid="config-feature-inline-editor-nginx-forbidden-path-403"
      aria-label="配置：禁止指定路径（HTTP 403）"
    >
      <header>
        <strong>配置：禁止指定路径（HTTP 403）</strong>
        <span>{enabled ? "已添加" : "尚未添加"}</span>
      </header>
      <label htmlFor="config-inline-value-nginx-forbiddenPath">
        <span>禁止路径</span>
        <input
          id="config-inline-value-nginx-forbiddenPath"
          data-testid="config-inline-value-nginx-forbiddenPath"
          value={path}
          disabled={!enabled}
          maxLength={512}
          spellCheck={false}
          aria-invalid={pathRefused}
          aria-describedby="config-inline-value-nginx-forbiddenPath-hint"
          onChange={(event) => onIntent({ type: "set-value", product: "nginx", key: "forbiddenPath", value: event.currentTarget.value })}
        />
        <small id="config-inline-value-nginx-forbiddenPath-hint" className={pathRefused ? "is-invalid" : undefined}>
          {pathRefused
            ? "这个路径生成时会被拒绝：需以 / 开头、不以 / 结尾、不含空段或 . ..，只能用字母、数字和 - _ . ~。"
            : "以 / 开头，例如 /admin；只能用字母、数字和 - _ . ~。"}
        </small>
      </label>
      <label htmlFor="config-inline-value-nginx-forbiddenScope">
        <span>禁止范围</span>
        <select
          id="config-inline-value-nginx-forbiddenScope"
          data-testid="config-inline-value-nginx-forbiddenScope"
          value={scope}
          disabled={!enabled}
          onChange={(event) => onIntent({ type: "set-value", product: "nginx", key: "forbiddenScope", value: event.currentTarget.value })}
        >
          {scopeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </label>
    </section>
  );
}

type MySqlMaxConnectionsInlineEditorProps = MySqlMaxConnectionsInputProps;

export function MySqlMaxConnectionsInlineEditor({
  value,
  enabled,
  onIntent,
}: MySqlMaxConnectionsInlineEditorProps) {
  return (
    <section
      className="config-feature-inline-editor config-inline-numeric-editor config-mysql-max-connections-editor"
      data-testid="config-feature-inline-editor-mysql-max-connections"
      aria-label="配置：限制最大连接数"
    >
      <header>
        <strong>配置：限制最大连接数</strong>
        <span>{enabled ? "已添加" : "尚未添加"}</span>
      </header>
      <label htmlFor="config-inline-value-mysql-maxConnections">
        <span>最大连接数</span>
        <MySqlMaxConnectionsInput value={value} enabled={enabled} onIntent={onIntent} />
        <small>允许范围 1 - 100000；生成 max_connections。</small>
      </label>
    </section>
  );
}

interface PostgreSqlLockWaitInputProps {
  value: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function PostgreSqlLockWaitInput({
  value,
  enabled,
  onIntent,
}: PostgreSqlLockWaitInputProps) {
  return (
    <input
      id="config-inline-value-postgresql-lockWaitThreshold"
      data-testid="config-inline-value-postgresql-lockWaitThreshold"
      value={value}
      disabled={!enabled}
      inputMode="decimal"
      maxLength={7}
      spellCheck={false}
      onChange={(event) => onIntent({
        type: "set-value",
        product: "postgresql",
        key: "lockWaitThreshold",
        value: event.currentTarget.value,
      })}
    />
  );
}

export function PostgreSqlLockWaitInlineEditor({
  value,
  enabled,
  onIntent,
}: PostgreSqlLockWaitInputProps) {
  return (
    <section
      className="config-feature-inline-editor config-inline-numeric-editor"
      data-testid="config-feature-inline-editor-postgresql-lock-wait-logging"
      aria-label="配置：按明确阈值记录锁等待"
    >
      <header>
        <strong>配置：按明确阈值记录锁等待</strong>
        <span>{enabled ? "已添加" : "尚未添加"}</span>
      </header>
      <label htmlFor="config-inline-value-postgresql-lockWaitThreshold">
        <span>deadlock_timeout / log_lock_waits（毫秒）</span>
        <PostgreSqlLockWaitInput value={value} enabled={enabled} onIntent={onIntent} />
        <small>允许范围 1 - 3600000；成组生成 deadlock_timeout 与 log_lock_waits。</small>
      </label>
    </section>
  );
}

interface MariaDbBinaryLogRetentionInputProps {
  value: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function MariaDbBinaryLogRetentionInput({
  value,
  enabled,
  onIntent,
}: MariaDbBinaryLogRetentionInputProps) {
  return (
    <input
      id="config-inline-value-mariadb-binlogRetention"
      data-testid="config-inline-value-mariadb-binlogRetention"
      value={value}
      disabled={!enabled}
      inputMode="decimal"
      maxLength={7}
      spellCheck={false}
      onChange={(event) => onIntent({
        type: "set-value",
        product: "mariadb",
        key: "binlogRetention",
        value: event.currentTarget.value,
      })}
    />
  );
}

export function MariaDbBinaryLogRetentionInlineEditor({
  value,
  enabled,
  onIntent,
}: MariaDbBinaryLogRetentionInputProps) {
  return (
    <section
      className="config-feature-inline-editor config-inline-numeric-editor"
      data-testid="config-feature-inline-editor-mariadb-binary-log-retention"
      aria-label="配置：设置二进制日志保留时间"
    >
      <header>
        <strong>配置：设置二进制日志保留时间</strong>
        <span>{enabled ? "已添加" : "尚未添加"}</span>
      </header>
      <label htmlFor="config-inline-value-mariadb-binlogRetention">
        <span>binlog_expire_logs_seconds</span>
        <MariaDbBinaryLogRetentionInput value={value} enabled={enabled} onIntent={onIntent} />
        <small>允许范围 1 - 8553600；启用时同时加入 BinaryLogging 依赖。</small>
      </label>
    </section>
  );
}

type RedisSlowLogValueKey = "slowlogThreshold" | "slowlogLength";

interface RedisSlowLogValueInputProps {
  valueKey: RedisSlowLogValueKey;
  value: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function RedisSlowLogValueInput({
  valueKey,
  value,
  enabled,
  onIntent,
}: RedisSlowLogValueInputProps) {
  const inputId = `config-inline-value-redis-${valueKey}`;
  return (
    <input
      id={inputId}
      data-testid={inputId}
      value={value}
      disabled={!enabled}
      inputMode="decimal"
      maxLength={11}
      spellCheck={false}
      onChange={(event) => onIntent({
        type: "set-value",
        product: "redis",
        key: valueKey,
        value: event.currentTarget.value,
      })}
    />
  );
}

interface RedisSlowLogInlineEditorProps {
  threshold: string;
  length: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function RedisSlowLogInlineEditor({
  threshold,
  length,
  enabled,
  onIntent,
}: RedisSlowLogInlineEditorProps) {
  return (
    <section
      className="config-feature-inline-editor config-inline-numeric-editor"
      data-testid="config-feature-inline-editor-redis-slow-log"
      aria-label="配置：记录慢命令"
    >
      <header>
        <strong>配置：记录慢命令</strong>
        <span>{enabled ? "已添加" : "尚未添加"}</span>
      </header>
      <label htmlFor="config-inline-value-redis-slowlogThreshold">
        <span>slowlog-log-slower-than（微秒）</span>
        <RedisSlowLogValueInput
          valueKey="slowlogThreshold"
          value={threshold}
          enabled={enabled}
          onIntent={onIntent}
        />
        <small>允许范围 0 - 86400000000；0 表示记录所有命令。</small>
      </label>
      <label htmlFor="config-inline-value-redis-slowlogLength">
        <span>slowlog-max-len</span>
        <RedisSlowLogValueInput
          valueKey="slowlogLength"
          value={length}
          enabled={enabled}
          onIntent={onIntent}
        />
        <small>允许范围 1 - 1000000。</small>
      </label>
    </section>
  );
}

type TomcatConnectorLimitValueKey =
  | "maxThreads"
  | "acceptCount"
  | "maxConnections"
  | "maxPostSize"
  | "maxSwallowSize";

const TOMCAT_CONNECTOR_LIMIT_FIELDS: readonly {
  key: TomcatConnectorLimitValueKey;
  label: string;
  detail: string;
  maxLength: number;
}[] = [
  { key: "maxThreads", label: "maxThreads", detail: "允许范围 1 - 10000。", maxLength: 5 },
  { key: "acceptCount", label: "acceptCount", detail: "允许范围 1 - 100000。", maxLength: 6 },
  { key: "maxConnections", label: "maxConnections", detail: "允许范围 1 - 1000000。", maxLength: 7 },
  { key: "maxPostSize", label: "maxPostSize", detail: "参数转换字节上限，允许范围 1 - 1073741824。", maxLength: 10 },
  { key: "maxSwallowSize", label: "maxSwallowSize", detail: "中止上传吞咽字节上限，允许范围 1 - 1073741824。", maxLength: 10 },
];

interface TomcatConnectorLimitValueInputProps {
  valueKey: TomcatConnectorLimitValueKey;
  value: string;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function TomcatConnectorLimitValueInput({
  valueKey,
  value,
  enabled,
  onIntent,
}: TomcatConnectorLimitValueInputProps) {
  const field = TOMCAT_CONNECTOR_LIMIT_FIELDS.find((item) => item.key === valueKey)!;
  const inputId = `config-inline-value-tomcat-${valueKey}`;
  return (
    <input
      id={inputId}
      data-testid={inputId}
      value={value}
      disabled={!enabled}
      inputMode="decimal"
      maxLength={field.maxLength}
      spellCheck={false}
      onChange={(event) => onIntent({
        type: "set-value",
        product: "tomcat",
        key: valueKey,
        value: event.currentTarget.value,
      })}
    />
  );
}

interface TomcatConnectorLimitsInlineEditorProps {
  values: Record<TomcatConnectorLimitValueKey, string>;
  enabled: boolean;
  onIntent(intent: ConfigValueIntent): void;
}

export function TomcatConnectorLimitsInlineEditor({
  values,
  enabled,
  onIntent,
}: TomcatConnectorLimitsInlineEditorProps) {
  return (
    <section
      className="config-feature-inline-editor config-inline-numeric-editor"
      data-testid="config-feature-inline-editor-tomcat-connector-limits"
      aria-label="配置：限制 Connector 容量、参数转换与中止上传吞咽量"
    >
      <header>
        <strong>配置：Connector 容量与请求处理边界</strong>
        <span>{enabled ? "已添加" : "尚未添加"}</span>
      </header>
      {TOMCAT_CONNECTOR_LIMIT_FIELDS.map((field) => (
        <label key={field.key} htmlFor={`config-inline-value-tomcat-${field.key}`}>
          <span>{field.label}</span>
          <TomcatConnectorLimitValueInput
            valueKey={field.key}
            value={values[field.key]}
            enabled={enabled}
            onIntent={onIntent}
          />
          <small>{field.detail}</small>
        </label>
      ))}
    </section>
  );
}

interface ConfigFeatureCatalogEntryProps {
  product: ConfigProductKey;
  feature: ConfigFeature;
  checked: boolean;
  supported: boolean;
  selected: boolean;
  inlineEditor?: ReactNode;
  rowRef?(element: HTMLLabelElement | null): void;
  onIntent(intent: ConfigFeatureIntent): void;
}

export function ConfigFeatureCatalogEntry({
  product,
  feature,
  checked,
  supported,
  selected,
  inlineEditor,
  rowRef,
  onIntent,
}: ConfigFeatureCatalogEntryProps) {
  const subjectId = `${product}:${feature.key}`;
  const hasInlineEditor = selected && (product === "apache" || inlineEditor !== undefined);
  return (
    <>
      <label
        className={`${selected ? "selected " : ""}${
          hasInlineEditor ? "inline-editor-anchor " : ""
        }${supported ? "" : "unsupported"}`}
        tabIndex={-1}
        ref={rowRef}
        data-config-subject={subjectId}
        data-testid={`config-feature-row-${product}-${feature.key}`}
      >
        <ConfigFeatureToggle
          product={product}
          featureKey={feature.key}
          checked={checked}
          disabled={!supported}
          data-testid={`config-feature-${product}-${feature.key}`}
          onIntent={onIntent}
        />
        <span>
          <strong>{feature.title}</strong>
          <small>{feature.summary}</small>
          <em>{feature.scope}</em>
        </span>
      </label>
      {selected && inlineEditor !== undefined ? inlineEditor : selected && product === "apache" ? (
        <section
          className="config-feature-inline-editor"
          data-testid={`config-feature-inline-editor-apache-${feature.key}`}
          aria-label={`配置：${feature.title}`}
        >
          <header>
            <strong>配置：{feature.title}</strong>
            <span>{checked ? "已添加" : "尚未添加"}</span>
          </header>
          <p>{feature.summary}</p>
          <small>{feature.scope} · 固定使用已审查模板，无额外自由文本参数。</small>
        </section>
      ) : null}
    </>
  );
}

interface ConfigReadOnlyStatusPanelProps {
  artifacts: readonly ConfigReadOnlyArtifactStatus[];
  selectedArtifactKey: string | null;
  onSelect(artifactKey: string): void;
}

export function ConfigReadOnlyStatusPanel({
  artifacts,
  selectedArtifactKey,
  onSelect,
}: ConfigReadOnlyStatusPanelProps) {
  const selected = selectConfigReadOnlyArtifactStatus(artifacts, selectedArtifactKey);
  if (selected === null) return null;
  const reasonLabel =
    selected.reason === "generated-artifact"
      ? "服务器或工具生成"
      : selected.reason === "vendor-schema-required"
        ? "需要匹配版本的厂商 schema"
        : "目录策略只读";

  return (
    <section className="config-read-only-status" aria-labelledby="config-read-only-status-title">
      <div>
        <h2 id="config-read-only-status-title">数据库只读工件</h2>
        <p>目录响应不携带工件字节；预览、复制、另存、修改、应用和部署均不可用。</p>
      </div>
      <label>
        <span>只读工件</span>
        <select
          value={selected.artifactKey}
          data-testid="config-read-only-artifact-select"
          onChange={(event) => onSelect(event.currentTarget.value)}
        >
          {artifacts.map((artifact) => (
            <option key={artifact.artifactKey} value={artifact.artifactKey}>
              {artifact.productTitle} · {artifact.title}
            </option>
          ))}
        </select>
      </label>
      <div
        className="config-read-only-detail"
        role="status"
        aria-live="polite"
        data-config-read-only-reason={selected.reason}
        data-config-mutation-authority={selected.authority}
      >
        <strong>{selected.productTitle} · {selected.title}</strong>
        <span>{reasonLabel}</span>
        <p>{selected.notice}</p>
      </div>
    </section>
  );
}

function resolveApi(api: ConfigGeneratorApi | undefined): ConfigGeneratorApi {
  return api ?? window.lovelyhawk;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message.trim().length > 0 ? error.message : fallback;
}

export const ConfigGeneratorPage = forwardRef<ConfigGeneratorPageHandle, ConfigGeneratorPageProps>(
function ConfigGeneratorPage({ api, embedded = false, modeSwitch, onOpenVisual, onOpenVisualView }, ref) {
  const configApi = resolveApi(api);
  const [catalog, setCatalog] = useState<ConfigCatalog | null>(null);
  const [editor, dispatch] = useReducer(configEditorReducer, undefined, createConfigEditorState);
  const [draft, setDraft] = useState<ConfigDraft | null>(null);
  const [activeArtifactKey, setActiveArtifactKey] = useState<string | null>(null);
  const [selectedReadOnlyArtifactKey, setSelectedReadOnlyArtifactKey] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<"generate" | "copy" | "export" | "close" | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const featureRefs = useRef(new Map<string, HTMLLabelElement>());
  const artifactTabRefs = useRef(new Map<string, HTMLButtonElement>());
  const requestLifecycleRef = useRef<ConfigRequestLifecycle | null>(null);
  requestLifecycleRef.current ??= new ConfigRequestLifecycle();
  const requestLifecycle = requestLifecycleRef.current;
  const visibleDraft =
    draft !== null && isConfigPreviewCurrent(editor, draft.product) ? draft : null;

  useEffect(() => {
    requestLifecycle.activate();
    return () => requestLifecycle.deactivate();
  }, [configApi, requestLifecycle]);

  useEffect(() => {
    let active = true;
    void configApi
      .getConfigCatalog()
      .then((loaded) => {
        if (!active) return;
        if (!isConfigCatalog(loaded)) {
          throw new Error("配置目录未通过 9 产品 / 137 特性完整性校验。");
        }
        setCatalog(loaded);
        setSelectedReadOnlyArtifactKey(loaded.readOnlyArtifacts[0]?.artifactKey ?? null);
        dispatch({ type: "catalog-loaded", catalog: loaded });
      })
      .catch((error: unknown) => {
        if (!active) return;
        setNotice({ tone: "error", message: errorMessage(error, "无法读取本地配置目录。") });
      });
    return () => {
      active = false;
    };
  }, [configApi]);

  useEffect(() => {
    if (visibleDraft === null) {
      setActiveArtifactKey(null);
      return;
    }
    setActiveArtifactKey((current) =>
      current !== null && visibleDraft.artifacts.some((artifact) => artifact.key === current)
        ? current
        : (visibleDraft.artifacts[0]?.key ?? null),
    );
  }, [visibleDraft]);

  useEffect(() => {
    const subject = editor.selectedSubject;
    if (subject === null) return;
    const element = featureRefs.current.get(`${subject.product}:${subject.featureKey}`);
    element?.focus();
  }, [editor.selectedProduct, editor.selectedSubject]);

  const selectedProduct = useMemo(
    () => catalog?.products.find((product) => product.key === editor.selectedProduct) ?? null,
    [catalog, editor.selectedProduct],
  );
  const searchResults = useMemo(
    () => (catalog === null ? [] : searchConfigCatalog(catalog, editor.query)),
    [catalog, editor.query],
  );
  // A sentence such as "让 /admin 从外部访问返回 403" matches no catalogue
  // entry word for word; read it as the goal it states instead.
  const forbiddenGoal = useMemo(() => forbiddenGoalFromQuery(editor.query), [editor.query]);
  const [goalAssignmentShown, setGoalAssignmentShown] = useState(false);
  const visibleSelectedFeatures = useMemo(
    () => selectedProduct === null
      ? []
      : selectVisibleConfigFeatures(selectedProduct, searchResults, editor.query),
    [editor.query, searchResults, selectedProduct],
  );
  const activeArtifact =
    visibleDraft?.artifacts.find((artifact) => artifact.key === activeArtifactKey) ??
    visibleDraft?.artifacts[0] ??
    null;
  const totalFeatures = catalog?.products.reduce((total, product) => total + product.features.length, 0) ?? 0;
  const busy = busyAction !== null;

  /** A feature box's intent; a removal core would refuse says why instead of doing nothing. */
  function featureIntent(action: ConfigEditorAction) {
    if (action.type === "set-feature" && !action.enabled) {
      const refusal = configFeatureRemovalRefusal(action.product, editor.enabledFeatures[action.product], action.featureKey);
      if (refusal !== null) {
        setNotice({ tone: "error", message: refusal });
        return;
      }
    }
    dispatch(action);
  }

  function chooseSearchResult(subject: ConfigSearchSubject) {
    dispatch({ type: "select-search-result", subject });
  }

  function applyForbiddenGoal(path: string | null) {
    for (const action of forbiddenGoalActions(path)) dispatch(action);
  }

  /** A reviewed recipe the goal search found, as the generator's own steps. */
  function applyRecipe(key: string) {
    if (catalog === null) return;
    const actions = recipeActions(catalog, editor, key, editor.query);
    if (actions.length === 0) {
      setNotice({ tone: "error", message: "快速生成还没有这个做法的设置项。" });
      return;
    }
    for (const action of actions) dispatch(action);
  }

  async function generate() {
    if (busy) return;
    const input = buildConfigGenerateInput(editor);
    if (input === null || !isConfigGenerateInput(input)) {
      setNotice({ tone: "error", message: "当前配置值不完整，无法提交到本地生成器。" });
      return;
    }
    const submittedInputRevision = editor.inputRevisions[input.product];
    const currentDraft = draft;
    setBusyAction("generate");
    setNotice(null);
    await requestLifecycle.run({
      work: () => currentDraft === null
        ? configApi.generateConfig(input)
        : configApi.reviseConfig(currentDraft.handle, currentDraft.revision, input),
      onStaleSuccess: (next) => releaseLateConfigDraft(
        next,
        (handle, revision) => configApi.closeConfigDraft(handle, revision),
      ),
      onSuccess: (next) => {
        setDraft(next);
        dispatch({
          type: "preview-generated",
          product: input.product,
          inputRevision: submittedInputRevision,
        });
        setNotice({
          tone: "info",
          message:
            currentDraft === null
              ? `已生成 ${next.artifacts.length} 个本地审阅草稿。`
              : `草稿已更新到第 ${next.revision} 版。`,
        });
      },
      onError: (error) => {
        setNotice({ tone: "error", message: errorMessage(error, "配置生成失败。") });
      },
      onFinally: () => setBusyAction(null),
    });
  }

  async function copyDraft() {
    if (busy || draft === null) return;
    setBusyAction("copy");
    setNotice(null);
    const currentDraft = draft;
    await requestLifecycle.run({
      work: () => configApi.copyConfig(currentDraft.handle, currentDraft.revision),
      onSuccess: (result) => {
        setNotice({
          tone: "info",
          message: `已复制 ${result.artifactCount} 个文件（${result.byteLength} 字节）。`,
        });
      },
      onError: (error) => {
        setNotice({ tone: "error", message: errorMessage(error, "复制草稿失败。") });
      },
      onFinally: () => setBusyAction(null),
    });
  }

  async function exportArtifact() {
    if (busy || draft === null || activeArtifact === null) return;
    setBusyAction("export");
    setNotice(null);
    const currentDraft = draft;
    const currentArtifact = activeArtifact;
    await requestLifecycle.run({
      work: () => configApi.exportConfigArtifact(
        currentDraft.handle,
        currentDraft.revision,
        currentArtifact.key,
      ),
      onSuccess: (result) => {
        setNotice({
          tone: "info",
          message: result.saved ? `已导出 ${result.fileName ?? currentArtifact.relativePath}。` : "已取消导出。",
        });
      },
      onError: (error) => {
        setNotice({ tone: "error", message: errorMessage(error, "导出草稿失败。") });
      },
      onFinally: () => setBusyAction(null),
    });
  }

  /** Every file of a multi-file draft into one new folder the generator names. */
  async function exportBundle() {
    if (busy || draft === null || draft.artifacts.length < 2) return;
    setBusyAction("export");
    setNotice(null);
    const currentDraft = draft;
    await requestLifecycle.run({
      work: () => configApi.exportConfigBundle(currentDraft.handle, currentDraft.revision),
      onSuccess: (result) => {
        setNotice({
          tone: "info",
          message: result.saved
            ? `已新建文件夹 ${result.directoryName ?? ""}，写入 ${result.fileCount ?? currentDraft.artifacts.length} 个文件。`
            : "已取消导出。",
        });
      },
      onError: (error) => {
        setNotice({ tone: "error", message: errorMessage(error, "导出草稿失败。") });
      },
      onFinally: () => setBusyAction(null),
    });
  }

  async function closeDraft() {
    await releaseDraft();
  }

  // Not the page's busy state: releasing the draft on the way out checks it.
  const openingVisualRef = useRef(false);
  const [openingVisual, setOpeningVisual] = useState(false);
  async function openVisual() {
    if (onOpenVisual === undefined || busy || openingVisualRef.current || visibleDraft === null ||
      !isConfigVisualProduct(visibleDraft.product) || activeArtifact === null) return;
    openingVisualRef.current = true;
    setOpeningVisual(true);
    setNotice(null);
    try {
      await onOpenVisual({ handle: visibleDraft.handle, revision: visibleDraft.revision, artifactKey: activeArtifact.key });
    } catch (error) {
      setNotice({ tone: "error", message: errorMessage(error, "没能在可视化编辑中打开这份草稿。") });
    } finally {
      openingVisualRef.current = false;
      setOpeningVisual(false);
    }
  }

  async function releaseDraft(): Promise<boolean> {
    if (draft === null) return true;
    if (busy) {
      setNotice({ tone: "error", message: "请等待当前配置操作完成后再离开页面。" });
      return false;
    }
    setBusyAction("close");
    setNotice(null);
    const currentDraft = draft;
    const outcome = await requestLifecycle.run({
      work: () => configApi.closeConfigDraft(currentDraft.handle, currentDraft.revision),
      onSuccess: () => {
        setDraft(null);
        dispatch({ type: "clear-preview" });
        setNotice({ tone: "info", message: "本地草稿能力已关闭。" });
      },
      onError: (error) => {
        setNotice({ tone: "error", message: errorMessage(error, "关闭草稿失败。") });
      },
      onFinally: () => setBusyAction(null),
    });
    return outcome !== "failed";
  }

  function selectAdjacentArtifact(currentKey: string, direction: "first" | "last" | "next" | "previous") {
    if (visibleDraft === null) return;
    const currentIndex = visibleDraft.artifacts.findIndex((artifact) => artifact.key === currentKey);
    if (currentIndex < 0) return;
    let nextIndex = currentIndex;
    if (direction === "first") nextIndex = 0;
    else if (direction === "last") nextIndex = visibleDraft.artifacts.length - 1;
    else if (direction === "next") nextIndex = (currentIndex + 1) % visibleDraft.artifacts.length;
    else nextIndex = (currentIndex - 1 + visibleDraft.artifacts.length) % visibleDraft.artifacts.length;
    const nextKey = visibleDraft.artifacts[nextIndex]?.key;
    if (nextKey === undefined) return;
    setActiveArtifactKey(nextKey);
    artifactTabRefs.current.get(nextKey)?.focus();
  }

  useImperativeHandle(ref, () => ({ beforeDeactivate: releaseDraft }), [busy, configApi, draft]);

  return (
    <section
      className={embedded ? "page config-generator-page is-embedded" : "page config-generator-page"}
      aria-label="配置生成"
    >
      {/* Inside the configuration workbench the page already carries the title
          and says what this half does. Two headings stacked read as two pages. */}
      <header className="page-heading config-generator-heading">
        {embedded ? modeSwitch : (
          <div>
            <h1>配置生成器</h1>
            <p>生成纯文本配置草稿供人工审阅；不联网、不部署到目标。</p>
          </div>
        )}
        <div className="config-catalog-count" aria-label="配置目录规模">
          <strong>{catalog?.products.length ?? 0}</strong><span>产品</span>
          <strong>{totalFeatures}</strong><span>特性</span>
        </div>
      </header>

      {notice === null ? null : (
        <div
          className={`config-notice ${notice.tone}`}
          role={notice.tone === "error" ? "alert" : "status"}
          aria-live={notice.tone === "error" ? "assertive" : "polite"}
        >
          {notice.message}
        </div>
      )}

      <label className="config-search">
        <span aria-hidden="true">⌕</span>
        <span className="visually-hidden">搜索全部配置特性</span>
        <input
          type="search"
          value={editor.query}
          onChange={(event) => dispatch({ type: "set-query", query: event.currentTarget.value })}
          placeholder="搜索 9 个产品的标题、特性、别名或作用域"
          maxLength={256}
          aria-controls="config-search-results"
        />
        {editor.query.trim().length === 0 ? null : <small>{searchResults.length} 个匹配</small>}
      </label>

      {editor.query.trim().length === 0 ? null : (
        <div className="config-search-results" id="config-search-results">
          <ConfigGoalResults
            api={configApi}
            query={editor.query}
            onRecipe={applyRecipe}
            onQuery={(query) => dispatch({ type: "set-query", query })}
            onOpenVisual={onOpenVisualView}
            onAssignment={setGoalAssignmentShown}
            hiddenRecipes={forbiddenGoal === null ? [] : ["nginx.forbidden-path-403"]}
          />
          {/* An assignment is answered on its own card, never mixed with other matches. */}
          {goalAssignmentShown ? null : forbiddenGoal === null ? null : (
            <div className="config-search-goal" data-testid="config-forbidden-goal">
              <p>{forbiddenGoal.path === null ? "想让某个路径从外部访问时返回 403？" : `想让 ${forbiddenGoal.path} 从外部访问时返回 403？`}</p>
              <button type="button" data-testid="config-forbidden-goal-apply" onClick={() => applyForbiddenGoal(forbiddenGoal.path)}>
                {forbiddenGoal.path === null ? "配置 Nginx 禁止指定路径" : `用 Nginx 让 ${forbiddenGoal.path} 返回 403`}
              </button>
            </div>
          )}
          {goalAssignmentShown ? null : searchResults.length === 0 ? (
            <p>{forbiddenGoal === null ? "没有匹配的本地目录条目。" : "没有其他匹配的本地目录条目。"}</p>
          ) : (
            <ul aria-label="配置特性搜索结果">
              {searchResults.map((result) => (
                <li key={result.id}>
                  <button
                    type="button"
                    onClick={() => chooseSearchResult({ product: result.product, featureKey: result.featureKey })}
                  >
                    <span>{result.productTitle}</span>
                    <strong>{result.title}</strong>
                    <small>{result.summary}</small>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* The read-only database files are a database matter; above a web
          server or a cache they were a yellow box about something else. */}
      {catalog === null || selectedProduct?.family !== "database" ? null : (
        <ConfigReadOnlyStatusPanel
          artifacts={catalog.readOnlyArtifacts}
          selectedArtifactKey={selectedReadOnlyArtifactKey}
          onSelect={setSelectedReadOnlyArtifactKey}
        />
      )}

      {catalog === null || selectedProduct === null ? (
        <div className="config-loading" role="status">正在读取随包分发的配置目录…</div>
      ) : (
        <div className="config-generator-workbench">
          {/* The products down the side rather than across the top: nine of
              them in a row left each one too narrow to read, and the row cost
              a band of height that the editor below it needed. */}
          <nav className="config-product-list" aria-label="配置产品">
            {groupProductsByFamily(catalog.products).map((group) => (
              <Fragment key={group.family}>
                <p className="config-product-family">{configFamilyLabel(group.family)}</p>
                {group.products.map((product) => (
                  <button
                    className={editor.selectedProduct === product.key ? "active" : ""}
                    type="button"
                    key={product.key}
                    aria-pressed={editor.selectedProduct === product.key}
                    onClick={() => dispatch({ type: "select-product", product: product.key })}
                    data-testid={`config-product-${product.key}`}
                  >
                    <strong>{product.title}</strong>
                    <small>{product.features.length} 个特性</small>
                  </button>
                ))}
              </Fragment>
            ))}
          </nav>

          <div className="config-workbench">
            <form
              className="config-editor"
              onSubmit={(event) => {
                event.preventDefault();
                void generate();
              }}
            >
              <div className="config-section-heading">
                <div><span>{configFamilyLabel(selectedProduct.family)}</span><h2>{selectedProduct.title}</h2></div>
                <small>{selectedProduct.scopeNotice}</small>
              </div>

              <fieldset className="config-choice-fieldset">
                <legend>{selectedProduct.choiceKind === "mode" ? "生成模式" : "目标版本"}</legend>
                <div className="config-choice-grid">
                  {selectedProduct.choices.map((choice) => {
                    const choiceTestId = getConfigChoiceTestId(selectedProduct)(choice.key);
                    return (
                      <label
                        className={editor.choices[selectedProduct.key] === choice.key ? "active" : ""}
                        key={choice.key}
                      >
                        <input
                          type="radio"
                          name={`config-choice-${selectedProduct.key}`}
                          value={choice.key}
                          checked={editor.choices[selectedProduct.key] === choice.key}
                          data-testid={choiceTestId}
                          onChange={() => dispatch(choiceAction(selectedProduct,
                            editor.choices[selectedProduct.key] ?? selectedProduct.defaultChoice, choice.key))}
                        />
                        <span><strong>{choice.label}</strong>{choice.isDefault ? <em>默认</em> : null}</span>
                        <small>{choice.detail}</small>
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              <fieldset className="config-feature-fieldset">
                <legend>配置特性</legend>
                <p>默认项来自本地目录；不支持当前模式或版本的项保持不可选。</p>
                <div className="config-feature-list">
                  {visibleSelectedFeatures.map((feature) => {
                    const supported = feature.supportedChoices.includes(
                      editor.choices[selectedProduct.key] ?? selectedProduct.defaultChoice,
                    );
                    const checked = supported && editor.enabledFeatures[selectedProduct.key].includes(feature.key);
                    const subjectId = `${selectedProduct.key}:${feature.key}`;
                    const selected =
                      editor.selectedSubject?.product === selectedProduct.key &&
                      editor.selectedSubject.featureKey === feature.key;
                    let inlineEditor: ReactNode = undefined;
                    if (selectedProduct.key === "mysql" && feature.key === "max-connections") {
                      inlineEditor = (
                        <MySqlMaxConnectionsInlineEditor
                          value={editor.values.mysql.maxConnections}
                          enabled={checked}
                          onIntent={dispatch}
                        />
                      );
                    } else if (selectedProduct.key === "nginx" && feature.key === "forbidden-path-403") {
                      inlineEditor = (
                        <NginxForbiddenPathInlineEditor
                          path={editor.values.nginx.forbiddenPath}
                          scope={editor.values.nginx.forbiddenScope}
                          enabled={checked}
                          onIntent={dispatch}
                        />
                      );
                    } else if (
                      selectedProduct.key === "postgresql" &&
                      feature.key === "lock-wait-logging"
                    ) {
                      inlineEditor = (
                        <PostgreSqlLockWaitInlineEditor
                          value={editor.values.postgresql.lockWaitThreshold}
                          enabled={checked}
                          onIntent={dispatch}
                        />
                      );
                    } else if (
                      selectedProduct.key === "mariadb" &&
                      feature.key === "binary-log-retention"
                    ) {
                      inlineEditor = (
                        <MariaDbBinaryLogRetentionInlineEditor
                          value={editor.values.mariadb.binlogRetention}
                          enabled={checked}
                          onIntent={dispatch}
                        />
                      );
                    } else if (
                      selectedProduct.key === "redis" &&
                      feature.key === "slow-log"
                    ) {
                      inlineEditor = (
                        <RedisSlowLogInlineEditor
                          threshold={editor.values.redis.slowlogThreshold}
                          length={editor.values.redis.slowlogLength}
                          enabled={checked}
                          onIntent={dispatch}
                        />
                      );
                    } else if (
                      selectedProduct.key === "tomcat" &&
                      feature.key === "connector-limits"
                    ) {
                      inlineEditor = (
                        <TomcatConnectorLimitsInlineEditor
                          values={{
                            maxThreads: editor.values.tomcat.maxThreads,
                            acceptCount: editor.values.tomcat.acceptCount,
                            maxConnections: editor.values.tomcat.maxConnections,
                            maxPostSize: editor.values.tomcat.maxPostSize,
                            maxSwallowSize: editor.values.tomcat.maxSwallowSize,
                          }}
                          enabled={checked}
                          onIntent={dispatch}
                        />
                      );
                    }
                    return (
                      <Fragment key={feature.key}>
                        <ConfigFeatureCatalogEntry
                          product={selectedProduct.key}
                          feature={feature}
                          checked={checked}
                          supported={supported}
                          selected={selected}
                          inlineEditor={inlineEditor}
                          rowRef={(element) => {
                            if (element === null) featureRefs.current.delete(subjectId);
                            else featureRefs.current.set(subjectId, element);
                          }}
                          onIntent={featureIntent}
                        />
                      </Fragment>
                    );
                  })}
                </div>
              </fieldset>

              <fieldset className="config-values-fieldset">
                <legend>产品参数</legend>
                <div className="config-values-grid">
                  {CONFIG_VALUE_FIELDS[selectedProduct.key].map((field) => {
                    const values = editor.values[selectedProduct.key] as unknown as Record<string, string>;
                    const value = values[field.key] ?? "";
                    const inputId = `config-value-${selectedProduct.key}-${field.key}`;
                    return (
                      <label key={field.key} htmlFor={inputId}>
                        <span>{field.label}</span>
                        {field.options === undefined ? (
                          <input
                            id={inputId}
                            value={value}
                            inputMode={field.inputMode}
                            maxLength={4096}
                            spellCheck={false}
                            onChange={(event) => dispatch({
                              type: "set-value",
                              product: selectedProduct.key,
                              key: field.key,
                              value: event.currentTarget.value,
                            })}
                          />
                        ) : (
                          <select
                            id={inputId}
                            value={value}
                            onChange={(event) => dispatch({
                              type: "set-value",
                              product: selectedProduct.key,
                              key: field.key,
                              value: event.currentTarget.value,
                            })}
                          >
                            {field.options.map((option) => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        )}
                        <small>{field.description}</small>
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              <div className="config-generate-row">
                <p>生成只创建有限期本地草稿；部署与目标验证仍需独立完成。</p>
                <div>
                  <button
                    className="config-reset-product"
                    type="button"
                    disabled={busy}
                    data-testid={`config-reset-${selectedProduct.key}`}
                    onClick={() => {
                      dispatch({ type: "reset-product", product: selectedProduct });
                      // A message about the values just thrown away is stale now.
                      setNotice(null);
                    }}
                  >
                    恢复当前产品默认值
                  </button>
                  <button type="submit" disabled={busy} data-testid="config-generate">
                    {busyAction === "generate" ? "生成中…" : draft === null ? "生成审阅草稿" : "按当前值修订草稿"}
                  </button>
                </div>
              </div>
            </form>

            <aside
              className="config-preview"
              aria-label="配置草稿预览"
              data-config-preview-product={visibleDraft?.product ?? "none"}
            >
              {visibleDraft === null || activeArtifact === null ? (
                <div className="config-preview-empty">
                  <span aria-hidden="true">{`{ }`}</span>
                  <h2>{draft === null ? "尚未生成草稿" : "草稿预览已失效"}</h2>
                  <p>
                    {draft === null
                      ? "选择模式、特性和参数后生成。内容会以纯文本显示。"
                      : "产品、模式、特性或参数已改动，旧预览已收起；点“按当前值修订草稿”得到新的一版。"}
                  </p>
                </div>
              ) : (
                <>
                  <header>
                    <div><span>第 {visibleDraft.revision} 版草稿</span><strong>{visibleDraft.suggestedName}</strong></div>
                    <button type="button" disabled={busy} onClick={() => void closeDraft()} aria-label="关闭配置草稿">×</button>
                  </header>
                  <div className="config-artifact-tabs" role="tablist" aria-label="草稿文件">
                    {visibleDraft.artifacts.map((artifact) => (
                      <button
                        id={`config-artifact-tab-${artifact.key}`}
                        type="button"
                        role="tab"
                        key={artifact.key}
                        aria-selected={activeArtifact.key === artifact.key}
                        aria-controls={`config-artifact-panel-${artifact.key}`}
                        tabIndex={activeArtifact.key === artifact.key ? 0 : -1}
                        onClick={() => setActiveArtifactKey(artifact.key)}
                        ref={(element) => {
                          if (element === null) artifactTabRefs.current.delete(artifact.key);
                          else artifactTabRefs.current.set(artifact.key, element);
                        }}
                        onKeyDown={(event) => {
                          const direction =
                            event.key === "ArrowRight" ? "next" :
                            event.key === "ArrowLeft" ? "previous" :
                            event.key === "Home" ? "first" :
                            event.key === "End" ? "last" : null;
                          if (direction === null) return;
                          event.preventDefault();
                          selectAdjacentArtifact(artifact.key, direction);
                        }}
                      >
                        {artifact.relativePath}
                      </button>
                    ))}
                  </div>
                  <div
                    className="config-artifact-panel"
                    id={`config-artifact-panel-${activeArtifact.key}`}
                    role="tabpanel"
                    aria-labelledby={`config-artifact-tab-${activeArtifact.key}`}
                    tabIndex={0}
                  >
                    <ConfigArtifactPreview artifact={activeArtifact} />
                  </div>
                  {isConfigVisualProduct(visibleDraft.product)
                    ? <ConfigArtifactNotes product={visibleDraft.product} text={activeArtifact.preview} />
                    : null}
                  {visibleDraft.notices.map((item, index) => <p className="config-draft-notice" key={`${index}:${item}`}>{item}</p>)}
                  <footer>
                    <button type="button" disabled={busy || !visibleDraft.copyAllowed} onClick={() => void copyDraft()}>
                      {busyAction === "copy" ? "复制中…" : "复制全部"}
                    </button>
                    <button type="button" disabled={busy} onClick={() => void exportArtifact()}>
                      {busyAction === "export" ? "导出中…" : "导出当前文件…"}
                    </button>
                    {visibleDraft.artifacts.length > 1 ? (
                      <button type="button" disabled={busy} onClick={() => void exportBundle()}
                        data-testid="config-export-bundle"
                        title={`在所选位置新建一个文件夹，按原有目录结构写入全部 ${visibleDraft.artifacts.length} 个文件；不会覆盖已有内容`}>
                        {`导出全部 ${visibleDraft.artifacts.length} 个文件…`}
                      </button>
                    ) : null}
                    {onOpenVisual !== undefined && isConfigVisualProduct(visibleDraft.product) ? (
                      <button type="button" disabled={busy || openingVisual} onClick={() => void openVisual()}
                        data-testid="config-open-visual">
                        {openingVisual ? "打开中…" : "在可视化编辑中打开"}
                      </button>
                    ) : null}
                  </footer>
                </>
              )}
            </aside>
          </div>
        </div>
      )}
    </section>
  );
});

/**
 * The catalogue names a family by key; the list shows it in words. A key this
 * page does not know yet is shown as it came rather than dropped.
 */
export function configFamilyLabel(family: string): string {
  switch (family) {
    case "web": return "Web 服务";
    case "proxy": return "代理与负载均衡";
    case "database": return "数据库";
    case "cache": return "缓存";
    case "application-server": return "应用服务器";
    default: return family;
  }
}

/** The nine products, kept in catalogue order, under the family they belong to. */
function groupProductsByFamily(
  products: ConfigCatalog["products"],
): { family: string; products: ConfigCatalog["products"] }[] {
  const groups: { family: string; products: ConfigCatalog["products"] }[] = [];
  for (const product of products) {
    const last = groups.at(-1);
    if (last !== undefined && last.family === product.family) last.products.push(product);
    else groups.push({ family: product.family, products: [product] });
  }
  return groups;
}
