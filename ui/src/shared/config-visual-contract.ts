/**
 * A configuration file edited as a tree (Nginx, Apache httpd, Redis, HAProxy). The document lives in
 * the backend; the page holds its handle, the revision it was shown and the
 * rows of that revision. Opening a local file, copying and saving go through
 * host commands, so no path or whole text passes through here.
 */
export type ConfigVisualKind = "directive" | "block" | "comment" | "opaque";
export type ConfigVisualSource = "blank" | "competition" | "quick" | "import" | "starter" | "goal";
export type ConfigVisualProduct = "nginx" | "apache" | "redis" | "haproxy" | "mysql" | "mariadb";
/** What a document is: one of the products, or a catalogued database file. */
export type ConfigVisualDocumentProduct = ConfigVisualProduct | "database";

export interface ConfigVisualRow {
  /** Valid for this revision only; every edit hands out new ones. */
  id: string;
  parentId: string | null;
  depth: number;
  kind: ConfigVisualKind;
  name: string | null;
  arguments: string | null;
  preview: string;
  childCount: number;
  truncated: boolean;
  editable: boolean;
  sensitive: boolean;
  /**
   * A database file's row: "catalog" when the chosen version's catalogue
   * describes it (guidance, never a check against a server), else "syntax".
   * Null for every other document.
   */
  meaning: "catalog" | "syntax" | null;
  /** The described parameter's place in `database.parameters`. */
  parameterIndex: number | null;
  /** What a database file's row is found by; never a value. Empty otherwise. */
  searchTerms: string[];
}

export type ConfigVisualReadOnly = "vendor-schema" | "generated";
export type ConfigVisualValueKind = "boolean" | "integer" | "enumeration" | "text";
export type ConfigVisualScope = "session" | "instance" | "component" | "cluster" | "global" | "vendor-defined";
export type ConfigVisualActivation = "dynamic" | "reload" | "restart" | "rolling-restart" | "vendor-procedure";
export type ConfigVisualRisk = "informational" | "low" | "medium" | "high" | "critical";
export type ConfigVisualSensitivity = "public" | "operational-metadata" | "may-contain-secrets" | "private-key-reference";

export interface ConfigVisualSchema {
  index: number;
  label: string;
  version: string;
  complete: boolean;
}

/** One reviewed parameter of the chosen version, in the file or not. */
export interface ConfigVisualParameter {
  index: number;
  key: string;
  aliases: string[];
  group: string | null;
  valueKind: ConfigVisualValueKind;
  /** The accepted values, in words. */
  valueDomain: string;
  scope: ConfigVisualScope;
  activation: ConfigVisualActivation;
  risk: ConfigVisualRisk;
  sensitivity: ConfigVisualSensitivity;
  /** The catalogue's own explanation, as written there. */
  rationale: string;
  purpose: string;
  reference: string | null;
  capability: string | null;
  documentedDefault: string | null;
  /** Whether a value can be set here: public, editable file, nothing extra needed. */
  settable: boolean;
  /** How many lines of the file are this parameter. */
  occurrences: number;
  searchTerms: string[];
}

export interface ConfigVisualDatabase {
  product: string;
  productLabel: string;
  artifactKey: string;
  fileLabel: string;
  syntax: string;
  readOnly: ConfigVisualReadOnly | null;
  schemas: ConfigVisualSchema[];
  schemaIndex: number | null;
  parameters: ConfigVisualParameter[];
}

export interface ConfigVisualDatabaseFile {
  key: string;
  label: string;
  syntax: string;
  readOnly: ConfigVisualReadOnly | null;
  schemas: number;
}

export interface ConfigVisualDatabaseCatalog {
  products: Array<{ product: string; label: string; files: ConfigVisualDatabaseFile[] }>;
}

export interface ConfigVisualView {
  documentHandle: string;
  revision: number;
  product: ConfigVisualDocumentProduct;
  source: ConfigVisualSource;
  structured: boolean;
  /** Parts kept as written because they are another language (Apache <Perl>). */
  partlyOpaque: boolean;
  containsSensitive: boolean;
  totalBytes: number;
  suggestedName: string;
  rows: ConfigVisualRow[];
  totalRows: number;
  rowsTruncated: boolean;
  /** The whole text, absent when it holds hidden values or is not UTF-8. */
  text: string | null;
  textTruncated: boolean;
  copyAllowed: boolean;
  /** Set for a catalogued database file, null otherwise. */
  database: ConfigVisualDatabase | null;
}

/** The visual document the page has open, as it shows it, for a goal to land in. */
export interface ConfigGoalDocument {
  documentHandle: string;
  revision: number;
  /** Whether it holds edits not yet saved to a file. */
  unsaved: boolean;
}

/** One reviewed parameter of one reviewed version of one catalogued file. */
export interface ConfigGoalTarget {
  product: string;
  productLabel: string;
  artifactKey: string;
  fileLabel: string;
  schema: ConfigVisualSchema;
  parameterIndex: number;
  key: string;
  group: string | null;
  valueDomain: string;
  activation: ConfigVisualActivation;
  risk: ConfigVisualRisk;
}

/** Why something found cannot be drafted here yet. */
export type ConfigGoalGap =
  | "no-reviewed-intent" | "no-recipe" | "no-version-catalogue" | "version-not-catalogued" | "file-not-editable"
  | "no-value-rules" | "needs-capability" | "needs-outside-steps" | "secret-value";
/** Why an assignment sentence was refused; never its value. */
export type ConfigGoalRejection =
  | "query-refused" | "unsupported-operator" | "missing-target" | "missing-value" | "multiple-operators"
  | "missing-product" | "ambiguous-product" | "invalid-version" | "version-not-catalogued" | "no-version-catalogue"
  | "missing-parameter" | "invalid-qualifier" | "unknown-file" | "file-of-another-product" | "unknown-group"
  | "unknown-parameter" | "unknown-candidate" | "too-many-candidates" | "file-not-editable" | "secret-value"
  | "needs-capability" | "no-value-rules" | "value-refused" | "empty-value";
/** Why a resolved assignment cannot go into the draft now. */
export type ConfigGoalBlock =
  | "file-not-editable" | "other-file-unsaved" | "other-version-unsaved" | "duplicate" | "line-locked"
  | "ambiguous-group" | "writer-refused";

export type ConfigGoalAssignment =
  | {
    lease: string; state: "ready"; target: ConfigGoalTarget; value: string;
    /** Where a confirmed value goes; null when it is blocked. */
    landing: "open-draft" | "new-draft" | null;
    blocked: ConfigGoalBlock | null; candidates: []; rejection: null;
  }
  | {
    lease: string; state: "ambiguous"; target: null; value: null; landing: null; blocked: null;
    candidates: ConfigGoalTarget[]; rejection: null;
  }
  | {
    lease: null; state: "rejected"; target: null; value: null; landing: null; blocked: null; candidates: [];
    rejection: ConfigGoalRejection;
  };

export interface ConfigGoalStep {
  title: string;
  explanation: string;
  required: boolean;
  /** The version's reviewed parameters for this step; none means it happens outside the file. */
  parameters: string[];
}

export type ConfigGoalResult =
  | { kind: "recipe"; key: string; product: string; productLabel: string; title: string; summary: string; effect: string }
  | {
    kind: "database-goal"; key: string; product: string; productLabel: string; title: string; summary: string;
    artifactKey: string; fileLabel: string; schema: ConfigVisualSchema; steps: ConfigGoalStep[];
    missingRequired: number; gap: ConfigGoalGap | null;
  }
  | { kind: "database-parameter"; target: ConfigGoalTarget; draftable: boolean; gap: ConfigGoalGap | null }
  | {
    kind: "database-file"; product: string; productLabel: string; artifactKey: string; fileLabel: string;
    opens: boolean; readOnly: boolean; gap: ConfigGoalGap | null;
  }
  | {
    kind: "unavailable"; subject: string; family: "middleware" | "database"; recipes: number; parameters: number;
    files: number; gap: ConfigGoalGap;
  };

export interface ConfigGoalSearch {
  /** Set when the sentence is an assignment; then there are no results. */
  assignment: ConfigGoalAssignment | null;
  results: ConfigGoalResult[];
  truncated: boolean;
}

export const MAX_CONFIG_GOAL_QUERY_CHARS = 128;

export type ConfigVisualRequest =
  | { action: "goal-search"; query: string; document: ConfigGoalDocument | null }
  | { action: "goal-choose"; lease: string; candidate: number; document: ConfigGoalDocument | null }
  | { action: "goal-confirm"; lease: string; value: string; document: ConfigGoalDocument | null }
  | { action: "database-catalog" }
  | { action: "new-database"; artifactKey: string }
  | { action: "select-schema"; documentHandle: string; revision: number; schema: number | null }
  | { action: "set-parameter"; documentHandle: string; revision: number; parameterIndex: number; value: string }
  | { action: "new"; product: ConfigVisualProduct; template: "blank" | "competition" }
  | { action: "open-quick"; handle: string; revision: number; artifactKey: string }
  | { action: "view"; documentHandle: string; revision: number }
  | {
    action: "add"; documentHandle: string; revision: number; parentId: string | null;
    kind: "directive" | "block"; name: string; arguments: string;
    /** A comment written on the line just above, in the same edit. */
    note?: string;
  }
  | { action: "add"; documentHandle: string; revision: number; parentId: string | null; kind: "comment"; text: string }
  | { action: "update"; documentHandle: string; revision: number; nodeId: string; name: string; arguments: string }
  | { action: "update"; documentHandle: string; revision: number; nodeId: string; text: string }
  | { action: "remove"; documentHandle: string; revision: number; nodeId: string }
  | { action: "move"; documentHandle: string; revision: number; nodeId: string; direction: "up" | "down" }
  | { action: "close"; documentHandle: string; revision: number };

export interface ConfigVisualClosed {
  closed: true;
}

export interface ConfigVisualCopyResult {
  byteLength: number;
}

export interface ConfigVisualSaveResult {
  saved: boolean;
  fileName: string | null;
}

/** Everything config.visual can answer the page with. */
export type ConfigVisualAnswer = ConfigVisualView | ConfigVisualClosed | ConfigVisualDatabaseCatalog | ConfigGoalSearch;

export interface ConfigVisualApi {
  configVisual(request: ConfigVisualRequest): Promise<ConfigVisualAnswer>;
  /** Null when the operator closed the open dialog. */
  importConfigVisual(product: ConfigVisualProduct): Promise<ConfigVisualView | null>;
  /** A local copy of a catalogued database file; null when the dialog was closed. */
  importConfigVisualDatabase(artifactKey: string): Promise<ConfigVisualView | null>;
  copyConfigVisual(documentHandle: string, revision: number): Promise<ConfigVisualCopyResult>;
  saveConfigVisual(documentHandle: string, revision: number): Promise<ConfigVisualSaveResult>;
}

export const MAX_CONFIG_VISUAL_FIELD_BYTES = 64 * 1024;
const MAX_ROW_TEXT_BYTES = 4 * 1024;
const MAX_PREVIEW_BYTES = 2 * 1024;
const MAX_ROWS = 2_000;
const MAX_TEXT_BYTES = 128 * 1024;
const encoder = new TextEncoder();
const KINDS: readonly string[] = ["directive", "block", "comment", "opaque"];
const SOURCES: readonly string[] = ["blank", "competition", "quick", "import", "starter", "goal"];
const READ_ONLY: readonly string[] = ["vendor-schema", "generated"];
const VALUE_KINDS: readonly string[] = ["boolean", "integer", "enumeration", "text"];
const SCOPES: readonly string[] = ["session", "instance", "component", "cluster", "global", "vendor-defined"];
const ACTIVATIONS: readonly string[] = ["dynamic", "reload", "restart", "rolling-restart", "vendor-procedure"];
const RISKS: readonly string[] = ["informational", "low", "medium", "high", "critical"];
const SENSITIVITIES: readonly string[] = ["public", "operational-metadata", "may-contain-secrets", "private-key-reference"];
const MAX_SEARCH_TERMS = 64;
const MAX_PARAMETER_TERMS = 128;
const MAX_SCHEMAS = 32;
const MAX_PARAMETERS = 512;
const MAX_LABEL_BYTES = 512;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function bytes(value: string): number {
  return encoder.encode(value).length;
}
function handle(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9-]{1,128}$/u.test(value);
}
function nodeId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{1,40}$/u.test(value);
}
function revision(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}
function count(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}
function field(value: unknown): value is string {
  return typeof value === "string" && bytes(value) <= MAX_CONFIG_VISUAL_FIELD_BYTES && !value.includes("\u0000");
}
function optionalText(value: unknown, maximum: number): value is string | null {
  return value === null || typeof value === "string" && bytes(value) <= maximum;
}
function label(value: unknown, maximum = MAX_LABEL_BYTES): value is string {
  return typeof value === "string" && value.length > 0 && bytes(value) <= maximum && !/[\u0000-\u001f\u007f]/u.test(value);
}
function artifactKey(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9][a-z0-9.-]{0,127}$/u.test(value);
}
function terms(value: unknown, maximum: number): value is string[] {
  return Array.isArray(value) && value.length <= maximum && value.every((term) => label(term, MAX_ROW_TEXT_BYTES));
}
function oneOf(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === "string" && allowed.includes(value);
}

export function isConfigVisualProduct(value: unknown): value is ConfigVisualProduct {
  return value === "nginx" || value === "apache" || value === "redis" || value === "haproxy" ||
    value === "mysql" || value === "mariadb";
}

export function isConfigVisualRequest(value: unknown): value is ConfigVisualRequest {
  if (!record(value) || typeof value.action !== "string") return false;
  const document = handle(value.documentHandle) && revision(value.revision);
  switch (value.action) {
    case "goal-search":
      return exact(value, ["action", "query", "document"]) && goalQuery(value.query) && goalDocument(value.document);
    case "goal-choose":
      return exact(value, ["action", "lease", "candidate", "document"]) && handle(value.lease) &&
        count(value.candidate, MAX_GOAL_CANDIDATES - 1) && goalDocument(value.document);
    case "goal-confirm":
      return exact(value, ["action", "lease", "value", "document"]) && handle(value.lease) && field(value.value) &&
        goalDocument(value.document);
    case "database-catalog":
      return exact(value, ["action"]);
    case "new-database":
      return exact(value, ["action", "artifactKey"]) && artifactKey(value.artifactKey);
    case "select-schema":
      return exact(value, ["action", "documentHandle", "revision", "schema"]) && document &&
        (value.schema === null || count(value.schema, 65_535));
    case "set-parameter":
      return exact(value, ["action", "documentHandle", "revision", "parameterIndex", "value"]) && document &&
        count(value.parameterIndex, MAX_PARAMETERS - 1) && field(value.value);
    case "new":
      return exact(value, ["action", "product", "template"]) && isConfigVisualProduct(value.product) &&
        (value.template === "blank" || value.template === "competition");
    case "open-quick":
      return exact(value, ["action", "handle", "revision", "artifactKey"]) && handle(value.handle) &&
        revision(value.revision) && typeof value.artifactKey === "string" && /^[A-Za-z0-9._-]{1,128}$/u.test(value.artifactKey);
    case "view":
    case "close":
      return exact(value, ["action", "documentHandle", "revision"]) && document;
    case "add":
      if (!document || !(value.parentId === null || nodeId(value.parentId))) return false;
      return value.kind === "comment"
        ? exact(value, ["action", "documentHandle", "revision", "parentId", "kind", "text"]) && field(value.text)
        : (value.kind === "directive" || value.kind === "block") &&
          (exact(value, ["action", "documentHandle", "revision", "parentId", "kind", "name", "arguments"]) ||
            exact(value, ["action", "documentHandle", "revision", "parentId", "kind", "name", "arguments", "note"]) &&
              field(value.note)) &&
          field(value.name) && field(value.arguments);
    case "update":
      if (!document || !nodeId(value.nodeId)) return false;
      return Object.hasOwn(value, "text")
        ? exact(value, ["action", "documentHandle", "revision", "nodeId", "text"]) && field(value.text)
        : exact(value, ["action", "documentHandle", "revision", "nodeId", "name", "arguments"]) &&
          field(value.name) && field(value.arguments);
    case "remove":
      return exact(value, ["action", "documentHandle", "revision", "nodeId"]) && document && nodeId(value.nodeId);
    case "move":
      return exact(value, ["action", "documentHandle", "revision", "nodeId", "direction"]) && document &&
        nodeId(value.nodeId) && (value.direction === "up" || value.direction === "down");
    default:
      return false;
  }
}

function isRow(value: unknown): value is ConfigVisualRow {
  if (!record(value) || !exact(value, [
    "id", "parentId", "depth", "kind", "name", "arguments", "preview", "childCount", "truncated", "editable", "sensitive",
    "meaning", "parameterIndex", "searchTerms",
  ])) return false;
  return nodeId(value.id) && (value.parentId === null || nodeId(value.parentId)) && count(value.depth, 128) &&
    KINDS.includes(String(value.kind)) && optionalText(value.name, MAX_ROW_TEXT_BYTES) &&
    optionalText(value.arguments, MAX_ROW_TEXT_BYTES) && typeof value.preview === "string" &&
    bytes(value.preview) <= MAX_PREVIEW_BYTES && count(value.childCount, 65_536) &&
    typeof value.truncated === "boolean" && typeof value.editable === "boolean" && typeof value.sensitive === "boolean" &&
    // A row with hidden content shows no arguments and is never editable.
    (!value.sensitive || (value.arguments === null && !value.editable)) &&
    (value.kind !== "opaque" || !value.editable) &&
    (value.meaning === null || value.meaning === "catalog" || value.meaning === "syntax") &&
    (value.parameterIndex === null || count(value.parameterIndex, MAX_PARAMETERS - 1)) &&
    // Only a row the catalogue describes points at a parameter.
    ((value.meaning === "catalog") === (value.parameterIndex !== null)) &&
    terms(value.searchTerms, MAX_SEARCH_TERMS);
}

const MAX_GOAL_CANDIDATES = 64;
const MAX_GOAL_RESULTS = 80;
const MAX_GOAL_STEPS = 16;
const GOAL_GAPS: readonly string[] = [
  "no-reviewed-intent", "no-recipe", "no-version-catalogue", "version-not-catalogued", "file-not-editable",
  "no-value-rules", "needs-capability", "needs-outside-steps", "secret-value",
];
const GOAL_REJECTIONS: readonly string[] = [
  "query-refused", "unsupported-operator", "missing-target", "missing-value", "multiple-operators", "missing-product",
  "ambiguous-product", "invalid-version", "version-not-catalogued", "no-version-catalogue", "missing-parameter",
  "invalid-qualifier", "unknown-file", "file-of-another-product", "unknown-group", "unknown-parameter",
  "unknown-candidate", "too-many-candidates", "file-not-editable", "secret-value", "needs-capability",
  "no-value-rules", "value-refused", "empty-value",
];
const GOAL_BLOCKS: readonly string[] = [
  "file-not-editable", "other-file-unsaved", "other-version-unsaved", "duplicate", "line-locked", "ambiguous-group",
  "writer-refused",
];

function goalQuery(value: unknown): value is string {
  if (typeof value !== "string" || value.trim() === "") return false;
  return [...value].length <= MAX_CONFIG_GOAL_QUERY_CHARS && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

function goalDocument(value: unknown): value is ConfigGoalDocument | null {
  return value === null || record(value) && exact(value, ["documentHandle", "revision", "unsaved"]) &&
    handle(value.documentHandle) && revision(value.revision) && typeof value.unsaved === "boolean";
}

function optionalGap(value: unknown): boolean {
  return value === null || oneOf(value, GOAL_GAPS);
}

function isGoalTarget(value: unknown): value is ConfigGoalTarget {
  return record(value) && exact(value, [
    "product", "productLabel", "artifactKey", "fileLabel", "schema", "parameterIndex", "key", "group", "valueDomain",
    "activation", "risk",
  ]) && label(value.product, 64) && label(value.productLabel) && artifactKey(value.artifactKey) &&
    label(value.fileLabel) && isSchema(value.schema) && count(value.parameterIndex, MAX_PARAMETERS - 1) &&
    label(value.key) && (value.group === null || label(value.group)) && label(value.valueDomain, MAX_ROW_TEXT_BYTES) &&
    oneOf(value.activation, ACTIVATIONS) && oneOf(value.risk, RISKS);
}

function isGoalAssignment(value: unknown): value is ConfigGoalAssignment {
  if (!record(value) || !exact(value, [
    "lease", "state", "target", "value", "landing", "blocked", "candidates", "rejection",
  ]) || !Array.isArray(value.candidates)) return false;
  switch (value.state) {
    case "ready":
      // A value lands somewhere or is blocked, never both and never neither.
      return handle(value.lease) && isGoalTarget(value.target) && label(value.value, MAX_ROW_TEXT_BYTES) &&
        ((value.landing === "open-draft" || value.landing === "new-draft") !== (value.blocked !== null)) &&
        (value.landing === null || value.landing === "open-draft" || value.landing === "new-draft") &&
        (value.blocked === null || oneOf(value.blocked, GOAL_BLOCKS)) &&
        value.candidates.length === 0 && value.rejection === null;
    case "ambiguous":
      return handle(value.lease) && value.target === null && value.value === null && value.landing === null &&
        value.blocked === null && value.candidates.length >= 2 && value.candidates.length <= MAX_GOAL_CANDIDATES &&
        value.candidates.every(isGoalTarget) && value.rejection === null;
    case "rejected":
      return value.lease === null && value.target === null && value.value === null && value.landing === null &&
        value.blocked === null && value.candidates.length === 0 && oneOf(value.rejection, GOAL_REJECTIONS);
    default:
      return false;
  }
}

function isGoalStep(value: unknown): value is ConfigGoalStep {
  return record(value) && exact(value, ["title", "explanation", "required", "parameters"]) && label(value.title) &&
    label(value.explanation, MAX_ROW_TEXT_BYTES) && typeof value.required === "boolean" &&
    terms(value.parameters, MAX_PARAMETERS);
}

function isGoalResult(value: unknown): value is ConfigGoalResult {
  if (!record(value)) return false;
  switch (value.kind) {
    case "recipe":
      return exact(value, ["kind", "key", "product", "productLabel", "title", "summary", "effect"]) &&
        label(value.key, 128) && label(value.product, 64) && label(value.productLabel) && label(value.title) &&
        label(value.summary, MAX_ROW_TEXT_BYTES) && label(value.effect, MAX_ROW_TEXT_BYTES);
    case "database-goal":
      return exact(value, [
        "kind", "key", "product", "productLabel", "title", "summary", "artifactKey", "fileLabel", "schema", "steps",
        "missingRequired", "gap",
      ]) && label(value.key, 128) && label(value.product, 64) && label(value.productLabel) && label(value.title) &&
        label(value.summary, MAX_ROW_TEXT_BYTES) && artifactKey(value.artifactKey) && label(value.fileLabel) &&
        isSchema(value.schema) && Array.isArray(value.steps) && value.steps.length > 0 &&
        value.steps.length <= MAX_GOAL_STEPS && value.steps.every(isGoalStep) &&
        count(value.missingRequired, value.steps.length) && optionalGap(value.gap);
    case "database-parameter":
      return exact(value, ["kind", "target", "draftable", "gap"]) && isGoalTarget(value.target) &&
        typeof value.draftable === "boolean" && optionalGap(value.gap) &&
        // A parameter a value can be drafted for has no gap to explain.
        (!value.draftable || value.gap === null);
    case "database-file":
      return exact(value, ["kind", "product", "productLabel", "artifactKey", "fileLabel", "opens", "readOnly", "gap"]) &&
        label(value.product, 64) && label(value.productLabel) && artifactKey(value.artifactKey) &&
        label(value.fileLabel) && typeof value.opens === "boolean" && typeof value.readOnly === "boolean" &&
        optionalGap(value.gap);
    case "unavailable":
      return exact(value, ["kind", "subject", "family", "recipes", "parameters", "files", "gap"]) &&
        label(value.subject) && (value.family === "middleware" || value.family === "database") &&
        count(value.recipes, 4096) && count(value.parameters, 65_536) && count(value.files, 4096) &&
        oneOf(value.gap, GOAL_GAPS);
    default:
      return false;
  }
}

export function isConfigGoalSearch(value: unknown): value is ConfigGoalSearch {
  if (!record(value) || !exact(value, ["assignment", "results", "truncated"]) || !Array.isArray(value.results) ||
    value.results.length > MAX_GOAL_RESULTS || typeof value.truncated !== "boolean") return false;
  if (value.assignment !== null) {
    // An assignment is never mixed with fuzzy results.
    return isGoalAssignment(value.assignment) && value.results.length === 0 && !value.truncated;
  }
  return value.results.every(isGoalResult);
}

function isSchema(value: unknown): value is ConfigVisualSchema {
  return record(value) && exact(value, ["index", "label", "version", "complete"]) && count(value.index, 65_535) &&
    label(value.label) && label(value.version) && typeof value.complete === "boolean";
}

function isParameter(value: unknown): value is ConfigVisualParameter {
  if (!record(value) || !exact(value, [
    "index", "key", "aliases", "group", "valueKind", "valueDomain", "scope", "activation", "risk", "sensitivity",
    "rationale", "purpose", "reference", "capability", "documentedDefault", "settable", "occurrences", "searchTerms",
  ])) return false;
  return count(value.index, MAX_PARAMETERS - 1) && label(value.key) && terms(value.aliases, 32) &&
    (value.group === null || label(value.group)) && oneOf(value.valueKind, VALUE_KINDS) &&
    label(value.valueDomain, MAX_ROW_TEXT_BYTES) && oneOf(value.scope, SCOPES) && oneOf(value.activation, ACTIVATIONS) &&
    oneOf(value.risk, RISKS) && oneOf(value.sensitivity, SENSITIVITIES) &&
    label(value.rationale, MAX_ROW_TEXT_BYTES) && label(value.purpose, MAX_ROW_TEXT_BYTES) &&
    (value.reference === null || label(value.reference)) && (value.capability === null || label(value.capability)) &&
    optionalText(value.documentedDefault, MAX_ROW_TEXT_BYTES) && typeof value.settable === "boolean" &&
    count(value.occurrences, 65_536) && terms(value.searchTerms, MAX_PARAMETER_TERMS) &&
    // A secret is never set from here.
    (!value.settable || value.sensitivity === "public");
}

function isDatabase(value: unknown): value is ConfigVisualDatabase {
  if (!record(value) || !exact(value, [
    "product", "productLabel", "artifactKey", "fileLabel", "syntax", "readOnly", "schemas", "schemaIndex", "parameters",
  ])) return false;
  if (!label(value.product, 64) || !label(value.productLabel) || !artifactKey(value.artifactKey) ||
    !label(value.fileLabel) || !label(value.syntax, 64) || !(value.readOnly === null || oneOf(value.readOnly, READ_ONLY)) ||
    !Array.isArray(value.schemas) || value.schemas.length > MAX_SCHEMAS || !value.schemas.every(isSchema) ||
    !Array.isArray(value.parameters) || value.parameters.length > MAX_PARAMETERS ||
    !value.parameters.every(isParameter)) return false;
  const schemas = value.schemas as ConfigVisualSchema[];
  const parameters = value.parameters as ConfigVisualParameter[];
  // The chosen version is one of this file's; with none chosen there is no catalogue.
  if (value.schemaIndex === null) return parameters.length === 0;
  return count(value.schemaIndex, 65_535) && schemas.some((schema) => schema.index === value.schemaIndex) &&
    parameters.every((parameter, index) => parameter.index === index) &&
    // A read-only file takes no value.
    (value.readOnly === null || parameters.every((parameter) => !parameter.settable));
}

export function isConfigVisualDatabaseCatalog(value: unknown): value is ConfigVisualDatabaseCatalog {
  if (!record(value) || !exact(value, ["products"]) || !Array.isArray(value.products) || value.products.length > 128) {
    return false;
  }
  return value.products.every((product: unknown) => record(product) && exact(product, ["product", "label", "files"]) &&
    label(product.product, 64) && label(product.label) && Array.isArray(product.files) &&
    product.files.length > 0 && product.files.length <= 64 &&
    product.files.every((file: unknown) => record(file) && exact(file, ["key", "label", "syntax", "readOnly", "schemas"]) &&
      artifactKey(file.key) && label(file.label) && label(file.syntax, 64) &&
      (file.readOnly === null || oneOf(file.readOnly, READ_ONLY)) && count(file.schemas, MAX_SCHEMAS)));
}

export function isConfigVisualView(value: unknown): value is ConfigVisualView {
  if (!record(value) || !exact(value, [
    "documentHandle", "revision", "product", "source", "structured", "partlyOpaque", "containsSensitive", "totalBytes",
    "suggestedName", "rows", "totalRows", "rowsTruncated", "text", "textTruncated", "copyAllowed", "database",
  ])) return false;
  const databaseFile = value.product === "database";
  if (databaseFile ? !isDatabase(value.database) : value.database !== null) return false;
  if (!handle(value.documentHandle) || !revision(value.revision) ||
    !(databaseFile || isConfigVisualProduct(value.product)) ||
    !SOURCES.includes(String(value.source)) || typeof value.structured !== "boolean" ||
    typeof value.partlyOpaque !== "boolean" || (value.product === "nginx" && value.partlyOpaque) ||
    typeof value.containsSensitive !== "boolean" || !count(value.totalBytes, 4 * 1024 * 1024) ||
    typeof value.suggestedName !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(value.suggestedName) ||
    !Array.isArray(value.rows) || value.rows.length > MAX_ROWS || !count(value.totalRows, 65_536) ||
    value.rows.length > value.totalRows || typeof value.rowsTruncated !== "boolean" ||
    !optionalText(value.text, MAX_TEXT_BYTES) || typeof value.textTruncated !== "boolean" ||
    typeof value.copyAllowed !== "boolean") return false;
  // Hidden values never come back as text and never reach the clipboard.
  if (value.containsSensitive && (value.text !== null || value.copyAllowed)) return false;
  const ids = new Set<string>();
  const parameterCount = databaseFile ? (value.database as ConfigVisualDatabase).parameters.length : 0;
  for (const row of value.rows) {
    if (!isRow(row) || ids.has(row.id) || (row.parentId !== null && !ids.has(row.parentId))) return false;
    // Meaning and search words come with database files only, and point inside their catalogue.
    if (databaseFile ? row.meaning === null || (row.parameterIndex !== null && row.parameterIndex >= parameterCount)
      : row.meaning !== null || row.searchTerms.length > 0) return false;
    // redis.conf is flat: no blocks, nothing nested.
    if (value.product === "redis" && (row.kind === "block" || row.depth !== 0 || row.parentId !== null)) return false;
    // haproxy.cfg: sections only at the top, their lines one level below.
    if (value.product === "haproxy" && (row.kind === "block" ? row.depth !== 0 : row.depth > 1)) return false;
    // my.cnf: [groups] only at the top, their options one level below.
    if ((value.product === "mysql" || value.product === "mariadb") &&
      (row.kind === "block" ? row.depth !== 0 : row.depth > 1)) return false;
    ids.add(row.id);
  }
  return true;
}

export function isConfigVisualClosed(value: unknown): value is ConfigVisualClosed {
  return record(value) && exact(value, ["closed"]) && value.closed === true;
}

export function isConfigVisualCopyResult(value: unknown): value is ConfigVisualCopyResult {
  return record(value) && exact(value, ["byteLength"]) && count(value.byteLength, 256 * 1024);
}

export function isConfigVisualSaveResult(value: unknown): value is ConfigVisualSaveResult {
  return record(value) && exact(value, ["saved", "fileName"]) && typeof value.saved === "boolean" &&
    (value.fileName === null || typeof value.fileName === "string" && bytes(value.fileName) <= 1024) &&
    (value.saved === (value.fileName !== null));
}

/** Whether an answer belongs to the request: a new document, or the one asked about. */
export function matchesConfigVisualResponse(request: ConfigVisualRequest, value: unknown): boolean {
  if (request.action === "close") return isConfigVisualClosed(value);
  if (request.action === "database-catalog") return isConfigVisualDatabaseCatalog(value);
  if (request.action === "goal-search") return isConfigGoalSearch(value);
  // Choosing a candidate resolves it, or refuses it; it never asks again.
  if (request.action === "goal-choose") return isConfigGoalSearch(value) && value.assignment !== null && value.assignment.state !== "ambiguous";
  if (!isConfigVisualView(value)) return false;
  if (request.action === "goal-confirm") {
    // Into the open document at the next revision, or a new draft of a database file.
    return request.document !== null && value.documentHandle === request.document.documentHandle
      ? value.revision === request.document.revision + 1
      : value.revision === 1 && value.source === "goal" && value.product === "database";
  }
  switch (request.action) {
    case "new": return value.revision === 1 && value.source === (request.template === "blank" ? "blank" : "competition");
    case "open-quick": return value.revision === 1 && value.source === "quick";
    case "new-database":
      return value.revision === 1 && (value.source === "starter" || value.source === "blank") &&
        value.database?.artifactKey === request.artifactKey;
    case "view": return value.documentHandle === request.documentHandle && value.revision === request.revision;
    default: return value.documentHandle === request.documentHandle && value.revision === request.revision + 1;
  }
}
