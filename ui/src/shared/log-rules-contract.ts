/**
 * The operator's own log match rules, kept in the portable data directory.
 * Mirrors crates/lovelyhawk-backend/src/log_rules_api.rs; the limits are
 * core's (crates/lovelyhawk-core/src/log_analysis.rs).
 */
export type LogRuleSeverity = "low" | "medium" | "high" | "critical";

export const LOG_RULE_SEVERITIES: readonly LogRuleSeverity[] = Object.freeze(["low", "medium", "high", "critical"]);

export const LOG_RULE_LIMITS = Object.freeze({
  maximumRules: 128,
  maximumNameBytes: 128,
  maximumPatternBytes: 1_024,
  maximumMatchLines: 500,
  maximumMatchLineBytes: 16 * 1_024,
} as const);

export interface LogRule {
  id: string;
  name: string;
  pattern: string;
  severity: LogRuleSeverity;
}

export interface LogRuleList {
  rules: LogRule[];
  maximum: number;
}

export interface LogRuleHit {
  id: string;
  name: string;
  severity: LogRuleSeverity;
}

/** One answer per line asked about, in order. */
export interface LogRuleMatches {
  matches: (LogRuleHit | null)[];
  ruleCount: number;
}

export interface LogRuleRemovalProposal {
  handle: string;
  summary: string;
  expiresInSeconds: number;
}

export interface LogRuleRemovalResult {
  ruleId: string;
  verified: boolean;
}

export interface LogRuleRemovalCancellation {
  cancelled: true;
}

export type LogRulesRequest =
  | { action: "list" }
  | { action: "add"; name: string; pattern: string; severity: LogRuleSeverity }
  | { action: "match"; lines: string[] }
  | { action: "plan-remove"; id: string }
  | { action: "confirm-remove" | "cancel-remove"; handle: string };

export type LogRulesResponse =
  | LogRuleList
  | LogRule
  | LogRuleMatches
  | LogRuleRemovalProposal
  | LogRuleRemovalResult
  | LogRuleRemovalCancellation;

const encoder = new TextEncoder();
const byteLength = (value: string) => encoder.encode(value).byteLength;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

export function isLogRuleSeverity(value: unknown): value is LogRuleSeverity {
  return typeof value === "string" && (LOG_RULE_SEVERITIES as readonly string[]).includes(value);
}

export function isLogRuleId(value: unknown): value is string {
  return typeof value === "string" &&
    /^log-rule-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value);
}

function isPlanHandle(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value);
}

/** A name the core will take: not blank, no control characters, within its bound. */
export function isLogRuleName(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "" && !CONTROL.test(value) &&
    byteLength(value.trim()) <= LOG_RULE_LIMITS.maximumNameBytes;
}

/** Whether the pattern compiles is core's to say; this checks only its shape. */
export function isLogRulePattern(value: unknown): value is string {
  return typeof value === "string" && value !== "" && !CONTROL.test(value) &&
    byteLength(value) <= LOG_RULE_LIMITS.maximumPatternBytes;
}

export function isLogRulesRequest(value: unknown): value is LogRulesRequest {
  if (!record(value) || typeof value.action !== "string") return false;
  switch (value.action) {
    case "list":
      return exactKeys(value, ["action"]);
    case "add":
      return exactKeys(value, ["action", "name", "pattern", "severity"]) && isLogRuleName(value.name) &&
        isLogRulePattern(value.pattern) && isLogRuleSeverity(value.severity);
    case "match":
      return exactKeys(value, ["action", "lines"]) && Array.isArray(value.lines) &&
        value.lines.length <= LOG_RULE_LIMITS.maximumMatchLines &&
        value.lines.every((line) => typeof line === "string" && byteLength(line) <= LOG_RULE_LIMITS.maximumMatchLineBytes);
    case "plan-remove":
      return exactKeys(value, ["action", "id"]) && isLogRuleId(value.id);
    case "confirm-remove":
    case "cancel-remove":
      return exactKeys(value, ["action", "handle"]) && isPlanHandle(value.handle);
    default:
      return false;
  }
}

function isRule(value: unknown): value is LogRule {
  return record(value) && exactKeys(value, ["id", "name", "pattern", "severity"]) && isLogRuleId(value.id) &&
    isLogRuleName(value.name) && isLogRulePattern(value.pattern) && isLogRuleSeverity(value.severity);
}

function isHit(value: unknown): value is LogRuleHit {
  return record(value) && exactKeys(value, ["id", "name", "severity"]) && isLogRuleId(value.id) &&
    isLogRuleName(value.name) && isLogRuleSeverity(value.severity);
}

/** The answer has the shape its request asks for, and says nothing else. */
export function matchesLogRulesResponse(request: LogRulesRequest, value: unknown): value is LogRulesResponse {
  if (!record(value)) return false;
  switch (request.action) {
    case "list":
      return exactKeys(value, ["rules", "maximum"]) && Array.isArray(value.rules) &&
        value.maximum === LOG_RULE_LIMITS.maximumRules && value.rules.length <= LOG_RULE_LIMITS.maximumRules &&
        value.rules.every(isRule);
    case "add":
      return isRule(value) && value.name === request.name.trim() && value.pattern === request.pattern &&
        value.severity === request.severity;
    case "match":
      return exactKeys(value, ["matches", "ruleCount"]) && Array.isArray(value.matches) &&
        value.matches.length === request.lines.length &&
        value.matches.every((hit) => hit === null || isHit(hit)) &&
        typeof value.ruleCount === "number" && Number.isSafeInteger(value.ruleCount) &&
        value.ruleCount >= 0 && value.ruleCount <= LOG_RULE_LIMITS.maximumRules;
    case "plan-remove":
      return exactKeys(value, ["handle", "summary", "expiresInSeconds"]) && isPlanHandle(value.handle) &&
        typeof value.summary === "string" && value.summary !== "" && value.summary.length <= 1_024 &&
        typeof value.expiresInSeconds === "number" && Number.isSafeInteger(value.expiresInSeconds) &&
        value.expiresInSeconds > 0 && value.expiresInSeconds <= 3_600;
    case "confirm-remove":
      return exactKeys(value, ["ruleId", "verified"]) && isLogRuleId(value.ruleId) && typeof value.verified === "boolean";
    case "cancel-remove":
      return exactKeys(value, ["cancelled"]) && value.cancelled === true;
  }
}
