import { isPostgresqlObjectsSummary, type PostgresqlObjectsSummary } from "./postgresql-object-contract.js";
import { isRoleGraphSummary, type RoleGraphSummary } from "./postgresql-role-contract.js";
export const accessSections = ["hba", "ident", "roles", "memberships"] as const;
export type AccessSection = typeof accessSections[number];
export const accessReasons = ["permission-denied", "query-failed", "invalid-output", "limit-exceeded", "changed"] as const;
export type AccessReason = typeof accessReasons[number];
export const accessFindings = ["server-issue", "trust", "password-transport", "md5-rule", "broad-source", "unknown-method", "unknown-option", "login-superuser", "login-bypassrls", "login-createrole", "login-replication", "md5-verifier", "password-expired", "unrecognized-verifier", "membership-admin"] as const;
export type AccessFinding = typeof accessFindings[number];
const sectionFindings: Record<AccessSection, readonly AccessFinding[]> = {
  hba: accessFindings.slice(0, 7), ident: ["server-issue"], roles: accessFindings.slice(7, 14), memberships: ["membership-admin"],
};
export type AccessSectionSummary =
  | { state: "available"; reason: null; total: number; flagged: number; findings: { code: AccessFinding; count: number }[] }
  | { state: "unavailable"; reason: AccessReason; total: null; flagged: null; findings: [] };
export interface PostgresqlAccessSummary { objects: PostgresqlObjectsSummary; hba: AccessSectionSummary; ident: AccessSectionSummary; roles: AccessSectionSummary; memberships: AccessSectionSummary; roleGraph: RoleGraphSummary; passwordClassification: boolean }
export interface PostgresqlHbaRow {
  ruleNumber: number | null; fileName: string | null; lineNumber: number | null; connectionType: string | null;
  databases: string[] | null; users: string[] | null; address: string | null; netmask: string | null;
  method: string | null; optionNames: string[]; hasIssue: boolean; findings: AccessFinding[];
}
export interface PostgresqlIdentRow {
  mapNumber: number | null; fileName: string | null; lineNumber: number | null; mapName: string | null;
  systemUser: string | null; databaseUser: string | null; hasIssue: boolean; findings: AccessFinding[];
}
export interface PostgresqlRoleRow {
  oid: number; name: string; canLogin: boolean; superuser: boolean; inherit: boolean; createRole: boolean;
  createDatabase: boolean; replication: boolean; bypassRls: boolean; connectionLimit: number;
  passwordExpiresAt: string | null; passwordExpired: boolean;
  passwordKind: "none" | "md5" | "scram-sha-256" | "unrecognized" | "unavailable"; findings: AccessFinding[];
}
export interface PostgresqlMembershipRow { oid: number; roleOid: number; memberOid: number; grantorOid: number; adminOption: boolean; inheritOption: boolean; setOption: boolean; memberName: string | null; roleName: string | null; grantorName: string | null; findings: AccessFinding[] }
export type PostgresqlAccessPage = { kind: "access-rows"; jobHandle: string; query: string; offset: number; matched: number; total: number } & (
  { section: "hba"; rows: PostgresqlHbaRow[] } | { section: "ident"; rows: PostgresqlIdentRow[] } | { section: "roles"; rows: PostgresqlRoleRow[] } | { section: "memberships"; rows: PostgresqlMembershipRow[] }
);
const encoder = new TextEncoder();
function record(v: unknown): v is Record<string, unknown> { return v !== null && typeof v === "object" && !Array.isArray(v); }
function keys(v: Record<string, unknown>, fields: string[]): boolean { return Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k)); }
function text(v: unknown, cap: number, empty = false): v is string {
  return typeof v === "string" && (empty || v.length > 0) && encoder.encode(v).length <= cap && !/[\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(v);
}
function integer(v: unknown, max: number, min = 0): v is number { return typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max; }
function oneOf(v: unknown, items: readonly string[]): boolean { return typeof v === "string" && items.includes(v); }
function optionalText(v: unknown, cap: number): boolean { return v === null || text(v, cap); }
function line(v: unknown): boolean { return v === null || integer(v, 2147483647, 1); }
function selectors(v: unknown): boolean { return v === null || Array.isArray(v) && v.length > 0 && v.length <= 64 && v.every(s => text(s, 4096)); }
function findings(v: unknown, section: AccessSection): v is AccessFinding[] {
  return Array.isArray(v) && v.length <= sectionFindings[section].length && v.every(s => oneOf(s, sectionFindings[section])) && new Set(v).size === v.length;
}
function summary(v: unknown, section: AccessSection): v is AccessSectionSummary {
  if (!record(v) || !keys(v, ["state", "reason", "total", "flagged", "findings"]) || !Array.isArray(v.findings)) return false;
  if (v.state === "unavailable") return oneOf(v.reason, accessReasons) && v.total === null && v.flagged === null && v.findings.length === 0;
  if (v.state !== "available" || v.reason !== null || !integer(v.total, section === "memberships" ? 2048 : section === "roles" ? 1024 : 512) || !integer(v.flagged, v.total)) return false;
  const count = v.flagged;
  return v.findings.length <= sectionFindings[section].length && v.findings.every(f => record(f) && keys(f, ["code", "count"]) && oneOf(f.code, sectionFindings[section]) && integer(f.count, count, 1)) &&
    new Set(v.findings.map(f => f.code)).size === v.findings.length && (count === 0 ? v.findings.length === 0 : v.findings.reduce((sum, f) => sum + f.count, 0) >= count);
}
export function isPostgresqlAccessSummary(v: unknown): v is PostgresqlAccessSummary {
  return record(v) && keys(v, ["hba", "ident", "roles", "memberships", "roleGraph", "passwordClassification", "objects"]) && isPostgresqlObjectsSummary(v.objects) && summary(v.hba, "hba") && summary(v.ident, "ident") && summary(v.roles, "roles") &&
    summary(v.memberships, "memberships") && isRoleGraphSummary(v.roleGraph) && (v.roleGraph.state !== "available" || v.roles.state === "available" && v.memberships.state === "available" && v.roleGraph.additionalManagementLogins <= v.roles.total) && typeof v.passwordClassification === "boolean" && (!v.passwordClassification || v.roles.state === "available");
}
function hba(v: unknown): v is PostgresqlHbaRow {
  return record(v) && keys(v, ["ruleNumber", "fileName", "lineNumber", "connectionType", "databases", "users", "address", "netmask", "method", "optionNames", "hasIssue", "findings"]) &&
    line(v.ruleNumber) && line(v.lineNumber) && optionalText(v.fileName, 2048) && optionalText(v.connectionType, 32) && selectors(v.databases) && selectors(v.users) &&
    optionalText(v.address, 4096) && optionalText(v.netmask, 64) && optionalText(v.method, 64) && Array.isArray(v.optionNames) && v.optionNames.length <= 64 && v.optionNames.every(s => text(s, 128) && !s.includes("=")) &&
    typeof v.hasIssue === "boolean" && (v.hasIssue || [v.ruleNumber, v.fileName, v.lineNumber, v.connectionType, v.databases, v.users, v.method].every(v => v !== null)) && findings(v.findings, "hba");
}
function ident(v: unknown): v is PostgresqlIdentRow {
  return record(v) && keys(v, ["mapNumber", "fileName", "lineNumber", "mapName", "systemUser", "databaseUser", "hasIssue", "findings"]) &&
    line(v.mapNumber) && line(v.lineNumber) && optionalText(v.fileName, 2048) && [v.mapName, v.systemUser, v.databaseUser].every(s => optionalText(s, 4096)) &&
    typeof v.hasIssue === "boolean" && (v.hasIssue || [v.mapNumber, v.fileName, v.lineNumber, v.mapName, v.systemUser, v.databaseUser].every(v => v !== null)) && findings(v.findings, "ident");
}
function role(v: unknown): v is PostgresqlRoleRow {
  return record(v) && keys(v, ["oid", "name", "canLogin", "superuser", "inherit", "createRole", "createDatabase", "replication", "bypassRls", "connectionLimit", "passwordExpiresAt", "passwordExpired", "passwordKind", "findings"]) &&
    integer(v.oid, 4294967295, 1) && text(v.name, 256) && [v.canLogin, v.superuser, v.inherit, v.createRole, v.createDatabase, v.replication, v.bypassRls, v.passwordExpired].every(v => typeof v === "boolean") &&
    integer(v.connectionLimit, 2147483647, -1) && optionalText(v.passwordExpiresAt, 128) && (!v.passwordExpired || v.passwordExpiresAt !== null) &&
    oneOf(v.passwordKind, ["none", "md5", "scram-sha-256", "unrecognized", "unavailable"]) && findings(v.findings, "roles");
}
function membership(v: unknown): v is PostgresqlMembershipRow {
  return record(v) && keys(v,["oid","roleOid","memberOid","grantorOid","adminOption","inheritOption","setOption","memberName","roleName","grantorName","findings"]) &&
    [v.oid,v.roleOid,v.memberOid,v.grantorOid].every(n => integer(n,4294967295,1)) && v.roleOid !== v.memberOid &&
    [v.adminOption,v.inheritOption,v.setOption].every(b => typeof b === "boolean") && [v.memberName,v.roleName,v.grantorName].every(n => optionalText(n,256)) && findings(v.findings,"memberships");
}
export function isPostgresqlAccessPage(v: unknown): v is PostgresqlAccessPage {
  if (!record(v) || !keys(v, ["kind", "jobHandle", "section", "query", "offset", "matched", "total", "rows"]) || v.kind !== "access-rows" || !text(v.jobHandle, 128) || !text(v.query, 128, true) ||
    !integer(v.offset, v.section === "memberships" ? 2048 : 1024) || !integer(v.total, v.section === "memberships" ? 2048 : v.section === "roles" ? 1024 : 512) || !integer(v.matched, v.total) || !Array.isArray(v.rows) || v.rows.length !== Math.min(50, Math.max(0, v.matched - v.offset))) return false;
  return v.section === "hba" ? v.rows.every(hba) : v.section === "ident" ? v.rows.every(ident) : v.section === "roles" ? v.rows.every(role) : v.section === "memberships" && v.rows.every(membership);
}
