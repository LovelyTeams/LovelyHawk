import { isRoleAttributes, type RoleAttributes } from "./postgresql-role-contract.js";

export const objectSections = ["database", "schemas", "relations", "columns", "routines", "types", "languages", "tablespaces", "foreign-wrappers", "foreign-servers", "large-objects", "parameters", "defaults"] as const;
export type ObjectSection = typeof objectSections[number];
export const objectLimits: Record<ObjectSection, number> = { database: 128, schemas: 512, relations: 2048, columns: 2048, routines: 2048, types: 2048, languages: 128, tablespaces: 256, "foreign-wrappers": 128, "foreign-servers": 512, "large-objects": 2048, parameters: 1024, defaults: 512 };
export const objectFilters = ["all", "public", "delegated", "security-definer", "unfixed-definer"] as const;
export type ObjectFilter = typeof objectFilters[number];
export const objectPrivileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "CREATE", "CONNECT", "TEMPORARY", "EXECUTE", "USAGE", "SET", "ALTER SYSTEM", "MAINTAIN"] as const;
export type ObjectPrivilege = typeof objectPrivileges[number];
export type ObjectReason = "permission-denied" | "query-failed" | "invalid-output" | "limit-exceeded" | "changed";
export type ObjectSummary =
  | { state: "available"; reason: null; total: number; omittedDefaults: number; publicObjects: number; delegatedObjects: number; securityDefiners: number; unfixedDefiners: number }
  | { state: "unavailable"; reason: ObjectReason; total: null; omittedDefaults: null; publicObjects: null; delegatedObjects: null; securityDefiners: null; unfixedDefiners: null };
export type PostgresqlObjectsSummary = Record<ObjectSection, ObjectSummary>;
export type ObjectProperties =
  | { kind: "database"; allowConnections: boolean; isTemplate: boolean }
  | { kind: "schema"; sessionTemporary: boolean; otherTemporary: boolean }
  | { kind: "relation" | "column"; relationKind: string; rowSecurity: boolean; forceRowSecurity: boolean }
  | { kind: "routine"; routineKind: string; languageOid: number; argumentTypeOids: number[]; securityDefiner: boolean; fixedSearchPath: boolean }
  | { kind: "type"; typeKind: string; objectOwnerOid: number; aclTypeOid: number; aclTypeName: string }
  | { kind: "language"; trusted: boolean }
  | { kind: "tablespace" | "foreign-wrapper" | "foreign-server" | "large-object" | "parameter" }
  | { kind: "default"; objectType: string };
export interface PostgresqlObjectRow {
  oid: number; subId: number; name: string | null; ownerOid: number; ownerName: string | null;
  namespaceOid: number | null; namespaceName: string | null; parentName: string | null; detail: ObjectProperties;
  aclSource: "explicit" | "builtin-default" | "future-global" | "future-schema";
  catalogWriteRestricted: boolean; grantCount: number; publicPrivileges: ObjectPrivilege[]; delegated: boolean;
}
export type ObjectGrantVia = "public" | "self" | "inherit" | "after-set" | "unreachable" | "unknown-role" | "not-selected" | "future-default";
export interface ObjectGrant {
  grantorOid: number; grantorName: string | null; granteeOid: number; granteeName: string | null;
  privileges: ObjectPrivilege[]; grantOptions: ObjectPrivilege[]; via: ObjectGrantVia;
}
type ObjectImplicit = { sourceOid: number; sourceName: string; via: "superuser" | "superuser-after-set" | "self" | "inherit" | "after-set"; privileges: ObjectPrivilege[] };
export type ObjectAnalysis =
  | { state: "available"; reason: null; currentPrivileges: ObjectPrivilege[]; currentGrantOptions: ObjectPrivilege[]; additionalAfterSet: ObjectPrivilege[]; additionalGrantOptionsAfterSet: ObjectPrivilege[]; ownerVia: "superuser" | "self" | "inherit" | "after-set" | "unreachable"; schemaUsage: boolean | null; implicit: ObjectImplicit[] }
  | { state: "unavailable"; reason: "table-unavailable" | "unknown-role" | "temporary-namespace" | "database-context"; currentPrivileges: null; currentGrantOptions: null; additionalAfterSet: null; additionalGrantOptionsAfterSet: null; ownerVia: null; schemaUsage: null; implicit: [] };
export interface PostgresqlObjectPage {
  kind: "object-rows"; jobHandle: string; section: ObjectSection; query: string; filter: ObjectFilter;
  offset: number; total: number; matched: number; rows: PostgresqlObjectRow[];
}
export interface PostgresqlObjectDetail {
  kind: "object-detail"; jobHandle: string; section: ObjectSection; oid: number; subId: number; roleOid: number | null;
  object: PostgresqlObjectRow; grants: ObjectGrant[]; tableGrants: ObjectGrant[]; role: RoleAttributes | null; analysis: ObjectAnalysis | null;
}
const encoder = new TextEncoder();
function record(v: unknown): v is Record<string, unknown> { return v !== null && typeof v === "object" && !Array.isArray(v); }
function keys(v: Record<string, unknown>, fields: string[]): boolean { return Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v,k)); }
function text(v: unknown, empty = false): v is string { return typeof v === "string" && (empty || v.length > 0) && encoder.encode(v).length <= 256 && !/[\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(v); }
function integer(v: unknown, max: number, min = 0): v is number { return typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max; }
function oid(v: unknown): v is number { return integer(v,4294967295,1); }
function oneOf<T extends string>(v: unknown, choices: readonly T[]): v is T { return typeof v === "string" && choices.includes(v as T); }
function nullableName(v: unknown): boolean { return v === null || text(v); }
function summary(v: unknown, section: ObjectSection): v is ObjectSummary {
  const counts = ["total","omittedDefaults","publicObjects","delegatedObjects","securityDefiners","unfixedDefiners"];
  if (!record(v) || !keys(v,["state","reason",...counts])) return false;
  if (v.state === "unavailable") return oneOf(v.reason,["permission-denied","query-failed","invalid-output","limit-exceeded","changed"]) && counts.every(k => v[k] === null);
  return v.state === "available" && v.reason === null && integer(v.total,objectLimits[section]) && integer(v.omittedDefaults,["columns","routines","types"].includes(section) ? 4294967295 : 0) &&
    integer(v.publicObjects,v.total) && integer(v.delegatedObjects,v.total) && integer(v.securityDefiners,section === "routines" ? v.total : 0) && integer(v.unfixedDefiners,v.securityDefiners);
}
export function isPostgresqlObjectsSummary(v: unknown): v is PostgresqlObjectsSummary { return record(v) && keys(v,[...objectSections]) && objectSections.every(s => summary(v[s],s)); }
function properties(v: unknown, section: ObjectSection): v is ObjectProperties {
  if (!record(v)) return false;
  switch (section) {
    case "database": return v.kind === "database" && keys(v,["kind","allowConnections","isTemplate"]) && typeof v.allowConnections === "boolean" && typeof v.isTemplate === "boolean";
    case "schemas": return v.kind === "schema" && keys(v,["kind","sessionTemporary","otherTemporary"]) && typeof v.sessionTemporary === "boolean" && typeof v.otherTemporary === "boolean" && !(v.sessionTemporary && v.otherTemporary);
    case "relations": case "columns": return v.kind === (section === "relations" ? "relation" : "column") && keys(v,["kind","relationKind","rowSecurity","forceRowSecurity"]) && oneOf(v.relationKind,section === "relations" ? ["r","p","v","m","f","S"] : ["r","p","v","m","f"]) && typeof v.rowSecurity === "boolean" && typeof v.forceRowSecurity === "boolean";
    case "routines": return v.kind === "routine" && keys(v,["kind","routineKind","languageOid","argumentTypeOids","securityDefiner","fixedSearchPath"]) && oneOf(v.routineKind,["f","p","a","w"]) && oid(v.languageOid) && Array.isArray(v.argumentTypeOids) && v.argumentTypeOids.length <= 100 && v.argumentTypeOids.every(oid) && typeof v.securityDefiner === "boolean" && typeof v.fixedSearchPath === "boolean";
    case "types": return v.kind === "type" && keys(v,["kind","typeKind","objectOwnerOid","aclTypeOid","aclTypeName"]) && oneOf(v.typeKind,["b","c","d","e","p","r","m"]) && oid(v.objectOwnerOid) && oid(v.aclTypeOid) && text(v.aclTypeName);
    case "languages": return v.kind === "language" && keys(v,["kind","trusted"]) && typeof v.trusted === "boolean";
    case "defaults": return v.kind === "default" && keys(v,["kind","objectType"]) && oneOf(v.objectType,["r","S","f","T","n"]);
    default: return keys(v,["kind"]) && v.kind === ({ tablespaces: "tablespace", "foreign-wrappers": "foreign-wrapper", "foreign-servers": "foreign-server", "large-objects": "large-object", parameters: "parameter" } as const)[section];
  }
}
function rights(detail: ObjectProperties): readonly ObjectPrivilege[] {
  switch (detail.kind) {
    case "database": return ["CREATE","CONNECT","TEMPORARY"];
    case "schema": return ["USAGE","CREATE"];
    case "relation": return detail.relationKind === "S" ? ["SELECT","UPDATE","USAGE"] : ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","MAINTAIN"];
    case "column": return ["SELECT","INSERT","UPDATE","REFERENCES"];
    case "routine": return ["EXECUTE"];
    case "type": case "language": case "foreign-wrapper": case "foreign-server": return ["USAGE"];
    case "tablespace": return ["CREATE"];
    case "large-object": return ["SELECT","UPDATE"];
    case "parameter": return ["SET","ALTER SYSTEM"];
    case "default": return detail.objectType === "r" ? ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","MAINTAIN"] : detail.objectType === "S" ? ["SELECT","UPDATE","USAGE"] : detail.objectType === "f" ? ["EXECUTE"] : detail.objectType === "T" ? ["USAGE"] : ["USAGE","CREATE"];
  }
}
function privileges(v: unknown, allowed: readonly ObjectPrivilege[]): v is ObjectPrivilege[] { return Array.isArray(v) && v.length <= allowed.length && v.every(p => oneOf(p,allowed)) && new Set(v).size === v.length; }
function metadata(v: unknown, section: ObjectSection): v is PostgresqlObjectRow {
  if (!record(v) || !keys(v,["oid","subId","name","ownerOid","ownerName","namespaceOid","namespaceName","parentName","detail","aclSource","catalogWriteRestricted","grantCount","publicPrivileges","delegated"]) ||
    !oid(v.oid) || !oid(v.ownerOid) || !integer(v.subId,section === "columns" ? 32767 : 0,section === "columns" ? 1 : 0) || !properties(v.detail,section) ||
    !nullableName(v.ownerName) || !nullableName(v.namespaceName) || (section === "columns" ? !nullableName(v.parentName) : v.parentName !== null) ||
    (["large-objects","defaults"].includes(section) ? v.name !== null : !text(v.name)) || !integer(v.grantCount,128) || !privileges(v.publicPrivileges,rights(v.detail)) || typeof v.delegated !== "boolean") return false;
  const namespaceRequired = ["relations","columns","routines","types"].includes(section);
  if (namespaceRequired ? !oid(v.namespaceOid) : section === "defaults" ? v.namespaceOid !== null && !oid(v.namespaceOid) : v.namespaceOid !== null) return false;
  if (v.namespaceOid === null && v.namespaceName !== null) return false;
  const source = section === "defaults" ? v.namespaceOid === null ? "future-global" : "future-schema" : null;
  if (source ? v.aclSource !== source : !oneOf(v.aclSource,section === "columns" ? ["explicit"] : ["explicit","builtin-default"])) return false;
  const protectedCatalog = (v.detail.kind === "relation" || v.detail.kind === "column") && v.detail.relationKind !== "v" && (v.oid < 12000 || v.namespaceOid === 99);
  return v.catalogWriteRestricted === protectedCatalog;
}
export function isPostgresqlObjectPage(v: unknown): v is PostgresqlObjectPage {
  if (!record(v) || !keys(v,["kind","jobHandle","section","query","filter","offset","total","matched","rows"]) || v.kind !== "object-rows" || !text(v.jobHandle) || encoder.encode(v.jobHandle).length > 128 ||
    !oneOf(v.section,objectSections) || !oneOf(v.filter,objectFilters) || !text(v.query,true) || encoder.encode(v.query).length > 128 || !integer(v.offset,2048) || !integer(v.total,objectLimits[v.section]) || !integer(v.matched,v.total) ||
    !Array.isArray(v.rows) || v.rows.length !== Math.min(50,Math.max(0,v.matched-v.offset))) return false;
  const section = v.section;
  return v.rows.every(r => metadata(r,section)) && new Set(v.rows.map(r => `${r.oid}:${r.subId}`)).size === v.rows.length && v.rows.every(r => v.filter === "all" || v.filter === "public" ? v.filter === "all" || r.publicPrivileges.length > 0 : v.filter === "delegated" ? r.delegated : r.detail.kind === "routine" && r.detail.securityDefiner && (v.filter === "security-definer" || !r.detail.fixedSearchPath));
}
function grants(v: unknown, allowed: readonly ObjectPrivilege[], role: RoleAttributes | null, future: boolean): v is ObjectGrant[] {
  if (!Array.isArray(v) || v.length > 128) return false;
  return v.every((g,i) => record(g) && keys(g,["grantorOid","grantorName","granteeOid","granteeName","privileges","grantOptions","via"]) && oid(g.grantorOid) && integer(g.granteeOid,4294967295) && nullableName(g.grantorName) && nullableName(g.granteeName) &&
    privileges(g.privileges,allowed) && g.privileges.length > 0 && privileges(g.grantOptions,g.privileges) &&
    (g.granteeOid !== 0 || g.granteeName === "PUBLIC" && g.grantOptions.length === 0) &&
    (future ? g.via === "future-default" : g.granteeOid === 0 ? g.via === "public" : role === null ? g.via === "not-selected" : g.granteeOid === role.oid ? g.via === "self" : oneOf(g.via,["inherit","after-set","unreachable","unknown-role"])) &&
    (i === 0 || v[i-1].grantorOid < g.grantorOid || v[i-1].grantorOid === g.grantorOid && v[i-1].granteeOid < g.granteeOid));
}
function analysis(v: unknown, object: PostgresqlObjectRow, role: RoleAttributes): v is ObjectAnalysis {
  const fields = ["currentPrivileges","currentGrantOptions","additionalAfterSet","additionalGrantOptionsAfterSet"];
  if (!record(v) || !keys(v,["state","reason",...fields,"ownerVia","schemaUsage","implicit"]) || !Array.isArray(v.implicit)) return false;
  if (v.state === "unavailable") return oneOf(v.reason,["table-unavailable","unknown-role","temporary-namespace","database-context"]) && [...fields,"ownerVia","schemaUsage"].every(k => v[k] === null) && v.implicit.length === 0;
  const allowed = rights(object.detail);
  if (v.state !== "available" || v.reason !== null || !fields.every(k => privileges(v[k],allowed)) || !oneOf(v.ownerVia,["superuser","self","inherit","after-set","unreachable"]) || (object.namespaceOid === null ? v.schemaUsage !== null : v.schemaUsage !== null && typeof v.schemaUsage !== "boolean") || v.implicit.length > 5) return false;
  const current = v.currentPrivileges as ObjectPrivilege[], options = v.currentGrantOptions as ObjectPrivilege[];
  return (v.additionalAfterSet as ObjectPrivilege[]).every(p => !current.includes(p)) && (v.additionalGrantOptionsAfterSet as ObjectPrivilege[]).every(p => !options.includes(p)) &&
    (v.ownerVia !== "superuser" || role.superuser) && v.implicit.every(g => record(g) && keys(g,["sourceOid","sourceName","via","privileges"]) && oid(g.sourceOid) && text(g.sourceName) && privileges(g.privileges,allowed) && g.privileges.length > 0 &&
      (g.via === "superuser" ? role.superuser && g.sourceOid === role.oid && g.sourceName === role.name : g.via === "superuser-after-set" ? g.sourceOid !== role.oid : oneOf(g.via,["self","inherit","after-set"]) &&
        (g.sourceOid === 6181 && g.sourceName === "pg_read_all_data" || g.sourceOid === 6182 && g.sourceName === "pg_write_all_data" || g.sourceOid === 6337 && g.sourceName === "pg_maintain")));
}
export function isPostgresqlObjectDetail(v: unknown): v is PostgresqlObjectDetail {
  if (!record(v) || !keys(v,["kind","jobHandle","section","oid","subId","roleOid","object","grants","tableGrants","role","analysis"]) || v.kind !== "object-detail" || !text(v.jobHandle) || encoder.encode(v.jobHandle).length > 128 ||
    !oneOf(v.section,objectSections) || !metadata(v.object,v.section) || v.oid !== v.object.oid || v.subId !== v.object.subId ||
    (v.roleOid === null ? v.role !== null || v.analysis !== null : !oid(v.roleOid) || !isRoleAttributes(v.role) || v.role.oid !== v.roleOid || !analysis(v.analysis,v.object,v.role)) ||
    v.section === "defaults" && v.roleOid !== null) return false;
  const role = v.role as RoleAttributes | null, object = v.object;
  if (!grants(v.grants,rights(object.detail),role,v.section === "defaults") || v.grants.length !== object.grantCount ||
    !grants(v.tableGrants,["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","MAINTAIN"],role,false) || v.section !== "columns" && v.tableGrants.length > 0) return false;
  const publicRights = [...new Set(v.grants.filter(g => g.granteeOid === 0).flatMap(g => g.privileges))];
  return publicRights.length === object.publicPrivileges.length && publicRights.every(p => object.publicPrivileges.includes(p)) && object.delegated === v.grants.some(g => g.granteeOid !== object.ownerOid && g.grantOptions.length > 0);
}
