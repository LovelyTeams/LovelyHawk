export const roleAccessModes = ["member", "inherit", "set", "after-set"] as const;
export type RoleAccessMode = typeof roleAccessModes[number];
export type RoleGraphReason = "roles-unavailable" | "memberships-unavailable" | "database-unavailable" | "invalid-graph";
export interface RoleDatabaseContext { oid: number; name: string; ownerOid: number }
export type RoleGraphSummary =
  | { state: "available"; reason: null; database: RoleDatabaseContext; additionalManagementLogins: number }
  | { state: "unavailable"; reason: RoleGraphReason; database: null; additionalManagementLogins: null };
export interface RoleReference { oid: number; name: string }
export interface RoleAttributes extends RoleReference { canLogin: boolean; superuser: boolean; createRole: boolean; createDatabase: boolean; replication: boolean; bypassRls: boolean }
export interface RolePathStep { role: RoleReference; via: "source" | "grant" | "database-owner" | "superuser"; grantOid: number | null; operation: "member" | "inherit" | "set" | null }
export interface RolePathRow { target: RoleAttributes; hops: number; truncated: boolean; steps: RolePathStep[] }
export interface PostgresqlRolePage {
  kind: "role-access"; jobHandle: string; roleOid: number; source: RoleAttributes; database: RoleDatabaseContext;
  mode: RoleAccessMode; query: string; offset: number; total: number; matched: number; rows: RolePathRow[];
}
const encoder = new TextEncoder();
function record(v: unknown): v is Record<string, unknown> { return v !== null && typeof v === "object" && !Array.isArray(v); }
function keys(v: Record<string, unknown>, fields: string[]): boolean { return Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v,k)); }
function text(v: unknown, cap: number, empty = false): v is string {
  return typeof v === "string" && (empty || v.length > 0) && encoder.encode(v).length <= cap && !/[\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(v);
}
function integer(v: unknown, max: number, min = 0): v is number { return typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max; }
function oid(v: unknown): v is number { return integer(v,4294967295,1); }
function database(v: unknown): v is RoleDatabaseContext { return record(v) && keys(v,["oid","name","ownerOid"]) && oid(v.oid) && oid(v.ownerOid) && text(v.name,256); }
function reference(v: unknown): v is RoleReference { return record(v) && keys(v,["oid","name"]) && oid(v.oid) && text(v.name,256); }
export function isRoleAttributes(v: unknown): v is RoleAttributes {
  return record(v) && keys(v,["oid","name","canLogin","superuser","createRole","createDatabase","replication","bypassRls"]) && oid(v.oid) && text(v.name,256) &&
    [v.canLogin,v.superuser,v.createRole,v.createDatabase,v.replication,v.bypassRls].every(b => typeof b === "boolean");
}
const role = isRoleAttributes;
export function isRoleGraphSummary(v: unknown): v is RoleGraphSummary {
  if (!record(v) || !keys(v,["state","reason","database","additionalManagementLogins"])) return false;
  return v.state === "available" ? v.reason === null && database(v.database) && integer(v.additionalManagementLogins,1024) :
    v.state === "unavailable" && typeof v.reason === "string" && ["roles-unavailable","memberships-unavailable","database-unavailable","invalid-graph"].includes(v.reason) && v.database === null && v.additionalManagementLogins === null;
}
function step(v: unknown): v is RolePathStep {
  return record(v) && keys(v,["role","via","grantOid","operation"]) && reference(v.role) &&
    (v.via === "grant" ? oid(v.grantOid) : v.grantOid === null && ["source","database-owner","superuser"].includes(v.via as string)) &&
    (v.via === "source" ? v.operation === null : ["member","inherit","set"].includes(v.operation as string));
}
function path(v: unknown, source: RoleAttributes, context: RoleDatabaseContext, mode: RoleAccessMode): v is RolePathRow {
  if (!record(v) || !keys(v,["target","hops","truncated","steps"]) || !role(v.target) || v.target.oid === source.oid || !integer(v.hops,1024,1) ||
    typeof v.truncated !== "boolean" || v.truncated !== (v.hops + 1 > 32) || !Array.isArray(v.steps) || v.steps.length !== Math.min(32,v.hops + 1) || !v.steps.every(step)) return false;
  const steps = v.steps;
  if (steps[0]!.via !== "source" || steps[0]!.role.oid !== source.oid || steps[0]!.role.name !== source.name || new Set(steps.map(s => s.role.oid)).size !== steps.length) return false;
  if (!v.truncated && (steps.at(-1)!.role.oid !== v.target.oid || steps.at(-1)!.role.name !== v.target.name)) return false;
  let inheriting = false;
  return steps.slice(1).every((s,i) => {
    if (s.via === "source" || s.operation === null || mode !== "after-set" && s.operation !== mode) return false;
    if (mode === "after-set") {
      if (s.operation === "member" || inheriting && s.operation === "set") return false;
      inheriting ||= s.operation === "inherit";
    }
    if (s.via === "database-owner" && (s.role.oid !== 6171 || steps[i]!.role.oid !== context.ownerOid)) return false;
    if (s.via === "superuser" && !(i === 0 && source.superuser || mode === "after-set" && s.operation === "inherit" && i > 0)) return false;
    return true;
  });
}
export function isPostgresqlRolePage(v: unknown): v is PostgresqlRolePage {
  if (!record(v) || !keys(v,["kind","jobHandle","roleOid","source","database","mode","query","offset","total","matched","rows"]) ||
    v.kind !== "role-access" || !text(v.jobHandle,128) || !oid(v.roleOid) || !role(v.source) || v.roleOid !== v.source.oid || !database(v.database) ||
    typeof v.mode !== "string" || !roleAccessModes.includes(v.mode as RoleAccessMode) || !text(v.query,128,true) || !integer(v.offset,1024) ||
    !integer(v.total,1023) || !integer(v.matched,v.total) || !Array.isArray(v.rows) || v.rows.length !== Math.min(20,Math.max(0,v.matched-v.offset))) return false;
  const source = v.source, context = v.database, mode = v.mode as RoleAccessMode;
  return v.rows.every(row => path(row,source,context,mode)) && new Set(v.rows.map(row => row.target.oid)).size === v.rows.length;
}
