import { objectSections, type PostgresqlObjectRow, type PostgresqlObjectPage, type PostgresqlObjectDetail, type PostgresqlObjectsSummary } from "./postgresql-object-contract";
export function unavailableObjects(): PostgresqlObjectsSummary {
  return Object.fromEntries(objectSections.map(s => [s,{ state: "unavailable", reason: "permission-denied", total: null, omittedDefaults: null, publicObjects: null, delegatedObjects: null, securityDefiners: null, unfixedDefiners: null }])) as PostgresqlObjectsSummary;
}

export const objectRow: PostgresqlObjectRow = { oid: 18000, subId: 0, name: "<script>fixture</script>", ownerOid: 10, ownerName: "owner", namespaceOid: 2200, namespaceName: "public", parentName: null, detail: { kind: "relation", relationKind: "r", rowSecurity: true, forceRowSecurity: false }, aclSource: "explicit", catalogWriteRestricted: false, grantCount: 1, publicPrivileges: ["SELECT"], delegated: false };
export const objectPage: PostgresqlObjectPage = { kind: "object-rows", jobHandle: "j", section: "relations", query: "", filter: "all", offset: 0, total: 1, matched: 1, rows: [objectRow] };
export const objectDetail: PostgresqlObjectDetail = { kind: "object-detail", jobHandle: "j", section: "relations", oid: 18000, subId: 0, roleOid: null, object: objectRow, grants: [{ grantorOid: 10, grantorName: "owner", granteeOid: 0, granteeName: "PUBLIC", privileges: ["SELECT"], grantOptions: [], via: "public" }], tableGrants: [], role: null, analysis: null };
