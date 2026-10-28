import { describe, expect, it } from "vitest";

import {
  isConfigGoalSearch,
  isConfigVisualDatabaseCatalog,
  isConfigVisualRequest,
  isConfigVisualSaveResult,
  isConfigVisualView,
  matchesConfigVisualResponse,
  type ConfigVisualView,
} from "./config-visual-contract";

const HANDLE = "00000000-0000-4000-8000-000000000001";
export const visualView: ConfigVisualView = {
  documentHandle: HANDLE, revision: 2, product: "nginx", source: "competition", structured: true, partlyOpaque: false,
  containsSensitive: false, totalBytes: 40, suggestedName: "nginx-visual.conf",
  rows: [
    { id: "18446744073709551617", parentId: null, depth: 0, kind: "block", name: "server", arguments: null,
      preview: "server { listen 80; }", childCount: 1, truncated: false, editable: true, sensitive: false, meaning: null, parameterIndex: null, searchTerms: [] },
    { id: "18446744073709551618", parentId: "18446744073709551617", depth: 1, kind: "directive", name: "listen",
      arguments: "80", preview: "listen 80;", childCount: 0, truncated: false, editable: true, sensitive: false, meaning: null, parameterIndex: null, searchTerms: [] },
  ],
  totalRows: 2, rowsTruncated: false, text: "server {\n    listen 80;\n}\n", textTruncated: false, copyAllowed: true, database: null,
};

describe("visual configuration boundary", () => {
  it("accepts only the page's own actions, exactly shaped", () => {
    const base = { documentHandle: HANDLE, revision: 2 };
    for (const ok of [
      { action: "new", product: "nginx", template: "competition" },
      { action: "new", product: "apache", template: "blank" },
      { action: "new", product: "redis", template: "competition" },
      { action: "open-quick", handle: HANDLE, revision: 1, artifactKey: "site" },
      { action: "view", ...base },
      { action: "add", ...base, parentId: null, kind: "block", name: "server", arguments: "" },
      { action: "add", ...base, parentId: null, kind: "directive", name: "listen", arguments: "80", note: "监听 80 端口" },
      { action: "add", ...base, parentId: "18446744073709551617", kind: "comment", text: "说明" },
      { action: "update", ...base, nodeId: "18446744073709551618", name: "listen", arguments: "8080" },
      { action: "update", ...base, nodeId: "18446744073709551618", text: "说明" },
      { action: "remove", ...base, nodeId: "1" },
      { action: "move", ...base, nodeId: "1", direction: "down" },
      { action: "close", ...base },
    ]) expect(isConfigVisualRequest(ok), JSON.stringify(ok)).toBe(true);
    for (const bad of [
      // Reading a local file and handing out the whole text are not the page's.
      { action: "import", product: "nginx", selectedPath: "C:/nginx.conf" },
      { action: "export", ...base, purpose: "copy" },
      { action: "new", product: "tomcat", template: "blank" },
      { action: "view", ...base, selectedPath: "C:/x" },
      // A note rides on a new directive or block only, and is a field like the rest.
      { action: "add", ...base, parentId: null, kind: "comment", text: "x", note: "说明" },
      { action: "add", ...base, parentId: null, kind: "directive", name: "listen", arguments: "80", note: "a\u0000b" },
      { action: "add", ...base, parentId: null, kind: "directive", name: "listen", arguments: "80", note: "x".repeat(70_000) },
      { action: "add", ...base, parentId: null, kind: "directive", name: "listen", arguments: "80", note: null },
      { action: "remove", ...base, nodeId: "1; rm" },
      { action: "remove", ...base, nodeId: "-1" },
      { action: "move", ...base, nodeId: "1", direction: "left" },
      { action: "add", ...base, parentId: null, kind: "directive", name: "a\u0000b", arguments: "" },
      { action: "add", ...base, parentId: null, kind: "directive", name: "listen", arguments: "x".repeat(70_000) },
      { action: "add", ...base, parentId: null, kind: "comment", text: "x", name: "listen" },
      { action: "view", documentHandle: "../x", revision: 2 },
      { action: "view", ...base, revision: 0 },
    ]) expect(isConfigVisualRequest(bad), JSON.stringify(bad).slice(0, 80)).toBe(false);
  });

  it("never accepts hidden values as text, rows out of order, or an editable hidden row", () => {
    expect(isConfigVisualView(visualView)).toBe(true);
    const [block, listen] = visualView.rows;
    for (const bad of [
      { ...visualView, containsSensitive: true },
      { ...visualView, containsSensitive: true, text: null },
      { ...visualView, rows: [listen, block] },
      { ...visualView, rows: [block, { ...listen!, sensitive: true }] },
      { ...visualView, rows: [block, { ...listen!, sensitive: true, arguments: null }] },
      { ...visualView, rows: [block, { ...listen!, kind: "opaque" }] },
      { ...visualView, rows: [block, { ...listen!, id: block!.id }] },
      // redis.conf has no blocks and nothing nested.
      { ...visualView, product: "redis" },
      { ...visualView, product: "redis", rows: [{ ...block!, kind: "directive", childCount: 0 }, listen] },
      // Nginx never keeps parts of a file as written inside a parsed one.
      { ...visualView, partlyOpaque: true },
      { ...visualView, totalRows: 1 },
      { ...visualView, localPath: "C:/x" },
    ]) expect(isConfigVisualView(bad), JSON.stringify(bad).slice(0, 120)).toBe(false);
    // A hidden row is shown hidden and locked: that is a valid view.
    const hidden = { ...visualView, containsSensitive: true, text: null, copyAllowed: false,
      rows: [block, { ...listen!, sensitive: true, arguments: null, editable: false, preview: "[敏感内容已隐藏]" }] };
    expect(isConfigVisualView(hidden)).toBe(true);
    expect(isConfigVisualView({ ...visualView, product: "apache", partlyOpaque: true, suggestedName: "httpd-visual.conf" })).toBe(true);
    const flat = { ...listen!, id: "18446744073709551619", parentId: null, depth: 0 };
    expect(isConfigVisualView({ ...visualView, product: "redis", partlyOpaque: true, suggestedName: "redis.conf",
      rows: [flat], totalRows: 1, text: "listen 80\n" })).toBe(true);
    // HAProxy: a section at the top with its lines one level below, never deeper.
    const haproxy = { ...visualView, product: "haproxy", suggestedName: "haproxy.cfg" };
    expect(isConfigVisualView(haproxy)).toBe(true);
    expect(isConfigVisualView({ ...haproxy, rows: [block, { ...listen!, kind: "block", childCount: 0 }] })).toBe(false);
    expect(isConfigVisualView({ ...haproxy, rows: [block, { ...listen!, depth: 2 }] })).toBe(false);
    // MySQL and MariaDB option files: [groups] at the top, options one level below.
    for (const product of ["mysql", "mariadb"]) {
      const options = { ...visualView, product, suggestedName: "my.cnf" };
      expect(isConfigVisualView(options), product).toBe(true);
      expect(isConfigVisualView({ ...options, rows: [block, { ...listen!, kind: "block", childCount: 0 }] }), product).toBe(false);
      expect(isConfigVisualView({ ...options, rows: [block, { ...listen!, depth: 2 }] }), product).toBe(false);
    }
    expect(isConfigVisualView({ ...visualView, product: "postgresql" })).toBe(false);
  });

  it("takes a database file's version, catalogue and meanings only in their exact shapes", () => {
    const base = { documentHandle: HANDLE, revision: 2 };
    for (const ok of [
      { action: "database-catalog" },
      { action: "new-database", artifactKey: "postgresql.conf" },
      { action: "select-schema", ...base, schema: 3 },
      { action: "select-schema", ...base, schema: null },
      { action: "set-parameter", ...base, parameterIndex: 0, value: "200" },
    ]) expect(isConfigVisualRequest(ok), JSON.stringify(ok)).toBe(true);
    for (const bad of [
      // Reading a database file from disk is the host's, never the page's.
      { action: "import-database", artifactKey: "postgresql.conf", selectedPath: "C:/pg.conf" },
      { action: "database-catalog", product: "postgresql" },
      { action: "new-database", artifactKey: "../postgresql.conf" },
      { action: "select-schema", ...base, schema: -1 },
      { action: "select-schema", ...base, schema: "PostgreSQL 16" },
      { action: "select-schema", ...base },
      { action: "set-parameter", ...base, parameterIndex: 512, value: "1" },
      { action: "set-parameter", ...base, parameterIndex: 0, value: "1\u0000" },
      { action: "set-parameter", ...base, parameterIndex: 0, value: "1", key: "max_connections" },
    ]) expect(isConfigVisualRequest(bad), JSON.stringify(bad).slice(0, 80)).toBe(false);

    const parameter = {
      index: 0, key: "max_connections", aliases: [], group: null, valueKind: "integer", valueDomain: "1 到 262143 的整数",
      scope: "instance", activation: "restart", risk: "medium", sensitivity: "public", rationale: "连接上限",
      purpose: "限制同时连接", reference: null, capability: null, documentedDefault: "100", settable: true, occurrences: 1,
      searchTerms: ["max_connections", "连接"],
    };
    const database = {
      product: "postgresql", productLabel: "PostgreSQL", artifactKey: "postgresql.conf", fileLabel: "postgresql.conf",
      syntax: "postgresql-conf", readOnly: null, schemas: [{ index: 3, label: "PostgreSQL 16.x", version: "16.0.0 及以上、低于 17.0.0", complete: false }],
      schemaIndex: 3, parameters: [parameter],
    };
    const line = { id: "18446744073709551617", parentId: null, depth: 0, kind: "directive", name: "max_connections",
      arguments: "100", preview: "max_connections = 100", childCount: 0, truncated: false, editable: true, sensitive: false,
      meaning: "catalog", parameterIndex: 0, searchTerms: ["max_connections", "连接"] };
    const view = { ...visualView, product: "database", source: "starter", suggestedName: "postgresql.conf", rows: [line],
      totalRows: 1, text: "max_connections = 100\n", database };
    expect(isConfigVisualView(view)).toBe(true);
    // Without a chosen version, rows are read by syntax and there is no catalogue.
    expect(isConfigVisualView({ ...view, rows: [{ ...line, meaning: "syntax", parameterIndex: null }],
      database: { ...database, schemaIndex: null, parameters: [] } })).toBe(true);
    for (const bad of [
      // Only a database file carries a catalogue, and every database file does.
      { ...visualView, database },
      { ...view, database: null },
      // The chosen version is one of this file's, and no catalogue comes without one.
      { ...view, database: { ...database, schemaIndex: 4 } },
      { ...view, database: { ...database, schemaIndex: null } },
      { ...view, database: { ...database, parameters: [{ ...parameter, index: 1 }] } },
      // A secret is never set from here, and a read-only file takes no value.
      { ...view, database: { ...database, parameters: [{ ...parameter, sensitivity: "may-contain-secrets" }] } },
      { ...view, database: { ...database, readOnly: "generated" } },
      // A row described by the catalogue points inside it; others point nowhere.
      { ...view, rows: [{ ...line, parameterIndex: null }] },
      { ...view, rows: [{ ...line, parameterIndex: 1 }] },
      { ...view, rows: [{ ...line, meaning: "syntax" }] },
      { ...view, rows: [{ ...line, meaning: null, parameterIndex: null }] },
      { ...visualView, rows: [{ ...visualView.rows[0]!, searchTerms: ["server"] }], totalRows: 1 },
      { ...view, database: { ...database, localPath: "C:/pg.conf" } },
    ]) expect(isConfigVisualView(bad), JSON.stringify(bad).slice(0, 160)).toBe(false);
    expect(matchesConfigVisualResponse({ action: "new-database", artifactKey: "postgresql.conf" },
      { ...view, revision: 1 })).toBe(true);
    expect(matchesConfigVisualResponse({ action: "new-database", artifactKey: "pg_hba.conf" },
      { ...view, revision: 1 })).toBe(false);
    expect(matchesConfigVisualResponse({ action: "set-parameter", ...base, revision: 1, parameterIndex: 0, value: "200" },
      view)).toBe(true);

    const catalog = { products: [{ product: "postgresql", label: "PostgreSQL", files: [
      { key: "postgresql.conf", label: "postgresql.conf", syntax: "postgresql-conf", readOnly: null, schemas: 2 },
      { key: "postgresql.auto.conf", label: "postgresql.auto.conf", syntax: "postgresql-conf", readOnly: "generated", schemas: 0 },
    ] }] };
    expect(isConfigVisualDatabaseCatalog(catalog)).toBe(true);
    expect(matchesConfigVisualResponse({ action: "database-catalog" }, catalog)).toBe(true);
    expect(isConfigVisualDatabaseCatalog({ products: [{ ...catalog.products[0], files: [] }] })).toBe(false);
    expect(isConfigVisualDatabaseCatalog({ products: [{ ...catalog.products[0], files: [
      { ...catalog.products[0]!.files[0], key: "../x" }] }] })).toBe(false);
    expect(isConfigVisualDatabaseCatalog({ products: [{ ...catalog.products[0], files: [
      { ...catalog.products[0]!.files[0], readOnly: "locked" }] }] })).toBe(false);
  });

  it("ties every answer to the document and the revision after the edit", () => {
    const base = { documentHandle: HANDLE, revision: 1 };
    expect(matchesConfigVisualResponse({ action: "remove", ...base, nodeId: "1" }, visualView)).toBe(true);
    expect(matchesConfigVisualResponse({ action: "remove", ...base, revision: 2, nodeId: "1" }, visualView)).toBe(false);
    expect(matchesConfigVisualResponse({ action: "view", ...base, revision: 2 }, visualView)).toBe(true);
    expect(matchesConfigVisualResponse({ action: "remove", documentHandle: "other", revision: 1, nodeId: "1" }, visualView)).toBe(false);
    expect(matchesConfigVisualResponse({ action: "new", product: "nginx", template: "competition" }, { ...visualView, revision: 1 })).toBe(true);
    expect(matchesConfigVisualResponse({ action: "new", product: "nginx", template: "blank" }, { ...visualView, revision: 1 })).toBe(false);
    expect(matchesConfigVisualResponse({ action: "close", ...base }, { closed: true })).toBe(true);
    expect(isConfigVisualSaveResult({ saved: true, fileName: null })).toBe(false);
    expect(isConfigVisualSaveResult({ saved: false, fileName: null })).toBe(true);
  });

  it("takes goal sentences, assignments and goal results only in their exact shapes", () => {
    const document = { documentHandle: HANDLE, revision: 3, unsaved: true };
    const lease = "00000000-0000-4000-8000-0000000000aa";
    for (const ok of [
      { action: "goal-search", query: "PostgreSQL 16 max_connections = 200", document: null },
      { action: "goal-search", query: "允许数据库远程连接", document },
      { action: "goal-choose", lease, candidate: 2, document: null },
      { action: "goal-confirm", lease, value: "300", document },
    ]) expect(isConfigVisualRequest(ok), JSON.stringify(ok)).toBe(true);
    for (const bad of [
      { action: "goal-search", query: "", document: null },
      { action: "goal-search", query: "数".repeat(129), document: null },
      { action: "goal-search", query: "ab", document: null },
      { action: "goal-search", query: "x" },
      { action: "goal-search", query: "x", document: { ...document, selectedPath: "C:/x" } },
      { action: "goal-search", query: "x", document: { ...document, revision: 0 } },
      { action: "goal-choose", lease: "../lease", candidate: 0, document: null },
      { action: "goal-choose", lease, candidate: 64, document: null },
      { action: "goal-confirm", lease, value: "a b", document: null },
      { action: "goal-confirm", lease, value: "1", document: null, key: "max_connections" },
    ]) expect(isConfigVisualRequest(bad), JSON.stringify(bad).slice(0, 80)).toBe(false);

    const schema = { index: 3, label: "PostgreSQL 16.x", version: "16.0.0 及以上、低于 17.0.0", complete: false };
    const target = { product: "postgresql", productLabel: "PostgreSQL", artifactKey: "postgresql-main",
      fileLabel: "postgresql.conf", schema, parameterIndex: 4, key: "max_connections", group: null,
      valueDomain: "文本（1 到 32 字节）", activation: "restart", risk: "high" };
    const ready = { lease, state: "ready", target, value: "250", landing: "new-draft", blocked: null, candidates: [], rejection: null };
    const answer = (assignment: unknown, results: unknown[] = [], truncated = false) => ({ assignment, results, truncated });
    expect(isConfigGoalSearch(answer(ready))).toBe(true);
    expect(isConfigGoalSearch(answer({ ...ready, landing: null, blocked: "duplicate" }))).toBe(true);
    expect(isConfigGoalSearch(answer({ lease, state: "ambiguous", target: null, value: null, landing: null, blocked: null,
      candidates: [target, { ...target, group: "mysqld" }], rejection: null }))).toBe(true);
    expect(isConfigGoalSearch(answer({ lease: null, state: "rejected", target: null, value: null, landing: null,
      blocked: null, candidates: [], rejection: "value-refused" }))).toBe(true);
    for (const bad of [
      // A value lands somewhere or is blocked: never both, never neither.
      answer({ ...ready, blocked: "duplicate" }),
      answer({ ...ready, landing: null }),
      // An ambiguous assignment shows where, never a waiting value, and offers a real choice.
      answer({ lease, state: "ambiguous", target: null, value: "60", landing: null, blocked: null, candidates: [target, target], rejection: null }),
      answer({ lease, state: "ambiguous", target: null, value: null, landing: null, blocked: null, candidates: [target], rejection: null }),
      // A refusal holds nothing to confirm.
      answer({ lease, state: "rejected", target: null, value: null, landing: null, blocked: null, candidates: [], rejection: "value-refused" }),
      answer({ lease: null, state: "rejected", target: null, value: null, landing: null, blocked: null, candidates: [], rejection: "typed" }),
      // An assignment is never mixed with fuzzy results.
      answer(ready, [{ kind: "recipe", key: "nginx.static-site", product: "nginx", productLabel: "Nginx", title: "t", summary: "s", effect: "e" }]),
      answer({ ...ready, target: { ...target, localPath: "C:/x" } }),
    ]) expect(isConfigGoalSearch(bad), JSON.stringify(bad).slice(0, 120)).toBe(false);

    const results = [
      { kind: "recipe", key: "apache.disable-trace", product: "apache", productLabel: "Apache httpd", title: "禁用 TRACE",
        summary: "生成本地草稿。", effect: "TRACE 返回 405。" },
      { kind: "database-goal", key: "database.remote-access", product: "postgresql", productLabel: "PostgreSQL",
        title: "允许远端访问", summary: "检查监听与访问控制。", artifactKey: "postgresql-main", fileLabel: "postgresql.conf", schema,
        steps: [{ title: "监听地址", explanation: "绑定的网卡。", required: true, parameters: ["listen_addresses"] },
          { title: "访问控制", explanation: "另外完成。", required: true, parameters: [] }],
        missingRequired: 1, gap: "needs-outside-steps" },
      { kind: "database-parameter", target, draftable: true, gap: null },
      { kind: "database-parameter", target: { ...target, key: "ssl_key_file" }, draftable: false, gap: "secret-value" },
      { kind: "database-file", product: "mogdb", productLabel: "MogDB", artifactKey: "mogdb-main", fileLabel: "postgresql.conf",
        opens: true, readOnly: false, gap: null },
      { kind: "unavailable", subject: "PostgreSQL", family: "database", recipes: 0, parameters: 120, files: 4, gap: "version-not-catalogued" },
    ];
    expect(isConfigGoalSearch(answer(null, results, true))).toBe(true);
    for (const bad of [
      { ...results[2], gap: "secret-value" },
      { ...results[5], gap: null },
      { ...results[5], family: "cache" },
      { ...results[1], missingRequired: 3 },
      { ...results[1], steps: [] },
      { ...results[0], value: "1" },
    ]) expect(isConfigGoalSearch(answer(null, [bad])), JSON.stringify(bad).slice(0, 120)).toBe(false);

    // A confirmed value lands in the open document at its next revision, or in a new database draft.
    const confirm = { action: "goal-confirm" as const, lease, value: "300", document };
    expect(matchesConfigVisualResponse(confirm, { ...visualView, revision: 4 })).toBe(true);
    expect(matchesConfigVisualResponse(confirm, { ...visualView, revision: 5 })).toBe(false);
    const draft = { ...visualView, documentHandle: "00000000-0000-4000-8000-0000000000bb", revision: 1, source: "goal",
      product: "database", suggestedName: "postgresql.conf", rows: [], totalRows: 0, text: "",
      database: { product: "postgresql", productLabel: "PostgreSQL", artifactKey: "postgresql-main", fileLabel: "postgresql.conf",
        syntax: "postgresql-conf", readOnly: null, schemas: [schema], schemaIndex: null, parameters: [] } };
    expect(matchesConfigVisualResponse(confirm, draft)).toBe(true);
    expect(matchesConfigVisualResponse({ ...confirm, document: null }, draft)).toBe(true);
    expect(matchesConfigVisualResponse({ ...confirm, document: null }, { ...draft, source: "starter" })).toBe(false);
    // Choosing a candidate never answers with another choice.
    expect(matchesConfigVisualResponse({ action: "goal-choose", lease, candidate: 0, document: null }, answer(ready))).toBe(true);
    expect(matchesConfigVisualResponse({ action: "goal-choose", lease, candidate: 0, document: null },
      answer({ lease, state: "ambiguous", target: null, value: null, landing: null, blocked: null, candidates: [target, target], rejection: null }))).toBe(false);
  });
});
