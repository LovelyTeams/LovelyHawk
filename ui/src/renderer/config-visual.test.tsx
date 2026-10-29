import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  ConfigVisualApi,
  ConfigVisualDatabase,
  ConfigVisualParameter,
  ConfigVisualProduct,
  ConfigVisualRow,
  ConfigVisualView,
} from "../shared/config-visual-contract";
import { ConfigArtifactNotes } from "./ConfigArtifactNotes";
import {
  DatabaseParameterDetail,
  DatabaseVersionPanels,
  databaseParameterMatches,
} from "./DatabaseFilePanels";
import {
  configVisualCatalog,
  configVisualFileItems,
  configVisualHelp,
  configVisualPlace,
  configVisualRowHelp,
  configVisualSuggestions,
} from "./config-visual-glossary";
import {
  configVisualCheckAdvice,
  configVisualRowLabel,
  configVisualRowReason,
  configVisualSignature,
  nearestConfigVisualRow,
  visibleConfigVisualRows,
} from "./config-visual-helpers";
import { ConfigVisualEditor } from "./ConfigVisualEditor";

function row(id: string, parentId: string | null, depth: number, kind: ConfigVisualRow["kind"], name: string | null,
  args: string | null, extra: Partial<ConfigVisualRow> = {}): ConfigVisualRow {
  return { id, parentId, depth, kind, name, arguments: args, preview: `${name ?? "#"} ${args ?? ""}`, childCount: 0,
    truncated: false, editable: kind !== "opaque", sensitive: false, meaning: null, parameterIndex: null,
    searchTerms: [], ...extra };
}

const rows: ConfigVisualRow[] = [
  row("1", null, 0, "block", "http", null, { childCount: 2 }),
  row("2", "1", 1, "comment", null, "location of the admin area"),
  row("3", "1", 1, "block", "server", null, { childCount: 2 }),
  row("4", "3", 2, "directive", "proxy_pass", "http://location-backend:8080"),
  row("5", "3", 2, "block", "location", "/admin/", { childCount: 0 }),
  row("6", null, 0, "directive", "user", "nginx"),
];

describe("visual configuration helpers", () => {
  it("searches only kinds and names, and keeps every block a match sits in", () => {
    expect(visibleConfigVisualRows(rows, "LOCATION").map((r) => r.id)).toEqual(["1", "3", "5"]);
    // The word sits in a comment and an argument, which are never searched.
    expect(visibleConfigVisualRows(rows, "admin")).toEqual([]);
    expect(visibleConfigVisualRows(rows, "backend")).toEqual([]);
    expect(visibleConfigVisualRows(rows, "注释").map((r) => r.id)).toEqual(["1", "2"]);
    expect(visibleConfigVisualRows(rows, "  ")).toHaveLength(rows.length);
    expect(visibleConfigVisualRows(rows, "loc\u0007")).toEqual([]);
    expect(visibleConfigVisualRows(rows, "x".repeat(129))).toEqual([]);
  });

  it("names rows in words and says why a row is locked", () => {
    expect(configVisualRowLabel(rows[2]!)).toBe("块 · server · 2 个子项");
    expect(configVisualRowLabel(rows[3]!)).toBe("指令 · proxy_pass");
    expect(configVisualRowLabel(rows[1]!)).toBe("注释");
    expect(configVisualRowReason(rows[3]!)).toBeNull();
    expect(configVisualRowReason({ ...rows[3]!, sensitive: true, editable: false, arguments: null })).toContain("已隐藏");
    expect(configVisualRowReason(row("9", null, 0, "opaque", null, null))).toContain("原样保留");
    expect(configVisualRowReason({ ...rows[3]!, editable: false, truncated: true })).toContain("太长");
    // A file the server writes is shown, never changed, whatever its rows look like.
    expect(configVisualRowReason({ ...rows[3]!, editable: false }, "database", true)).toContain("这个文件只读");
  });

  it("finds the edited row again by what it is, nearest where it was", () => {
    const moved = [rows[0]!, rows[2]!, rows[1]!, rows[3]!, rows[4]!, rows[5]!];
    expect(nearestConfigVisualRow(moved, configVisualSignature(rows[1]!), 1)?.id).toBe("2");
    expect(nearestConfigVisualRow(moved, configVisualSignature({ kind: "directive", depth: 0, name: "missing", arguments: null }), 0)).toBeNull();
  });

  it("a Chinese query also finds items by their built-in note, never by values", () => {
    // user's note says it is the account the workers run as.
    expect(visibleConfigVisualRows(rows, "账号").map((r) => r.id)).toEqual(["6"]);
    expect(visibleConfigVisualRows(rows, "转发").map((r) => r.id)).toEqual(["1", "3", "4"]);
    // An ASCII word is matched against names and kinds only, as before.
    expect(visibleConfigVisualRows(rows, "account")).toEqual([]);
  });

  it("tells each product how to check a file before it is deployed", () => {
    expect(configVisualCheckAdvice("nginx")).toContain("nginx -t");
    expect(configVisualCheckAdvice("apache")).toContain("apachectl -t");
    expect(configVisualCheckAdvice("redis")).toContain("redis-server");
    expect(configVisualCheckAdvice("redis")).not.toContain("-t");
    expect(configVisualCheckAdvice("haproxy")).toContain("haproxy -c -f");
  });
});

describe("built-in Chinese notes", () => {
  const products: readonly ConfigVisualProduct[] = ["nginx", "apache", "redis", "haproxy", "mysql", "mariadb"];

  it("reads option files the way MySQL and MariaDB do: groups, - and _ alike, include lines", () => {
    // Option names are read without regard to case, with - and _ alike.
    expect(configVisualHelp("mysql", "directive", "BIND_ADDRESS")?.summary).toContain("127.0.0.1");
    expect(configVisualHelp("mariadb", "directive", "max-connections")?.caution).toContain("内存");
    expect(configVisualHelp("mysql", "directive", "!includedir")?.summary).toContain(".cnf");
    expect(configVisualHelp("mysql", "directive", "! include")?.summary).toContain("选项文件");
    const names = (product: ConfigVisualProduct, kind: "directive" | "block", place: string) =>
      configVisualSuggestions(product, kind, place).map((entry) => entry.name);
    expect(names("mysql", "block", "")).toEqual(expect.arrayContaining(["mysqld", "client", "mysqldump"]));
    expect(names("mysql", "block", "")).not.toContain("galera");
    expect(names("mariadb", "block", "")).toEqual(expect.arrayContaining(["mysqld", "server", "mariadb", "galera"]));
    expect(names("mysql", "directive", "mysqld")).toEqual(expect.arrayContaining(
      ["bind-address", "max_connections", "local_infile", "secure_file_priv", "skip-name-resolve", "!include", "!includedir"]));
    expect(names("mysql", "directive", "mysqld")).not.toContain("safe-updates");
    expect(names("mysql", "directive", "client")).toEqual(expect.arrayContaining(["user", "host", "port", "default-character-set"]));
    expect(names("mysql", "directive", "client")).not.toContain("bind-address");
    // The same word means different things in a server group and a client group.
    expect(configVisualHelp("mysql", "directive", "user", "mysqld")?.summary).toContain("系统账号");
    expect(configVisualHelp("mysql", "directive", "user", "client")?.summary).toContain("数据库账号");
    // Every server group is a server place, whatever MariaDB or a version calls it.
    const group = (name: string) => ({ id: name, parentId: null, depth: 0, kind: "block" as const, name, arguments: null,
      preview: `[${name}]`, childCount: 1, truncated: false, editable: true, sensitive: false, meaning: null, parameterIndex: null, searchTerms: [] });
    for (const [name, place] of [["mysqld", "mysqld"], ["mysqld-8.0", "mysqld"], ["server", "mysqld"], ["mariadb", "mysqld"],
      ["galera", "mysqld"], ["client-server", "client"], ["mysqldump", "mysqldump"], ["mysqld_safe", "mysqld_safe"]] as const) {
      expect(configVisualPlace([group(name)], group(name), "mariadb"), name).toBe(place);
    }
    // Every option the generators write (crates/lovelyhawk-core/src/{mysql,mariadb}_config.rs) is explained.
    for (const [product, names] of [
      ["mysql", ["bind_address", "port", "mysqlx", "local_infile", "secure_file_priv", "skip_networking", "max_connections",
        "connect_timeout", "max_connect_errors", "wait_timeout", "interactive_timeout", "slow_query_log", "long_query_time",
        "log_error_verbosity", "log_bin", "server_id", "binlog_expire_logs_seconds"]],
      ["mariadb", ["bind_address", "port", "local_infile", "skip_name_resolve", "max_connections", "connect_timeout", "wait_timeout",
        "interactive_timeout", "max_connect_errors", "max_allowed_packet", "character_set_server", "collation_server", "log_error",
        "log_output", "log_slow_query", "log_slow_query_file", "log_slow_query_time", "slow_query_log", "long_query_time",
        "innodb_buffer_pool_size", "innodb_doublewrite", "innodb_flush_log_at_trx_commit", "innodb_lock_wait_timeout",
        "innodb_print_all_deadlocks", "log_bin", "server_id", "binlog_expire_logs_seconds", "sync_binlog"]],
    ] as const) {
      for (const name of names) expect(configVisualHelp(product, "directive", name, "mysqld"), `${product} ${name}`).not.toBeNull();
    }
    // A generated option file lists its groups and options once each, not its include lines.
    const items = configVisualFileItems("mariadb", "# 说明\n[mariadb]\nbind_address = 127.0.0.1\nskip-name-resolve\n; 注释\n!includedir /etc/mysql/conf.d/\n[client]\nport=3306\nbind-address = ::1\n");
    expect(items.map((item) => `${item.kind}:${item.name}`)).toEqual(
      ["block:mariadb", "directive:bind_address", "directive:skip-name-resolve", "block:client", "directive:port"]);
    expect(items[1]?.help?.summary).toContain("网卡地址");
  });
  // A note can be written into the file as a comment; any of these words
  // would make the editor treat the whole file as holding a secret.
  const secretWords = /authorization|password|passwd|secret|credential|api_?key|bearer |private[_ ]key|access_token|requirepass|masterauth|:\/\//iu;

  it("every note is plain Chinese, one line, and could be written as a comment", () => {
    for (const product of products) {
      const catalog = configVisualCatalog(product);
      expect(catalog.length, product).toBeGreaterThan(30);
      for (const entry of catalog) {
        const label = `${product} ${entry.kind} ${entry.name}`;
        expect(entry.summary, label).toMatch(/\p{Script=Han}/u);
        expect(entry.summary, label).not.toMatch(secretWords);
        for (const text of [entry.summary, entry.example ?? "", entry.caution ?? ""]) {
          expect(text, label).not.toMatch(/[\u0000-\u001f\u007f]/u);
        }
        expect(entry.name, label).toMatch(/^[A-Za-z][A-Za-z0-9_.-]*$/u);
      }
    }
  });

  it("knows names the way each server does: Nginx exactly, Apache and Redis in any case", () => {
    expect(configVisualHelp("nginx", "directive", "listen")?.summary).toContain("端口");
    expect(configVisualHelp("nginx", "directive", "LISTEN")).toBeNull();
    expect(configVisualHelp("apache", "directive", "servertokens")?.example).toBe("Prod");
    expect(configVisualHelp("redis", "directive", "PROTECTED-MODE")?.caution).toContain("no");
    expect(configVisualHelp("nginx", "directive", "no_such_thing")).toBeNull();
    expect(configVisualHelp("nginx", "directive", "  ")).toBeNull();
  });

  it("offers what fits where the new item goes", () => {
    const names = (product: ConfigVisualProduct, kind: "directive" | "block", place: string) =>
      configVisualSuggestions(product, kind, place).map((entry) => entry.name);
    expect(names("nginx", "directive", "server")).toEqual(expect.arrayContaining(["listen", "server_name", "root"]));
    expect(names("nginx", "directive", "server")).not.toContain("worker_connections");
    expect(names("nginx", "directive", "server")).not.toContain("proxy_pass");
    expect(names("nginx", "directive", "stream-server")).toEqual(expect.arrayContaining(["listen", "proxy_pass"]));
    expect(names("nginx", "directive", "events")).toEqual(expect.arrayContaining(["worker_connections"]));
    expect(names("nginx", "block", "")).toEqual(expect.arrayContaining(["events", "http"]));
    expect(names("nginx", "block", "")).not.toContain("location");
    expect(names("apache", "directive", "directory")).toEqual(expect.arrayContaining(["AllowOverride", "Require", "Options"]));
    expect(names("apache", "directive", "directory")).not.toContain("Listen");
    expect(names("redis", "directive", "")).toEqual(expect.arrayContaining(["bind", "protected-mode", "maxmemory", "rename-command"]));
    expect(names("redis", "block", "")).toEqual([]);
    expect(names("haproxy", "block", "")).toEqual(expect.arrayContaining(["global", "defaults", "frontend", "backend", "listen"]));
    expect(names("haproxy", "block", "frontend")).toEqual([]);
    expect(names("haproxy", "directive", "frontend")).toEqual(expect.arrayContaining(["bind", "default_backend", "http-request"]));
    expect(names("haproxy", "directive", "frontend")).not.toContain("balance");
    expect(names("haproxy", "directive", "backend")).toEqual(expect.arrayContaining(["server", "balance", "http-check"]));
    expect(names("haproxy", "directive", "backend")).not.toContain("bind");
    // The same word means different things in different sections.
    expect(configVisualHelp("haproxy", "directive", "user", "global")?.summary).toContain("系统账号");
    expect(configVisualHelp("haproxy", "directive", "user", "userlist")?.summary).toContain("口令");
  });

  it("lists what a generated file uses, once each, skipping value pairs and comments", () => {
    const nginx = "# 注释 listen\nhttp {\n    map $a $b {\n        default upgrade;\n        '' close;\n    }\n    server {\n        listen 80;\n        listen 443 ssl;\n        no_such_thing on;\n    }\n}\n";
    const items = configVisualFileItems("nginx", nginx);
    expect(items.map((item) => `${item.kind}:${item.name}`)).toEqual(
      ["block:http", "block:map", "block:server", "directive:listen", "directive:no_such_thing"]);
    expect(items.find((item) => item.name === "listen")?.help?.summary).toContain("端口");
    expect(items.find((item) => item.name === "no_such_thing")?.help).toBeNull();
    const apache = configVisualFileItems("apache", "<VirtualHost *:80>\n  ServerName a\n  servername b\n</VirtualHost>\n");
    expect(apache.map((item) => `${item.kind}:${item.name}`)).toEqual(["block:VirtualHost", "directive:ServerName"]);
    const redis = configVisualFileItems("redis", "bind 127.0.0.1\n# port 1\nport 6379\nBIND ::1\n");
    expect(redis.map((item) => item.name)).toEqual(["bind", "port"]);
    const html = renderToStaticMarkup(<ConfigArtifactNotes product="redis" text={"bind 127.0.0.1\nprotected-mode yes\n"} />);
    expect(html).toContain("这份文件用到的 2 个配置项");
    expect(html).toContain("保护模式");
    expect(html).toContain("注意：");
    expect(renderToStaticMarkup(<ConfigArtifactNotes product="redis" text={"# only a comment\n"} />)).toBe("");
  });

  it("finds the place from the blocks around it, seeing through Apache's IfModule", () => {
    const nginx = [
      row("1", null, 0, "block", "stream", null, { childCount: 1 }),
      row("2", "1", 1, "block", "server", null),
      row("3", null, 0, "block", "http", null, { childCount: 1 }),
      row("4", "3", 1, "block", "server", null, { childCount: 1 }),
      row("5", "4", 2, "block", "map", "$a $b", { childCount: 1 }),
      row("6", "5", 3, "directive", "default", "0"),
    ];
    expect(configVisualPlace(nginx, nginx[1]!, "nginx")).toBe("stream-server");
    expect(configVisualPlace(nginx, nginx[3]!, "nginx")).toBe("server");
    expect(configVisualPlace(nginx, null, "nginx")).toBe("");
    // A line inside map is a pair of values, not a directive called default.
    expect(configVisualRowHelp(nginx[5]!, nginx, "nginx")?.summary).toContain("对应关系");
    const apache = [
      row("1", null, 0, "block", "VirtualHost", "*:80", { childCount: 1 }),
      row("2", "1", 1, "block", "IfModule", "headers_module", { childCount: 0 }),
      row("3", null, 0, "block", "Directory", "/srv", { childCount: 0 }),
    ];
    expect(configVisualPlace(apache, apache[1]!, "apache")).toBe("virtualhost");
    expect(configVisualPlace(apache, apache[2]!, "apache")).toBe("directory");
    const haproxy = [row("1", null, 0, "block", "frontend", "web", { childCount: 1 }), row("2", "1", 1, "directive", "bind", ":80")];
    expect(configVisualPlace(haproxy, haproxy[0]!, "haproxy")).toBe("frontend");
    expect(configVisualRowHelp(haproxy[1]!, haproxy, "haproxy")?.summary).toContain("监听的地址和端口");
    expect(configVisualFileItems("haproxy", "global\n    daemon\n# x\nfrontend web # main\n    bind :80\n    .if defined(X)\n")
      .map((item) => `${item.kind}:${item.name}`)).toEqual(["block:global", "directive:daemon", "block:frontend", "directive:bind"]);
  });
});

describe("visual configuration editor", () => {
  const api: ConfigVisualApi = {
    configVisual: vi.fn(async () => ({ closed: true as const })),
    importConfigVisual: vi.fn(async () => null),
    importConfigVisualDatabase: vi.fn(async () => null),
    copyConfigVisual: vi.fn(async () => ({ byteLength: 0 })),
    saveConfigVisual: vi.fn(async () => ({ saved: false, fileName: null })),
  };

  it("explains what it is for before any document is open", () => {
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} />);
    expect(html).toContain("把 Nginx、Apache httpd、Redis、HAProxy、MySQL 或 MariaDB 配置当成一棵树来改");
    expect(html).toContain(">MySQL</button>");
    expect(html).toContain(">MariaDB</button>");
    expect(html).toContain("中文说明");
    expect(html).toContain(">Redis</button>");
    expect(html).toContain("新建比赛模板");
    expect(html).toContain("导入本地文件…");
    expect(html).toContain("在可视化编辑中打开");
  });

  it("shows a document's rows and full text, and hides both for hidden values", () => {
    const view: ConfigVisualView = {
      documentHandle: "doc-1", revision: 3, product: "nginx", source: "quick", structured: true, partlyOpaque: false, containsSensitive: false,
      totalBytes: 30, suggestedName: "nginx-visual.conf", rows: rows.slice(0, 3), totalRows: 3, rowsTruncated: false,
      text: "http {\n    # <script>alert(1)</script>\n}\n", textTruncated: false, copyAllowed: true, database: null,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={view} />);
    expect(html).toContain("来自快速生成");
    expect(html).toContain("块 · server · 2 个子项");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("nginx -t");
    const hidden = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={{
      ...view, containsSensitive: true, text: null, copyAllowed: false,
      rows: [{ ...rows[0]!, sensitive: true, editable: false, preview: "[敏感内容已隐藏]" }], totalRows: 1,
    }} />);
    expect(hidden).toContain("疑似口令、令牌");
    expect(hidden).toContain("不在这里显示全文");
    expect(hidden).toContain("内容已隐藏");
    const copy = hidden.match(/<button[^>]*>复制全部<\/button>/u)?.[0] ?? "";
    expect(copy).toContain("disabled=\"\"");
  });

  it("nginx_import_result_replaces_a_stale_apache_visual_document", () => {
    const source = readFileSync(new URL("./ConfigVisualEditor.tsx", import.meta.url), "utf8");
    const replace = source.slice(source.indexOf("async function replaceDocument"), source.indexOf("async function openNew"));
    // Unsaved edits are asked about before any dialog opens; a cancelled dialog changes nothing.
    expect(replace.indexOf("confirmDiscard()")).toBeGreaterThan(-1);
    expect(replace.indexOf("confirmDiscard()")).toBeLessThan(replace.indexOf("await open()"));
    expect(replace).toContain("if (next === null) return;");
    // Only once the new document is in hand is the one it replaces released,
    // and the new one starts clean: nothing selected, no search, nothing unsaved.
    expect(replace.indexOf('action: "close", documentHandle: previous.documentHandle')).toBeGreaterThan(replace.indexOf("if (next === null) return;"));
    for (const reset of ["setView(next);", "setDirty(false);", "setSelectedId(null);", 'setQuery("");']) expect(replace).toContain(reset);
    expect(source).toContain("await replaceDocument(() => api.importConfigVisual(product),");

    const imported: ConfigVisualView = {
      documentHandle: "doc-9", revision: 1, product: "nginx", source: "import", structured: true, partlyOpaque: false, containsSensitive: false,
      totalBytes: 41, suggestedName: "nginx.conf", rows: [row("1", null, 0, "block", "events", null), row("2", null, 0, "block", "http", null, { childCount: 1 })],
      totalRows: 2, rowsTruncated: false, text: "events {}\nhttp { server { listen 80; } }\n", textTruncated: false, copyAllowed: true, database: null,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={imported} />);
    expect(html).toMatch(/data-testid="config-visual-status"><strong>Nginx<\/strong><span>导入的文件<\/span>/u);
    expect(html).toContain("没有未另存的修改");
    expect(html).toContain("events {}\nhttp { server { listen 80; } }\n");
    expect(html).not.toContain("Apache httpd 配置");
  });

  it("speaks Apache's words for an Apache file", () => {
    const view: ConfigVisualView = {
      documentHandle: "doc-2", revision: 1, product: "apache", source: "import", structured: true, partlyOpaque: true,
      containsSensitive: false, totalBytes: 60, suggestedName: "httpd-visual.conf",
      rows: [row("1", null, 0, "block", "VirtualHost", "*:80", { childCount: 1 }), row("2", "1", 1, "directive", "ServerName", "a.test"),
        row("3", null, 0, "opaque", null, null, { preview: "<Perl> …" })],
      totalRows: 3, rowsTruncated: false, text: "<VirtualHost *:80>\n    ServerName a.test\n</VirtualHost>\n", textTruncated: false,
      copyAllowed: true, database: null,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={view} />);
    expect(html).toContain("Apache httpd");
    expect(html).toContain("区段 · VirtualHost · 1 个子项");
    expect(html).not.toContain("apachectl -t");
    expect(html).toContain("&lt;Perl&gt; 段");
    expect(html).not.toContain("nginx -t");
    expect(visibleConfigVisualRows(view.rows, "区段", "apache").map((r) => r.id)).toEqual(["1"]);
    // Each known row carries its note in Chinese.
    expect(html).toContain("站点的主机名");
  });

  it("shows HAProxy sections with their lines, and asks for a section before a setting", () => {
    const view: ConfigVisualView = {
      documentHandle: "doc-4", revision: 2, product: "haproxy", source: "competition", structured: true, partlyOpaque: false,
      containsSensitive: false, totalBytes: 40, suggestedName: "haproxy.cfg",
      rows: [row("1", null, 0, "block", "frontend", "web", { childCount: 1 }), row("2", "1", 1, "directive", "bind", ":80")],
      totalRows: 2, rowsTruncated: false, text: "frontend web\n    bind :80\n", textTruncated: false, copyAllowed: true, database: null,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={view} />);
    expect(html).toContain("区段 · frontend · 1 个子项");
    expect(html).toContain("对外入口");
    expect(html).not.toContain("haproxy -c -f");
    expect(html).not.toContain("nginx -t");
    // Nothing selected: a setting has no section to go into yet.
    expect(html).toContain("HAProxy 的设置必须写在区段里");
    const submit = html.match(/<button type="submit"[^>]*>添加指令<\/button>/u)?.[0] ?? "";
    expect(submit).toContain("disabled=\"\"");
  });

  it("shows a MySQL option file as groups of options, and asks for a group before an option", () => {
    const view: ConfigVisualView = {
      documentHandle: "doc-6", revision: 2, product: "mysql", source: "competition", structured: true, partlyOpaque: false,
      containsSensitive: false, totalBytes: 60, suggestedName: "my.cnf",
      rows: [row("1", null, 0, "block", "mysqld", null, { childCount: 2 }), row("2", "1", 1, "directive", "bind-address", "127.0.0.1"),
        row("3", "1", 1, "directive", "skip-name-resolve", null)],
      totalRows: 3, rowsTruncated: false, text: "[mysqld]\nbind-address=127.0.0.1\nskip-name-resolve\n", textTruncated: false,
      copyAllowed: true, database: null,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={view} />);
    expect(html).toContain("选项组 · mysqld · 2 个子项");
    expect(html).toContain("选项 · bind-address");
    expect(html).toContain("只允许本机连接");
    expect(html).toContain("不对客户端地址做反向域名解析");
    expect(html).not.toContain("--validate-config");
    expect(html).not.toContain("nginx -t");
    // Nothing selected: an option has no group to go into yet; only include lines may stand outside one.
    expect(html).toContain("选项必须写在选项组里");
    const submit = html.match(/<button type="submit"[^>]*>添加选项<\/button>/u)?.[0] ?? "";
    expect(submit).toContain("disabled=\"\"");
    expect(html).toContain("<span>值</span>");
    // Product advice is shown after saving, rather than as a permanent banner.
    const mariadb = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={{ ...view, product: "mariadb" }} />);
    expect(mariadb).not.toContain("my_print_defaults");
    expect(mariadb).not.toContain("--validate-config");
  });

  it("shows a Redis file as one flat list, with notes, and offers no blocks", () => {
    const view: ConfigVisualView = {
      documentHandle: "doc-3", revision: 2, product: "redis", source: "competition", structured: true, partlyOpaque: true,
      containsSensitive: false, totalBytes: 40, suggestedName: "redis.conf",
      rows: [row("1", null, 0, "comment", null, "只监听本机"), row("2", null, 0, "directive", "bind", "127.0.0.1 -::1"),
        row("3", null, 0, "opaque", null, null, { preview: "bind \"broken" })],
      totalRows: 3, rowsTruncated: false, text: "# 只监听本机\nbind 127.0.0.1 -::1\nbind \"broken\n", textTruncated: false,
      copyAllowed: true, database: null,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={view} />);
    expect(html).toContain("配置项 · bind");
    expect(html).toContain("监听哪些网卡地址");
    expect(html).not.toContain("redis-server");
    expect(html).not.toContain("nginx -t");
    expect(html).toContain("Redis 配置没有块");
    expect(html).not.toContain("加在文件最外层");
    expect(html).not.toMatch(/name="config-visual-add-kind"[^>]*\/?>块</u);
    expect(html).toContain("引号没有闭合");
    // The common items come with their notes, and a note goes above a new item by default.
    expect(html).toContain("protected-mode — 保护模式");
    const toggle = html.match(/<input[^>]*data-testid="config-visual-note-toggle"[^>]*>/u)?.[0] ?? "";
    expect(toggle).toContain("checked=\"\"");
    expect(html).toContain("在上方加一行中文注释");
  });
});

describe("catalogued database files", () => {
  const parameter = (index: number, key: string, extra: Partial<ConfigVisualParameter> = {}): ConfigVisualParameter => ({
    index, key, aliases: [], group: null, valueKind: "integer", valueDomain: "1 到 262143 的整数", scope: "instance",
    activation: "restart", risk: "medium", sensitivity: "public", rationale: "连接太多会耗尽内存。", purpose: "限制同时连接的数量。",
    reference: null, capability: null, documentedDefault: "100", settable: true, occurrences: 0, searchTerms: [key], ...extra,
  });
  const database: ConfigVisualDatabase = {
    product: "postgresql", productLabel: "PostgreSQL", artifactKey: "postgresql.conf", fileLabel: "postgresql.conf",
    syntax: "postgresql-conf", readOnly: null,
    schemas: [{ index: 3, label: "PostgreSQL 16.x", version: "16.0.0 及以上、低于 17.0.0", complete: false },
      { index: 4, label: "MySQL 8.0.11 及以上、低于 8.1.0", version: "8.0.11 及以上、低于 8.1.0", complete: true }],
    schemaIndex: 3,
    parameters: [
      parameter(0, "max_connections", { occurrences: 1, searchTerms: ["max_connections", "连接"] }),
      parameter(1, "ssl", { valueKind: "boolean", valueDomain: "on 或 off", activation: "reload", risk: "high", searchTerms: ["ssl", "加密"] }),
      parameter(2, "ssl_key_file", { valueKind: "text", valueDomain: "文件路径", sensitivity: "private-key-reference", settable: false,
        documentedDefault: "", rationale: "<script>alert(1)</script>" }),
    ],
  };
  const noop = { onSchema: () => undefined, onSetParameter: async () => false };
  const api: ConfigVisualApi = {
    configVisual: vi.fn(async () => ({ closed: true as const })),
    importConfigVisual: vi.fn(async () => null),
    importConfigVisualDatabase: vi.fn(async () => null),
    copyConfigVisual: vi.fn(async () => ({ byteLength: 0 })),
    saveConfigVisual: vi.fn(async () => ({ saved: false, fileName: null })),
  };

  it("says which version a file is read against, and lists that version's parameters", () => {
    const html = renderToStaticMarkup(<DatabaseVersionPanels database={database} working={false} {...noop} />);
    expect(html).toContain("对照的版本");
    expect(html).toContain("PostgreSQL · postgresql.conf");
    expect(html).toContain("不对照（只按语法显示）");
    expect(html).toContain("PostgreSQL 16.x（16.0.0 及以上、低于 17.0.0） · 部分参数");
    // A name that already spells out its range does not repeat it.
    expect(html).toContain(">MySQL 8.0.11 及以上、低于 8.1.0<");
    expect(html).toContain("目录里的参数（3）");
    expect(html).toContain("文件里有 1 处 · 中风险");
    expect(html).toContain("文件里没有 · 高风险");
    expect(html).toContain("没有核对过目标服务器");
    // Nothing is chosen yet, so nothing can be written.
    expect(html).not.toContain("config-visual-parameter-apply");
    // Without a chosen version there is no catalogue to list.
    const plain = renderToStaticMarkup(<DatabaseVersionPanels database={{ ...database, schemaIndex: null, parameters: [] }} working={false} {...noop} />);
    expect(plain).not.toContain("目录里的参数");
    const generated = renderToStaticMarkup(<DatabaseVersionPanels database={{ ...database, readOnly: "generated" }} working={false} {...noop} />);
    expect(generated).toContain("由服务器或厂商工具生成");
    const vendor = renderToStaticMarkup(<DatabaseVersionPanels database={{ ...database, readOnly: "vendor-schema", schemas: [], schemaIndex: null, parameters: [] }} working={false} {...noop} />);
    expect(vendor).toContain("选择版本也不会解锁修改");
    expect(vendor).toContain("内置目录还没有这个文件的版本说明");
  });

  it("explains a parameter from the catalogue only, as plain text", () => {
    const html = renderToStaticMarkup(<DatabaseParameterDetail parameter={database.parameters[2]!} testId="detail" />);
    expect(html).toContain("私钥引用，值会被隐藏");
    expect(html).toContain("重启后生效");
    expect(html).toContain("实例");
    expect(html).toContain("（空字符串）");
    expect(html).toContain("以上来自内置目录，没有核对过任何服务器。");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
  });

  it("finds parameters by their reviewed words and Chinese labels, never by a value", () => {
    const [connections, ssl] = database.parameters;
    expect(databaseParameterMatches(connections!, "MAX_conn")).toBe(true);
    expect(databaseParameterMatches(connections!, "连接")).toBe(true);
    expect(databaseParameterMatches(ssl!, "高风险")).toBe(true);
    expect(databaseParameterMatches(ssl!, "重新加载")).toBe(true);
    expect(databaseParameterMatches(connections!, "高风险")).toBe(false);
    expect(databaseParameterMatches(connections!, "x".repeat(129))).toBe(false);
    expect(databaseParameterMatches(connections!, "max\u0000")).toBe(false);
    // A database file's tree is searched by the words core gave each row, not its arguments.
    const rows = [
      row("1", null, 0, "directive", "max_connections", "secret-looking-value", { meaning: "catalog", parameterIndex: 0, searchTerms: ["max_connections", "连接"] }),
      row("2", null, 0, "directive", "custom.thing", "1", { meaning: "syntax", searchTerms: ["custom.thing"] }),
    ];
    expect(visibleConfigVisualRows(rows, "连接", "database").map((item) => item.id)).toEqual(["1"]);
    expect(visibleConfigVisualRows(rows, "secret", "database")).toEqual([]);
    expect(visibleConfigVisualRows(rows, "custom", "database").map((item) => item.id)).toEqual(["2"]);
    expect(configVisualRowLabel(rows[0]!, "database")).toBe("配置项 · max_connections");
    expect(configVisualCheckAdvice("database")).toContain("没有核对过任何服务器");
  });

  it("opens a database file with its version panels and marks the rows the catalogue describes", () => {
    const view: ConfigVisualView = {
      documentHandle: "doc-db", revision: 2, product: "database", source: "starter", structured: true, partlyOpaque: false,
      containsSensitive: false, totalBytes: 22, suggestedName: "postgresql.conf",
      rows: [
        row("1", null, 0, "directive", "max_connections", "100", { meaning: "catalog", parameterIndex: 0, searchTerms: ["max_connections"] }),
        row("2", null, 0, "directive", "custom.thing", "1", { meaning: "syntax", searchTerms: ["custom.thing"] }),
      ],
      totalRows: 2, rowsTruncated: false, text: "max_connections = 100\ncustom.thing = 1\n", textTruncated: false,
      copyAllowed: true, database,
    };
    const html = renderToStaticMarkup(<ConfigVisualEditor api={api} initialView={view} />);
    expect(html).toContain("PostgreSQL · postgresql.conf");
    expect(html.match(/data-testid="config-visual-row-catalog"/gu)?.length).toBe(1);
    expect(html).toContain("目录里的参数（3）");
    expect(html).toContain("例如 max_connections");
    expect(html).toContain("起始内容");
    // postgresql.conf has no groups, and is not called Redis for it.
    expect(html).toContain("这种文件没有分组，新配置项加在文件末尾");
    expect(html).not.toContain("Redis 配置没有块");
    // A read-only file offers no way to add to it.
    const readOnly = renderToStaticMarkup(<ConfigVisualEditor api={api}
      initialView={{ ...view, source: "blank", rows: [], totalRows: 0, text: "", database: { ...database, readOnly: "generated",
        parameters: database.parameters.map((item) => ({ ...item, settable: false })) } }} />);
    expect(readOnly).toContain("由服务器或厂商工具生成");
    expect(readOnly).toContain("这个文件只读，不能添加新项。");
    expect(readOnly).toContain("这个文件只读，不能修改或添加。");
    expect(readOnly).not.toContain("config-visual-add-kind");
  });
});
