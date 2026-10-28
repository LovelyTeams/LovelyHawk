import type {
  ConfigVisualDocumentProduct,
  ConfigVisualKind,
  ConfigVisualProduct,
  ConfigVisualRow,
  ConfigVisualSource,
} from "../shared/config-visual-contract";
import { configVisualRowHelps } from "./config-visual-glossary";

export const MAX_CONFIG_VISUAL_QUERY_CHARS = 128;

/** MySQL and MariaDB read the same option-file syntax: [groups] of options. */
export function isOptionFileProduct(product: ConfigVisualDocumentProduct): product is "mysql" | "mariadb" {
  return product === "mysql" || product === "mariadb";
}

/**
 * A container is a block in Nginx, a section (<VirtualHost …>, frontend …)
 * in Apache and HAProxy, an option group ([mysqld]) in a MySQL or MariaDB
 * option file, and a 分组 in a catalogued database file. A Redis line is a
 * 配置项: redis.conf has no containers; an option-file line is a 选项.
 */
export function configVisualKindLabel(kind: ConfigVisualKind, product: ConfigVisualDocumentProduct = "nginx"): string {
  switch (kind) {
    case "directive":
      return product === "redis" || product === "database" ? "配置项" : isOptionFileProduct(product) ? "选项" : "指令";
    case "block":
      return product === "apache" || product === "haproxy" ? "区段"
        : isOptionFileProduct(product) ? "选项组" : product === "database" ? "分组" : "块";
    case "comment": return "注释";
    case "opaque": return "原文";
  }
}

export function configVisualProductLabel(product: ConfigVisualDocumentProduct): string {
  switch (product) {
    case "nginx": return "Nginx";
    case "apache": return "Apache httpd";
    case "redis": return "Redis";
    case "haproxy": return "HAProxy";
    case "mysql": return "MySQL";
    case "mariadb": return "MariaDB";
    case "database": return "数据库配置文件";
  }
}

/** How to check a file on the target before it is deployed, as a sentence. */
export function configVisualCheckAdvice(product: ConfigVisualDocumentProduct): string {
  switch (product) {
    case "nginx": return "部署前请在目标上用 nginx -t 检查。";
    case "apache": return "部署前请在目标上用 apachectl -t 检查。";
    // redis-server has no switch that only checks a file.
    case "redis": return "Redis 没有单独检查配置文件的命令，部署前请先在测试环境用 redis-server 加载这个文件，确认能启动、日志里没有报错。";
    case "haproxy": return "部署前请在目标上用同一版本的 haproxy -c -f 加文件路径检查。";
    case "mysql": return "部署前请在目标上用同一版本的 mysqld --defaults-file=文件路径 --validate-config 检查（MySQL 8.0.16 起支持）。";
    // MariaDB has no switch that only checks a file.
    case "mariadb": return "MariaDB 没有单独检查配置文件的命令，部署前请在目标上用 my_print_defaults --defaults-file=文件路径 mysqld 核对会生效的选项，再在测试环境用这个文件启动，确认日志里没有报错。";
    case "database": return "这里的参数说明来自内置目录，没有核对过任何服务器；部署前请在目标上用对应产品和版本的官方工具检查，并在测试环境确认能正常启动。";
  }
}

export function configVisualSourceLabel(source: ConfigVisualSource): string {
  switch (source) {
    case "blank": return "空白文档";
    case "competition": return "比赛模板";
    case "quick": return "来自快速生成";
    case "import": return "导入的文件";
    case "starter": return "起始内容";
    case "goal": return "按赋值新建";
  }
}

/**
 * Rows a search keeps: those whose kind or name matches, with every block
 * they sit in, in document order.
 *
 * Only the kind and the name are searched — never arguments, comment text or
 * the preview, which may hold paths, upstream addresses or values a person
 * would not want a stray search to surface. A query in Chinese also matches
 * the built-in note for an item (端口 finds listen), which is fixed text and
 * not from the file. Matching is ASCII case-insensitive; a query that is too
 * long or carries control characters matches nothing.
 */
export function visibleConfigVisualRows(rows: readonly ConfigVisualRow[], rawQuery: string,
  product: ConfigVisualDocumentProduct = "nginx"): ConfigVisualRow[] {
  const query = rawQuery.trim();
  if (query === "") return [...rows];
  if ([...query].length > MAX_CONFIG_VISUAL_QUERY_CHARS || /[\u0000-\u001f\u007f-\u009f]/u.test(query)) return [];
  const needle = asciiLower(query);
  // A database file's rows carry the words core allows them to be found by
  // (name and reviewed catalogue words, never a value); other files use the
  // built-in notes.
  const notes = product !== "database" && /\p{Script=Han}/u.test(query) ? configVisualRowHelps(rows, product) : null;
  const byId = new Map(rows.map((row) => [row.id, row]));
  const keep = new Set<string>();
  for (const row of rows) {
    const haystacks = [configVisualKindLabel(row.kind, product), row.kind];
    if (product === "database") haystacks.push(...row.searchTerms);
    else if ((row.kind === "directive" || row.kind === "block") && row.name !== null) haystacks.push(row.name);
    const note = notes?.get(row.id);
    if (note !== undefined) haystacks.push(note.summary);
    if (!haystacks.some((text) => asciiLower(text).includes(needle))) continue;
    for (let current: ConfigVisualRow | undefined = row; current !== undefined && !keep.has(current.id);
      current = current.parentId === null ? undefined : byId.get(current.parentId)) {
      keep.add(current.id);
    }
  }
  return rows.filter((row) => keep.has(row.id));
}

function asciiLower(text: string): string {
  return text.replace(/[A-Z]/gu, (letter) => letter.toLowerCase());
}

/** The one line a tree row shows: what it is, and its name. */
export function configVisualRowLabel(row: ConfigVisualRow, product: ConfigVisualDocumentProduct = "nginx"): string {
  const kind = configVisualKindLabel(row.kind, product);
  if (row.kind === "block") return `${kind} · ${row.name ?? "（无名称）"}${row.childCount > 0 ? ` · ${row.childCount} 个子项` : ""}`;
  if (row.kind === "directive") return `${kind} · ${row.name ?? "（无名称）"}`;
  return kind;
}

/** Why a row can or cannot be changed here, in words. */
export function configVisualRowReason(row: ConfigVisualRow, product: ConfigVisualDocumentProduct = "nginx",
  fileReadOnly = false): string | null {
  if (fileReadOnly) return "这个文件只读，这一项只能查看，不能在这里修改、删除或移动。另存的副本与原文件逐字节相同。";
  if (row.sensitive) return "这一项含有疑似口令、令牌或带账号的地址，内容已隐藏，不能在这里修改、删除、移动或往里添加。另存文件时会原样保留。";
  if (row.kind === "opaque") return `这段内容没能按 ${configVisualProductLabel(product)} 语法解析（${unparsedExample(product)}），只能原样保留，不能逐项编辑。`;
  if (!row.editable) return "这一项的名称或参数太长，页面上显示不全，为了不截掉后面的内容，不能在这里修改。";
  return null;
}

function unparsedExample(product: ConfigVisualDocumentProduct): string {
  switch (product) {
    case "nginx": return "例如不是 UTF-8 文本";
    case "apache": return "例如 Apache 的 <Perl> 段，或不是 UTF-8 文本";
    case "redis": return "例如引号没有闭合，或只有名称没有值";
    case "haproxy": return "例如引号没有闭合、.if 这类条件行，或写在所有区段之外的设置";
    case "mysql":
    case "mariadb": return "例如写在所有选项组之外的选项、带引号或转义的 !include 路径，或文件开头的 BOM";
    case "database": return "例如这种文件的语法读不懂的行，或不是 UTF-8 的内容";
  }
}

/** Parts of a readable file kept as written, said for each product. */
export function configVisualPartlyOpaqueNotice(product: ConfigVisualDocumentProduct): string {
  switch (product) {
    case "redis":
      return "文件里有几行不能按 Redis 的规则拆成名称和值（例如引号没有闭合），标为“原文”原样保留，不能逐项编辑；其余行可以正常修改。";
    case "haproxy":
      return "文件里有几行不能按 HAProxy 的规则读取（例如引号没有闭合、.if 这类条件行，或写在所有区段之外的设置），标为“原文”原样保留，不能逐项编辑；其余行可以正常修改。";
    case "mysql":
    case "mariadb":
      return `文件里有几行不能按 ${configVisualProductLabel(product)} 选项文件的规则读取（${unparsedExample(product)}），标为“原文”原样保留，不能逐项编辑；其余行可以正常修改。`;
    case "database":
      return `文件里有几行不能按这种文件的语法读取（${unparsedExample(product)}），标为“原文”原样保留，不能逐项编辑；其余行可以正常查看。`;
    default:
      return "文件里有一部分（例如 <Perl> 段）不是 Apache 指令，标为“原文”原样保留，不能逐项编辑；其余部分可以正常修改。";
  }
}

/** The facts about a row's place in the file, without its values. */
export function configVisualRowFacts(row: ConfigVisualRow, product: ConfigVisualDocumentProduct = "nginx"): string {
  return [
    `类型：${configVisualKindLabel(row.kind, product)}`,
    `层级：${row.depth + 1}`,
    row.kind === "block" ? `直接子项：${row.childCount}` : null,
    `能在这里修改：${row.editable ? "能" : "不能"}`,
  ].filter((part) => part !== null).join(" · ");
}

/** What identifies a row across an edit, which hands out new ids. */
export function configVisualSignature(row: Pick<ConfigVisualRow, "kind" | "name" | "arguments" | "depth">): string {
  return JSON.stringify([row.kind, row.depth, row.name, row.arguments]);
}

/**
 * The row to select after an edit: the one with this signature nearest the
 * place the old selection was, or none.
 */
export function nearestConfigVisualRow(rows: readonly ConfigVisualRow[], signature: string, nearIndex: number): ConfigVisualRow | null {
  let best: ConfigVisualRow | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  rows.forEach((row, index) => {
    if (configVisualSignature(row) !== signature) return;
    const distance = Math.abs(index - nearIndex);
    if (distance < bestDistance) {
      best = row;
      bestDistance = distance;
    }
  });
  return best;
}

export function formatConfigVisualBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
