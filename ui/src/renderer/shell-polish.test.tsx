import { readdirSync, readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ConnectionSummary, PageDescriptor } from "../shared/contract";
import { hasNavIcon, NavIcon } from "./nav-icons";
import { SidebarTarget } from "./SidebarTarget";
import { quickConnections, TargetRequiredBanner } from "./TargetRequiredBanner";
import { applyUiPreferences, sidebarWidthFor, SIDEBAR_WIDTH_RANGE } from "./ui-preferences";
import { WelcomeView } from "./WelcomeView";

const backendSource = readFileSync(new URL("../../../crates/lovelyhawk-backend/src/lib.rs", import.meta.url), "utf8");
const pageIds = [...backendSource.matchAll(/PageDescriptor \{\s*id: "([a-z-]+)"/gu)].map((match) => match[1] ?? "");

function connection(id: string, name: string, lastConnectedAt: string | null): ConnectionSummary {
  return {
    id, name, host: "10.0.0.8", port: 22, username: "ops", authMethod: "password", tags: [], group: null,
    environment: null, lastConnectedAt, hasPassword: true, hasKeyPassphrase: false,
    jumpHostHasPassword: false, jumpHostHasKeyPassphrase: false,
  } as ConnectionSummary;
}

class FakeRoot {
  readonly dataset: Record<string, string> = {};
  readonly properties = new Map<string, string>();
  readonly style = { setProperty: (name: string, value: string) => { this.properties.set(name, value); } };
}

describe("interface settings", () => {
  it("applies every stored setting and clamps the drawn sidebar width", () => {
    const root = new FakeRoot();
    const applied = applyUiPreferences(root as unknown as HTMLElement, {
      sidebarWidth: 800, showStatusBar: false, compactMode: true, animationsEnabled: false,
    });
    expect(applied).toEqual({ sidebarWidth: SIDEBAR_WIDTH_RANGE.maximum, showStatusBar: false, compactMode: true, animationsEnabled: false });
    expect(root.properties.get("--sidebar-width")).toBe("360px");
    expect(root.dataset).toEqual({ density: "compact", motion: "reduced" });
    expect(sidebarWidthFor(120)).toBe(200);
    expect(sidebarWidthFor(Number.NaN)).toBe(240);
    expect(sidebarWidthFor(271.6)).toBe(272);
  });

  it("keeps the status bar's entries reachable when it is hidden", () => {
    const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(app).toContain('uiPreferences.showStatusBar ? "window-shell" : "window-shell no-statusbar"');
    expect(app).toContain('data-testid="sidebar-open-application-log"');
    expect(app).toContain('data-testid="sidebar-open-disposal-report"');
    expect(app).toContain("error={uiPreferences.showStatusBar ? null : targetError}");
    const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
    expect(css).toContain(".window-shell.no-statusbar { grid-template-rows: var(--titlebar-height) minmax(0, 1fr); }");
    expect(css).toContain(':root[data-motion="reduced"]');
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
  });
});

describe("navigation", () => {
  it("draws an icon for every page the backend registers", () => {
    expect(pageIds).toHaveLength(15);
    for (const id of pageIds) expect(hasNavIcon(id), id).toBe(true);
    expect(renderToStaticMarkup(<NavIcon pageId="docker" glyph="▣" />)).toContain("<svg");
    // An unknown page still shows its registry glyph, as plain text.
    expect(renderToStaticMarkup(<NavIcon pageId="future-page" glyph="<b>" />)).toBe('<span class="nav-glyph" aria-hidden="true">&lt;b&gt;</span>');
  });

  it("names pages in Chinese", () => {
    expect(backendSource).toMatch(/id: "notes",\s*group: Investigation,\s*title: "笔记",/u);
  });

  it("labels dialogs in Chinese and never with the old product name", () => {
    const files = ["DialogHost.tsx", "AiHistoryPage.tsx", "ConnectionManager.tsx", "Notes.tsx", "SshAttemptDialog.tsx"];
    for (const file of files) {
      const text = readFileSync(new URL(`./${file}`, import.meta.url), "utf8");
      // An eyebrow is a few words of plain Chinese, not an English capitalised tag.
      expect(text, file).not.toMatch(/eyebrow[^>]*>\s*[!A-Z][A-Z /!]{3,}</u);
      expect(text, file).not.toMatch(/DANGEROUS OPERATION|KEYBOARD INTERACTIVE|"CONFIRM"|"LOVELYRES"/u);
    }
    const dialog = readFileSync(new URL("./DialogHost.tsx", import.meta.url), "utf8");
    expect(dialog).toContain('{dangerous ? "危险操作" : dialog.kind === "confirm" ? "请确认" : "提示"}');
  });

  it("keeps implementation words out of Chinese interface text", () => {
    const directory = new URL("./", import.meta.url);
    const files = readdirSync(directory).filter((name) => /\.tsx?$/u.test(name) && !name.includes(".test."));
    const jargon = /Rust|sidecar|RPC|renderer|preload|opaque|句柄|代际|边界校验|本地预算|绑定快照|目标绑定|当前绑定|绑定可能|能力可能|SSH 绑定|切换绑定|绑定终端|主机密钥绑定|安全绑定|不可变|固定根目录|固定入口|页面失活|领域化|消费者|字节安全边界|Phase \d/u;
    const offenders: string[] = [];
    for (const file of files) {
      const text = readFileSync(new URL(file, directory), "utf8");
      // A visible string: quoted or between tags, holding Chinese and one of the words.
      for (const match of text.matchAll(/["'`>]([^"'`<>\n]*)["'`<]/gu)) {
        const value = match[1] ?? "";
        if (/[一-鿿]/u.test(value) && jargon.test(value)) offenders.push(`${file}: ${value.trim()}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("labels things in Chinese unless the label is a proper name", () => {
    const directory = new URL("./", import.meta.url);
    // Proper names and the standard technical terms an operator matches against
    // other tools: log levels as they appear in the records, Docker's own names.
    const names = new Set(["LovelyHawk", "Kubernetes", "Docker", "Cascadia Mono", "SSH", "SFTP", "PostgreSQL", "Redis", "Nginx",
      "MySQL", "API Key", "HTTP", "IPAM", "Ingress", "DEBUG", "INFO", "WARN", "ERROR"]);
    const offenders: string[] = [];
    for (const file of readdirSync(directory).filter((name) => name.endsWith(".tsx") && !name.includes(".test."))) {
      const text = readFileSync(new URL(file, directory), "utf8");
      // A text node between tags made only of English words, like >Provider<.
      // `(?<![=-])` skips arrow types such as `=> Promise<void>`.
      for (const match of text.matchAll(/(?<![=-])>\s*([A-Za-z][A-Za-z ]{2,}[A-Za-z])\s*</gu)) {
        const label = match[1] ?? "";
        if (!names.has(label)) offenders.push(`${file}: ${label}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("target status and connecting", () => {
  it("shows the target as plain text and offers terminal and disconnect", () => {
    const connected = renderToStaticMarkup(
      <SidebarTarget
        target={{ connectionId: "c", host: "</strong><script>x()</script>", port: 22, username: "root", timestamp: "t" }}
        disconnecting={false}
        onConnect={() => undefined}
        onOpenTerminal={() => undefined}
        onDisconnect={() => undefined}
      />,
    );
    expect(connected).toContain("已连接");
    expect(connected).toContain("root@&lt;/strong&gt;&lt;script&gt;x()&lt;/script&gt;:22");
    expect(connected).toContain('data-testid="sidebar-open-terminal"');
    expect(connected).toContain('data-testid="sidebar-disconnect-target"');
    const idle = renderToStaticMarkup(
      <SidebarTarget target={null} disconnecting={false} onConnect={() => undefined}
        onOpenTerminal={() => undefined} onDisconnect={() => undefined} error="SSH 目标断开失败。" />,
    );
    expect(idle).toContain("未连接目标");
    expect(idle).toContain('data-testid="sidebar-connect-target"');
    expect(idle).toContain('role="alert"');
  });

  it("offers the three most recently used connections first", () => {
    const list = [
      connection("a", "旧", "2026-01-01T00:00:00Z"),
      connection("b", "从未", null),
      connection("c", "最新", "2026-10-01T00:00:00Z"),
      connection("d", "较新", "2026-05-01T00:00:00Z"),
    ];
    expect(quickConnections(list).map((item) => item.id)).toEqual(["c", "d", "a"]);
    const markup = renderToStaticMarkup(<TargetRequiredBanner pageTitle="Docker" connections={list} onConnect={() => undefined} />);
    expect(markup).toContain("「Docker」需要先连接一台 SSH 目标");
    expect(markup.match(/class="content-connect-recent"/gu)).toHaveLength(3);
    expect(markup).toContain('data-testid="content-connect-target"');
    const empty = renderToStaticMarkup(<TargetRequiredBanner pageTitle="Docker" connections={[]} onConnect={() => undefined} />);
    expect(empty).toContain("还没有保存的连接");
    // With nothing saved the one way forward is named for what it does.
    expect(empty).toContain(">新建连接</button>");
    // The card says what the page is for and what it shows once connected.
    const described = renderToStaticMarkup(<TargetRequiredBanner pageTitle="Docker" summary="检查容器、镜像、网络与运行日志。"
      sections={["容器与安全风险", "日志与容器终端"]} connections={list} onConnect={() => undefined} />);
    expect(described).toContain("<h1>Docker</h1>");
    expect(described).toContain("检查容器、镜像、网络与运行日志。");
    expect(described).toContain("连接后可以使用");
    expect(described.match(/<li>/gu)).toHaveLength(2);
    expect(described).toContain(">连接目标</button>");
  });
});

describe("welcome view", () => {
  it("starts with connecting and offers the tools that need no target as small buttons", () => {
    const offline = [
      { id: "notes", title: "笔记", summary: "记录笔记。", icon: "▤" },
      { id: "security-reference", title: "安全速查", summary: "离线速查。", icon: "◇" },
    ] as PageDescriptor[];
    const markup = renderToStaticMarkup(
      <WelcomeView connections={[]} offlinePages={offline} onNavigate={() => undefined}
        onOpenConnections={() => undefined} onConnectionAction={() => undefined} onCreateConnection={() => undefined} />,
    );
    expect(markup).toContain("开始一次应急响应");
    // The start screen keeps to the start: no step-by-step route under it.
    expect(markup).not.toContain("welcome-flow");
    expect(markup).toContain('data-testid="welcome-tool-notes"');
    // A tool is a name and an icon; what it does is its tooltip.
    expect(markup).toContain('title="记录笔记。"');
    expect(markup).not.toContain("<small>记录笔记。</small>");
    expect(markup).toContain('data-testid="welcome-open-connections"');
    // One "新建连接" button: the empty list points at it instead of repeating it.
    expect(markup.match(/class="welcome-create-button"/gu)).toHaveLength(1);
  });

  it("does not call an unreadable connection store empty", () => {
    const markup = renderToStaticMarkup(
      <WelcomeView connections={[]} connectionsError="无法读取本机保存的连接文件。 (connections-store-unreadable)"
        onConnectionAction={() => undefined} onCreateConnection={() => undefined} />,
    );
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("无法读取本机保存的连接文件");
    expect(markup).not.toContain("还没有保存任何连接");
  });
});

describe("host overview", () => {
  it("points a truncated table at something that exists", () => {
    const page = readFileSync(new URL("./SystemInfoPage.tsx", import.meta.url), "utf8");
    // Filtering only covers the current snapshot. More rows need a new collect.
    expect(page).not.toContain("用上面的筛选");
    expect(page).toContain("重新采集前");
    expect(page).toContain("changeRowLimit(nextLimit)");
    expect(page).toContain("已达采集行数或大小上限");
  });
});

describe("startup", () => {
  it("does not let the connection list keep the app from starting", () => {
    const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    // Bootstrap is the only read the shell waits for; the list's failure is kept.
    expect(app).toContain("void Promise.all([window.lovelyhawk.bootstrap(), savedConnections])");
    expect(app).toMatch(/const savedConnections = window\.lovelyhawk\.listConnections\(\)\.then\(\s*\(list\) => \(\{ list, error: null \}\),/u);
    expect(app).toContain("connectionsError={connectionsError}");
  });
});
