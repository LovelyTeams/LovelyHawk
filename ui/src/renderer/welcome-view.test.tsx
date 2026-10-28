import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { lastConnectedLabel, welcomeConnectionOrder, WelcomeView } from "./WelcomeView";
import type { ConnectionSummary } from "../shared/contract";

const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");

function connection(overrides: Partial<ConnectionSummary> = {}): ConnectionSummary {
  return {
    id: "connection-1",
    name: "生产跳板",
    host: "10.0.0.8",
    port: 22,
    username: "ops",
    authMethod: "password",
    tags: [],
    group: null,
    environment: null,
    ...overrides,
  } as ConnectionSummary;
}

describe("WelcomeView", () => {
  it("lists saved connections as plain text without leaking secrets or handles", () => {
    const markup = renderToStaticMarkup(
      <WelcomeView
        connections={[connection(), connection({ id: "connection-2", name: "数据库", host: "10.0.0.9" })]}
        onConnectionAction={() => undefined}
        onCreateConnection={() => undefined}
      />,
    );

    expect(markup).toContain('data-testid="welcome-view"');
    expect(markup).toContain("ops@10.0.0.8:22");
    expect(markup.match(/class="connection-card"/gu)).toHaveLength(2);
    // Each row offers connect / edit / delete as labelled buttons.
    for (const label of ["连接", "设置", "删除"]) {
      expect(markup.match(new RegExp(`title="${label}"`, "gu")), label).toHaveLength(2);
    }
    expect(markup.match(/<button[^>]*title=/gu)).toHaveLength(6);
    expect(markup).toContain('aria-label="删除 生产跳板"');
    expect(markup).not.toMatch(/password|secret|bindingHandle|sessionId|authMethod/iu);
  });

  it("puts the product and the start beside the saved connections, most recently used first", () => {
    const now = new Date(2026, 9, 11, 15, 0);
    const markup = renderToStaticMarkup(
      <WelcomeView
        now={now}
        connections={[
          connection({ id: "a", name: "从没连过", lastConnectedAt: null }),
          connection({ id: "b", name: "上周的", lastConnectedAt: new Date(2026, 9, 3, 11, 28).toISOString() }),
          connection({ id: "c", name: "昨天的", lastConnectedAt: new Date(2026, 9, 10, 20, 36).toISOString() }),
        ]}
        onConnectionAction={() => undefined}
        onCreateConnection={() => undefined}
      />,
    );
    expect(markup).toContain("welcome-hero-logo");
    expect(markup).toContain("LovelyHawk");
    expect(markup).toContain("Linux 应急响应 / 运维工作台");
    expect(markup).toContain("能自动识别的系统");
    const names = [...markup.matchAll(/<strong>([^<]+)<\/strong>/gu)].map((match) => match[1]);
    expect(names.filter((name) => ["从没连过", "上周的", "昨天的"].includes(name ?? ""))).toEqual(["昨天的", "上周的", "从没连过"]);
    expect(markup).toContain("昨天 20:36");
    expect(markup).toContain("10-03 11:28");
    expect(markup).toContain("还没有连接过");
  });

  it("says when a connection was last used in the operator's own clock", () => {
    const now = new Date(2026, 9, 11, 9, 0);
    expect(lastConnectedLabel(new Date(2026, 9, 11, 8, 5).toISOString(), now)).toBe("今天 08:05");
    expect(lastConnectedLabel(new Date(2026, 9, 10, 23, 59).toISOString(), now)).toBe("昨天 23:59");
    expect(lastConnectedLabel(new Date(2025, 11, 31, 10, 0).toISOString(), now)).toBe("2025-12-31");
    expect(lastConnectedLabel(null, now)).toBe("还没有连接过");
    expect(lastConnectedLabel("not a time", now)).toBe("时间无法识别");
    expect(welcomeConnectionOrder([connection({ id: "x", name: "乙" }), connection({ id: "y", name: "甲" })])
      .map((item) => item.id)).toEqual(["y", "x"]);
  });

  /**
   * A squeezed column wraps Chinese one character per line — so "实验靶机 alma"
   * read downwards and root@host:port was clipped to a single letter. Rows in
   * the welcome card clip instead, and the cards stack once two no longer fit.
   */
  it("keeps a connection's name and target on one line, and stacks the cards when narrow", () => {
    const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
    const card = css.match(/\.connection-card \{[^}]*\}/u)?.[0] ?? "";
    expect(card).toContain("36px minmax(0, 1fr) auto");
    const name = css.match(/\.connection-card strong \{[^}]*\}/u)?.[0] ?? "";
    expect(name).toContain("white-space: nowrap");
    expect(name).toContain("text-overflow: ellipsis");
    expect(css).toMatch(/@media \(max-width: 1200px\) \{\s*\.app-frame:not\(\.is-welcome\) \.welcome-grid \{ grid-template-columns: minmax\(0, 1fr\); \}/u);
    expect(css).toMatch(/@media \(max-width: 900px\) \{\s*\.welcome-grid \{ grid-template-columns: minmax\(0, 1fr\); \}/u);
    // On the start screen the sidebar steps aside, unless it carries the
    // entries a hidden status bar would otherwise take away.
    expect(css).toContain(".app-frame.is-welcome > .sidebar { display: none; }");
    // Centred in the window, and still scrollable when the window is short:
    // a minimum height, never a fixed one that would cut off its top.
    const page = css.match(/\.welcome-page \{[^}]*\}/u)?.[0] ?? "";
    expect(page).toContain("justify-content: center");
    expect(page).toContain("min-height: 100%");
    expect(page).not.toMatch(/(?<!-)height: 100%/u);
    expect(appSource).toContain(
      "const welcomeScreen = activePage === null && activeTarget === null && uiPreferences.showStatusBar;");
    expect(appSource).toContain('["app-frame", welcomeScreen ? "is-welcome" : "", rail ? "is-rail" : ""]');
    // Every colour in the new welcome rules comes from a theme token.
    const welcome = css.slice(css.indexOf("/* Welcome: the product"), css.indexOf(".welcome-tools {"));
    expect(welcome.length).toBeGreaterThan(1000);
    expect(welcome).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(/iu);
  });

  it("renders hostile connection names as inert text", () => {
    const markup = renderToStaticMarkup(
      <WelcomeView
        connections={[connection({ name: "</strong><script>steal()</script>" })]}
        onConnectionAction={() => undefined}
        onCreateConnection={() => undefined}
      />,
    );

    expect(markup).toContain("&lt;/strong&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()");
  });

  it("offers connection creation when nothing is saved yet", () => {
    const markup = renderToStaticMarkup(
      <WelcomeView
        connections={[]}
        onConnectionAction={() => undefined}
        onCreateConnection={() => undefined}
      />,
    );

    expect(markup).toContain("还没有保存任何连接。");
    expect(markup).toContain("新建连接");
    expect(markup).not.toContain("connection-card");
  });
});

describe("connection card intents", () => {
  const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  const managerSource = readFileSync(new URL("./ConnectionManager.tsx", import.meta.url), "utf8");

  it("hands every card action to the connection manager instead of acting locally", () => {
    const welcomeSource = readFileSync(new URL("./WelcomeView.tsx", import.meta.url), "utf8");
    // The welcome view must not touch SSH, secrets, or delete plans itself.
    expect(welcomeSource).not.toMatch(/window\.lovelyhawk/u);
    expect(appSource).toContain(
      "onConnectionAction={(connectionId, intent, returnFocus) =>",
    );
    expect(appSource).toContain("openConnectionManager({ connectionId, startCreating: false, intent }, returnFocus)");
  });

  it("never passes a click event into an optional connection parameter", () => {
    // beginEdit/requestDelete/startConnect default their argument to the
    // selected connection, so a bare `onClick={handler}` would silently hand
    // them a React event instead.
    for (const handler of ["beginEdit", "requestDelete", "startConnect"]) {
      expect(managerSource, handler).not.toContain(`={${handler}}`);
    }
  });

  it("runs the intent against the connection the manager actually loaded", () => {
    expect(managerSource).toContain('export type ConnectionManagerIntent = "connect" | "edit" | "delete";');
    // `loaded` is passed through because the state set during refresh is not
    // readable in the same closure.
    expect(managerSource).toMatch(/const loaded = await refreshConnections\(initialConnectionId\);/u);
    expect(managerSource).toContain("loaded.id !== initialConnectionId");
    expect(managerSource).toContain('if (initialIntent === "connect") void startConnect(loaded.id);');
    expect(managerSource).toContain('else if (initialIntent === "edit") beginEdit(loaded);');
    expect(managerSource).toContain("else void requestDelete(loaded);");
  });
});

describe("welcome landing state", () => {
  it("opens on the welcome view and leaves it only once a target binds", () => {
    expect(appSource).toContain('export const WELCOME_PAGE_ID = "welcome";');
    expect(appSource).toContain("useState(WELCOME_PAGE_ID)");
    expect(appSource).toMatch(
      /setActivePageId\(\(current\) => \(current === WELCOME_PAGE_ID \? FIRST_CONNECTED_PAGE_ID : current\)\)/u,
    );
    // The welcome view owns no editor, so it needs no dirty-navigation handshake.
    expect(appSource).toContain("activePage === null ? (");
  });
});
