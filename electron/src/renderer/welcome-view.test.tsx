import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { WelcomeView } from "./WelcomeView";
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
        productName="LovelyRes"
        connections={[connection(), connection({ id: "connection-2", name: "数据库", host: "10.0.0.9" })]}
        onConnectionAction={() => undefined}
        onCreateConnection={() => undefined}
      />,
    );

    expect(markup).toContain('data-testid="welcome-view"');
    expect(markup).toContain("ops@10.0.0.8:22");
    expect(markup.match(/class="connection-card"/gu)).toHaveLength(2);
    // Each card offers connect / edit / delete as labelled icon buttons.
    for (const label of ["连接", "设置", "删除"]) {
      expect(markup.match(new RegExp(`title="${label}"`, "gu")), label).toHaveLength(2);
    }
    expect(markup.match(/<svg/gu)).toHaveLength(6);
    expect(markup).toContain('aria-label="删除 生产跳板"');
    expect(markup).not.toMatch(/password|secret|bindingHandle|sessionId|authMethod/iu);
  });

  it("renders hostile connection names as inert text", () => {
    const markup = renderToStaticMarkup(
      <WelcomeView
        productName="LovelyRes"
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
        productName="LovelyRes"
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
    expect(welcomeSource).not.toMatch(/window\.lovelyres/u);
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
