import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const pageSource = readFileSync(new URL("./SystemInfoPage.tsx", import.meta.url), "utf8");
const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("system info summary tab", () => {
  it("renders the summary as a realtime-group tab instead of a page-level block", () => {
    expect(pageSource).toContain('group.key === "realtime"');
    expect(pageSource).toMatch(/aria-pressed=\{summaryTabActive\}[\s\S]{0,240}系统信息/u);
    // Exactly one summary grid, and it lives inside the tab panel.
    expect(pageSource.match(/className="system-info-summary"/gu)).toHaveLength(1);
    const panel = pageSource.slice(pageSource.indexOf('className="system-info-table-panel"'));
    expect(panel).toContain('className="system-info-summary"');
  });

  it("stays a renderer-only tab that never sends a collect request", () => {
    // The summary reuses the loaded snapshot; only real catalog keys reach the API.
    expect(pageSource).toMatch(/function selectTab\(tab: SystemInfoTabKey\) \{[\s\S]*?setSummaryTabActive\(false\);/u);
    expect(pageSource).not.toMatch(/collectSystemInfo\([^)]*summary/u);
    expect(pageSource).not.toContain('"summary" as SystemInfoTabKey');
  });

  it("refreshes the summary through its own version, not the table's", () => {
    expect(pageSource).toMatch(/function refreshSummary\(\) \{[\s\S]*?setSummaryVersion/u);
    expect(pageSource).toContain("}, [api, bindingHandle, scope, summaryVersion]);");
    expect(pageSource).toMatch(/onClick=\{summaryTabActive \? refreshSummary : refreshTable\}/u);
  });

  it("deactivates the catalog tabs while the summary tab is showing", () => {
    expect(pageSource).toContain("!summaryTabActive && selectedTab === tab.key");
  });
});

describe("system info tab collection", () => {
  /**
   * Re-selecting the current tab resets it to "idle" without changing
   * selectedTab, so keying the collect on the tab alone left the panel stuck on
   * "正在采集当前标签…" until the user pressed refresh.
   */
  it("collects whenever the table is idle, not only when the tab changes", () => {
    const effect = pageSource.slice(
      pageSource.indexOf("void api.collectSystemInfo") - 900,
      pageSource.indexOf("void api.collectSystemInfo"),
    );
    expect(effect).toContain('state.tableStatus !== "idle"');
    expect(pageSource).toContain(
      "}, [api, bindingHandle, scope, state.scope, state.selectedTab, state.status, state.tableStatus]);",
    );
  });

  it("refreshes by returning the tab to idle rather than a separate counter", () => {
    expect(pageSource).toMatch(
      /function refreshTable\(\) \{[\s\S]*?dispatch\(\{ type: "tab-selected", scope, tab: selectedTab \}\);/u,
    );
    // The old refresh counter is gone; idle is the single trigger.
    expect(pageSource).not.toContain("refreshVersion");
  });
});

describe("system info page chrome", () => {
  it("drops the page heading and keeps copy next to refresh in the panel", () => {
    expect(pageSource).not.toContain('className="page-heading system-info-heading"');
    expect(pageSource).not.toContain("<h1>System Info</h1>");
    const panel = pageSource.slice(pageSource.indexOf('className="system-info-table-panel"'));
    expect(panel).toContain('className="system-info-panel-actions"');
    // The copy action follows the active tab instead of sitting in a page header.
    expect(panel).toMatch(/summaryTabActive \? \(\s*<button[\s\S]{0,200}复制摘要/u);
    expect(panel).toMatch(/\) : \(\s*<button[\s\S]{0,200}复制表格/u);
  });
});

describe("connect intent lands on the target", () => {
  const managerSource = readFileSync(new URL("./ConnectionManager.tsx", import.meta.url), "utf8");

  it("closes the panel as soon as a target binds", () => {
    const handler = managerSource.slice(
      managerSource.indexOf("function handleSshTerminal"),
      managerSource.indexOf("function closeSshAttempt"),
    );
    expect(handler).toContain("onTargetConnected(status.bindingHandle, status.target);");
    expect(handler).toMatch(/setSshAttempt\(null\);\s*onClose\(\);/u);
    // Secrets and in-flight reads are dropped on the way out.
    expect(handler).toContain("invalidateReads();");
    expect(handler).toContain("resetSecrets();");
  });

  it("hides the manager chrome for a connect intent and restores it on failure", () => {
    expect(managerSource).toContain('useState(initialIntent === "connect")');
    expect(managerSource).toContain('className={chromeHidden ? "connection-manager is-hidden" : "connection-manager"}');
    // Anything other than a successful connect must show the panel again.
    expect(managerSource.match(/setChromeHidden\(false\);/gu)?.length).toBeGreaterThanOrEqual(3);
  });
});

describe("target status placement", () => {
  it("moves the target and its disconnect control into the status bar", () => {
    expect(appSource).not.toContain('className="target-status"');
    expect(cssSource).not.toContain(".target-status");
    const statusbar = appSource.slice(appSource.indexOf('className="statusbar-target"'));
    expect(statusbar).toContain('data-testid="disconnect-target"');
    expect(statusbar).toMatch(/disabled=\{disconnecting\}/u);
    expect(statusbar).toContain("void disconnectTarget()");
    // The connect error follows the target it belongs to.
    expect(statusbar).toMatch(/className="statusbar-error" role="alert"/u);
  });

  it("keeps the disconnect control out of the tree while nothing is bound", () => {
    expect(appSource).toMatch(
      /\{activeTarget !== null \? \(\s*<button[\s\S]{0,240}data-testid="disconnect-target"/u,
    );
  });
});
