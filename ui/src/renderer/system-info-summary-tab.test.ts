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
      pageSource.indexOf("void api.collectSystemInfo") - 1_400,
      pageSource.indexOf("void api.collectSystemInfo"),
    );
    expect(effect).toContain('state.tableStatus !== "idle"');
    expect(pageSource).toMatch(
      /\}, \[\s*api, bindingHandle, scope, state\.scope, state\.selectedTab, state\.status, state\.tableStatus,\s*summaryTabActive,\s*\]\);/u,
    );
  });

  /**
   * The page opens on the summary. Collecting the first catalog tab underneath
   * it sent a five-hundred-row process sweep nobody had asked for, and then a
   * second one when that tab was actually opened — two collects of the same
   * tab in flight at once.
   */
  it("sends no collect while the summary tab is the one showing", () => {
    const effect = pageSource.slice(
      pageSource.indexOf("void api.collectSystemInfo") - 1_400,
      pageSource.indexOf("void api.collectSystemInfo"),
    );
    expect(effect).toMatch(/summaryTabActive\s*\)\s*return;/u);
  });

  /**
   * Two collects of one tab can still overlap when a tab is left and returned
   * to, and the scope and tab alone cannot tell them apart. Whichever landed
   * last used to win, so a slow earlier collect could put an older snapshot
   * back under whatever the operator had already opened against the newer one.
   */
  it("numbers each collect so a superseded response cannot land", () => {
    expect(pageSource).toContain("tableRequestRef.current += 1;");
    expect(pageSource).toMatch(/dispatch\(\{ type: "table-started",[^}]*request \}\);/u);
    const stateSource = readFileSync(new URL("./system-info-state.ts", import.meta.url), "utf8");
    expect(stateSource).toContain("state.tableRequest !== action.request");
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

  it("keeps SSH disconnect hidden without a target and while Windows IR is active", () => {
    expect(appSource).toMatch(
      /\{activePageId !== WINDOWS_INCIDENT_PAGE_ID && activeTarget !== null \? \(\s*<button[\s\S]{0,240}data-testid="disconnect-target"/u,
    );
  });
});

describe("summary values", () => {
  it("says the collector's placeholder words in Chinese and keeps the word itself", async () => {
    const { describeSystemInfoValue } = await import("./system-info-helpers");
    expect(describeSystemInfoValue("virtualization", "physical-or-unknown")).toBe("未检测到虚拟化（物理机，或无法判断）（physical-or-unknown）");
    expect(describeSystemInfoValue("selinux", "unavailable")).toBe("没有 SELinux 工具（getenforce 不存在）（unavailable）");
    expect(describeSystemInfoValue("selinux", "Permissive")).toBe("宽容模式（只记录不拦截）（Permissive）");
    expect(describeSystemInfoValue("apparmor", "enabled")).toBe("已启用（enabled）");
    expect(describeSystemInfoValue("locale", "unknown")).toBe("未设置（LANG 为空）（unknown）");
    // PID 1 that is no init is said to be one.
    expect(describeSystemInfoValue("initSystem", "sleep")).toContain("PID 1 不是常见的 init");
    expect(describeSystemInfoValue("initSystem", "systemd")).toBe("systemd");
    // What the host reported is never rewritten.
    expect(describeSystemInfoValue("virtualization", "kvm")).toBe("kvm");
    expect(describeSystemInfoValue("hostname", "unavailable")).toBe("unavailable");
    expect(pageSource).toContain("describeSystemInfoValue(field.key, formatSystemInfoValue(");
  });
});

describe("resource gauges", () => {
  it("works out how full memory, disk, CPU and swap are, with plain tones", async () => {
    const { systemInfoGauges } = await import("./system-info-helpers");
    const gib = 1024 ** 3;
    const base = {
      memoryTotalBytes: 16 * gib, memoryAvailableBytes: 2 * gib, rootTotalBytes: 100 * gib, rootAvailableBytes: 50 * gib,
      loadAverage: ["21.0", "1", "1"] as [string, string, string], cpuCores: 20, swapTotalBytes: 0, swapFreeBytes: 0,
    };
    const gauges = systemInfoGauges(base as never);
    const byId = Object.fromEntries(gauges.map((gauge) => [gauge.id, gauge]));
    expect(byId.memory?.value).toBe("88%");
    expect(byId.memory?.tone).toBe("warning");
    expect(byId.disk?.value).toBe("50%");
    expect(byId.disk?.tone).toBe("ok");
    // 21 on 20 cores is more than one per core.
    expect(byId.load?.tone).toBe("high");
    expect(byId.load?.ratio).toBe(1);
    expect(byId.load?.detail).toContain("20 核");
    expect(byId.swap?.value).toBe("未启用");
    expect(byId.swap?.ratio).toBeNull();
    // Nothing read is said, not shown as empty.
    const unknown = systemInfoGauges({ ...base, memoryTotalBytes: 0, rootTotalBytes: 0, cpuCores: 0 } as never);
    expect(unknown.find((gauge) => gauge.id === "memory")?.detail).toBe("没有读到内存总量");
    expect(unknown.find((gauge) => gauge.id === "load")?.tone).toBe("none");
    expect(pageSource).toContain('<section className="system-info-gauges" aria-label="资源占用">');
    expect(pageSource).toContain("不等于出了问题");
  });
});

describe("table columns", () => {
  it("leaves the collector's raw 风险 column off the screen, since 级别 says it in Chinese", async () => {
    const { shownColumn } = await import("./SystemInfoPage");
    const columns = ["风险", "PID", "命令"];
    expect(columns.map((_, index) => shownColumn(columns, index))).toEqual([false, true, true]);
    expect(pageSource).toContain("shownColumn(table.columns, index) ? <th key={column}>{column}</th> : null");
    expect(pageSource).toContain("!shownColumn(table.columns, index) ? null : (");
  });
});
