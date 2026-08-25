import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  FirewallHistory,
  FirewallInspection,
  FirewallReadApi,
} from "../shared/firewall-read-contract";
import { FirewallPage } from "./FirewallPage";
import { firewallReadScope } from "./firewall-read-helpers";
import { createFirewallReadState, type FirewallReadState } from "./firewall-read-state";

const snapshotHandle = "11111111-1111-4111-8111-111111111111";
const historyHandle = "22222222-2222-4222-8222-222222222222";
const changeHandle = "33333333-3333-4333-8333-333333333333";
const bindingHandle = "binding-secret-capability";
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

const api: FirewallReadApi = {
  inspectFirewall: vi.fn(async (_bindingHandle: string) => inspection()),
  listFirewallChangeHistory: vi.fn(async (_bindingHandle: string) => history()),
};

function inspection(overrides: Partial<FirewallInspection> = {}): FirewallInspection {
  return {
    snapshotHandle,
    backend: "firewalld",
    engine: "iptables",
    active: true,
    rules: `allow 22\n${hostile}\ndrop all`,
    rulesTruncated: false,
    capturedAt: "2026-08-24T00:00:00Z",
    expiresInSeconds: 300,
    ...overrides,
  };
}

function history(overrides: Partial<FirewallHistory> = {}): FirewallHistory {
  return {
    historyHandle,
    entries: [{
      changeHandle,
      backend: "firewalld",
      engine: "iptables",
      changeKind: "block-ipv4",
      label: hostile,
      state: "awaiting-keep",
      sshPort: 22,
      createdAt: "2026-08-24T00:00:00Z",
      deadmanDeadline: "2026-08-24T00:01:00Z",
      updatedAt: "2026-08-24T00:00:30Z",
      textTruncated: true,
    }],
    displayed: 1,
    truncated: false,
    expiresInSeconds: 300,
    ...overrides,
  };
}

function readyState(overrides: Partial<FirewallReadState> = {}): FirewallReadState {
  return {
    ...createFirewallReadState(firewallReadScope(bindingHandle)),
    inspectionStatus: "ready",
    inspection: inspection(),
    historyStatus: "ready",
    history: history(),
    selectedChangeHandle: changeHandle,
    ...overrides,
  };
}

describe("standalone firewall read page", () => {
  it("renders hostile rules and labels literally without exposing opaque capabilities", () => {
    const html = renderToStaticMarkup(
      <FirewallPage
        bindingHandle={bindingHandle}
        api={api}
        writeClipboard={vi.fn(async () => undefined)}
        initialState={readyState()}
      />,
    );
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>steal()</script>");
    expect(html).not.toContain(bindingHandle);
    expect(html).not.toContain(snapshotHandle);
    expect(html).not.toContain(historyHandle);
    expect(html).not.toContain(changeHandle);
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });

  it("renders exactly the two honest tabs and no unavailable response tab", () => {
    const html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(html).toMatch(/aria-current="page"[^>]*>当前规则<\/button>/u);
    expect(html).toContain(">变更历史</button>");
    expect((html.match(/role="tab"/gu) ?? [])).toHaveLength(2);
    expect(html).not.toContain("隔离计划");
  });

  it("renders backend, engine, status, captured time, search, copy availability, and truncation", () => {
    let html = renderToStaticMarkup(
      <FirewallPage
        bindingHandle={bindingHandle}
        api={api}
        writeClipboard={vi.fn(async () => undefined)}
        initialState={readyState({ inspection: inspection({ rulesTruncated: true }) })}
      />,
    );
    expect(html).toContain("firewalld");
    expect(html).toContain("iptables isolated chain");
    expect(html).toContain("已启用");
    expect(html).toContain("2026-08-24T00:00:00Z");
    expect(html).toContain("复制规则纯文本</button>");
    expect(html).toContain("规则快照已截断");

    html = renderToStaticMarkup(
      <FirewallPage
        bindingHandle={bindingHandle}
        api={api}
        initialState={readyState({ ruleQuery: "not-present" })}
      />,
    );
    expect(html).toContain("当前快照没有匹配搜索条件");
    expect(html).toContain('disabled=""');
  });

  it("renders disconnected, inactive, loading, empty, error, and history-truncated states", () => {
    let html = renderToStaticMarkup(<FirewallPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后调查防火墙");
    html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} active={false} />,
    );
    expect(html).toContain("防火墙调查页面已停用");
    expect(html).toContain("拒绝仍在途的旧目标结果");

    html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} initialState={readyState({
        inspectionStatus: "loading", inspection: null,
      })} />,
    );
    expect(html).toContain("正在读取防火墙规则快照");

    html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} initialState={readyState({
        inspectionStatus: "error", inspection: null, inspectionError: "目标已断开。",
      })} />,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain("目标已断开");

    html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} initialState={readyState({
        activeTab: "history",
        history: history({ entries: [], displayed: 0 }),
        selectedChangeHandle: null,
      })} />,
    );
    expect(html).toContain("没有 LovelyRes 防火墙变更记录");
    expect(html).not.toContain("示例记录");

    html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} initialState={readyState({
        activeTab: "history", history: history({ truncated: true }),
      })} />,
    );
    expect(html).toContain("历史记录已达到显示上限");
  });

  it("shows stable history selection and an honest non-actionable detail", () => {
    const html = renderToStaticMarkup(
      <FirewallPage bindingHandle={bindingHandle} api={api} initialState={readyState({
        activeTab: "history",
      })} />,
    );
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain("历史 IPv4 封禁");
    expect(html).toContain("等待保留确认（只读记录）");
    expect(html).toContain("本阶段不执行 reconcile，不能据此推断远端最终状态");
    expect(html).toContain("标签已截断");
  });

  it("uses only the injected clipboard and two fixed read methods", () => {
    const source = readFileSync(new URL("./FirewallPage.tsx", import.meta.url), "utf8");
    expect([...source.matchAll(/\bapi\.(\w+)/gu)].map((match) => match[1]).sort()).toEqual([
      "inspectFirewall",
      "listFirewallChangeHistory",
    ]);
    expect(source).toContain("const copy = firewallCopyText(inspection)");
    expect(source).toContain("await writeClipboard(copy.text)");
    expect(source).toContain("truncated: copy.truncated");
    expect(source).not.toContain("window.lovelyres");
    for (const forbidden of [
      "dangerouslySetInnerHTML",
      "隔离计划",
      "创建封禁计划",
      "创建放行计划",
      "确认执行",
      "保留规则",
      "立即恢复",
      ["planFirewall", "Mutation"].join(""),
      ["confirmFirewall", "Mutation"].join(""),
      ["executeFirewall", "Command"].join(""),
      ["openFirewall", "Terminal"].join(""),
      ["exportFirewall", "Rules"].join(""),
      ["TO", "DO"].join(""),
    ]) expect(source).not.toContain(forbidden);
  });

  it("is centrally mounted with only the 请先建立 SSH 连接 and fixed read/clipboard APIs", () => {
    const source = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(source).toMatch(
      /activePage\.id === "firewall"[\s\S]*?<FirewallPage[\s\S]*?bindingHandle=\{activeTarget\?\.bindingHandle \?\? null\}[\s\S]*?api=\{window\.lovelyres\}[\s\S]*?writeClipboard=\{window\.lovelyres\.writeClipboard\}/u,
    );
    const mount = source.match(/<FirewallPage[\s\S]*?\/>/u)?.[0] ?? "";
    expect(mount).not.toMatch(/\b(?:target|connection|host|port|username|session|guard)=/iu);
  });

  it("clears on deactivation and scope-changes every remote request", () => {
    const source = readFileSync(new URL("./FirewallPage.tsx", import.meta.url), "utf8");
    expect(source).toMatch(/dispatch\(\{ type: "scope-changed", scope \}\)/u);
    expect(source).toMatch(/if \(enabled\) return;[\s\S]*?type: "deactivated"/u);
    expect(source).toMatch(/inspection-loaded[\s\S]*?scope,[\s\S]*?inspectionRequest/u);
    expect(source).toMatch(/history-loaded[\s\S]*?scope,[\s\S]*?historyRequest/u);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./firewall-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(55);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/\.firewall-page\s*\{[^}]*background:\s*var\(--console-bg\)[^}]*color:\s*var\(--console-text\)/su);
  });
});


