import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  PacketCaptureLiveApi,
  PacketCapturePacketEvent,
} from "../shared/packet-capture-live-contract";
import { PacketCapturePage } from "./PacketCapturePage";
import { packetCaptureScope } from "./packet-capture-live-helpers";
import {
  createPacketCaptureLiveState,
  type PacketCaptureLiveState,
} from "./packet-capture-live-state";

const interfaceHandle = "11111111-1111-4111-8111-111111111111";
const captureHandle = "22222222-2222-4222-8222-222222222222";
const bindingHandle = "binding-secret-capability";
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

const api: PacketCaptureLiveApi = {
  listPacketCaptureInterfaces: vi.fn(async () => ({})),
  startPacketCapture: vi.fn(async () => ({})),
  pollPacketCapture: vi.fn(async () => ({})),
  stopPacketCapture: vi.fn(async () => ({})),
};

function packet(sequence = 2): PacketCapturePacketEvent {
  return {
    kind: "packet",
    sequence,
    observedAt: "2026-08-24T00:00:01Z",
    timestamp: "21:00:01.000000",
    protocol: "HTTPS",
    source: "10.0.0.1.443",
    destination: "10.0.0.2.51000",
    length: "128",
    info: hostile,
    raw: `raw ${hostile}`,
    textTruncated: true,
  };
}

function readyState(overrides: Partial<PacketCaptureLiveState> = {}): PacketCaptureLiveState {
  return {
    ...createPacketCaptureLiveState(packetCaptureScope(bindingHandle)),
    interfacesStatus: "ready",
    interfaces: {
      interfaces: [{
        interfaceHandle,
        name: "eth0",
        mac: null,
        addresses: ["10.0.0.1/24"],
        textTruncated: false,
      }],
      displayed: 1,
      truncated: false,
      expiresInSeconds: 300,
    },
    selectedInterfaceHandle: interfaceHandle,
    ...overrides,
  };
}

describe("standalone packet capture live page", () => {
  it("renders hostile packet fields literally without exposing opaque capabilities", () => {
    const html = renderToStaticMarkup(
      <PacketCapturePage
        bindingHandle={bindingHandle}
        api={api}
        initialState={readyState({
          captureStatus: "running",
          captureHandle,
          packets: [packet()],
          selectedPacketSequence: 2,
          totalPackets: 1,
          totalBytes: 128,
        })}
      />,
    );
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>steal()</script>");
    expect(html).not.toContain(bindingHandle);
    expect(html).not.toContain(interfaceHandle);
    expect(html).not.toContain(captureHandle);
    expect(html).not.toContain("dangerouslySetInnerHTML");
    expect(html).toContain("字段已截断");
  });

  it("renders disconnected and deactivated states with explicit cleanup semantics", () => {
    let html = renderToStaticMarkup(<PacketCapturePage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后开始受控网络抓包");
    expect(html).toContain("实时抓包只在当前 SSH 目标上进行");

    html = renderToStaticMarkup(
      <PacketCapturePage bindingHandle={bindingHandle} api={api} active={false} />,
    );
    expect(html).toContain("网络抓包页面已停用");
    expect(html).toContain("请求停止并释放 live capture");
  });

  it("shows bounded parameters, status, metrics, protocol summary, and stable selection", () => {
    const html = renderToStaticMarkup(
      <PacketCapturePage
        bindingHandle={bindingHandle}
        api={api}
        initialState={readyState({
          captureStatus: "running",
          captureHandle,
          form: { filter: "tcp port 443", packetLimit: "5000", durationSeconds: "60" },
          packets: [packet(2), { ...packet(3), protocol: "DNS" }],
          selectedPacketSequence: 2,
          totalPackets: 12,
          totalBytes: 1_024,
          droppedEvents: 3,
        })}
      />,
    );
    expect(html).toContain("eth0 · 10.0.0.1/24");
    expect(html).toContain('value="tcp port 443"');
    expect(html).toContain('value="5000"');
    expect(html).toContain('value="60"');
    expect(html).toContain("● 正在采集");
    expect(html).toContain("1.0 KiB");
    expect(html).toContain("HTTPS</strong>1");
    expect(html).toContain("DNS</strong>1");
    expect(html).toContain('aria-pressed="true"');
  });

  it("renders loading, empty, error, search-empty, and truncation states without invented rows", () => {
    let html = renderToStaticMarkup(
      <PacketCapturePage bindingHandle={bindingHandle} api={api} initialState={readyState({
        interfacesStatus: "loading",
        interfaces: null,
        selectedInterfaceHandle: null,
      })} />,
    );
    expect(html).toContain("正在读取目标网卡");

    html = renderToStaticMarkup(
      <PacketCapturePage bindingHandle={bindingHandle} api={api} initialState={readyState({
        interfaces: {
          interfaces: [], displayed: 0, truncated: false, expiresInSeconds: 300,
        },
        selectedInterfaceHandle: null,
      })} />,
    );
    expect(html).toContain("当前目标没有可用网卡");
    expect(html).not.toContain("示例数据包");

    html = renderToStaticMarkup(
      <PacketCapturePage bindingHandle={bindingHandle} api={api} initialState={readyState({
        interfacesStatus: "error",
        interfaces: null,
        selectedInterfaceHandle: null,
        error: "目标已断开。",
      })} />,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain("目标已断开");

    html = renderToStaticMarkup(
      <PacketCapturePage bindingHandle={bindingHandle} api={api} initialState={readyState({
        packets: [packet()],
        search: "not-present",
        truncated: true,
      })} />,
    );
    expect(html).toContain("当前缓冲没有匹配搜索条件");
    expect(html).toContain("缓冲已达上限，较早的事件可能已丢弃");
  });

  it("keeps the API fixed and contains no phase-two or generic execution surface", () => {
    const source = readFileSync(new URL("./PacketCapturePage.tsx", import.meta.url), "utf8");
    expect([...source.matchAll(/\bapi\.(\w+)/gu)].map((match) => match[1]).sort()).toEqual([
      "listPacketCaptureInterfaces",
      "pollPacketCapture",
      "startPacketCapture",
      "stopPacketCapture",
    ]);
    for (const forbidden of [
      "dangerouslySetInnerHTML",
      ["createPacketCapture", "Evidence"].join(""),
      ["downloadPacketCapture", "Pcap"].join(""),
      ["exportPacketCapture", "Pcap"].join(""),
      ["cleanupPacketCapture", "Artifact"].join(""),
      ["executePacketCapture", "Command"].join(""),
      ["openPacketCapture", "File"].join(""),
      ["TO", "DO"].join(""),
    ]) expect(source).not.toContain(forbidden);
    expect(source).not.toMatch(
      /\b(?:host|username|port|sessionId|connectionId|targetIdentity|targetGeneration|guard|command|remotePath)\s*:/u,
    );
    expect(source).toContain("bindingHandle: string | null;");
    expect(source).not.toContain("SshTargetSummary");
    expect(source).not.toContain("PacketCaptureConnection");
    expect(source).not.toMatch(/\.target\.(?:host|port|username|connectionId|timestamp)/u);
  });

  it("requests stop on switch, deactivation, unmount, late start, poll failure, and completion", () => {
    const source = readFileSync(new URL("./PacketCapturePage.tsx", import.meta.url), "utf8");
    expect(source.match(/stopOwner\(/gu)?.length).toBeGreaterThanOrEqual(7);
    expect(source).toMatch(/owner\.scope !== scope[\s\S]*?stopOwner\(api, owner\)/u);
    expect(source).toMatch(/if \(enabled\) return;[\s\S]*?stopOwner\(api, owner\)/u);
    expect(source).toMatch(/mountedRef\.current = false;[\s\S]*?stopOwner\(apiRef\.current, owner\)/u);
    expect(source).toMatch(/!mountedRef\.current \|\| !activeRef\.current \|\| scopeRef\.current !== scope[\s\S]*?stopOwner/u);
    expect(source).toContain("startPendingRef.current");
    expect(source).toMatch(/requestRef\.current !== request[\s\S]*?stopOwner/u);
    expect(source).toMatch(/result\.status !== "running"[\s\S]*?stopOwner/u);
    expect(source).toMatch(/catch \{[\s\S]*?"poll-failed"[\s\S]*?stopOwner/u);
    expect(source).toMatch(
      /let cancelled = false;[\s\S]*?listPacketCaptureInterfaces[\s\S]*?cancelled \|\| scopeRef\.current !== scope \|\| !activeRef\.current/u,
    );
    expect(source).toMatch(/return \(\) => \{\s*cancelled = true;\s*\};/u);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./packet-capture-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(50);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});


