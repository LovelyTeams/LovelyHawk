import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  DockerLogs,
  DockerReadApi,
  DockerSecurityAudit,
} from "../shared/docker-read-contract";
import {
  dockerCollectionForTab,
  dockerReadScope,
  filterDockerContainers,
} from "./docker-read-helpers";
import {
  DockerLogsText,
  DockerPage,
  DockerSecurityView,
} from "./DockerPage";

const api: DockerReadApi = {
  refreshDockerContainers: vi.fn(async () => ({})),
  getDockerCollection: vi.fn(async () => ({})),
  inspectDockerResource: vi.fn(async () => ({})),
  getDockerSecurityAudit: vi.fn(async () => ({})),
  getDockerLogs: vi.fn(async () => ({})),
};
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

describe("standalone Docker read page", () => {
  it("renders a disconnected read boundary without internal capabilities", () => {
    const markup = renderToStaticMarkup(<DockerPage bindingHandle={null} api={api} />);
    expect(markup).toContain("连接目标后调查 Docker");
    expect(markup).toContain("只读取资源快照，不会修改容器");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
    expect(markup).not.toContain("bindingHandle");
  });

  it("renders hostile findings and logs only as escaped plain text", () => {
    const audit: DockerSecurityAudit = {
      snapshotHandle: "snapshot-1",
      containersScanned: 1,
      findings: [{
        severity: "critical",
        severityLabel: "严重",
        category: "privileged",
        categoryLabel: hostile,
        containerName: hostile,
        description: hostile,
        recommendation: hostile,
        textTruncated: false,
      }],
      summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1, score: 10 },
      truncated: false,
    };
    const logs: DockerLogs = {
      snapshotHandle: "snapshot-1",
      containerHandle: "container-1",
      tail: 200,
      text: hostile,
      truncated: false,
    };
    const markup = renderToStaticMarkup(
      <><DockerSecurityView status="ready" audit={audit} onRefresh={() => undefined} /><DockerLogsText logs={logs} /></>,
    );
    expect(markup).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()</script>");
    expect(markup).not.toContain("执行修复");
    expect(markup).not.toContain("删除容器");
    expect(markup).not.toContain("打开终端");
  });

  it("renders explicit loading, empty and truncated evidence states", () => {
    const loading = renderToStaticMarkup(
      <DockerSecurityView status="loading" audit={null} onRefresh={() => undefined} />,
    );
    const empty = renderToStaticMarkup(
      <DockerSecurityView status="ready" audit={null} onRefresh={() => undefined} />,
    );
    const truncated = renderToStaticMarkup(<DockerLogsText logs={{
      snapshotHandle: "snapshot-1",
      containerHandle: "container-1",
      tail: 200,
      text: "bounded",
      truncated: true,
    }} />);
    expect(loading).toContain("正在运行 Docker 安全调查");
    expect(empty).toContain("安全审计尚不可用");
    expect(truncated).toContain("结果已按敏感信息与 UTF-8 字节安全边界处理");
  });

  it("filters container display data and maps tabs only to closed collection kinds", () => {
    const containers = [{
      containerHandle: "container-1",
      name: hostile,
      image: "app:1",
      state: "running",
      status: "Up",
      ports: "8080/tcp",
      createdAt: "now",
    }];
    expect(filterDockerContainers(containers, "onerror")).toHaveLength(1);
    expect(filterDockerContainers(containers, "missing")).toHaveLength(0);
    expect(dockerCollectionForTab("containers")).toBe("stats");
    expect(dockerCollectionForTab("security")).toBeNull();
  });

  it("scopes renderer state only by the current 请先建立 SSH 连接 handle", () => {
    expect(dockerReadScope("binding-1")).toBe("binding-1");
    expect(dockerReadScope("binding-1")).not.toBe(dockerReadScope("binding-2"));
    const markup = renderToStaticMarkup(<DockerPage bindingHandle="binding-secret" api={api} />);
    expect(markup).toContain("当前目标的只读 Docker 快照");
    expect(markup).not.toContain("binding-secret");
  });

  it("keeps the phase-one renderer free of mutation, file, terminal and generic execution APIs", () => {
    const source = readFileSync(new URL("./DockerPage.tsx", import.meta.url), "utf8");
    for (const forbidden of [
      ["container", "Action"].join(""),
      ["mutate", "Docker"].join(""),
      ["readDocker", "File"].join(""),
      ["writeDocker", "File"].join(""),
      ["copyDocker", "File"].join(""),
      ["launchDocker", "Terminal"].join(""),
      ["executeDocker", "Command"].join(""),
      "dangerouslySetInnerHTML",
    ]) {
      expect(source).not.toContain(forbidden);
    }
    for (const forbidden of [
      "SshTargetSummary", "DockerConnection", "connectionId", "sessionId", "targetGuard",
      "generation", "username", "timestamp",
    ]) expect(source).not.toContain(forbidden);
    expect(source).toContain("bindingHandle: string | null");
    expect(source).toContain("dockerReadScope(bindingHandle)");
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./docker-page.css", import.meta.url), "utf8");
    const quickCss = readFileSync(new URL("./quick-detection.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(10);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/\.docker-log-text\s*\{[^}]*color:\s*var\(--console-text\)[^}]*background:\s*var\(--console-bg\)/su);
    expect(quickCss).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(quickCss).toMatch(/\.quick-detection-module-detail pre\s*\{[^}]*color:\s*var\(--console-text\);[^}]*background:\s*var\(--console-bg\);/su);
  });
});
