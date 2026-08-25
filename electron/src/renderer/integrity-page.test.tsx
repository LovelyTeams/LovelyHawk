import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  INTEGRITY_PRESET_DEFINITIONS,
  type IntegrityApi,
} from "../shared/integrity-contract";
import { IntegrityPage } from "./IntegrityPage";
import { createIntegrityState, type IntegrityState } from "./integrity-state";

const api: IntegrityApi = {
  getIntegrityPresets: async () => ({}),
  listIntegrityBaselines: async () => ({}),
  startIntegrityComparison: async () => ({}),
  pollIntegrityComparison: async () => ({}),
  cancelIntegrityComparison: async () => ({}),
};

const bindingHandle = "binding-secret-capability";
const hostile = "/var/www/</code><img src=x onerror=steal()><script>bad()</script>";

function readyState(stage: IntegrityState["operationStage"] = "completed"): IntegrityState {
  return {
    ...createIntegrityState(bindingHandle),
    catalogStatus: "ready",
    catalog: {
      presets: INTEGRITY_PRESET_DEFINITIONS.map((preset) => ({ ...preset })),
      maximumSelected: 6,
    },
    listStatus: "ready",
    baselineList: {
      items: [{
        baselineHandle: "baseline-one",
        createdAt: "2026-08-25T00:00:00Z",
        paths: ["/var/www"],
        pathsTruncated: false,
        redactedPathCount: 0,
        textProjected: false,
        fileCount: 10,
      }],
      truncated: false,
    },
    selectedBaselineHandle: "baseline-one",
    operationHandle: stage === "idle" ? null : "operation-one",
    operationBaselineHandle: stage === "idle" ? null : "baseline-one",
    operationStage: stage,
    comparison: stage === "completed" ? {
      baselineHandle: "baseline-one",
      added: 1,
      removed: 1,
      modified: 0,
      displayed: 2,
      redactedPathCount: 0,
      textProjected: false,
      truncated: false,
      entries: [
        {
          path: hostile,
          pathRedacted: false,
          pathTruncated: false,
          pathProjected: false,
          kind: "added",
          severity: "high",
        },
        {
          path: "/var/www/removed",
          pathRedacted: false,
          pathTruncated: false,
          pathProjected: false,
          kind: "removed",
          severity: "medium",
        },
      ],
    } : null,
  };
}

describe("standalone Integrity page", () => {
  it("renders hostile remote paths only as escaped text and hides capabilities", () => {
    const html = renderToStaticMarkup(
      <IntegrityPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(html).toContain("&lt;img src=x onerror=steal()&gt;");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>bad()");
    expect(html).not.toContain(bindingHandle);
    expect(html).not.toContain("operation-one");
    expect(html).not.toContain("dangerouslySetInnerHTML");
    expect(html).toContain("新增</span><strong>1");
  });

  it("is visibly read-only with no create, quarantine, path, shell, or export control", () => {
    const html = renderToStaticMarkup(
      <IntegrityPage bindingHandle={bindingHandle} api={api} initialState={readyState("idle")} />,
    );
    expect(html).toContain("仅列出并比较已有基线");
    expect(html).toContain("开始只读比较");
    expect(html).not.toContain(">创建基线<");
    expect(html).not.toContain(">隔离");
    expect(html).not.toContain("<input");
    expect(html).not.toContain("<textarea");
    expect(html).not.toContain("导出");
    expect(html).not.toContain("终端");
  });

  it("shows bounded running and disconnected states without target metadata", () => {
    let html = renderToStaticMarkup(
      <IntegrityPage bindingHandle={bindingHandle} api={api} initialState={readyState("running")} />,
    );
    expect(html).toContain("比较进行中，可安全取消");
    expect(html).toContain("取消比较");
    html = renderToStaticMarkup(<IntegrityPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后检查文件完整性");
    expect(html).toContain("连接目标后可比对文件完整性基线");
    expect(html).not.toContain("server.example");
    expect(html).not.toContain("root@");
  });

  it("accepts only a binding handle prop and contains no legacy mutation API", () => {
    const source = readFileSync(new URL("./IntegrityPage.tsx", import.meta.url), "utf8");
    const props = source.slice(
      source.indexOf("interface IntegrityPageProps"),
      source.indexOf("interface IntegrityLifecycle"),
    );
    expect(props).toContain("bindingHandle: string | null");
    for (const forbidden of [
      "connection:", "target:", "sessionId", "connectionId", "host:", "username:",
      "createIntegrityBaseline", "Quarantine", "dangerouslySetInnerHTML",
    ]) {
      expect(`${props}\n${source}`).not.toContain(forbidden);
    }
    expect(source).toContain("setPollVersion((version) => version + 1)");
    expect(source).toContain("api.cancelIntegrityComparison(bindingHandle, result.operationHandle)");
  });
});
