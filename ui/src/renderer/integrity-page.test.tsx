import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { EmergencyCommandApi } from "../shared/emergency-command-contract";
import type { FileEvidenceApi } from "../shared/file-evidence-contract";
import {
  INTEGRITY_PRESET_DEFINITIONS,
  type IntegrityApi,
} from "../shared/integrity-contract";
import { IntegrityPage } from "./IntegrityPage";
import { createIntegrityState, type IntegrityState } from "./integrity-state";

const api: IntegrityApi & EmergencyCommandApi & FileEvidenceApi = {
  getIntegrityPresets: async () => ({}),
  listIntegrityBaselines: async () => ({}),
  startIntegrityComparison: async () => ({}),
  pollIntegrityComparison: async () => ({}),
  cancelIntegrityComparison: async () => ({}),
  startIntegrityBaselineCreation: async () => ({}),
  pollIntegrityBaselineCreation: async () => ({}),
  cancelIntegrityBaselineCreation: async () => ({}),
  loadEmergencyCommandCatalog: async () => ({}),
  runEmergencyCommand: async () => ({}),
  inspectEmergencyPath: async () => ({}),
  planEmergencyPathAction: async () => ({}),
  confirmEmergencyPathAction: async () => ({}),
  executeEmergencyPathAction: async () => ({}),
  cancelEmergencyPathAction: async () => undefined,
  undoEmergencyPathAction: async () => ({}),
  locateEmergencyHistoryCommand: async () => ({}),
  fileEvidence: async () => null,
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
      modified: 1,
      displayed: 3,
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
          pathHandle: null,
        },
        {
          path: "/var/www/removed",
          pathRedacted: false,
          pathTruncated: false,
          pathProjected: false,
          kind: "removed",
          severity: "medium",
          pathHandle: null,
        },
        {
          path: "/usr/bin/changed",
          pathRedacted: false,
          pathTruncated: false,
          pathProjected: false,
          kind: "modified",
          severity: "high",
          pathHandle: "path-handle-one",
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

  it("records preset locations only, with no path, shell or export input", () => {
    const html = renderToStaticMarkup(
      <IntegrityPage bindingHandle={bindingHandle} api={api} initialState={readyState("idle")} />,
    );
    expect(html).not.toContain("integrity-boundary-note");
    expect(html).toContain("开始比较");
    expect(html).toContain("新建基线");
    // Checkboxes choose among the presets.
    const inputs = html.match(/<input[^>]*>/gu) ?? [];
    expect(inputs).toHaveLength(INTEGRITY_PRESET_DEFINITIONS.length);
    expect(inputs.every((input) => input.includes('type="checkbox"'))).toBe(true);
    // The catalogue's defaults start ticked.
    expect(inputs.filter((input) => input.includes("checked")).length)
      .toBe(INTEGRITY_PRESET_DEFINITIONS.filter((preset) => preset.defaultSelected).length);
    // Nothing takes a typed path.
    expect(html).not.toContain("<textarea");
    expect(html).not.toContain("导出");
    expect(html).not.toContain("终端");
    expect(html).not.toMatch(/Phase \d/u);
  });

  it("offers file actions only on a file shown whole that is there to act on", () => {
    const html = renderToStaticMarkup(
      <IntegrityPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    const buttons = html.match(/aria-label="文件操作：[^"]*"/gu) ?? [];
    expect(buttons).toEqual(['aria-label="文件操作：/usr/bin/changed"']);
    // The handle marks the row for the menu and focus; it is not shown as text.
    expect(html).toContain('data-path-handle="path-handle-one"');
    expect(html).not.toContain(">path-handle-one<");
  });

  it("shows bounded running and disconnected states without target metadata", () => {
    let html = renderToStaticMarkup(
      <IntegrityPage bindingHandle={bindingHandle} api={api} initialState={readyState("running")} />,
    );
    expect(html).toContain("比较进行中，可安全取消");
    expect(html).toContain("取消比较");
    html = renderToStaticMarkup(<IntegrityPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后检查文件完整性");
    expect(html).toContain("连接目标后可以新建基线");
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
