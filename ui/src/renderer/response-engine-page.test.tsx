import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  ResponseEngineApi,
  ResponseEngineScan,
  ResponseIssue,
} from "../shared/response-engine-contract";
import { ResponseEnginePage, type ResponseFixRowState } from "./ResponseEnginePage";

const api: ResponseEngineApi = {
  responseEngine: async () => ({}),
};

const bindingHandle = "binding-secret-capability";
const hostile = "<script>alert(1)</script><img src=x onerror=steal()>";

function issue(overrides: Partial<ResponseIssue> = {}): ResponseIssue {
  return {
    issueHandle: "issue-handle-one",
    kind: "empty-password",
    severity: "high",
    summary: "账户 watcher 的口令为空",
    evidence: ["watcher::1000:1000::/home/watcher:/bin/bash"],
    fixable: true,
    fixSummary: "锁定账户口令",
    ...overrides,
  };
}

function scan(issues: ResponseIssue[], overrides: Partial<ResponseEngineScan> = {}): ResponseEngineScan {
  return {
    kind: "scan",
    scanHandle: "scan-handle-one",
    scannedAt: "2026-10-29T08:00:00+08:00",
    truncated: false,
    gaps: [],
    issues,
    ...overrides,
  };
}

describe("standalone ResponseEnginePage", () => {
  it("asks for a target before anything else when none is connected", () => {
    const html = renderToStaticMarkup(<ResponseEnginePage api={api} bindingHandle={null} />);
    expect(html).toContain("连接目标后开始应急处置");
    expect(html).not.toContain("开始扫描");
    expect(html).not.toContain("response-engine-scan");
  });

  it("shows the scan-item picker summary with every category selected by default", () => {
    // 面板默认收起（SSR 不做点击），但按钮上能看到 19/19 全选状态。
    const html = renderToStaticMarkup(<ResponseEnginePage api={api} bindingHandle={bindingHandle} />);
    expect(html).toContain("扫描项（19/19）");
    expect(html).toContain('aria-expanded="false"');
    // 收起时不出复选框，展开是运行时交互。
    expect(html).not.toContain('type="checkbox"');
  });

  it("offers the scan before any result and explains it is read-only", () => {
    const html = renderToStaticMarkup(<ResponseEnginePage api={api} bindingHandle={bindingHandle} />);
    expect(html).toContain("开始扫描");
    expect(html).toContain("扫描只读取状态，不改动目标");
  });

  it("renders issues with Chinese labels and escapes hostile remote text", () => {
    const html = renderToStaticMarkup(
      <ResponseEnginePage
        api={api}
        bindingHandle={bindingHandle}
        initialScan={scan([
          issue({ summary: hostile, evidence: [hostile] }),
          issue({ issueHandle: "issue-two", kind: "backdoor-process", severity: "high" }),
          issue({ issueHandle: "issue-three", kind: "cron-persistence", severity: "medium", fixable: false, fixSummary: null }),
        ], { truncated: true, gaps: ["缺少 sudo 权限，sudoers 检查未执行"] })}
      />,
    );
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("空口令账户");
    expect(html).toContain("后门进程");
    expect(html).toContain("cron 持久化");
    expect(html).toContain("高危");
    expect(html).toContain("中危");
    expect(html).toContain("扫描存在缺口");
    expect(html).toContain("已按安全上限截断");
    expect(html).toContain("重新扫描");
    // Handles are capabilities; they never reach the markup.
    expect(html).not.toContain("issue-handle-one");
    expect(html).not.toContain(bindingHandle);
  });

  it("keeps the fix button but disables it with a reason when the issue is not fixable", () => {
    const html = renderToStaticMarkup(
      <ResponseEnginePage
        api={api}
        bindingHandle={bindingHandle}
        initialScan={scan([issue({ fixable: false, fixSummary: null })])}
      />,
    );
    expect(html).toContain("暂不支持自动修复");
    expect(html).toMatch(/<button[^>]*disabled[^>]*>修复<\/button>/u);
  });

  it("shows the inline fix stages instead of the fix button", () => {
    const fixes: Record<string, ResponseFixRowState> = {
      "issue-running": { stage: "executing", operationHandle: "op-running" },
      "issue-pending": { stage: "verify-pending", operationHandle: "op-pending" },
      "issue-done": { stage: "completed", verifyPassed: true, summary: "修复完成并复验通过" },
      "issue-unverified": { stage: "completed", verifyPassed: false, summary: "复验未通过" },
      "issue-failed": { stage: "failed", summary: "执行失败" },
    };
    const html = renderToStaticMarkup(
      <ResponseEnginePage
        api={api}
        bindingHandle={bindingHandle}
        initialScan={scan([
          issue({ issueHandle: "issue-running" }),
          issue({ issueHandle: "issue-pending" }),
          issue({ issueHandle: "issue-done" }),
          issue({ issueHandle: "issue-unverified" }),
          issue({ issueHandle: "issue-failed" }),
        ])}
        initialFixes={fixes}
      />,
    );
    expect(html).toContain("正在执行…");
    expect(html).toContain("等待跨周期复验");
    expect(html).toContain("已执行并复验通过");
    expect(html).toContain("已执行，但复验未通过");
    expect(html).toContain("执行未成功");
    // Operation handles stay out of the DOM.
    expect(html).not.toContain("op-running");
    expect(html).not.toContain(">修复</button>");
  });

  it("says an empty result is not proof of a clean host", () => {
    const html = renderToStaticMarkup(
      <ResponseEnginePage api={api} bindingHandle={bindingHandle} initialScan={scan([])} />,
    );
    expect(html).toContain("未发现这十九类入侵痕迹");
    expect(html).toContain("不代表目标一定未被入侵");
  });

});
