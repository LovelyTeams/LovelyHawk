import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  EmergencyCommandApi,
  EmergencyCommandCatalogItem,
  EmergencyCommandResult,
} from "../shared/emergency-command-contract";
import {
  EmergencyCommandEmpty,
  EmergencyCommandError,
  EmergencyCommandGroupView,
  EmergencyCommandResultView,
  EmergencyCommandsPage,
  EmergencyCommandStatus,
  EmergencyCommandWorkbench,
} from "./EmergencyCommandsPage";
import { EmergencyPathDialog, EmergencyPathProperties, symbolicMode } from "./EmergencyPathDialog";
import { EmergencyPathMenu } from "./EmergencyPathMenu";

const api: EmergencyCommandApi = {
  loadEmergencyCommandCatalog: async () => { throw new Error(); },
  runEmergencyCommand: async () => { throw new Error(); },
  inspectEmergencyPath: async () => { throw new Error(); },
  planEmergencyPathAction: async () => { throw new Error(); },
  confirmEmergencyPathAction: async () => { throw new Error(); },
  executeEmergencyPathAction: async () => { throw new Error(); },
  cancelEmergencyPathAction: async () => { throw new Error(); },
};

const command: EmergencyCommandCatalogItem = {
  commandHandle: "opaque-command",
  category: "network",
  title: "监听端口",
  description: "只读收集监听状态。",
  timeoutSeconds: 30,
};

const groups = [{ category: "network" as const, commands: [command] }];

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const result: EmergencyCommandResult = {
  snapshotHandle: "opaque-snapshot",
  commandHandle: "opaque-command",
  resultKind: "permission-denied",
  exitCode: 1,
  output: `${hostile}\nroot:$6$salt$hash:19000:0:99999:7:::`,
  observedLineCount: 4,
  displayedLineCount: 2,
  findingLines: [0],
  findingReason: "标红的行不在发行版自带的 SUID 名单内。",
  truncated: true,
  paths: [],
};

const offer = { pathHandle: "opaque-path", line: 1, path: "/usr/local/lib/pyshared/.helper" };

describe("EmergencyCommandsPage", () => {
  it("renders an honest disconnected state", () => {
    const html = renderToStaticMarkup(<EmergencyCommandsPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接 SSH 目标后");
    expect(html).toContain("内置的只读调查命令");
    expect(html).not.toContain("opaque-command");
  });

  it("renders only safe catalog metadata without a shell preview", () => {
    const html = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      selected={command} selectedHandle={command.commandHandle} runStatus="idle" result={null} runError={null}
      search="" onSelect={() => undefined} onRun={() => undefined} />);
    expect(html).toContain("监听端口");
    expect(html).toContain("只读收集监听状态");
    expect(html).toContain("30 秒上限");
    expect(html).toContain("运行只读调查");
    expect(html).not.toContain("ss -tulpen");
    expect(html).not.toContain("network-listen");
  });

  it("renders the catalog as collapsible branches with a quick run per group", () => {
    const html = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      selected={command} selectedHandle={command.commandHandle} runStatus="idle" result={null} runError={null}
      search="" onSelect={() => undefined} onRun={() => undefined} />);
    expect(html).toContain("网络排查");
    expect(html).toContain('aria-expanded="true"');
    expect(html).toContain("快速执行");
    expect(html).toContain('aria-label="快速执行 网络排查 的 1 项调查"');

    const collapsed = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      collapsed={["network"]} selected={command} selectedHandle={command.commandHandle} runStatus="idle"
      result={null} runError={null} search="" onSelect={() => undefined} onRun={() => undefined} />);
    expect(collapsed).toContain('aria-expanded="false"');
    // Only the branch folds; the detail pane keeps showing what is selected.
    const tree = collapsed.slice(0, collapsed.indexOf("</aside>"));
    expect(tree).not.toContain("只读收集监听状态");
    expect(tree).toContain("快速执行");
  });

  it("shows an in-order group run with per-step progress and results", () => {
    const running = renderToStaticMarkup(<EmergencyCommandGroupView commands={[command]} run={{
      id: 1, snapshotHandle: "opaque-snapshot", category: "network",
      commandHandles: [command.commandHandle], entries: [], status: "loading",
    }} />);
    expect(running).toContain("网络排查 · 快速执行");
    expect(running).toContain("正在执行第 1 项，共 1 项");
    expect(running).toContain("监听端口");
    expect(running).not.toContain("opaque-command");

    const finished = renderToStaticMarkup(<EmergencyCommandGroupView commands={[command]} run={{
      id: 1, snapshotHandle: "opaque-snapshot", category: "network", commandHandles: [command.commandHandle],
      entries: [{ commandHandle: command.commandHandle, result, error: null, elapsedMs: 1230 }], status: "ready",
    }} />);
    expect(finished).toContain("已完成 1 项");
    expect(finished).toContain("1 项未成功");
    expect(finished).toContain("完成耗时 1.23 秒");
    expect(finished).toContain("权限不足");
  });

  it("renders hostile output as escaped plain text without hiding anything", () => {
    const html = renderToStaticMarkup(<EmergencyCommandResultView result={result} />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img src=x");
    // Nothing is hidden: what the target printed reaches the operator.
    expect(html).toContain("root:$6$salt$hash");
    expect(html).toContain("输出已按行数或大小上限截断");
    expect(html).toContain("权限不足");
  });

  /** Highlights only exist where the core marked a line. */
  it("marks the abnormal output lines and counts them", () => {
    const marked = { ...result, resultKind: "success" as const, exitCode: 0,
      output: "/usr/bin/passwd\n/tmp/.hidden/bash\n/home/ctf/rootshell",
      observedLineCount: 3, displayedLineCount: 3, truncated: false,
      findingLines: [1, 2] };
    const html = renderToStaticMarkup(<EmergencyCommandResultView result={marked} />);
    expect(html).toContain("2 处需要关注");
    // The operator has to be told why, not just where.
    expect(html).toContain("标红的行不在发行版自带的 SUID 名单内。");
    expect(html).toContain('<span class="is-abnormal">/tmp/.hidden/bash');
    expect(html).toContain('<span class="is-abnormal">/home/ctf/rootshell');
    // The stock binary keeps the neutral rendering.
    expect(html).toContain("<span>/usr/bin/passwd");

    const quiet = renderToStaticMarkup(<EmergencyCommandResultView
      result={{ ...marked, findingLines: [] }} />);
    expect(quiet).not.toContain("处需要关注");
    expect(quiet).not.toContain("is-abnormal");
    // Nothing marked means nothing to explain.
    expect(quiet).not.toContain("标红的行");
  });

  it("offers a right-click only on the lines that named a file", () => {
    const named = {
      ...result,
      resultKind: "success" as const,
      exitCode: 0,
      output: "总用量 4\n-rwsr-xr-x 1 root root 17 8月 25 23:36 /usr/local/lib/pyshared/.helper",
      observedLineCount: 2,
      displayedLineCount: 2,
      findingLines: [1],
      truncated: false,
      paths: [offer],
    };
    const html = renderToStaticMarkup(
      <EmergencyCommandResultView result={named} onPathMenu={() => undefined} />,
    );
    expect(html).toContain("1 行可右键处置");
    expect(html).toContain('class="is-abnormal has-path"');
    expect(html).toContain("右键可对 /usr/local/lib/pyshared/.helper 处置");
    // The line above named nothing, so it stays an ordinary line.
    expect(html).toContain("<span>总用量 4");

    // Without a handler there is nothing to right-click, and no promise of one.
    const inert = renderToStaticMarkup(<EmergencyCommandResultView result={named} />);
    expect(inert).not.toContain("has-path");
    expect(inert).not.toContain("行可右键处置");
    expect(inert).not.toContain("右键可对");
  });

  it("names the file in the menu without offering to run anything", () => {
    const html = renderToStaticMarkup(
      <EmergencyPathMenu position={{ x: 10, y: 20 }} offer={offer} busy={false}
        onAction={() => undefined} onDismiss={() => undefined} />,
    );
    expect(html).toContain("/usr/local/lib/pyshared/.helper");
    expect(html).toContain("查看属性");
    expect(html).toContain("去掉执行权限");
    expect(html).toContain("隔离");
    expect(html).toContain('role="menu"');
    // Every item leads to a plan the operator still has to read.
    expect(html).not.toContain("立即");
    expect(html).not.toContain("彻底删除");
  });

  it("shows what will happen before it happens, and what happened after", () => {
    const detail = {
      pathHandle: offer.pathHandle,
      path: offer.path,
      kind: "file" as const,
      size: "125688",
      mode: "4755",
      ownerId: 0,
      groupId: 0,
      modifiedAt: "2026-08-25T23:31:00+00:00",
      executable: true,
    };
    const plan = {
      planHandle: "opaque-plan",
      pathHandle: offer.pathHandle,
      path: offer.path,
      action: "disarm" as const,
      summary: "change /usr/local/lib/pyshared/.helper permissions from 4755 to 0644",
      dangerous: true,
      restoreDescription: "restore the captured permission bits",
      state: "planned" as const,
      expiresInSeconds: 300,
    };
    const planned = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={null} busy={false} error={null}
        onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(planned).toContain("去掉执行权限");
    expect(planned).toContain("4755（rwsr-xr-x）");
    expect(planned).toContain("change /usr/local/lib/pyshared/.helper permissions");
    expect(planned).toContain("restore the captured permission bits");
    expect(planned).toContain("确认并执行");

    const done = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "disarm",
          passed: true, detail: "remote mode is 0644", restored: false }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(done).toContain("已完成，并在目标机上核对过。");
    expect(done).toContain("remote mode is 0644");
    expect(done).not.toContain("确认并执行");

    const failed = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="quarantine" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "quarantine",
          passed: false, detail: "original path is still present", restored: true }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(failed).toContain("没有完成。");
    expect(failed).toContain("已还原到操作前的状态");

    const properties = renderToStaticMarkup(
      <EmergencyPathProperties path={offer.path} detail={detail} error={null}
        onClose={() => undefined} />,
    );
    expect(properties).toContain("可以，任何人都跑得起来");
    expect(properties).toContain("122.7 KB（125688 字节）");
    expect(properties).not.toContain("确认并执行");
  });

  it("reads a mode the way a listing on the target does", () => {
    expect(symbolicMode("4755")).toBe("rwsr-xr-x");
    expect(symbolicMode("0644")).toBe("rw-r--r--");
    expect(symbolicMode("1777")).toBe("rwxrwxrwt");
    expect(symbolicMode("2755")).toBe("rwxr-sr-x");
    // A set bit without the matching execute bit is the capital letter.
    expect(symbolicMode("4644")).toBe("rwSr--r--");
    expect(symbolicMode("nope")).toBe("nope");
  });

  it("exposes loading, error, empty and empty-output states", () => {
    const emptyResult = { ...result, resultKind: "empty" as const, exitCode: 0, output: "",
      observedLineCount: 0, displayedLineCount: 0, findingLines: [], findingReason: null,
      truncated: false, paths: [] };
    const html = [
      renderToStaticMarkup(<EmergencyCommandStatus label="执行中…" />),
      renderToStaticMarkup(<EmergencyCommandError message="固定公开错误" />),
      renderToStaticMarkup(<EmergencyCommandEmpty title="空目录" detail="没有项目" />),
      renderToStaticMarkup(<EmergencyCommandResultView result={emptyResult} />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("role=\"alert\"");
    expect(html).toContain("命令没有输出");
  });

  it("keeps phase one free of arbitrary input and adjacent action surfaces", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("api.loadEmergencyCommandCatalog(bindingHandle)");
    // Handles and nothing else, plus where to run it — and that is a handle
    // from the same catalogue too, never a container name or id.
    expect(source).toMatch(
      /api\.runEmergencyCommand\(\s*bindingHandle,\s*request\.snapshotHandle,\s*request\.commandHandle,\s*containerHandle \?\? undefined,\s*\)/u,
    );
    // Null is the target itself, which stays the default.
    expect(source).toContain("useState<string | null>(null)");
    expect(source).toContain("event.currentTarget.value === \"\" ? null : event.currentTarget.value");
    expect(source).toContain("bindingHandle: string | null;");
    expect(source).not.toContain("SshTargetSummary");
    expect(source).not.toContain("EmergencyCommandsConnection");
    for (const forbidden of [
      "dangerouslySetInnerHTML",
      "contentEditable",
      "<textarea",
      "setInterval",
      "window.open",
      ["open", "Terminal"].join(""),
      ["open", "File"].join(""),
      ["export", "Command"].join(""),
      ["plan", "Mutation"].join(""),
      ["run", "CustomCommand"].join(""),
      "commandText",
      "remotePath",
      "sessionId:",
      "generation:",
    ]) expect(source).not.toContain(forbidden);
    // The run call carries handles and nothing else. It used to be pinned as
    // "no fourth argument at all", which stopped being the right rule once
    // there was a legitimate fourth — so the rule now names what that one may
    // be rather than forbidding the position.
    for (const call of source.match(/api\.runEmergencyCommand\([\s\S]*?\)/gu) ?? []) {
      const passed = call
        .slice(call.indexOf("(") + 1, call.lastIndexOf(")"))
        .split(",")
        .map((argument) => argument.trim())
        .filter((argument) => argument !== "");
      expect(passed).toHaveLength(4);
      // The first three are plain identifiers the page was handed — never a
      // literal, a template or anything it composed itself.
      for (const argument of passed.slice(0, 3)) {
        expect(argument).toMatch(/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?$/u);
      }
      // And the fourth is the container, or the target when there is none.
      expect(passed[3]).toBe("containerHandle ?? undefined");
    }
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./emergency-commands.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(40);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/color:\s*var\(--console-text\);[\s\S]*?background:\s*var\(--console-bg\);/u);
  });
});


