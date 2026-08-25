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

const api: EmergencyCommandApi = {
  loadEmergencyCommandCatalog: async () => { throw new Error(); },
  runEmergencyCommand: async () => { throw new Error(); },
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
};

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

  it("exposes loading, error, empty and empty-output states", () => {
    const emptyResult = { ...result, resultKind: "empty" as const, exitCode: 0, output: "",
      observedLineCount: 0, displayedLineCount: 0, findingLines: [], findingReason: null,
      truncated: false };
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
    expect(source).toContain("api.runEmergencyCommand(bindingHandle, request.snapshotHandle, request.commandHandle)");
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
    expect(source).not.toMatch(/runEmergencyCommand\([^,]+,[^,]+,[^,)]+,[^)]/u);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./emergency-commands.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(40);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/color:\s*var\(--console-text\);[\s\S]*?background:\s*var\(--console-bg\);/u);
  });
});


