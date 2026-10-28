import { readdirSync, readFileSync } from "node:fs";

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
import { EmergencyPathDialog, EmergencyPathOutcome, EmergencyPathProperties, symbolicMode } from "./EmergencyPathDialog";
import { EmergencyPathMenu } from "./EmergencyPathMenu";

const api: EmergencyCommandApi & import("../shared/file-evidence-contract").FileEvidenceApi = {
  fileEvidence: async () => { throw new Error(); },
  loadEmergencyCommandCatalog: async () => { throw new Error(); },
  runEmergencyCommand: async () => { throw new Error(); },
  inspectEmergencyPath: async () => { throw new Error(); },
  planEmergencyPathAction: async () => { throw new Error(); },
  confirmEmergencyPathAction: async () => { throw new Error(); },
  executeEmergencyPathAction: async () => { throw new Error(); },
  cancelEmergencyPathAction: async () => { throw new Error(); },
  undoEmergencyPathAction: async () => { throw new Error(); },
  locateEmergencyHistoryCommand: async () => { throw new Error(); },
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

  // Connected, the page shows a compact toolbar and no title; while the
  // command list loads it had no heading at all for a screen reader.
  it("keeps its name for a screen reader once connected", () => {
    const html = renderToStaticMarkup(<EmergencyCommandsPage bindingHandle="binding" api={api} />);
    expect(html).toContain('<h1 class="emergency-commands-sr-only">应急命令工作台</h1>');
    expect(html).toContain("正在识别目标系统并加载命令目录");
  });

  it("says so only when the commands are the portable fallback", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    // A machine that answered needs no announcement; one that did not is about
    // to give shallower answers than it could have, and that is worth a line.
    expect(source).toContain('state.catalog?.commandSet === "portable"');
    expect(source).toContain("下面给的是通用命令");
    // It says what to do about it, and never names the distribution.
    expect(source).toContain("重新加载再试");
    expect(source).not.toMatch(/\b(?:rhel|debian|suse|alpine)\b/iu);
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

  it("turns running off, and says why, once the command list has expired", () => {
    const html = renderToStaticMarkup(<EmergencyCommandWorkbench groups={groups} commands={[command]}
      selected={command} selectedHandle={command.commandHandle} runStatus="idle" result={null} runError={null}
      search="" blockedReason="命令列表已过期，先点“重新加载”" onSelect={() => undefined} onRun={() => undefined} />);
    const run = html.match(/<button[^>]*class="emergency-command-run"[^>]*>/u)?.[0] ?? "";
    expect(run).toContain('disabled=""');
    expect(run).toContain("命令列表已过期");
    const group = html.match(/<button[^>]*class="emergency-command-group-run"[^>]*>/u)?.[0] ?? "";
    expect(group).toContain('disabled=""');
    // Picking another check still works: only running needs a fresh list.
    expect(html.match(/<button[^>]*aria-pressed="true"[^>]*>/u)?.[0] ?? "").not.toContain("disabled");

    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    // Running renews the list from when it was accepted, and only a run that
    // came back counts; a refusal for staleness settles it at once.
    expect(source).toContain("if (startedAt !== null) setCatalogUsedAt(startedAt);");
    expect(source).toContain('includes("emergency-command-catalog-unavailable")');
    expect(source).toContain("useListExpiry(state.catalog, state.catalog?.expiresInSeconds ?? null, catalogUsedAt)");
  });

  it("keeps where checks run by kind and name, and never falls back to the host on its own", () => {
    const source = readFileSync(new URL("./EmergencyCommandsPage.tsx", import.meta.url), "utf8");
    // The choice is looked up in the list on screen, not kept as a handle of
    // an earlier list (every reload hands out new ones).
    expect(source).toContain("container.kind === runChoice.kind && container.name === runChoice.name");
    expect(source).not.toContain("useState<string | null>(null);\n  // Where the checks run");
    // A choice the list no longer has blocks running and says so.
    expect(source).toContain("之前选的运行位置已不在列表里，请重新选择");
    expect(source).toContain("（已不在列表里）");
    // Another page's request chooses the place, or says why it cannot.
    expect(source).toContain("只有正在运行的 Pod 能在里面运行检查");
    expect(source).toContain("运行位置已切到");
    // A new target clears the choice.
    expect(source).toMatch(/dispatch\(\{ type: "scope-changed", scope \}\);\n\s*\/\/[^\n]*\n\s*setRunChoice\(null\);/u);
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
          passed: true, detail: "remote mode is 0644", restored: false, untouched: false, undoable: true }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(done).toContain("已完成，并在目标机上核对过。");
    expect(done).toContain("remote mode is 0644");
    expect(done).not.toContain("确认并执行");
    expect(done).toContain("撤销这次操作");
    expect(done).toContain("完成后 10 分钟内可以撤销一次。");

    const verified = { planHandle: "opaque-plan", path: offer.path, action: "disarm" as const,
      passed: true, detail: "remote mode is 0644", restored: false, untouched: false, undoable: true };
    const outcome = (props: Partial<Parameters<typeof EmergencyPathOutcome>[0]>) => renderToStaticMarkup(
      <EmergencyPathOutcome action="disarm" receipt={verified} undo={null} undoSpent={false} askingUndo={false}
        busy={false} error={null} onAskUndo={() => undefined} onKeep={() => undefined}
        onUndo={() => undefined} onClose={() => undefined} {...props} />,
    );
    // Asking says what comes back, and the safe choice comes first (it takes focus, see probe-ui).
    const asking = outcome({ askingUndo: true });
    expect(asking).toContain("这个文件会重新可以执行");
    expect(asking).toContain("只能撤销一次");
    expect(asking.indexOf("不撤销")).toBeLessThan(asking.indexOf("确认撤销"));
    expect(asking).toContain("确认撤销");
    expect(asking).not.toContain("撤销这次操作");
    expect(outcome({ askingUndo: true, action: "quarantine" })).toContain("原路径会重新出现这个文件");
    // Spent — whatever came back — it is not offered again.
    const undone = outcome({ undoSpent: true, undo: { planHandle: "opaque-plan", path: offer.path,
      undone: true, detail: "权限已经恢复为 4755" } });
    expect(undone).toContain("已撤销。");
    expect(undone).toContain("权限已经恢复为 4755");
    expect(undone).not.toContain("撤销这次操作");
    const declined = outcome({ undoSpent: true, undo: { planHandle: "opaque-plan", path: offer.path,
      undone: false, detail: "那次操作之后，目标机上的这个位置又有了变化，没有撤销。" } });
    expect(declined).toContain("没有撤销。");
    expect(declined).toContain("又有了变化");
    expect(outcome({ undoSpent: true, error: "撤销没有在时限内返回结果" })).toContain("role=\"alert\"");
    // Not verified, or not reversible: nothing to offer.
    expect(outcome({ receipt: { ...verified, undoable: false } })).not.toContain("撤销这次操作");

    const failed = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="quarantine" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "quarantine",
          passed: false, detail: "original path is still present", restored: true, untouched: false, undoable: false }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(failed).toContain("没有完成。");
    expect(failed).toContain("已还原到操作前的状态");

    // Refused before writing: says the file was left alone, never "could not restore".
    const refused = renderToStaticMarkup(
      <EmergencyPathDialog path={offer.path} action="disarm" detail={detail} plan={plan}
        receipt={{ planHandle: "opaque-plan", path: offer.path, action: "disarm",
          passed: false, detail: "权限位在你看过之后又被改过了，所以没有动它。", restored: false, untouched: true, undoable: false }}
        busy={false} error={null} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(refused).toContain("没有执行，文件保持原样。");
    expect(refused).not.toContain("未能自动还原");
    expect(refused).not.toContain("is-dangerous");

    const properties = renderToStaticMarkup(
      <EmergencyPathProperties path={offer.path} detail={detail} error={null}
        onClose={() => undefined} />,
    );
    expect(properties).toContain("能否运行还取决于账号权限、挂载选项和文件类型");
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

  it.each([
    { mode: "4700", kind: "file" as const, executable: true, text: "能否运行还取决于账号权限" },
    { mode: "4644", kind: "file" as const, executable: false, text: "脚本仍可能被解释器读取运行" },
    { mode: "0755", kind: "directory" as const, executable: true, text: "用于进入和访问目录" },
    { mode: null, kind: "file" as const, executable: false, text: "目标机未报告权限，无法判断" },
  ])("explains permission evidence without promising executability: $mode / $kind", (sample) => {
    const html = renderToStaticMarkup(<EmergencyPathProperties path="/tmp/evidence" detail={{
      pathHandle: "path-evidence", path: "/tmp/evidence", kind: sample.kind, mode: sample.mode,
      executable: sample.executable, size: "20", ownerId: 0, groupId: 0, modifiedAt: null,
    }} error={null} onClose={() => undefined} />);
    expect(html).toContain(sample.text);
    expect(html).not.toContain("任何人都跑得起来");
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
    // Null is the target itself, which stays the default. The select picks
    // from this catalogue's own entries, and what a run sends is the handle
    // of the entry in the list on screen.
    expect(source).toContain("useState<RunChoice | null>(null)");
    expect(source).toContain("container.containerHandle === event.currentTarget.value");
    expect(source).toContain("setRunChoice(picked === undefined ? null : { kind: picked.kind, name: picked.name });");
    expect(source).toContain("const containerHandle = chosenPlace?.containerHandle ?? null;");
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

  it("lets every file-action menu and dialog bring its own styles", () => {
    // They are opened from three pages. Borrowed from the workbench page's
    // sheet, the log page showed the evidence dialog as bare text below the
    // page, and the integrity page did too whenever it was opened first.
    const directory = new URL("./", import.meta.url);
    const users = readdirSync(directory)
      .filter((name) => name.endsWith(".tsx") && !name.includes(".test."))
      .filter((name) => /className="[^"]*emergency-path-(?:backdrop|dialog|menu)\b/u
        .test(readFileSync(new URL(name, directory), "utf8")));
    expect(users.sort()).toEqual([
      "EmergencyPathDialog.tsx", "EmergencyPathMenu.tsx", "FileEvidenceDialog.tsx", "LogRulesDialog.tsx",
    ]);
    for (const name of users) {
      expect(readFileSync(new URL(name, directory), "utf8"), name).toContain('import "./emergency-path.css";');
    }
    const page = readFileSync(new URL("./emergency-commands.css", import.meta.url), "utf8");
    expect(page).not.toContain(".emergency-path-");
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./emergency-commands.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(40);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/color:\s*var\(--console-text\);[\s\S]*?background:\s*var\(--console-bg\);/u);
  });
});
