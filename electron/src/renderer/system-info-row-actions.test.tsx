import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  isSystemInfoRowActionKey,
  isSystemInfoRowActions,
  isSystemInfoRowInspection,
  isSystemInfoRowPlan,
  isSystemInfoRowReceipt,
  type SystemInfoRow,
  type SystemInfoRowActions,
  type SystemInfoRowInspection,
  type SystemInfoRowPlan,
  type SystemInfoRowReceipt,
} from "../shared/system-info-contract";
import { buildSystemInfoRowCopy, groupShellConfigRows } from "./system-info-helpers";
import { rowActionFailureText } from "./system-info-row-actions";
import { SystemInfoRowActionDialog } from "./SystemInfoRowActionDialog";
import { SystemInfoRowMenu } from "./SystemInfoRowMenu";

const hostile = "<script>steal()</script>";

const row: SystemInfoRow = {
  id: "opaque-row-id",
  cells: ["normal", "4242", "1", "root", "S", "0.1", "0.5", "120", `/usr/bin/sshd -D ${hostile}`],
  risk: "normal",
  detail: true,
};

function actions(overrides: Partial<SystemInfoRowActions> = {}): SystemInfoRowActions {
  return {
    tab: "processes",
    rowId: "opaque-row-id",
    subject: "PID 4242 · /usr/bin/sshd -D",
    groups: [
      {
        key: "basics",
        label: "基本信息",
        actions: [
          { key: "process.command-line", label: "命令行参数", kind: "inspect", dangerous: false },
          { key: "process.executable", label: "可执行路径", kind: "inspect", dangerous: false },
        ],
      },
      {
        key: "change",
        label: "处置",
        actions: [
          { key: "process.signal.terminate", label: "终止进程（SIGTERM）", kind: "change", dangerous: true },
          { key: "process.signal.kill", label: "强制终止进程（SIGKILL）", kind: "change", dangerous: true },
        ],
      },
    ],
    ...overrides,
  };
}

function plan(overrides: Partial<SystemInfoRowPlan> = {}): SystemInfoRowPlan {
  return {
    planHandle: "opaque-plan",
    tab: "processes",
    rowId: "opaque-row-id",
    action: "process.signal.kill",
    label: "强制终止进程（SIGKILL）",
    subject: "PID 4242 · /usr/bin/sshd -D",
    summary: "强制终止进程（SIGKILL） PID 4242（sshd，启动时钟 1234）。此操作不可恢复。",
    dangerous: true,
    restoreDescription: null,
    confirmed: false,
    expiresInSeconds: 300,
    ...overrides,
  };
}

function receipt(overrides: Partial<SystemInfoRowReceipt> = {}): SystemInfoRowReceipt {
  return {
    planHandle: "opaque-plan",
    tab: "processes",
    rowId: "opaque-row-id",
    action: "process.signal.kill",
    label: "强制终止进程（SIGKILL）",
    subject: "PID 4242 · /usr/bin/sshd -D",
    verified: true,
    detail: "PID 4242 no longer has the confirmed start identity",
    restored: false,
    ...overrides,
  };
}

function inspection(overrides: Partial<SystemInfoRowInspection> = {}): SystemInfoRowInspection {
  return {
    tab: "processes",
    rowId: "opaque-row-id",
    action: "process.command-line",
    label: "命令行参数",
    subject: "PID 4242 · /usr/bin/sshd -D",
    output: `/usr/bin/sshd -D ${hostile}`,
    truncated: false,
    ...overrides,
  };
}

describe("system-info row action contract", () => {
  it("accepts only two- or three-segment kebab-case action keys", () => {
    for (const key of ["process.open-files", "process.signal.kill", "ssh-key.fingerprint", "a.b"]) {
      expect(isSystemInfoRowActionKey(key)).toBe(true);
    }
    for (const key of [
      "", "process", "process.", ".open-files", "Process.Open", "process.kill -9",
      "a.b.c.d", "process..kill", "process.open_files", `process.${"x".repeat(70)}`, 42,
    ]) {
      expect(isSystemInfoRowActionKey(key)).toBe(false);
    }
  });

  it("validates the row action list, refusing duplicates and unknown shapes", () => {
    expect(isSystemInfoRowActions(actions())).toBe(true);
    expect(isSystemInfoRowActions(actions({ groups: [] }))).toBe(true);
    const duplicated = actions();
    duplicated.groups[1]?.actions.push({
      key: "process.command-line", label: "again", kind: "inspect", dangerous: false,
    });
    expect(isSystemInfoRowActions(duplicated)).toBe(false);
    expect(isSystemInfoRowActions({ ...actions(), extra: true })).toBe(false);
    expect(isSystemInfoRowActions(actions({ tab: "nope" as never }))).toBe(false);
    const oddKind = actions();
    (oddKind.groups[0]?.actions[0] as { kind: string }).kind = "shell";
    expect(isSystemInfoRowActions(oddKind)).toBe(false);
    const emptyGroup = actions({ groups: [{ key: "basics", label: "基本信息", actions: [] }] });
    expect(isSystemInfoRowActions(emptyGroup)).toBe(false);
  });

  it("validates inspections, plans and receipts with their bounds", () => {
    expect(isSystemInfoRowInspection(inspection())).toBe(true);
    expect(isSystemInfoRowInspection(inspection({ output: "" }))).toBe(true);
    expect(isSystemInfoRowInspection(inspection({ output: "x".repeat(300 * 1024) }))).toBe(false);
    expect(isSystemInfoRowInspection({ ...inspection(), command: "id" })).toBe(false);

    expect(isSystemInfoRowPlan(plan())).toBe(true);
    expect(isSystemInfoRowPlan(plan({ restoreDescription: "已备份" }))).toBe(true);
    expect(isSystemInfoRowPlan(plan({ planHandle: "../etc" }))).toBe(false);
    expect(isSystemInfoRowPlan(plan({ expiresInSeconds: 0 }))).toBe(false);
    expect(isSystemInfoRowPlan(plan({ summary: "" }))).toBe(false);

    expect(isSystemInfoRowReceipt(receipt())).toBe(true);
    expect(isSystemInfoRowReceipt(receipt({ verified: "yes" as never }))).toBe(false);
    expect(isSystemInfoRowReceipt({ ...receipt(), remotePath: "/x" })).toBe(false);
  });
});

describe("system-info row menu", () => {
  it("offers the local items at once and the target's actions grouped when they arrive", () => {
    const loading = renderToStaticMarkup(
      <SystemInfoRowMenu
        position={{ x: 10, y: 10 }}
        row={row}
        cell={row.cells[8] ?? null}
        actions={null}
        error={null}
        onLocal={() => undefined}
        onAction={() => undefined}
        onDismiss={() => undefined}
      />,
    );
    expect(loading).toContain("复制这一格");
    expect(loading).toContain("复制整行");
    expect(loading).toContain("查看详情");
    expect(loading).toContain("正在读取这一行能做什么");
    expect(loading).not.toContain("<script>");
    expect(loading).not.toContain("opaque-row-id");

    const loaded = renderToStaticMarkup(
      <SystemInfoRowMenu
        position={{ x: 10, y: 10 }}
        row={{ ...row, detail: false }}
        cell={null}
        actions={actions()}
        error={null}
        onLocal={() => undefined}
        onAction={() => undefined}
        onDismiss={() => undefined}
      />,
    );
    expect(loaded).not.toContain("复制这一格");
    expect(loaded).not.toContain("查看详情");
    expect(loaded).toContain("PID 4242 · /usr/bin/sshd -D");
    expect(loaded).toContain("基本信息");
    expect(loaded).toContain("命令行参数");
    expect(loaded).toContain("处置");
    expect(loaded).toContain('class="is-dangerous"');
    expect(loaded.indexOf("命令行参数")).toBeLessThan(loaded.indexOf("强制终止进程"));
    expect(loaded).not.toContain("正在读取");

    const empty = renderToStaticMarkup(
      <SystemInfoRowMenu
        position={{ x: 10, y: 10 }}
        row={row}
        cell={null}
        actions={actions({ groups: [] })}
        error={null}
        onLocal={() => undefined}
        onAction={() => undefined}
        onDismiss={() => undefined}
      />,
    );
    expect(empty).toContain("没有可用的操作");
  });

  it("explains a refusal in the operator's terms", () => {
    expect(rowActionFailureText(new Error("That action does not apply. (system-info-action-unavailable)")))
      .toContain("刷新");
    expect(rowActionFailureText(new Error("Stale. (system-info-snapshot-invalid)"))).toContain("过期");
    expect(rowActionFailureText(new Error("Gone. (system-info-binding-unavailable)"))).toContain("断开");
    expect(rowActionFailureText(new Error("Used. (system-info-plan-unavailable)"))).toContain("失效");
    expect(rowActionFailureText(new Error("Slow. (system-info-timeout)"))).toContain("回应");
    expect(rowActionFailureText(new Error("目标机返回的结果无法识别。"))).toBe("目标机返回的结果无法识别。");
    expect(rowActionFailureText(undefined)).toBe("操作失败。");
  });
});

describe("system-info row action dialog", () => {
  it("shows inspection output whole and plain, and says when it was cut short", () => {
    const markup = renderToStaticMarkup(
      <SystemInfoRowActionDialog
        state={{
          subject: "PID 4242 · /usr/bin/sshd -D",
          action: { key: "process.command-line", label: "命令行参数", kind: "inspect", dangerous: false },
          inspection: inspection({ truncated: true }),
          plan: null,
          receipt: null,
          busy: false,
          error: null,
        }}
        onConfirm={() => undefined}
        onCopyOutput={() => undefined}
        onClose={() => undefined}
      />,
    );
    expect(markup).toContain("排查");
    expect(markup).toContain("命令行参数");
    expect(markup).toContain("&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>");
    expect(markup).toContain("只显示了目标机返回的前一部分");
    expect(markup).toContain("复制输出");
    expect(markup).not.toContain("确认并执行");
    expect(markup).not.toContain("opaque-row-id");
  });

  it("walks a change through plan, confirmation and receipt", () => {
    const base = {
      subject: "PID 4242 · /usr/bin/sshd -D",
      action: { key: "process.signal.kill", label: "强制终止进程（SIGKILL）", kind: "change" as const, dangerous: true },
      inspection: null,
      busy: false,
      error: null,
    };
    const planning = renderToStaticMarkup(
      <SystemInfoRowActionDialog
        state={{ ...base, plan: null, receipt: null, busy: true }}
        onConfirm={() => undefined}
        onCopyOutput={() => undefined}
        onClose={() => undefined}
      />,
    );
    expect(planning).toContain("准备计划");
    expect(planning).toMatch(/disabled=""[^>]*data-testid="system-info-row-action-execute"/u);

    const planned = renderToStaticMarkup(
      <SystemInfoRowActionDialog
        state={{ ...base, plan: plan(), receipt: null }}
        onConfirm={() => undefined}
        onCopyOutput={() => undefined}
        onClose={() => undefined}
      />,
    );
    expect(planned).toContain("处置");
    expect(planned).toContain("此操作不可恢复");
    expect(planned).toContain("高风险，需要确认");
    expect(planned).toContain("无备份，执行后不可自动还原");
    expect(planned).toContain("300 秒");
    expect(planned).toContain("确认并执行");
    expect(planned).not.toContain("opaque-plan");

    const done = renderToStaticMarkup(
      <SystemInfoRowActionDialog
        state={{ ...base, plan: plan({ confirmed: true }), receipt: receipt() }}
        onConfirm={() => undefined}
        onCopyOutput={() => undefined}
        onClose={() => undefined}
      />,
    );
    expect(done).toContain("已完成，并在目标机上核对过");
    expect(done).toContain("no longer has the confirmed start identity");
    expect(done).not.toContain("确认并执行");

    const failed = renderToStaticMarkup(
      <SystemInfoRowActionDialog
        state={{ ...base, plan: plan({ confirmed: true }), receipt: receipt({ verified: false, restored: true }) }}
        onConfirm={() => undefined}
        onCopyOutput={() => undefined}
        onClose={() => undefined}
      />,
    );
    expect(failed).toContain("没有完成");
    expect(failed).toContain("已还原到操作前的状态");
  });
});

describe("system-info row helpers", () => {
  it("copies one row as plain tab-separated text and keeps shell lines addressable", () => {
    expect(buildSystemInfoRowCopy({ ...row, cells: ["a\tb", "c\nd"] })).toBe("a b\tc d");
    const files = groupShellConfigRows({
      snapshotHandle: "opaque-snapshot",
      tab: "shell-configs",
      columns: ["文件", "所有者", "修改时间", "行号", "内容", "风险"],
      rows: [
        { id: "line-1", cells: ["/root/.bashrc", "root", "1700000000", "1", "# comment", "normal"], risk: "normal", detail: false },
        { id: "line-2", cells: ["/root/.bashrc", "root", "1700000000", "2", "curl x | sh", "high"], risk: "high", detail: false },
      ],
      truncated: false,
    });
    expect(files[0]?.lines.map((line) => line.rowId)).toEqual(["line-1", "line-2"]);
  });
});
