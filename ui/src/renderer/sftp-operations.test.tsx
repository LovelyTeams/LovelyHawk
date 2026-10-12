import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  SftpBrowserEntry,
  SftpOperationPlan,
  SftpOperationReceipt,
} from "../shared/sftp-browser-contract";
import { menuItems, SftpContextMenu } from "./SftpContextMenu";
import { sftpUndoFailure, transferStopped } from "./SftpBrowserPage";
import { SftpOperationDialog, SftpOperationOutcome, type SftpOperationDraft } from "./SftpOperationDialog";
import { SftpPropertiesDialog, specialBits, symbolicMode } from "./SftpPropertiesDialog";

const hostile = "<script>steal()</script>";

function plan(overrides: Partial<SftpOperationPlan> = {}): SftpOperationPlan {
  return {
    planHandle: "opaque-plan",
    browserHandle: "opaque-browser",
    kind: "remove",
    summary: "删除 /var/www/upload.php",
    dangerous: true,
    restoreDescription: "已备份原文件，校验失败会自动放回",
    state: "planned",
    expiresInSeconds: 120,
    ...overrides,
  };
}

function receipt(overrides: Partial<SftpOperationReceipt> = {}): SftpOperationReceipt {
  return {
    planHandle: "opaque-plan",
    kind: "remove",
    passed: true,
    detail: "目标已不存在。",
    restored: false,
    undoable: true,
    cancelled: false,
    ...overrides,
  };
}

function dialog(
  draft: SftpOperationDraft,
  value: SftpOperationPlan | null,
  result: SftpOperationReceipt | null = null,
): string {
  return renderToStaticMarkup(
    <SftpOperationDialog
      draft={draft}
      plan={value}
      receipt={result}
      busy={false}
      error={null}
      onPlan={() => undefined}
      onConfirm={() => undefined}
      onClose={() => undefined}
    />,
  );
}

const removeDraft: SftpOperationDraft = { kind: "remove", subject: "upload.php" };

describe("sftp operation dialog", () => {
  /**
   * The point of the plan step is that the operator reads it. All of it has to
   * be on screen before the button that runs it exists.
   */
  it("shows what the plan will do, what it risks and what it can put back", () => {
    const markup = dialog(removeDraft, plan());
    expect(markup).toContain("删除 /var/www/upload.php");
    expect(markup).toContain("高风险，需要确认");
    expect(markup).toContain("已备份原文件，校验失败会自动放回");
    // The dialog reads the window out loud rather than making an operator
    // divide by sixty on the screen where they are about to change a machine.
    expect(markup).toContain("2 分钟");
    expect(markup).not.toContain("120 秒");
    expect(markup).toContain("确认并执行");
  });

  /** A plan without a backup must say so rather than stay silent. */
  it("says plainly when nothing can be put back", () => {
    const markup = dialog(removeDraft, plan({ restoreDescription: null, dangerous: false }));
    expect(markup).toContain("无备份，执行后不可自动还原");
    expect(markup).toContain("常规操作");
    // A plain operation still runs behind a button that names the act.
    expect(markup).toContain(">执行<");
  });

  /** Before a plan exists there is nothing to confirm, so there is no run button. */
  it("cannot run anything before a plan has been generated", () => {
    const markup = dialog({ kind: "chmod", subject: "authorized_keys" }, null);
    expect(markup).toContain("生成计划");
    expect(markup).not.toContain("sftp-operation-execute");
    expect(markup).toContain("权限（八进制，如 644）");
  });

  it("reports the verification result, including a rollback", () => {
    const passed = dialog(removeDraft, plan(), receipt());
    expect(passed).toContain("已完成并通过校验");
    expect(passed).toContain("目标已不存在。");
    expect(passed).not.toContain("已回滚到操作前的状态。");

    const failed = dialog(
      removeDraft,
      plan(),
      receipt({ passed: false, detail: "目标仍然存在。", restored: true }),
    );
    expect(failed).toContain("未通过校验");
    expect(failed).toContain("已回滚到操作前的状态。");
    expect(failed).not.toContain("撤销这次操作");
  });

  it("offers one undo of verified work, asks first, and reports what came back", () => {
    expect(dialog(removeDraft, plan(), receipt())).toContain("撤销这次操作");
    expect(dialog(removeDraft, plan(), receipt())).toContain("完成后 10 分钟内可以撤销一次。");
    expect(dialog(removeDraft, plan(), receipt({ undoable: false }))).not.toContain("撤销这次操作");
    // A kind the core does not undo is never offered, whatever the receipt says.
    expect(dialog({ kind: "upload", subject: "/tmp" }, plan({ kind: "upload" }), receipt({ kind: "upload" })))
      .not.toContain("撤销这次操作");

    const outcome = (props: Partial<Parameters<typeof SftpOperationOutcome>[0]>) => renderToStaticMarkup(
      <SftpOperationOutcome receipt={receipt()} undo={null} undoSpent={false} askingUndo={false}
        busy={false} error={null} onAskUndo={() => undefined} onKeep={() => undefined}
        onUndo={() => undefined} onClose={() => undefined} {...props} />,
    );
    const asking = outcome({ askingUndo: true });
    expect(asking).toContain("撤销会把它从备份移回原来的位置，连同原来的权限。");
    expect(asking).toContain("只能撤销一次");
    expect(asking.indexOf("不撤销")).toBeLessThan(asking.indexOf("确认撤销"));
    expect(asking).not.toContain("撤销这次操作");
    expect(outcome({ askingUndo: true, receipt: receipt({ kind: "create-directory" }) }))
      .toContain("文件夹里已经放了东西时不会删除");

    const undone = outcome({ undoSpent: true, undo: { planHandle: "opaque-plan", kind: "remove", undone: true,
      detail: "文件已从备份移回原来的位置，并在目标机上核对过。" } });
    expect(undone).toContain("已撤销");
    expect(undone).not.toContain("撤销这次操作");
    const refused = outcome({ undoSpent: true, undo: { planHandle: "opaque-plan", kind: "remove", undone: false,
      detail: hostile } });
    expect(refused).toContain("没有撤销");
    expect(refused).not.toContain("<script>");
    expect(outcome({ undoSpent: true, error: "撤销的时限已过" })).toContain('role="alert"');
  });

  it("offers to stop an upload while it copies, and reports a stop as a stop", () => {
    const uploading = (cancellingTransfer: boolean, onCancelTransfer: (() => void) | undefined) => renderToStaticMarkup(
      <SftpOperationDialog draft={{ kind: "upload", subject: "/tmp" }} plan={plan({ kind: "upload" })}
        receipt={null} busy error={null} onPlan={() => undefined} onConfirm={() => undefined}
        onClose={() => undefined} onCancelTransfer={onCancelTransfer} cancellingTransfer={cancellingTransfer} />,
    );
    const running = uploading(false, () => undefined);
    expect(running).toContain("取消上传");
    expect(running).toContain("执行中…");
    // While it copies, closing is not what the left button does.
    expect(running).not.toMatch(/>取消<\/button>/u);
    expect(uploading(true, () => undefined)).toMatch(/<button[^>]*disabled=""[^>]*>正在取消…<\/button>/u);
    // Nothing to stop: the ordinary, disabled 取消.
    expect(uploading(false, undefined)).not.toContain("取消上传");

    const stopped = dialog({ kind: "upload", subject: "/tmp" }, plan({ kind: "upload" }), receipt({
      kind: "upload", passed: false, undoable: false, cancelled: true,
      detail: "传输已取消，写到一半的文件已经删除，没有留下不完整的文件。",
    }));
    expect(stopped).toContain("已取消上传");
    expect(stopped).not.toContain("未通过校验");
    expect(stopped).toContain("is-cancelled");
    expect(stopped).not.toContain("撤销这次操作");
  });

  it("tells a cancelled transfer apart from a failed one", () => {
    expect(transferStopped(new Error("传输已取消，写到一半的文件已经删除，没有留下不完整的文件。 (sftp-browser-cancelled)"))).toBe(true);
    expect(transferStopped(new Error("文件操作超出时限，请刷新后核对结果。 (sftp-browser-timeout)"))).toBe(false);
    expect(transferStopped("sftp-browser-cancelled")).toBe(false);
  });

  it("says what a failed undo means for the target", () => {
    expect(sftpUndoFailure(new Error("这个目录或文件入口已过期，请刷新。 (sftp-browser-unavailable)")))
      .toContain("没有改动任何东西");
    expect(sftpUndoFailure(new Error("文件操作超出时限，请刷新后核对结果。 (sftp-browser-timeout)")))
      .toContain("不确定是否已经放回");
    expect(sftpUndoFailure(new Error("文件管理对应的目标连接已断开或已切换。 (sftp-browser-binding-unavailable)")))
      .toBe("文件管理对应的目标连接已断开或已切换。");
    expect(sftpUndoFailure(new Error("Invalid SFTP undo request."))).toBe("撤销没有完成；请刷新查看现在的状态。");
  });

  /** The toolbar upload picks its file while planning, so the name may wait. */
  it("lets an upload plan without a typed name and says the file is picked next", () => {
    const fromToolbar = dialog({ kind: "upload", subject: "/tmp" }, null, null);
    const button = /<button[^>]*class="is-primary"[^>]*>生成计划<\/button>/u.exec(fromToolbar)?.[0] ?? "";
    expect(button).not.toBe("");
    expect(button).not.toContain("disabled");
    expect(fromToolbar).toContain("留空则沿用本机文件名");
    expect(fromToolbar).toContain("生成计划时会先请你选择本机文件");

    const fromLocalPane = dialog({ kind: "upload", subject: "/tmp", name: "a.txt", localFileHandle: "local-1" }, null, null);
    expect(fromLocalPane).not.toContain("生成计划时会先请你选择本机文件");

    const rename = dialog({ kind: "rename", subject: "a.txt", name: "" }, null, null);
    expect(/<button[^>]*class="is-primary"[^>]*disabled=""[^>]*>生成计划<\/button>/u.test(rename)).toBe(true);
  });

  /** Plan text comes from the target, so it is text and never markup. */
  it("keeps hostile plan and receipt text inert", () => {
    const markup = dialog(
      { kind: "rename", subject: hostile },
      plan({ summary: hostile, restoreDescription: hostile }),
      receipt({ detail: hostile }),
    );
    expect(markup).not.toContain("<script>");
    expect(markup).toContain("&lt;script&gt;");
  });
});

describe("sftp context menu", () => {
  function entry(overrides: Partial<SftpBrowserEntry> = {}): SftpBrowserEntry {
    return {
      entryHandle: "opaque-entry",
      name: "upload.php",
      nameTruncated: false,
      kind: "file",
      action: "preview",
      sizeBytes: "128",
      modifiedAt: null,
      mode: "0644",
      ownerId: 1_000,
      groupId: 1_000,
      ...overrides,
    };
  }

  /** The menu offers only what the entry can actually do. */
  it("offers opening for directories and downloading for files", () => {
    const directory = menuItems(entry({ kind: "directory", action: "browse" }))
      .map((item) => item.action);
    expect(directory).toContain("open");
    expect(directory).toContain("terminal");
    expect(directory).not.toContain("download");
    expect(directory).not.toContain("preview");

    const file = menuItems(entry()).map((item) => item.action);
    expect(file).toContain("download");
    expect(file).toContain("preview");
    expect(file).not.toContain("open");
    expect(file).not.toContain("terminal");

    // A symlink is neither browsed nor read, nor a folder to start a shell in,
    // but it can still be managed.
    const link = menuItems(entry({ kind: "symlink", action: "none" })).map((item) => item.action);
    expect(link).not.toContain("open");
    expect(link).not.toContain("preview");
    expect(link).not.toContain("download");
    expect(link).not.toContain("terminal");
    expect(link).toContain("remove");
    // A folder too deep to open is not offered as one to start in either.
    expect(menuItems(entry({ kind: "directory", action: "none" })).map((item) => item.action))
      .not.toContain("terminal");

    // Right-clicking the empty area offers what needs no entry: a new folder
    // here, or a terminal here.
    expect(menuItems(null).map((item) => item.action)).toEqual(["create-directory", "terminal"]);
    expect(menuItems(null).map((item) => item.label)).toEqual(["新建文件夹", "在这里打开终端"]);
  });

  it("names the entry it is about and keeps that name inert", () => {
    const markup = renderToStaticMarkup(
      <SftpContextMenu
        position={{ x: 12, y: 24 }}
        entry={entry({ name: hostile })}
        busy={false}
        onAction={() => undefined}
        onDismiss={() => undefined}
      />,
    );
    expect(markup).toContain("&lt;script&gt;");
    expect(markup).not.toContain("<script>");
    expect(markup).toContain("删除");
  });

  /** While an operation is in flight the menu must not start a second one. */
  it("disables every item while an operation is running", () => {
    const markup = renderToStaticMarkup(
      <SftpContextMenu
        position={{ x: 0, y: 0 }}
        entry={entry()}
        busy
        onAction={() => undefined}
        onDismiss={() => undefined}
      />,
    );
    const buttons = markup.match(/<button/gu) ?? [];
    const disabled = markup.match(/disabled=""/gu) ?? [];
    expect(buttons.length).toBeGreaterThan(0);
    expect(disabled).toHaveLength(buttons.length);
  });
});

describe("sftp properties", () => {
  function entry(overrides: Partial<SftpBrowserEntry> = {}): SftpBrowserEntry {
    return {
      entryHandle: "opaque-entry",
      name: "upload.php",
      nameTruncated: false,
      kind: "file",
      action: "preview",
      sizeBytes: "128",
      modifiedAt: "2026-08-24T10:00:00Z",
      mode: "0644",
      ownerId: 1_000,
      groupId: 1_000,
      ...overrides,
    };
  }

  function render(value: SftpBrowserEntry): string {
    return renderToStaticMarkup(
      <SftpPropertiesDialog entry={value} onChmod={() => undefined} onClose={() => undefined} />,
    );
  }

  /** The bits an operator actually reads off a listing during triage. */
  it("renders permission bits the way ls does", () => {
    expect(symbolicMode("0644")).toBe("rw-r--r--");
    expect(symbolicMode("0755")).toBe("rwxr-xr-x");
    expect(symbolicMode("0000")).toBe("---------");
    expect(symbolicMode("0777")).toBe("rwxrwxrwx");
    // The set-ID and sticky bits ride on the execute slot, upper case when
    // execute itself is off, so nothing about the mode disappears.
    expect(symbolicMode("4755")).toBe("rwsr-xr-x");
    expect(symbolicMode("4644")).toBe("rwSr--r--");
    expect(symbolicMode("2755")).toBe("rwxr-sr-x");
    expect(symbolicMode("1777")).toBe("rwxrwxrwt");
    expect(symbolicMode("1666")).toBe("rw-rw-rwT");
    expect(symbolicMode("6755")).toBe("rwsr-sr-x");
    // Anything that is not a mode renders as nothing rather than as a guess.
    expect(symbolicMode("644")).toBe("");
    expect(symbolicMode("0888")).toBe("");
  });

  it("calls out the bits worth hunting", () => {
    expect(specialBits("4755")).toEqual(["set-user-ID"]);
    expect(specialBits("2755")).toEqual(["set-group-ID"]);
    expect(specialBits("1777")).toEqual(["粘滞位", "其他用户可写"]);
    expect(specialBits("0644")).toEqual([]);
    expect(specialBits("0646")).toEqual(["其他用户可写"]);
  });

  it("shows the whole entry, and says so when the server reported nothing", () => {
    const markup = render(entry({ mode: "4755" }));
    expect(markup).toContain("upload.php");
    expect(markup).toContain("文件");
    expect(markup).toContain("128 字节");
    expect(markup).toContain("4755");
    expect(markup).toContain("rwsr-xr-x");
    expect(markup).toContain("set-user-ID");
    expect(markup).toContain("1000 / 1000");

    const bare = render(entry({ mode: null, ownerId: null, groupId: null, modifiedAt: null }));
    expect(bare.match(/服务器未提供/gu)).toHaveLength(3);
    expect(bare).not.toContain("null");
  });

  /** The name comes from the target, so it stays text. */
  it("keeps a hostile name inert", () => {
    const markup = render(entry({ name: hostile }));
    expect(markup).toContain("&lt;script&gt;");
    expect(markup).not.toContain("<script>");
  });

  /** Reading properties must not be able to change anything by itself. */
  it("offers the permission flow without running it", () => {
    const markup = render(entry());
    expect(markup).toContain("设置权限");
    expect(markup).not.toContain("sftp-operation-execute");
    expect(markup).not.toContain("生成计划");
  });
});
