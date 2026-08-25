import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  SftpBrowserEntry,
  SftpOperationPlan,
  SftpOperationReceipt,
} from "../shared/sftp-browser-contract";
import { menuItems, SftpContextMenu } from "./SftpContextMenu";
import { SftpOperationDialog, type SftpOperationDraft } from "./SftpOperationDialog";
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
    expect(markup).toContain("120 秒");
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
    expect(directory).not.toContain("download");
    expect(directory).not.toContain("preview");

    const file = menuItems(entry()).map((item) => item.action);
    expect(file).toContain("download");
    expect(file).toContain("preview");
    expect(file).not.toContain("open");

    // A symlink is neither browsed nor read, but it can still be managed.
    const link = menuItems(entry({ kind: "symlink", action: "none" })).map((item) => item.action);
    expect(link).not.toContain("open");
    expect(link).not.toContain("preview");
    expect(link).not.toContain("download");
    expect(link).toContain("remove");

    // Right-clicking the empty area offers only the one thing that needs no entry.
    expect(menuItems(null).map((item) => item.action)).toEqual(["create-directory"]);
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
