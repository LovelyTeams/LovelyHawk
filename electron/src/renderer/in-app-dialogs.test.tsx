import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { DialogHost } from "./DialogHost";
import { createDialog, resolveDialog, type AppDialog } from "./dialog-state";

function rendererSourceFiles(): string[] {
  const root = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
  return readdirSync(root)
    .filter((name) => /\.tsx?$/u.test(name) && !/\.test\.tsx?$/u.test(name))
    .map((name) => path.join(root, name));
}

describe("no system-level dialogs", () => {
  it("keeps window.alert/confirm/prompt out of every renderer module", () => {
    for (const file of rendererSourceFiles()) {
      const source = readFileSync(file, "utf8");
      expect(
        [...source.matchAll(/\bwindow\s*\.\s*(?:alert|confirm|prompt)\s*\(/gu)].map((m) => m[0]),
        path.basename(file),
      ).toEqual([]);
    }
  });

  it("routes both discard questions through the in-app confirm dialog", () => {
    for (const name of ["ConnectionManager.tsx", "SettingsPanel.tsx"]) {
      const source = readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
      expect(source, name).toContain("useConfirmDialog()");
      expect(source, name).toContain("discardConfirm.ask(");
      expect(source, name).toMatch(
        /<DialogHost dialog=\{discardConfirm\.dialog\} onResolve=\{discardConfirm\.resolve\} \/>/u,
      );
    }
  });
});

describe("confirm dialog", () => {
  function confirmDialog(): AppDialog {
    const dialog = createDialog("dialog-1", {
      kind: "confirm",
      title: "放弃未保存的更改",
      message: "当前连接配置尚未保存。确定放弃这些更改吗？",
      confirmLabel: "放弃更改",
    });
    if (dialog === null) throw new Error("confirm dialog fixture is invalid");
    return dialog;
  }

  it("renders a cancel-first pair of buttons with the caller's label", () => {
    const markup = renderToStaticMarkup(
      <DialogHost dialog={confirmDialog()} onResolve={vi.fn()} />,
    );

    expect(markup).toContain("放弃未保存的更改");
    expect(markup).toContain("放弃更改");
    expect(markup).toContain("取消");
    expect(markup).not.toContain("确认危险操作");
    expect(markup).toContain('role="dialog"');
    expect(markup.match(/<button/gu)).toHaveLength(2);
  });

  it("defaults the confirm label and resolves only on explicit approval", () => {
    const dialog = createDialog("dialog-2", {
      kind: "confirm",
      title: "确认",
      message: "继续？",
    });
    expect(dialog).toMatchObject({ kind: "confirm", confirmLabel: "确定" });

    const approved = resolveDialog(confirmDialog(), {
      type: "approve-confirm",
      dialogId: "dialog-1",
    });
    expect(approved).toEqual({ kind: "confirmed", dialogId: "dialog-1" });
    expect(resolveDialog(confirmDialog(), { type: "cancel", dialogId: "dialog-1" }))
      .toEqual({ kind: "cancelled", dialogId: "dialog-1" });
    // A stale id, or an action for another kind, must never confirm.
    expect(resolveDialog(confirmDialog(), { type: "approve-confirm", dialogId: "dialog-9" }))
      .toBeNull();
    expect(resolveDialog(confirmDialog(), {
      type: "approve-dangerous",
      dialogId: "dialog-1",
      confirmationKey: "key",
    })).toBeNull();
  });
});
