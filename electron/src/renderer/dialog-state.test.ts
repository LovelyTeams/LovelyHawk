import { describe, expect, it } from "vitest";

import {
  MAX_DIALOG_MESSAGE_BYTES,
  MAX_PROMPT_VALUE_BYTES,
  createDialog,
  nextDialogId,
  resolveDialog,
} from "./dialog-state";

const encoder = new TextEncoder();

describe("dialog state", () => {
  it("creates bounded dialogs and wraps ids without using external identifiers", () => {
    expect(nextDialogId(0)).toEqual({ sequence: 1, id: "dialog-1" });
    expect(nextDialogId(Number.MAX_SAFE_INTEGER)).toEqual({ sequence: 1, id: "dialog-1" });
    const dialog = createDialog("dialog-2", {
      kind: "prompt",
      title: "标题",
      message: "中".repeat(10_000),
      label: "值",
      initialValue: "界".repeat(10_000),
    });
    expect(dialog?.kind).toBe("prompt");
    if (dialog?.kind !== "prompt") throw new Error("expected prompt");
    expect(encoder.encode(dialog.message).byteLength).toBeLessThanOrEqual(MAX_DIALOG_MESSAGE_BYTES);
    expect(encoder.encode(dialog.value).byteLength).toBeLessThanOrEqual(MAX_PROMPT_VALUE_BYTES);
  });

  it("binds every action to the dialog id and dangerous capability key", () => {
    const dialog = createDialog("dialog-3", {
      kind: "dangerous",
      title: "永久删除？",
      summary: "不可恢复",
      confirmationKey: "opaque-123",
    });
    if (dialog?.kind !== "dangerous") throw new Error("expected dangerous dialog");
    expect(resolveDialog(dialog, {
      type: "approve-dangerous",
      dialogId: "dialog-4",
      confirmationKey: "opaque-123",
    })).toBeNull();
    expect(resolveDialog(dialog, {
      type: "approve-dangerous",
      dialogId: dialog.id,
      confirmationKey: "opaque-other",
    })).toBeNull();
    expect(resolveDialog(dialog, {
      type: "approve-dangerous",
      dialogId: dialog.id,
      confirmationKey: dialog.confirmationKey,
    })).toEqual({
      kind: "dangerous-approved",
      dialogId: dialog.id,
      confirmationKey: dialog.confirmationKey,
    });
  });

  it("rejects malformed ids and capability keys", () => {
    expect(createDialog("operation-from-core", {
      kind: "alert",
      title: "title",
      message: "message",
    })).toBeNull();
    expect(createDialog("dialog-1", {
      kind: "dangerous",
      title: "danger",
      summary: "summary",
      confirmationKey: "path/to/plan",
    })).toBeNull();
  });
});
