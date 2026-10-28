import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { DialogHost } from "./DialogHost";
import { createDialog } from "./dialog-state";

describe("DialogHost", () => {
  it("renders hostile prompt text inertly and only a non-secret text input", () => {
    const hostile = "</div><script>steal()</script>";
    const dialog = createDialog("dialog-1", {
      kind: "prompt",
      title: hostile,
      message: hostile,
      label: "普通文本",
      initialValue: hostile,
    });
    if (dialog === null) throw new Error("expected dialog");
    const markup = renderToStaticMarkup(
      <DialogHost dialog={dialog} onResolve={vi.fn()} />,
    );
    expect(markup).toContain('role="dialog"');
    expect(markup).toContain('aria-modal="true"');
    expect(markup).toContain('type="text"');
    expect(markup).not.toContain('type="password"');
    expect(markup).toContain("&lt;/div&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()");
  });

  it("uses alertdialog and keeps the opaque capability out of visible markup", () => {
    const dialog = createDialog("dialog-2", {
      kind: "dangerous",
      title: "危险操作",
      summary: "精确摘要",
      confirmationKey: "opaque-secret-handle",
    });
    if (dialog === null) throw new Error("expected dialog");
    const markup = renderToStaticMarkup(
      <DialogHost dialog={dialog} onResolve={vi.fn()} />,
    );
    expect(markup).toContain('role="alertdialog"');
    expect(markup).toContain("精确摘要");
    expect(markup).not.toContain("opaque-secret-handle");
  });

  it("makes the full review an accessible keyboard region when requested", () => {
    const message = "调查事实与限制。".repeat(130) + "完整记录结束";
    const dialog = createDialog("dialog-3", { kind: "confirm", title: "核对案件记录", message });
    if (dialog === null) throw new Error("expected dialog");
    const markup = renderToStaticMarkup(
      <DialogHost dialog={dialog} scrollMessage onResolve={vi.fn()} />,
    );
    expect(markup).toContain('tabindex="0" role="region" aria-label="完整确认内容"');
    expect(markup).toContain(message);
    const ordinary = renderToStaticMarkup(<DialogHost dialog={dialog} onResolve={vi.fn()} />);
    expect(ordinary).not.toContain('role="region"');
  });

  it("keeps its keys from the overlay that asked the question", () => {
    // Settings also traps Tab on the document; without this the dialog's own
    // Tab never moved from 取消 to the next button (probe-dialogs.mjs).
    const source = readFileSync(new URL("./DialogHost.tsx", import.meta.url), "utf8");
    expect(source).toContain('document.addEventListener("keydown", keydown, true);');
    expect(source).toContain('document.removeEventListener("keydown", keydown, true);');
    expect(source).toMatch(/if \(event\.key !== "Escape" && event\.key !== "Enter" && event\.key !== "Tab"\) return;\s*\/\/[^\n]*\n(?:\s*\/\/[^\n]*\n)*\s*event\.stopPropagation\(\);/u);
  });
});
