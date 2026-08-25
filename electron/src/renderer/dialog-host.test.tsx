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
});
