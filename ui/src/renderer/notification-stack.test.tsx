import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { NotificationStack } from "./NotificationStack";
import type { AppNotification } from "./notification-state";

describe("NotificationStack", () => {
  it("renders hostile messages as text with accessible status and dismiss controls", () => {
    const hostile = "</p><script>steal()</script>";
    const notifications: AppNotification[] = [{
      id: "notification-1",
      intent: "attention-required",
      severity: "warning",
      message: hostile,
      expiresAt: null,
    }];
    const markup = renderToStaticMarkup(
      <NotificationStack
        notifications={notifications}
        modalOpen={false}
        onDismiss={vi.fn()}
        onExpire={vi.fn()}
      />,
    );
    expect(markup).toContain('aria-live="polite"');
    expect(markup).toContain('role="status"');
    expect(markup).toContain('aria-label="关闭警告通知"');
    expect(markup).toContain("&lt;/p&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()");
  });

  it("uses assertive semantics for errors and renders nothing for an empty queue", () => {
    const error: AppNotification = {
      id: "notification-2",
      intent: "operation-failed",
      severity: "error",
      message: "failed",
      expiresAt: 5_000,
    };
    const markup = renderToStaticMarkup(
      <NotificationStack notifications={[error]} modalOpen={false} onDismiss={vi.fn()} onExpire={vi.fn()} />,
    );
    expect(markup).toContain('role="alert"');
    expect(renderToStaticMarkup(
      <NotificationStack notifications={[]} modalOpen={false} onDismiss={vi.fn()} onExpire={vi.fn()} />,
    )).toContain('class="notification-overlay-layer"');
  });
});
