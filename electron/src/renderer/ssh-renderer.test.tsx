import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { clearDisconnectedTarget, targetLabel } from "./App";
import { SshAttemptDialog, type SshAttemptApi } from "./SshAttemptDialog";

describe("renderer SSH surfaces", () => {
  it("formats only the bounded public target summary", () => {
    expect(
      targetLabel({
        connectionId: "server-1",
        host: "incident.example",
        port: 22,
        username: "responder",
        timestamp: "2026-08-24T09:00:00Z",
      }),
    ).toBe("responder@incident.example:22");
  });

  it("renders an isolated modal without exposing the opaque attempt handle", () => {
    const api: SshAttemptApi = {
      getAttempt: vi.fn(async () => ({ stage: "running" as const })),
      confirmHostKey: vi.fn(async () => ({ stage: "running" as const })),
      respondMfa: vi.fn(async () => ({ stage: "running" as const })),
      cancelAttempt: vi.fn(async () => ({ cancelled: true as const })),
      disconnectBinding: vi.fn(async () => ({
        disconnected: true as const,
        targetCleared: true,
      })),
    };
    const markup = renderToStaticMarkup(
      <SshAttemptDialog
        attempt={{ attemptHandle: "opaque-attempt-must-not-render", stage: "running" }}
        mode="connect"
        api={api}
        onTerminal={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    expect(markup).toContain('role="dialog"');
    expect(markup).toContain('aria-modal="true"');
    expect(markup).not.toContain("opaque-attempt-must-not-render");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
  });

  it("does not clear a newer target when an older disconnect resolves late", () => {
    const current = {
      bindingHandle: "new-binding",
      target: {
        connectionId: "server-2",
        host: "new.example",
        port: 22,
        username: "root",
        timestamp: "2026-08-24T09:01:00Z",
      },
    };
    expect(clearDisconnectedTarget(current, "old-binding")).toBe(current);
    expect(clearDisconnectedTarget(current, "new-binding")).toBeNull();
  });
});
