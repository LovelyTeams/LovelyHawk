import { readdirSync, readFileSync } from "node:fs";

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

  it("never reads an event inside a state updater, on any page", () => {
    // React clears currentTarget once a handler returns; an updater may run
    // later, at render. The MFA answer field did this and typing into it
    // blanked the whole window.
    const directory = new URL("./", import.meta.url);
    const offenders = readdirSync(directory)
      .filter((name) => name.endsWith(".tsx") && !name.includes(".test."))
      .flatMap((name) => readFileSync(new URL(name, directory), "utf8").split("\n")
        .filter((line) => /\bset[A-Z]\w*\(\s*\(\w*\)\s*=>.*\bevent\.(?:currentTarget|target)\b/u.test(line))
        .map((line) => `${name}: ${line.trim()}`));
    expect(offenders).toEqual([]);
    const dialog = readFileSync(new URL("./SshAttemptDialog.tsx", import.meta.url), "utf8");
    expect(dialog).toContain("const typed = event.currentTarget.value;");
  });

  it("never starts with focus on trusting a host key", () => {
    const source = readFileSync(new URL("./SshAttemptDialog.tsx", import.meta.url), "utf8");
    const trust = source.split('data-testid="ssh-host-key-trust"')[0]!.split("<button").at(-1)!;
    expect(trust).not.toContain("initialFocusRef");
    expect(source).toContain('status.stage === "running" || status.stage === "awaiting-host-key" ? (node) => { initialFocusRef.current = node; }');
    // The trust button is the only control in the host-key panel that acts.
    const panel = source.split('className="ssh-host-key-panel"')[1]!.split("</section>")[0]!;
    expect(panel.match(/<button/gu)).toHaveLength(1);
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
