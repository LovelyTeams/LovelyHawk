import { describe, expect, it } from "vitest";

import {
  isSshAttemptCancellation,
  isSshAttemptStarted,
  isSshAttemptStatus,
  isSshBindingDisconnection,
  isSshMfaResponses,
} from "./ssh-contract";

describe("SSH process-boundary validators", () => {
  it("accepts each closed renderer-safe attempt state", () => {
    expect(isSshAttemptStarted({ attemptHandle: "attempt-1", stage: "running" })).toBe(true);
    expect(isSshAttemptStatus({ stage: "running" })).toBe(true);
    expect(
      isSshAttemptStatus({
        stage: "awaiting-host-key",
        hostKeyPrompt: {
          promptHandle: "prompt-1",
          role: "target",
          host: "server.example",
          port: 22,
          username: "root",
          fingerprint: "SHA256:review-me",
        },
      }),
    ).toBe(true);
    expect(
      isSshAttemptStatus({
        stage: "awaiting-mfa",
        mfaPrompt: {
          promptHandle: "prompt-2",
          role: "jump-host",
          host: "jump.example",
          port: 22,
          username: "operator",
          name: "Verification",
          instructions: "Enter the current code",
          prompts: [{ prompt: "Code:", echo: false }],
        },
      }),
    ).toBe(true);
    expect(
      isSshAttemptStatus({
        stage: "connected",
        bindingHandle: "binding-1",
        target: {
          connectionId: "server-1",
          host: "server.example",
          port: 22,
          username: "root",
          timestamp: "2026-08-24T00:00:00Z",
        },
      }),
    ).toBe(true);
    expect(
      isSshAttemptStatus({
        stage: "failed",
        error: {
          code: "host-key-changed",
          message: "The recorded host key changed.",
          role: "target",
          host: "server.example",
          port: 22,
          repinSupported: false,
        },
      }),
    ).toBe(true);
    expect(isSshAttemptStatus({ stage: "cancelled" })).toBe(true);
    for (const code of ["ssh-attempt-failed", "ssh-host-not-found", "ssh-unreachable", "ssh-jump-failed",
      "ssh-auth-rejected", "ssh-key-unusable", "ssh-agent-unavailable"]) {
      expect(isSshAttemptStatus({ stage: "failed", error: { code, message: "fixed" } }), code).toBe(true);
      // A failure says what kind it was, never where or with whose words.
      expect(isSshAttemptStatus({ stage: "failed", error: { code, message: "fixed", host: "10.0.0.9" } }), code).toBe(false);
    }
    expect(isSshAttemptStatus({ stage: "failed", error: { code: "ssh-password-was-hunter2", message: "x" } })).toBe(false);
  });

  it("rejects leaked core state, unknown fields, malformed prompts and fake repin support", () => {
    expect(isSshAttemptStatus({ stage: "running", sessionId: "secret" })).toBe(false);
    expect(
      isSshAttemptStatus({
        stage: "connected",
        bindingHandle: "binding-1",
        target: {
          connectionId: "server-1",
          host: "server.example",
          port: 22,
          username: "root",
          timestamp: "2026-08-24T00:00:00Z",
          generation: 3,
        },
      }),
    ).toBe(false);
    expect(
      isSshAttemptStatus({
        stage: "awaiting-mfa",
        mfaPrompt: {
          promptHandle: "prompt-2",
          role: "target",
          host: "server.example",
          port: 22,
          username: "root",
          name: "Verification",
          instructions: "Code",
          prompts: [],
        },
      }),
    ).toBe(false);
    expect(
      isSshAttemptStatus({
        stage: "failed",
        error: {
          code: "host-key-changed",
          message: "changed",
          repinSupported: true,
        },
      }),
    ).toBe(false);
  });

  it("bounds secret MFA inputs by count, per-value bytes and total bytes", () => {
    expect(isSshMfaResponses(["123456"])).toBe(true);
    expect(isSshMfaResponses([])).toBe(false);
    expect(isSshMfaResponses(Array.from({ length: 17 }, () => "x"))).toBe(false);
    expect(isSshMfaResponses(["界".repeat(1_366)] )).toBe(false);
    expect(isSshMfaResponses(Array.from({ length: 16 }, () => "x".repeat(2_049)))).toBe(false);
  });

  it("requires exact terminal acknowledgement shapes", () => {
    expect(isSshAttemptCancellation({ cancelled: true })).toBe(true);
    expect(isSshAttemptCancellation({ cancelled: true, attemptHandle: "leak" })).toBe(false);
    expect(isSshBindingDisconnection({ disconnected: true, targetCleared: false })).toBe(true);
    expect(isSshBindingDisconnection({ disconnected: true })).toBe(false);
  });
});
