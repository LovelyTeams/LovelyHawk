import { describe, expect, it } from "vitest";

import {
  connectionExportNotice,
  connectionImportNotice,
  connectionSecretWrites,
  emptySecretDrafts,
  nextFocusIndex,
  parseConnectionTags,
  resolveSecretWrite,
  secretDraftReducer,
} from "./connection-helpers";

describe("secretDraftReducer", () => {
  it("replaces a secret and clears its remove intent atomically", () => {
    const state = { ...emptySecretDrafts(), removePassword: true };

    expect(
      secretDraftReducer(state, {
        type: "replace",
        slot: "password",
        value: "new-secret",
      }),
    ).toMatchObject({ password: "new-secret", removePassword: false });
  });

  it("clears a secret when remove is enabled", () => {
    const state = { ...emptySecretDrafts(), keyPassphrase: "transient" };

    expect(
      secretDraftReducer(state, {
        type: "toggle-remove",
        slot: "keyPassphrase",
      }),
    ).toMatchObject({ keyPassphrase: "", removeKeyPassphrase: true });
  });

  it("clears both jump secrets and intents when the jump scope is hidden", () => {
    const state = {
      ...emptySecretDrafts(),
      jumpHostPassword: "password",
      jumpHostKeyPassphrase: "passphrase",
      removeJumpHostPassword: true,
    };

    expect(
      secretDraftReducer(state, { type: "clear-scope", scope: "jump" }),
    ).toMatchObject({
      jumpHostPassword: "",
      jumpHostKeyPassphrase: "",
      removeJumpHostPassword: false,
      removeJumpHostKeyPassphrase: false,
    });
  });

  it("clears both target secrets when the target auth method changes", () => {
    const state = {
      ...emptySecretDrafts(),
      password: "password",
      keyPassphrase: "passphrase",
      removeKeyPassphrase: true,
    };

    expect(
      secretDraftReducer(state, { type: "clear-scope", scope: "target" }),
    ).toMatchObject({
      password: "",
      keyPassphrase: "",
      removePassword: false,
      removeKeyPassphrase: false,
    });
  });
});

describe("connection secret wire decisions", () => {
  it("gives remove priority over an inconsistent non-empty draft", () => {
    expect(resolveSecretWrite("stale", true)).toEqual({ action: "remove" });
  });

  it("removes inactive target secret kinds", () => {
    const writes = connectionSecretWrites(
      {
        authMethod: "public-key",
        jumpEnabled: false,
        jumpAuthMethod: "password",
      },
      { ...emptySecretDrafts(), password: "stale", keyPassphrase: "new" },
    );

    expect(writes).toEqual({
      password: { action: "remove" },
      keyPassphrase: { action: "replace", value: "new" },
      jumpHostPassword: { action: "remove" },
      jumpHostKeyPassphrase: { action: "remove" },
    });
  });

  it("removes every jump secret when ProxyJump is disabled", () => {
    const writes = connectionSecretWrites(
      {
        authMethod: "password",
        jumpEnabled: false,
        jumpAuthMethod: "certificate",
      },
      {
        ...emptySecretDrafts(),
        jumpHostPassword: "stale-password",
        jumpHostKeyPassphrase: "stale-passphrase",
      },
    );

    expect(writes.jumpHostPassword).toEqual({ action: "remove" });
    expect(writes.jumpHostKeyPassphrase).toEqual({ action: "remove" });
  });
});

describe("parseConnectionTags", () => {
  it("accepts Chinese and ASCII commas, trims, removes blanks, and deduplicates", () => {
    expect(parseConnectionTags("prod， database,prod， ，应急")).toEqual([
      "prod",
      "database",
      "应急",
    ]);
  });
});

describe("nextFocusIndex", () => {
  it("wraps focus in both tab directions", () => {
    expect(nextFocusIndex(2, 3, false)).toBe(0);
    expect(nextFocusIndex(0, 3, true)).toBe(2);
  });

  it("enters at the appropriate edge and handles an empty dialog", () => {
    expect(nextFocusIndex(-1, 3, false)).toBe(0);
    expect(nextFocusIndex(-1, 3, true)).toBe(2);
    expect(nextFocusIndex(-1, 0, false)).toBeNull();
  });
});

describe("connection file workflow notices", () => {
  it("shows all import counters and explicit cancellation", () => {
    expect(
      connectionImportNotice({
        cancelled: false,
        imported: 2,
        skippedExisting: 3,
        skippedDuplicate: 4,
      }),
    ).toBe("连接导入完成：导入 2，跳过已有 3，跳过文件内重复 4。");
    expect(
      connectionImportNotice({
        cancelled: true,
        imported: 0,
        skippedExisting: 0,
        skippedDuplicate: 0,
      }),
    ).toBe("连接导入已取消。");
  });

  it("shows only the export count and basename", () => {
    expect(
      connectionExportNotice({
        cancelled: false,
        count: 5,
        fileName: "incident-connections.json",
      }),
    ).toBe("已导出 5 个连接到 incident-connections.json。");
    expect(
      connectionExportNotice({ cancelled: true, count: 0, fileName: null }),
    ).toBe("连接导出已取消。");
  });
});
