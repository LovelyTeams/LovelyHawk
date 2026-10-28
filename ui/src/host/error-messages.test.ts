import { readdirSync, readFileSync } from "node:fs";

import { afterEach, describe, expect, it } from "vitest";

import { BACKEND_ERROR_MESSAGES, operatorErrorMessage } from "./error-messages";
import { createMainApi } from "./main-api";
import { hostError, setHostInvokerForTests } from "./transport";

const backendDirectory = new URL("../../../crates/lovelyhawk-backend/src/", import.meta.url);
/** Every (code, message) pair the backend can answer with, test modules left out. */
const backendErrors = readdirSync(backendDirectory)
  .filter((name) => name.endsWith(".rs"))
  .flatMap((name) => {
    const source = readFileSync(new URL(name, backendDirectory), "utf8");
    const live = source.split("#[cfg(test)]")[0] ?? "";
    return [...live.matchAll(/"([a-z][a-z0-9]*(?:-[a-z0-9]+)+)",?\s*(?:(?:public_)?message:\s*)?"([^"]{8,})"/gu)]
      .map((match) => ({ code: match[1] ?? "", message: match[2] ?? "" }));
  });
const englishErrors = backendErrors.filter(({ message }) => /^[A-Z]/u.test(message) && !/[一-鿿]/u.test(message));

afterEach(() => {
  setHostInvokerForTests(async () => {
    throw new Error("no host in tests");
  });
});

describe("backend error messages", () => {
  it("gives every code the backend answers in English a sentence for the operator", () => {
    // The scan must keep finding the codes, or this test would pass on nothing.
    expect(englishErrors.length).toBeGreaterThan(120);
    const missing = [...new Set(englishErrors.map(({ code }) => code))]
      .filter((code) => !Object.hasOwn(BACKEND_ERROR_MESSAGES, code));
    expect(missing).toEqual([]);
  });

  it("writes every sentence in plain Chinese, without implementation words", () => {
    for (const [code, sentence] of Object.entries(BACKEND_ERROR_MESSAGES)) {
      expect(sentence, code).toMatch(/[一-鿿]/u);
      expect(sentence, code).not.toMatch(/Rust|sidecar|RPC|renderer|preload|opaque|binding|句柄|代际|LovelyHawk could not/u);
      expect(sentence.endsWith("。"), code).toBe(true);
    }
  });

  it("swaps the English and keeps the code that pages look for", () => {
    expect(operatorErrorMessage("The note changed after it was read. Reload it before retrying. (notes-revision-conflict)"))
      .toBe("笔记在读取后被改动过，请重新打开后再保存。 (notes-revision-conflict)");
    expect(operatorErrorMessage("The SSH binding is missing or stale. (system-info-binding-unavailable)"))
      .toContain("(system-info-binding-unavailable)");
  });

  it("leaves everything else alone", () => {
    for (const text of [
      "The backend request timed out.",
      "所选文件已存在。导出只创建新文件，请换一个文件名。",
      "Something new. (a-code-nobody-knows)",
      "此案仍在采集文件，请等待采集完成或取消采集后再整理案件。 (case-library-busy)",
      "notes-operation-failed",
    ]) expect(operatorErrorMessage(text)).toBe(text);
  });

  it("is what a page sees when the host refuses", async () => {
    expect(hostError("LovelyHawk could not complete the notes operation. (notes-operation-failed)").message)
      .toBe(`${BACKEND_ERROR_MESSAGES["notes-operation-failed"]} (notes-operation-failed)`);
    setHostInvokerForTests(async () => {
      throw "The requested note does not exist. (note-not-found)";
    });
    await expect(createMainApi().getNote("00000000-0000-4000-8000-000000000000")).rejects.toThrow("这条笔记已不存在。 (note-not-found)");
  });
});
