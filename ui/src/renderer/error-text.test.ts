import { describe, expect, it } from "vitest";

import { errorText } from "./error-text";

describe("error text shown to the operator", () => {
  it("drops the trailing code and keeps the sentence", () => {
    expect(errorText(new Error("连接配置不完整或不正确，请检查必填项后重试。 (connection-invalid)"), "失败。"))
      .toBe("连接配置不完整或不正确，请检查必填项后重试。");
    expect(errorText(new Error("笔记已被修改 (notes-revision-conflict)"), "失败。")).toBe("笔记已被修改");
  });

  it("leaves text without a code alone and falls back when there is nothing to say", () => {
    expect(errorText(new Error("所选文件已存在。（只创建新文件）"), "失败。")).toBe("所选文件已存在。（只创建新文件）");
    expect(errorText(new Error("端口 (22) 不可用"), "失败。")).toBe("端口 (22) 不可用");
    expect(errorText(new Error(" (connection-invalid)"), "连接保存失败。")).toBe("连接保存失败。");
    expect(errorText("not an error", "连接保存失败。")).toBe("连接保存失败。");
  });

  it("never shows a developer's English refusal", () => {
    expect(errorText(new Error("Invalid connection creation request."), "连接没有保存。")).toBe("连接没有保存。");
  });
});
