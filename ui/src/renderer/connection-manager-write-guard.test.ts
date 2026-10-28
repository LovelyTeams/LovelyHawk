import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("./ConnectionManager.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

function functionBody(name: string): string {
  const start = source.indexOf(`async function ${name}(`);
  expect(start, `${name} is missing`).toBeGreaterThan(-1);
  const end = source.indexOf("\n  }", start);
  return source.slice(start, end);
}

describe("connection manager remote-operation guard", () => {
  /**
   * `busy` is React state, so a second click landing before the re-render still
   * passes the disabled check. Creating twice with the same generated id makes
   * the backend reject the duplicate, which surfaced as a save failure.
   */
  it("refuses a second in-flight write, probe, or connect", () => {
    for (const name of ["saveConnection", "startProbe", "startConnect"]) {
      const body = functionBody(name);
      expect(body, `${name} entry guard`).toMatch(/if \([^)]*operationInFlightRef\.current\) return;/u);
      expect(body, `${name} claims the flag`).toContain("operationInFlightRef.current = true;");
      expect(body, `${name} releases the flag`).toContain("operationInFlightRef.current = false;");
    }
  });

  it("claims the flag before awaiting and releases it exactly once per operation", () => {
    expect(source.match(/operationInFlightRef\.current = true;/gu)).toHaveLength(3);
    expect(source.match(/operationInFlightRef\.current = false;/gu)).toHaveLength(3);
    // Releases live in finally blocks so a rejected request cannot wedge the panel.
    for (const name of ["saveConnection", "startProbe", "startConnect"]) {
      expect(functionBody(name), `${name} releases in finally`)
        .toMatch(/\} finally \{\s*operationInFlightRef\.current = false;/u);
    }
  });

  it("still generates a fresh id per created connection", () => {
    expect(source).toMatch(/function emptyConnectionForm\(\): ConnectionForm \{\s*return \{\s*id: crypto\.randomUUID\(\)/u);
  });
});

describe("connection list states", () => {
  it("tells loading, unreadable and empty apart", () => {
    expect(source).toContain('{loading ? "读取中…" : "凭据已加密"}');
    expect(source).toContain('{listUnreadable ? "连接未读出" : `${connections.length} 个连接`}');
    expect(source).toContain("{!loading && listUnreadable ? <div className=\"connection-list-empty\">已保存的连接没有读出来，原因见上方提示。</div> : null}");
    expect(source).toContain("{!loading && !listUnreadable && visibleConnections.length === 0 ? (");
    // Nothing saved yet and nothing matching are different situations.
    expect(source).toContain('{connections.length === 0 ? "还没有保存的连接。点上方“新建连接”填写主机与账号，或“导入 JSON”。" : "没有匹配的连接，换个名称、主机或标签试试。"}');
  });
});

describe("connection delete confirmation", () => {
  it("asks for a plan first and shows the backend's own wording of it", () => {
    const request = functionBody("requestDelete");
    expect(request).toContain("window.lovelyhawk.planConnectionDelete(view.id)");
    expect(request).toContain("setDeletePrompt(prompt)");
    // The dialog quotes the plan; nothing in the page rewrites what will be deleted.
    expect(source).toContain('<p id="connection-delete-description">{deletePrompt.confirmationText}</p>');
    expect(source).toContain("<small>删除后无法恢复。</small>");
    expect(source).toContain('role="alertdialog"');
  });

  it("confirms the exact plan once and trusts only a verified outcome", () => {
    const confirm = functionBody("confirmDelete");
    expect(confirm).toContain("window.lovelyhawk.confirmConnectionDelete(deletePrompt.handle)");
    expect(confirm).toContain('if (!outcome.verified) throw new Error("删除结果未通过独立验证。");');
    // A failed or unverified delete drops the plan rather than letting it be retried.
    expect(confirm).toContain("setDeletePrompt(null);\n        setError(");
  });

  it("releases the plan when the operator backs out, by button or by Escape", () => {
    expect(functionBody("cancelDelete")).toContain("window.lovelyhawk.cancelConnectionDelete(deletePrompt.handle)");
    expect(source).toMatch(/function handleDeleteKeyDown[\s\S]*?event\.key !== "Escape"[\s\S]*?void cancelDelete\(\);/u);
    // The safe choice comes first and takes focus; confirming is a separate, labelled button.
    expect(source).toMatch(/<button ref=\{deleteCancelRef\} type="button" disabled=\{busy\} onClick=\{\(\) => void cancelDelete\(\)\}>取消<\/button>\s*<button type="button" className="danger-confirm"/u);
  });
});

describe("connection manager action rows", () => {
  it("pins the editor and detail actions to the bottom of the scrolling pane", () => {
    for (const selector of [
      "\\.connection-editor > footer",
      "\\.connection-details-view > footer",
    ]) {
      const rule = new RegExp(`${selector} \\{([^}]*)\\}`, "u").exec(cssSource)?.[1] ?? "";
      expect(rule, selector).toContain("position: sticky");
      expect(rule, selector).toContain("bottom: 0");
      // An opaque background is what keeps scrolled content from showing through.
      expect(rule, selector).toContain("background: var(--surface)");
    }
    // The pane itself must stay the scroll container for sticky to resolve against.
    expect(cssSource).toMatch(/\.connection-detail \{[^}]*overflow: auto;/u);
  });
});
