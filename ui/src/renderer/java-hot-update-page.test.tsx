import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { JavaHotUpdateApi, JavaPlan, JavaReceipt } from "../shared/java-hot-update-contract";
import { JavaHotUpdatePage, JavaPlanDialog } from "./JavaHotUpdatePage";

const api: JavaHotUpdateApi = {
  javaHotUpdate: vi.fn(async () => ({})),
  stageJavaClass: vi.fn(async () => ({ staged: false, class: null })),
};
const plan: JavaPlan = {
  kind: "plan",
  planHandle: "plan-1",
  operation: "update",
  summary: "替换 /opt/app/app.jar 中的 <script>x()</script>.class",
  jarPath: "/opt/app/app.jar",
  entry: "com/example/Main.class",
  classSha256: "a".repeat(64),
  restoreDescription: "从受管原始 JAR 备份原子恢复，并校验 SHA-256",
  confirmed: false,
  expiresInSeconds: 600,
};

describe("Java hot update page", () => {
  it("asks for a target first and says what the page is for", () => {
    const html = renderToStaticMarkup(<JavaHotUpdatePage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后");
    expect(html).not.toContain("扫描 Java 进程");
  });

  it("starts read-only, and is plain that it changes the JAR on disk, not the running process", () => {
    const html = renderToStaticMarkup(<JavaHotUpdatePage bindingHandle="binding-1" api={api} />);
    expect(html).toContain("扫描 Java 进程");
    expect(html).toContain("扫描只读取进程列表和 Java 版本，不改动任何东西");
    expect(html).toContain("替换磁盘 JAR 中的类文件；运行中的 JVM 需重启后生效");
    expect(html).toContain("JVM 需重启后生效");
    expect(html).toContain("替换记录");
  });

  it("says where the JDK tools come from, and does not blame a missing jar on the JRE alone", () => {
    const source = readFileSync(new URL("./JavaHotUpdatePage.tsx", import.meta.url), "utf8");
    expect(source).toContain("只用 root 或当前账号所有、其他账号不能改写的 JDK");
    expect(source).toContain("那个 JDK 目录其他账号也能改写，出于安全不使用");
    expect(source).not.toContain("没有 jar 工具（通常只装了 JRE）");
  });

  it("shows a plan with the way back, and leaves the decision to an explicit click", () => {
    const html = renderToStaticMarkup(
      <JavaPlanDialog state={{ plan, receipt: null, running: false, error: null }} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(html).toContain('role="dialog"');
    expect(html).toContain('aria-modal="true"');
    expect(html).toContain("从受管原始 JAR 备份原子恢复");
    expect(html).toContain("和生成计划时不同就不改动");
    expect(html).toContain("确认替换");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>x()");
    const source = readFileSync(new URL("./JavaHotUpdatePage.tsx", import.meta.url), "utf8");
    // Focus starts on 取消, never on the button that changes the JAR.
    expect(source).toContain("(receipt === null ? cancelRef.current : closeRef.current)?.focus()");
    expect(source).toContain('ref={cancelRef} type="button" data-testid="java-plan-cancel"');
  });

  it("reports what was checked, and that a restart is the operator's call", () => {
    const receipt: JavaReceipt = {
      kind: "receipt", planHandle: "plan-1", operation: "update", verified: true, recordId: "rec-1",
      jarPath: "/opt/app/app.jar", entry: "com/example/Main.class", jarSha256: "b".repeat(64), detail: "JAR 与类文件哈希一致",
    };
    const html = renderToStaticMarkup(
      <JavaPlanDialog state={{ plan, receipt, running: false, error: null }} onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(html).toContain("已替换，并核对过 JAR 里这个类与所选文件一致");
    expect(html).toContain("运行中的进程不会自动加载新类");
    const failed = renderToStaticMarkup(
      <JavaPlanDialog state={{ plan, receipt: { ...receipt, verified: false, recordId: null, jarSha256: null, detail: "x" }, running: false, error: null }}
        onConfirm={() => undefined} onClose={() => undefined} />,
    );
    expect(failed).toContain("替换没有完成或没有通过核对");
    expect(failed).not.toContain("运行中的进程不会自动加载新类");
  });

  it("never takes a command or a local file from the page, and a typed JAR path only for reading", () => {
    const source = readFileSync(new URL("./JavaHotUpdatePage.tsx", import.meta.url), "utf8");
    expect(source).not.toMatch(/\b(?:localPath|jarPath|command|path)\s*:/u);
    // Two inputs filter what the scan and the opened JAR listed; the third is a JAR path to read.
    expect(source.match(/<input/gu)).toHaveLength(3);
    expect(source).toContain('<input type="search" value={jarFilter}');
    expect(source).toContain('<input type="search" value={filter}');
    expect(source).toContain('<input type="text" value={typedPath}');
    expect(source).toContain('{ action: "inspect-path", bindingHandle: binding, snapshotHandle, path }');
    expect(source).toContain("if (scan === null || !isTypedJarPath(typedPath)) return;");
    expect(source.match(/action: "inspect-path"/gu)).toHaveLength(1);
    expect(source).toContain("onClick={() => openJar(offer.jarHandle)}");
    expect(source).toContain("api.stageJavaClass(binding)");
    // A second click while a request is out does nothing.
    expect(source).toContain("if (bindingHandle === null || inFlight.current) return;");
  });
});
