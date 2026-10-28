import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import path from "node:path";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { DockerPage } from "./DockerPage";
import { KubernetesPage } from "./KubernetesPage";
import { createDockerReadState } from "./docker-read-state";
import { createKubernetesReadState } from "./kubernetes-read-state";

/**
 * Renders both pages with a full, realistic snapshot and writes the result to
 * `target/preview-*.html`.
 *
 * Every other test here renders one or two rows, which proves the markup is
 * escaped and the handles do not leak but says nothing about what the page
 * looks like once it is full. These pages only ever appear inside a running
 * Electron window bound to a live target, so "is this any good to look at" was
 * a question nobody could answer without a lab host and a connection.
 *
 * The written file is a development aid — open it in a browser. The assertions
 * are the test: a page that throws or renders nothing on a full snapshot is a
 * page that would fail exactly when an operator finally had data.
 */
const OUT = path.join(
  path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1")),
  "..", "..", "..", "target",
);

const asyncNoop = vi.fn(async () => ({}));
const dockerApi = {
  refreshDockerContainers: asyncNoop,
  getDockerCollection: asyncNoop,
  inspectDockerResource: asyncNoop,
  getDockerSecurityAudit: asyncNoop,
  getDockerLogs: asyncNoop,
  planDockerContainerAction: asyncNoop,
  confirmDockerContainerAction: asyncNoop,
  executeDockerContainerAction: asyncNoop,
  cancelDockerContainerAction: asyncNoop,
  openDockerContainerTerminal: asyncNoop,
};
const kubernetesApi = {
  getKubernetesAvailability: asyncNoop,
  listKubernetesResources: asyncNoop,
  getKubernetesResourceDetail: asyncNoop,
  getKubernetesPodLogs: asyncNoop,
  planKubernetesWorkloadAction: asyncNoop,
  confirmKubernetesWorkloadAction: asyncNoop,
  executeKubernetesWorkloadAction: asyncNoop,
  cancelKubernetesWorkloadAction: asyncNoop,
  openKubernetesPodTerminal: asyncNoop,
  exportKubernetesManifest: asyncNoop,
};

function styles(...files: string[]): string {
  const renderer = path.dirname(
    new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"),
  );
  return files.map((file) => readFileSync(path.join(renderer, file), "utf8")).join("\n");
}

function write(name: string, markup: string, css: string): void {
  mkdirSync(OUT, { recursive: true });
  for (const theme of ["light", "dark"]) {
    writeFileSync(
      path.join(OUT, `preview-${name}-${theme}.html`),
      `<!doctype html>
<html lang="zh" data-theme="${theme}">
<head><meta charset="utf-8"><title>${name} 预览 · ${theme}</title>
<style>
html, body { margin: 0; padding: 0; background: var(--bg); }
body { font: 14px/1.5 "Segoe UI", "Microsoft YaHei", system-ui, sans-serif; }
.page { min-height: 100vh; }
${css}
</style></head>
<body>${markup}</body></html>`,
    );
  }
}

function dockerState() {
  const rows: readonly (readonly [string, string, string, string, string])[] = [
    ["web-frontend", "nginx:1.27", "running", "Up 4 hours", "127.0.0.1:8081->80/tcp"],
    ["api-backend", "registry.local/api:2.4", "running", "Up 4 hours", ""],
    ["cache-node", "redis:7.2", "running", "Up 4 hours", "6379/tcp"],
    ["legacy-agent", "incident-tools:latest", "running", "Up 2 days", ""],
    ["ci-runner", "alpine:3.20", "running", "Up 4 hours", ""],
    ["edge-proxy", "haproxy:3.0", "running", "Up 4 hours", ""],
    ["open-admin", "alpine:3.20", "running", "Up 4 hours", "0.0.0.0:9090->9090/tcp"],
    ["stopped-batch", "alpine:3.20", "exited", "Exited (0) 21 minutes ago", ""],
  ];
  const usage: readonly (readonly [string, string, string, string])[] = [
    ["1.42%", "48.2MiB / 15.53GiB", "0.30%", "12.4MB / 3.1MB"],
    ["6.08%", "210MiB / 15.53GiB", "1.32%", "88.1MB / 41MB"],
    ["0.11%", "8.4MiB / 15.53GiB", "0.05%", "1.1MB / 900kB"],
    ["0.00%", "360KiB / 15.53GiB", "0.00%", "1.52kB / 0B"],
    ["0.00%", "412KiB / 15.53GiB", "0.00%", "2.1kB / 0B"],
    ["0.34%", "22.7MiB / 15.53GiB", "0.14%", "5.5MB / 5.1MB"],
    ["0.02%", "3.1MiB / 15.53GiB", "0.02%", "0B / 0B"],
  ];
  return {
    ...createDockerReadState(),
    scope: "b",
    snapshotStatus: "ready" as const,
    snapshot: {
      snapshotHandle: "s",
      expiresInSeconds: 287,
      truncated: false,
      runtime: "docker" as const,
      installedRuntimes: ["docker" as const],
      containers: rows.map(([name, image, state, status, ports], index) => ({
        containerHandle: `c${index}`,
        shortId: `${index}`.repeat(12).slice(0, 12),
        name,
        image,
        state,
        status,
        ports,
        createdAt: "2026-08-27 01:00:00",
      })),
    },
    // The detail rail open on a row, because a preview that never shows it is
    // a preview of half the page.
    selectedContainerHandle: "c0",
    inspectionStatus: "ready" as const,
    inspection: {
      kind: "container" as const,
      snapshotHandle: "s",
      resourceHandle: "c0",
      name: "web-frontend",
      fields: [
        { label: "镜像", value: "nginx:1.27" },
        { label: "创建时间", value: "2026-08-27T01:00:00Z" },
        { label: "平台", value: "linux" },
        { label: "状态", value: "running" },
        { label: "重启次数", value: "0" },
        { label: "网络模式", value: "bridge" },
        { label: "特权模式", value: "false" },
      ],
      mounts: [
        { kind: "bind", source: "/data/config", destination: "/app/config", mode: "ro", readWrite: false },
        { kind: "volume", source: "lab-logs", destination: "/logs", mode: "", readWrite: true },
      ],
      networks: [
        { name: "bridge", macAddress: "02:42:ac:11:00:02", ipv4Address: "172.17.0.2", ipv6Address: "" },
      ],
      truncated: false,
    },
    collectionStatus: { stats: "ready" as const },
    collections: {
      stats: {
        kind: "stats" as const,
        snapshotHandle: "s",
        truncated: false,
        items: usage.map(([cpuPercent, memoryUsage, memoryPercent, networkIo], index) => ({
          containerHandle: `c${index}`,
          name: rows[index]?.[0] ?? "",
          cpuPercent,
          memoryUsage,
          memoryPercent,
          networkIo,
          blockIo: "0B / 0B",
          pids: 6,
        })),
      },
      // Loaded, so the summary cards show real counts rather than the dash
      // they correctly show for a collection that has not been read.
      images: {
        kind: "images" as const,
        snapshotHandle: "s",
        truncated: false,
        items: Array.from({ length: 12 }, (_unused, index) => ({
          repository: `image-${index}`, tag: "latest", digest: "", createdAt: "", size: "12MB",
        })),
      },
      networks: {
        kind: "networks" as const,
        snapshotHandle: "s",
        truncated: false,
        items: Array.from({ length: 8 }, (_unused, index) => ({
          networkHandle: `n${index}`, name: `net-${index}`, driver: "bridge",
          scope: "local", internal: false, ipv6: false,
        })),
      },
      volumes: {
        kind: "volumes" as const,
        snapshotHandle: "s",
        truncated: false,
        items: Array.from({ length: 14 }, (_unused, index) => ({
          volumeHandle: `v${index}`, name: `vol-${index}`, driver: "local",
          mountpoint: "/var/lib/docker/volumes", scope: "local", labels: "",
        })),
      },
    },
  };
}

function kubernetesState() {
  const pods: readonly (readonly [string, string, string, number, number, number, string])[] = [
    ["access-logger", "frontend", "Running", 1, 1, 0, "10.42.0.9"],
    ["storefront-6db4bb48db-mrljf", "frontend", "Running", 1, 1, 0, "10.42.0.2"],
    ["storefront-6db4bb48db-zxcsm", "frontend", "Running", 1, 1, 0, "10.42.0.5"],
    ["flapping-worker", "jobs", "CrashLoopBackOff", 0, 1, 7, "10.42.0.4"],
    ["nightly-report-7489ffd44f-7nx9d", "jobs", "ImagePullBackOff", 0, 1, 0, "10.42.0.6"],
    ["ledger-5d8f6d87d9-8kq7v", "payments", "Running", 1, 1, 0, "10.42.0.7"],
    ["ledger-5d8f6d87d9-pq6fc", "payments", "Running", 1, 1, 0, "10.42.0.8"],
  ];
  return {
    ...createKubernetesReadState("b"),
    availabilityStatus: "ready" as const,
    availability: {
      kubectlInstalled: true,
      apiReachable: true,
      currentContext: "default",
      contextTruncated: false,
      contextNamespace: "default",
    },
    namespacesStatus: "ready" as const,
    namespaces: {
      snapshotHandle: "ns",
      tab: "namespaces" as const,
      namespaceScoped: false,
      displayed: 4,
      truncated: false,
      expiresInSeconds: 300,
      rows: ["default", "frontend", "jobs", "payments"].map((name, index) => ({
        kind: "namespace" as const,
        rowHandle: `n${index}`,
        name,
        phase: "Active",
        // A real timestamp, so the age column can demonstrate itself rather
        // than sitting at the dash it correctly shows for unparseable input.
        createdAt: "2026-08-21T09:00:00Z",
        textTruncated: false,
      })),
    },
    listStatus: "ready" as const,
    listContext: "all",
    snapshot: {
      snapshotHandle: "p",
      tab: "pods" as const,
      namespaceScoped: false,
      displayed: pods.length,
      truncated: false,
      expiresInSeconds: 291,
      rows: pods.map(
        ([name, namespace, phase, readyContainers, totalContainers, restarts, podIp], index) => ({
          kind: "pod" as const,
          rowHandle: `p${index}`,
          namespace,
          name,
          phase,
          readyContainers,
          totalContainers,
          restarts,
          node: "worker-1",
          podIp,
          images: ["alpine:3.20"],
          createdAt: `2026-08-2${(index % 7) + 1}T0${(index % 9) + 1}:15:00Z`,
          supportsLogs: true,
          containers: [{ name: "app", image: "registry.example/app:1", ready: true, running: true, restarts: 0 }],
          defaultContainer: "app",
          textTruncated: false,
        }),
      ),
    },
    selectedRowHandle: "p3",
    detailStatus: "ready" as const,
    detail: {
      snapshotHandle: "p",
      rowHandle: "p3",
      contentKind: "detail" as const,
      text: [
        "Name:              flapping-worker",
        "Namespace:         jobs",
        "Node:              worker-1/172.17.0.25",
        "Status:            Running",
        "IP:                10.42.0.4",
        "Containers:",
        "  flapping-worker:",
        "    Image:         alpine:3.20",
        "    State:         Waiting",
        "      Reason:      CrashLoopBackOff",
        "    Last State:    Terminated",
        "      Exit Code:   1",
        "    Restart Count: 7",
      ].join("\n"),
      truncated: false,
    },
  };
}

describe("page preview with a full snapshot", () => {
  it("renders the Docker page with every column populated", () => {
    const markup = renderToStaticMarkup(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- preview fixture
      <DockerPage bindingHandle="b" api={dockerApi as any} initialState={dockerState() as any} />,
    );
    write("docker", markup, styles("theme/themes.css", "docker-page.css"));
    // A full snapshot has to produce a row per container and the usage columns
    // beside them; an empty table here would mean the page only ever looked
    // right because it had nothing to show.
    expect(markup).toContain("web-frontend");
    expect(markup).toContain("stopped-batch");
    // The used half only: the limit is the machine's memory, identical on
    // every row, and it is still shown in full in the rail.
    expect(markup).toContain("48.2MiB");
    expect(markup).toContain("127.0.0.1:8081-&gt;80/tcp");
    expect(markup).not.toContain("preview");

    // The summary band reports what was loaded, and the rail is open on a row.
    for (const shown of ["容器总数", "运行中", "已停止", "镜像", "网络", "存储卷"]) {
      expect(markup).toContain(shown);
    }
    expect(markup).toContain("<p class=\"docker-stat-value\">12</p>");
    expect(markup).toContain("<p class=\"docker-stat-value\">14</p>");
    // Details open over the table rather than beside it, so the table keeps
    // the whole width when nothing is selected.
    expect(markup).toContain("docker-detail-dialog");
    expect(markup).toContain('aria-modal="true"');
    expect(markup).not.toContain("docker-detail-rail");
    expect(markup).toContain("/app/config");
    expect(markup).toContain("172.17.0.2");
    // A collection that was never read shows no number at all: a zero here
    // would read as "there are none".
    expect(markup).not.toContain("<p class=\"docker-stat-value\">—</p>");

    // A shell is offered on every running container and on none of the
    // stopped ones. Counting is the point: asserting only that the button
    // exists somewhere would pass just as well if it were on every row.
    const running = dockerState().snapshot.containers.filter(
      (container: { state: string }) => container.state === "running",
    ).length;
    expect(running).toBeGreaterThan(0);
    expect(running).toBeLessThan(dockerState().snapshot.containers.length);
    expect(markup.match(/data-testid="docker-open-terminal"/gu) ?? []).toHaveLength(running);
  });

  it("renders the Kubernetes page with every column populated", () => {
    const markup = renderToStaticMarkup(
      <KubernetesPage
        bindingHandle="b"
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- preview fixture
        api={kubernetesApi as any}
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- preview fixture
        initialState={kubernetesState() as any}
      />,
    );
    write("kubernetes", markup, styles("theme/themes.css", "kubernetes-page.css"));
    expect(markup).toContain("flapping-worker");
    expect(markup).toContain("CrashLoopBackOff");
    // The address column was blank on every real cluster until the parser was
    // fixed; a preview that cannot show one would hide that regression coming
    // back.
    expect(markup).toContain("10.42.0.4");

    // Columns, not one run-on line per row. Restart counts and ready ratios
    // are the things you want to run your eye down a column of.
    const headers = [...markup.matchAll(/<th[^>]*>([^<]+)<\/th>/gu)].map((match) => match[1]);
    expect(headers).toEqual([
      "名称", "命名空间", "就绪", "重启", "节点", "地址", "存在时长", "状态", "操作",
    ]);
    // What a responder does with a pod sits on its row, not behind a click.
    for (const action of ["kubernetes-row-logs", "kubernetes-row-terminal", "kubernetes-row-previous-logs"]) {
      expect(markup).toContain(`data-testid="${action}"`);
    }
    // Counts line up under each other, which is the point of the column.
    expect(markup).toContain('<th class="is-numeric">重启</th>');
    // The rows that need looking at are marked, and there are fewer of them
    // than there are rows — a mark on everything marks nothing.
    const marked = (markup.match(/needs-attention/gu) ?? []).length;
    const rows = (markup.match(/<tr/gu) ?? []).length - 1;
    expect(marked).toBeGreaterThan(0);
    expect(marked).toBeLessThan(rows);
    // And the summary says how many before any scrolling.
    expect(markup).toContain("要看的");
    expect(markup).toContain("只看要处理的");
    // A tab nobody opened contributes no number rather than a zero.
    expect(markup).toContain("<p class=\"kubernetes-stat-value\">—</p>");
    // The details are over the table, not beside it.
    expect(markup).toContain("kubernetes-detail-backdrop");
    expect(markup).toContain('aria-modal="true"');
  });
});
