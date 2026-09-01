// Runs the five Docker read RPCs against the lab host that has a real daemon,
// and checks what came back against what was deliberately planted there.
//
// The page has never been pointed at a running daemon — every recorded piece
// of evidence for it is the disconnected view — so this is the first time the
// parsing is asked to survive real output.
//
//   node tools/lab/probe-docker.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

/** What plant.sh put on that host, and which audit branch each one is for. */
const PLANTED = {
  "legacy-agent": "特权容器",
  "monitor-sidecar": "宿主 PID 命名空间",
  "shm-worker": "宿主 IPC 命名空间",
  "net-tuner": "危险 capabilities",
  "ci-runner": "挂载 docker.sock",
  "config-sync": "读写挂载宿主 /etc",
  "edge-proxy": "宿主网络",
  "open-admin": "端口发布到所有网卡",
  "drifted-tool": "latest 标签",
};

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 90
    ? `${actual.slice(0, 90)}…`
    : String(actual);
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 实际 ${shown}`}`);
  return ok;
}

const target = labTarget("docker");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

/** Reads the inner daemon directly, so "it matches" is not the tool agreeing with itself. */
import { execFileSync } from "node:child_process";
function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc",
      `docker exec svc-docker sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  // --- 容器清单
  console.log("=== 容器");
  const snapshot = await sidecar.call("docker.containers.refresh", { bindingHandle: binding }, 90_000);
  const containers = snapshot.containers ?? [];
  const names = containers.map((item) => item.name);
  console.log(`  ${names.length} 个：${names.slice(0, 8).join(" ")}${names.length > 8 ? " …" : ""}`);
  check("拿到容器行", names.length, (value) => value >= 12);
  check("被截断的标记没有误报", snapshot.truncated, false);
  for (const name of ["legacy-agent", "ci-runner", "edge-proxy"]) {
    check(`列表里有 ${name}`, names.includes(name), true);
  }
  const stopped = containers.filter((item) => item.state !== "running");
  check("停掉的容器也在列表里", stopped.length, (value) => value >= 1);
  // A published port is a fact about the container, and the row is where an
  // operator reads it; an always-empty column would be a silent gap.
  const published = containers.filter((item) => (item.ports ?? "") !== "");
  check("发布了端口的容器，端口列不是空的", published.length, (value) => value >= 2);
  check("行里没有裸路径或命令", JSON.stringify(snapshot).includes("/var/run/docker.sock"), false);

  // The short id is shown next to the name so what is on screen matches what
  // `docker ps` prints on the machine. Checked against the host rather than
  // against itself: a value the tool made up would satisfy a format check just
  // as well as the real one.
  const hostIds = new Map(
    onHost("docker ps -a --format '{{.Names}} {{.ID}}'")
      .split("\n").map((line) => line.trim().split(/\s+/u))
      .filter((parts) => parts.length === 2),
  );
  const mismatched = containers.filter((item) => hostIds.get(item.name) !== item.shortId);
  check("短 id 和主机上 docker ps 打的一致", mismatched.length, 0);
  check("短 id 就是 12 位，不是全长", containers.every(
    (item) => /^[0-9a-f]{12}$/u.test(item.shortId ?? ""),
  ), true);
  // Display only: the full 64-character id must still never cross.
  check("全长 id 没有跟着过来", /[0-9a-f]{20,}/u.test(JSON.stringify(snapshot)), false);

  // --- 其余四个集合
  for (const [kind, label, least] of [
    // The 容器 tab shows this one, not the snapshot: CPU and memory per
    // container come from here, and nothing else fetches it.
    ["stats", "资源占用", 12],
    ["images", "镜像", 2],
    ["networks", "网络", 4],
    ["volumes", "存储卷", 2],
    ["compose-projects", "Compose 项目", 1],
  ]) {
    console.log(`\n=== ${label}`);
    let collection;
    try {
      collection = await sidecar.call("docker.collection.get", {
        bindingHandle: binding,
        snapshotHandle: snapshot.snapshotHandle,
        kind,
      }, 90_000);
    } catch (error) {
      failures += 1;
      console.log(`  ✗ 读取失败 —— ${error.message}`);
      continue;
    }
    const rows = collection.items ?? collection.rows ?? [];
    console.log(`  ${rows.length} 行`);
    check(`${label}读到了`, rows.length, (value) => value >= least);
    if (rows.length > 0) {
      const first = JSON.stringify(rows[0]);
      console.log(`  第一行：${first.length > 200 ? `${first.slice(0, 200)}…` : first}`);
    }
  }

  // --- 安全审计：靶机上每一类问题都要被说出来
  console.log("\n=== 安全审计");
  const audit = await sidecar.call("docker.security.audit.get", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
  }, 120_000);
  const findings = audit.findings ?? [];
  console.log(`  ${findings.length} 条发现`);
  const text = JSON.stringify(findings);
  for (const [name, why] of Object.entries(PLANTED)) {
    check(`${why}（${name}）被点名`, text.includes(name), true);
  }
  const bySeverity = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
  }
  console.log(`  按严重程度：${JSON.stringify(bySeverity)}`);
  if (findings.length > 0) {
    console.log(`  样例：${(findings[0].title ?? "").slice(0, 100)}`);
    console.log(`        ${(findings[0].detail ?? findings[0].description ?? "").slice(0, 140)}`);
  }

  // --- 日志
  console.log("\n=== 容器日志");
  const logged = containers.find((item) => item.name === "incident-collector")
    ?? containers.find((item) => item.state === "running");
  if (logged === undefined) {
    failures += 1;
    console.log("  ✗ 没有可读日志的运行中容器");
  } else {
    const logs = await sidecar.call("docker.container.logs.get", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      containerHandle: logged.containerHandle,
      tail: 100,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (logs.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ ${logged.name} 日志读取失败 —— ${logs.failed}`);
    } else {
      const body = logs.text ?? logs.content ?? "";
      const lines = body.split("\n").filter((line) => line.trim() !== "");
      console.log(`  ${logged.name}：${body.length} 字节 / ${lines.length} 行`);
      if (lines.length > 0) console.log(`  末行：${lines[lines.length - 1].slice(0, 90)}`);
      check("日志读到了内容", lines.length, (value) => value >= 3);
      check("日志是这个容器写的", body.includes("collected batch="), true);
    }
  }

  // --- 详情
  console.log("\n=== 容器详情");
  const inspectTarget = containers.find((item) => item.name === "legacy-agent");
  if (inspectTarget === undefined) {
    failures += 1;
    console.log("  ✗ 找不到 legacy-agent");
  } else {
    const detail = await sidecar.call("docker.resource.inspect", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      kind: "container",
      resourceHandle: inspectTarget.containerHandle,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (detail.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ 详情读取失败 —— ${detail.failed}`);
    } else {
      const fields = detail.fields ?? [];
      const value = (label) => fields.find((entry) => entry.label === label)?.value;
      console.log(`  ${fields.length} 个字段，挂载 ${(detail.mounts ?? []).length} 条，网络 ${(detail.networks ?? []).length} 条`);
      check("特权模式读到了 true", value("特权模式"), "true");
      check("网络模式有值", value("网络模式"), (item) => (item ?? "") !== "");
      check("详情没有带出裸的容器 id", JSON.stringify(detail).includes(inspectTarget.containerHandle), true);
    }

    // The audit parses mounts on its own path; this is the detail pane's.
    const mounted = containers.find((item) => item.name === "ci-runner");
    const mountDetail = await sidecar.call("docker.resource.inspect", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      kind: "container",
      resourceHandle: mounted.containerHandle,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (mountDetail.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ ci-runner 详情读取失败 —— ${mountDetail.failed}`);
    } else {
      const mounts = mountDetail.mounts ?? [];
      console.log(`  ci-runner 挂载 ${mounts.length} 条：${JSON.stringify(mounts[0] ?? null)}`);
      check("挂载解析出来了", mounts.length, (value) => value >= 1);
      check("挂载里能看到 docker.sock", JSON.stringify(mounts).includes("docker.sock"), true);
    }
  }
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exitCode = failures === 0 ? 0 : 1;
