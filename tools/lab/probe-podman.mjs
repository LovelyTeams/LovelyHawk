// The same Docker page, pointed at a host that has Podman and no `docker`.
//
// Before the runtime was detected rather than assumed, every question the
// page asked ran `docker …` and came back empty on a host like this — which
// reads as "no containers here" and is the worst kind of wrong answer, because
// it looks like an answer.
//
//   node tools/lab/probe-podman.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, backendBinary, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 100
    ? `${actual.slice(0, 100)}…`
    : String(actual);
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 实际 ${shown}`}`);
  return ok;
}

async function refuses(label, code, run) {
  try {
    await run();
    failures += 1;
    console.log(`  ✗ ${label} —— 居然成功了`);
  } catch (error) {
    const ok = String(error.message).includes(code);
    if (!ok) failures += 1;
    console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 期望 ${code}，实际 ${error.message}`}`);
  }
}

function onHost(container, command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc",
      `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const target = labTarget("podman");
const sidecar = new Sidecar(backendBinary(), newDataRoot());

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  // The premise of this whole probe: no docker binary anywhere on that host.
  console.log("=== 前提");
  check(
    "靶机上没有 docker",
    onHost("svc-podman", "command -v docker || echo none"),
    "none",
  );
  check(
    "靶机上有 podman",
    onHost("svc-podman", "command -v podman >/dev/null && echo yes || echo no"),
    "yes",
  );

  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  console.log("\n=== 容器清单");
  const snapshot = await sidecar.call(
    "docker.containers.refresh", { bindingHandle: binding }, 120_000,
  );
  const names = (snapshot.containers ?? []).map((item) => item.name);
  console.log(`  runtime=${snapshot.runtime} installed=${JSON.stringify(snapshot.installedRuntimes)}`);
  console.log(`  ${names.length} 个：${names.join(" ")}`);
  check("认出运行时是 podman", snapshot.runtime, "podman");
  check("只报告了 podman 一个", snapshot.installedRuntimes, (value) =>
    JSON.stringify(value) === '["podman"]');
  check("读到了容器", names.length, (value) => value >= 4);
  for (const name of ["app-frontend", "legacy-agent", "edge-proxy"]) {
    check(`列表里有 ${name}`, names.includes(name), true);
  }

  console.log("\n=== 其余集合");
  // 资源占用不在这里查：`podman stats` 要读 cgroup，而这台靶机是跑在
  // cgroups-v1 的容器里的 Podman，它自己就报 "cgroup deleted"。这是靶机环境
  // 的限制，不是工具的问题——真实的 openEuler / Anolis 主机上没有这一层。
  // 与其让探针假装验过，不如在这里说清楚它没验。
  console.log("  ⚠ 资源占用：这台靶机的 Podman 读不到 cgroup，本探针不覆盖（真实主机上无此限制）");
  let imageRows = [];
  for (const [kind, label, least] of [
    ["images", "镜像", 1],
    ["networks", "网络", 2],
    ["volumes", "存储卷", 1],
  ]) {
    let collection;
    try {
      collection = await sidecar.call("docker.collection.get", {
        bindingHandle: binding,
        snapshotHandle: snapshot.snapshotHandle,
        kind,
      }, 120_000);
    } catch (error) {
      failures += 1;
      console.log(`  ✗ ${label}读取失败 —— ${error.message}`);
      continue;
    }
    const rows = collection.items ?? [];
    check(`${label}读到了（${rows.length} 行）`, rows.length, (value) => value >= least);
    if (kind === "images") imageRows = rows;
  }

  // Podman names its listing fields differently from Docker and gives the
  // size and the build date as numbers, so these two columns are exactly the
  // ones that come back empty — or as a run of digits — when only Docker's
  // shape is known.
  console.log("\n=== 镜像（Podman 的字段名和 Docker 不一样）");
  if (imageRows.length === 0) {
    failures += 1;
    console.log("  ✗ 没有镜像可查");
  } else {
    const first = imageRows[0];
    console.log(`  ${first.repository}:${first.tag} · ${first.size} · ${first.createdAt}`);
    check("仓库名读到了", imageRows.every((row) => (row.repository ?? "") !== ""), true);
    check("短 id 就是 12 位", imageRows.every((row) => /^[0-9a-f]{12}$/u.test(row.shortId)), true);
    check("大小不是裸字节数", first.size, (value) => /^[0-9.]+(B|kB|MB|GB|TB)$/u.test(value ?? ""));
    check("构建时间不是 Unix 秒", first.createdAt, (value) => /\d{4}-\d{2}-\d{2}/u.test(value ?? ""));

    const detail = await sidecar.call("docker.resource.inspect", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      kind: "image",
      resourceHandle: first.imageHandle,
    }, 120_000).catch((error) => ({ failed: error.message }));
    if (detail.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ 镜像详情读取失败 —— ${detail.failed}`);
    } else {
      console.log(`  详情：${detail.os}/${detail.architecture} · 启动 ${[...detail.entrypoint, ...detail.command].join(" ") || "（无）"}`);
      check("是这个镜像，不是别的", detail.shortId, first.shortId);
      check("平台读到了", `${detail.os}/${detail.architecture}`, (value) => value.startsWith("linux/"));
      check("运行身份说清了", detail.user, (value) => (value ?? "") !== "");
    }
  }

  console.log("\n=== 安全审计");
  const audit = await sidecar.call("docker.security.audit.get", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
  }, 180_000);
  const text = JSON.stringify(audit.findings ?? []);
  console.log(`  ${(audit.findings ?? []).length} 条发现`);
  check("特权容器被点名", text.includes("legacy-agent"), true);
  check("宿主网络被点名", text.includes("edge-proxy"), true);

  console.log("\n=== 详情");
  const privileged = (snapshot.containers ?? []).find((item) => item.name === "legacy-agent");
  const detail = await sidecar.call("docker.resource.inspect", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    kind: "container",
    resourceHandle: privileged.containerHandle,
  }, 120_000);
  const value = (label) => (detail.fields ?? []).find((entry) => entry.label === label)?.value;
  check("特权模式读到了 true", value("特权模式"), "true");

  console.log("\n=== 容器动作（走的应该是 podman 的命令）");
  const worker = (snapshot.containers ?? []).find((item) => item.name === "app-worker");
  const plan = await sidecar.call("docker.container.action.plan", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: worker.containerHandle,
    containerName: worker.name,
    action: "stop",
  }, 120_000);
  console.log(`  ${plan.summary}`);
  check("计划说的是 Podman，不是 Docker", plan.summary, (item) => (item ?? "").includes("Podman"));
  await sidecar.call("docker.container.action.confirm", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 60_000);
  const receipt = await sidecar.call("docker.container.action.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 240_000);
  console.log(`  ${JSON.stringify(receipt)}`);
  check("停止验证通过", receipt.verified, true);
  check(
    "靶机上它真的停了",
    onHost("svc-podman", "podman inspect -f '{{.State.Status}}' app-worker"),
    "exited",
  );

  console.log("\n=== 复原靶机");
  onHost("svc-podman", "podman start app-worker >/dev/null 2>&1; true");
  check(
    "app-worker 回到运行",
    onHost("svc-podman", "podman inspect -f '{{.State.Status}}' app-worker"),
    "running",
  );

  // --- 一台既没有 docker 也没有 podman 的机器
  console.log("\n=== 没有任何容器运行时的主机");
  const bare = new Sidecar(backendBinary(), newDataRoot());
  try {
    const plain = await connect(bare, labTarget("ubuntu"));
    await refuses(
      "说清了这台机器没装容器运行时，而不是报「没有容器」",
      "docker-runtime-absent",
      () => bare.call("docker.containers.refresh", { bindingHandle: plain.bindingHandle }, 120_000),
    );
  } finally {
    bare.close();
  }
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exitCode = failures === 0 ? 0 : 1;
