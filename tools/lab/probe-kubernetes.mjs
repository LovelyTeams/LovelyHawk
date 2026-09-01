// Runs the four Kubernetes read RPCs against the lab host that holds kubectl
// against a real k3s cluster, and checks what came back against what was
// deliberately planted there.
//
// Like the Docker page, this one has only ever been photographed disconnected.
// A cluster is the one thing its parsing cannot be reasoned about without.
//
//   node tools/lab/probe-kubernetes.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

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

/** The row shape is the same for every kind; this reads it whatever it is called. */
function rowsOf(result) {
  return result.rows ?? result.items ?? result.resources ?? [];
}

const target = labTarget("kubernetes");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  // --- 可用性
  console.log("=== 可用性");
  const availability = await sidecar.call(
    "kubernetes.availability.get", { bindingHandle: binding }, 60_000,
  );
  console.log(`  ${JSON.stringify(availability)}`);
  check("认出装了 kubectl", availability.kubectlInstalled, true);
  check("认出 API server 连得上", availability.apiReachable, true);
  check("读到了当前上下文", availability.currentContext, (value) => (value ?? "") !== "");

  // --- 四类资源
  const collected = {};
  for (const [kind, label, least] of [
    ["namespaces", "命名空间", 7],
    ["nodes", "节点", 1],
    ["pods", "Pod", 8],
    ["deployments", "Deployment", 5],
  ]) {
    console.log(`\n=== ${label}`);
    let result;
    try {
      result = await sidecar.call("kubernetes.resources.list", {
        bindingHandle: binding,
        // null scope means every namespace; a scope is a Namespace row's own
        // capability, never a name the caller types.
        input: { tab: kind, namespaceScope: null },
      }, 90_000);
    } catch (error) {
      failures += 1;
      console.log(`  ✗ 读取失败 —— ${error.message}`);
      continue;
    }
    collected[kind] = result;
    const rows = rowsOf(result);
    console.log(`  ${rows.length} 行`);
    check(`${label}读到了`, rows.length, (value) => value >= least);
    if (rows.length > 0) {
      const first = JSON.stringify(rows[0]);
      console.log(`  第一行：${first.length > 220 ? `${first.slice(0, 220)}…` : first}`);
    }
    check(`${label}没有被误报截断`, result.truncated ?? false, false);
  }

  // --- 种下的具体工作负载要能看见
  console.log("\n=== 种下的工作负载");
  const podText = JSON.stringify(rowsOf(collected.pods ?? {}));
  const deployText = JSON.stringify(rowsOf(collected.deployments ?? {}));
  check("payments/ledger 在 Deployment 里", deployText.includes("ledger"), true);
  check("frontend/storefront 在 Deployment 里", deployText.includes("storefront"), true);
  check("拉不到镜像的 nightly-report 也在", deployText.includes("nightly-report"), true);
  check("命名空间分组不是全部落在 default", deployText.includes("payments"), true);
  check("反复重启的 flapping-worker 在 Pod 里", podText.includes("flapping-worker"), true);
  // A pod list where every row reads Running would not prove the状态 column works.
  const states = new Set(rowsOf(collected.pods ?? {}).map((row) => row.status ?? row.phase ?? ""));
  console.log(`  Pod 状态种类：${[...states].join(" / ")}`);
  check("Pod 状态不是清一色 Running", states.size, (value) => value >= 2);
  const restarted = rowsOf(collected.pods ?? {}).filter(
    (row) => Number(row.restarts ?? 0) > 0,
  );
  check("重启次数不是恒为 0", restarted.length, (value) => value >= 1);
  // A running pod always has an address; an always-blank column reads as
  // "no network" rather than "we did not parse it".
  const running = rowsOf(collected.pods ?? {}).filter((row) => row.phase === "Running");
  const addressed = running.filter((row) => (row.podIp ?? "") !== "");
  check(
    `运行中的 Pod 有地址（${addressed.length}/${running.length}）`,
    addressed.length,
    (value) => value === running.length,
  );

  // --- 详情
  console.log("\n=== 资源详情");
  const ledger = rowsOf(collected.deployments ?? {}).find(
    (row) => (row.name ?? "").startsWith("ledger"),
  );
  if (ledger === undefined) {
    failures += 1;
    console.log("  ✗ 找不到 ledger");
  } else {
    const detail = await sidecar.call("kubernetes.resource.detail.get", {
      bindingHandle: binding,
      snapshotHandle: (collected.deployments ?? {}).snapshotHandle,
      rowHandle: ledger.rowHandle ?? ledger.handle,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (detail.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ 详情读取失败 —— ${detail.failed}`);
    } else {
      const body = detail.text ?? detail.content ?? "";
      console.log(`  ${body.length} 字节`);
      check("详情读到了内容", body.length, (value) => value > 200);
      check("详情里是这个 Deployment", body.includes("ledger"), true);
      check("副本数在详情里", /replicas/iu.test(body), true);
    }
  }

  // --- Pod 日志
  console.log("\n=== Pod 日志");
  const logger = rowsOf(collected.pods ?? {}).find(
    (row) => (row.name ?? "") === "access-logger",
  );
  if (logger === undefined) {
    failures += 1;
    console.log("  ✗ 找不到 access-logger");
  } else {
    const logs = await sidecar.call("kubernetes.pod.logs.get", {
      bindingHandle: binding,
      snapshotHandle: (collected.pods ?? {}).snapshotHandle,
      rowHandle: logger.rowHandle ?? logger.handle,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (logs.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ 日志读取失败 —— ${logs.failed}`);
    } else {
      const body = logs.text ?? logs.content ?? "";
      const lines = body.split("\n").filter((line) => line.trim() !== "");
      console.log(`  ${body.length} 字节 / ${lines.length} 行`);
      if (lines.length > 0) console.log(`  末行：${lines[lines.length - 1].slice(0, 90)}`);
      check("日志读到了内容", lines.length, (value) => value >= 3);
      check("日志是这个 Pod 写的", body.includes("path=/health"), true);
    }
  }
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exitCode = failures === 0 ? 0 : 1;
