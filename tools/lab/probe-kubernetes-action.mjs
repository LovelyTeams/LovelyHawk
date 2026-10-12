// Drives a workload action all the way through against a real cluster:
// plan, confirm, execute, verify — and the paths that must refuse.
//
// Everything below acts on `payments/ledger` and the single k3s node, both
// of which the lab plants for exactly this. Verification covers the requested
// replica count and scheduling state; it does not certify workload health.
//
//   node tools/lab/probe-kubernetes-action.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 110
    ? `${actual.slice(0, 110)}…`
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

/** Reads the cluster directly, so "it worked" is not the tool marking its own work. */
function onCluster(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "svc-kubernetes", "sh", "-c", command],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

/**
 * Puts the cluster back to the starting state before anything runs.
 *
 * Cleaning up only at the end means a probe that crashes half way through can
 * never be run again, which is exactly when you most want to re-run it.
 */
const target = labTarget("kubernetes");
const outer = JSON.parse(execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "inspect", "svc-kubernetes"], { encoding: "utf8" }))[0];
if (outer.Config.Image !== "lovelyres-svc:kubernetes" || outer.HostConfig.Privileged ||
  outer.Mounts.length !== 1 || outer.Mounts[0].Name !== "lab-k3s-config" || outer.Mounts[0].RW) {
  throw new Error("Refusing to mutate a target that is not the isolated Kubernetes lab client");
}
const nodesBefore = JSON.parse(onCluster("kubectl get nodes -o json"));
const nodeName = nodesBefore.items[0]?.metadata.name;
const server = JSON.parse(execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "inspect", "lab-k3s"], { encoding: "utf8" }))[0];
if (server.Config.Image !== "docker.m.daocloud.io/rancher/k3s:v1.31.4-k3s1" ||
  !server.Mounts.some((mount) => mount.Name === "lab-k3s-config") ||
  server.Mounts.some((mount) => mount.Type === "bind" &&
    (mount.Source !== "/opt/lab-orchestration/k3s/registries.yaml" || mount.RW)) ||
  nodesBefore.items.length !== 1 || nodeName !== server.Id.slice(0, 12)) {
  throw new Error("Expected the single-node k3s lab; no reset was attempted");
}
function resetCluster() {
  onCluster("kubectl -n payments scale deployment ledger --replicas=3");
  onCluster(`kubectl uncordon ${nodeName}`);
}
resetCluster();
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const list = async (tab) => sidecar.call("kubernetes.resources.list", {
    bindingHandle: binding,
    input: { tab, namespaceScope: null },
  }, 90_000);

  // --- Deployment 扩缩容
  console.log("=== 计划：payments/ledger 从 3 副本缩到 1");
  let deployments = await list("deployments");
  const ledger = deployments.rows.find((row) => row.name === "ledger");
  check("集群里它现在是 3 副本", ledger?.desiredReplicas, 3);

  const plan = await sidecar.call("kubernetes.workload.action.plan", {
    bindingHandle: binding,
    snapshotHandle: deployments.snapshotHandle,
    rowHandle: ledger.rowHandle,
    resourceName: ledger.name,
    action: { kind: "scale-deployment", replicas: 1 },
  }, 90_000);
  console.log(`  ${JSON.stringify(plan)}`);
  check("说清了要做什么", plan.summary, (value) => (value ?? "").includes("副本数"));
  check("摘要里有原值与目标值", plan.summary, (value) =>
    (value ?? "").includes("3") && (value ?? "").includes("1"));
  check("标了这是危险操作", plan.dangerous, true);
  check("有回滚说明", plan.restoreDescription, (value) => (value ?? "") !== "");
  check("还没确认", plan.confirmed, false);
  check("计划有有效期", plan.expiresInSeconds, (value) => value > 0 && value <= 300);
  check("计划对应所选资源", plan.rowHandle, ledger.rowHandle);
  check("计划对应所选资源名称", plan.resourceName, ledger.name);

  console.log("\n=== 没确认就执行");
  await refuses("被拒绝", "kubernetes-action-not-confirmed", () =>
    sidecar.call("kubernetes.workload.action.execute", {
      bindingHandle: binding, planHandle: plan.planHandle,
    }, 90_000));

  console.log("\n=== 确认后执行");
  const confirmed = await sidecar.call("kubernetes.workload.action.confirm", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 60_000);
  check("确认状态回来了", confirmed.confirmed, true);

  const receipt = await sidecar.call("kubernetes.workload.action.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 180_000);
  console.log(`  ${JSON.stringify(receipt)}`);
  check("执行后验证通过", receipt.verified, true);
  check("没有触发回滚", receipt.restored, false);
  check(
    "集群里真的变成 1 了",
    onCluster("kubectl -n payments get deployment ledger -o jsonpath='{.spec.replicas}'"),
    "1",
  );

  console.log("\n=== 同一个计划再跑一次");
  await refuses("被拒绝", "kubernetes-action-plan-invalid", () =>
    sidecar.call("kubernetes.workload.action.execute", {
      bindingHandle: binding, planHandle: plan.planHandle,
    }, 90_000));

  // --- 目标值与现状相同，计划阶段就该拒
  console.log("\n=== 缩到和现在一样的副本数");
  deployments = await list("deployments");
  const atOne = deployments.rows.find((row) => row.name === "ledger");
  await refuses("计划阶段就拒了", "kubernetes-action-failed", () =>
    sidecar.call("kubernetes.workload.action.plan", {
      bindingHandle: binding,
      snapshotHandle: deployments.snapshotHandle,
      rowHandle: atOne.rowHandle,
      resourceName: atOne.name,
      action: { kind: "scale-deployment", replicas: 1 },
    }, 90_000));

  // --- 动作与资源种类对不上
  console.log("\n=== 对 Deployment 用节点隔离");
  await refuses("说清了是种类不匹配", "kubernetes-action-kind-mismatch", () =>
    sidecar.call("kubernetes.workload.action.plan", {
      bindingHandle: binding,
      snapshotHandle: deployments.snapshotHandle,
      rowHandle: atOne.rowHandle,
      resourceName: atOne.name,
      action: { kind: "cordon" },
    }, 90_000));

  // --- Pod 行没有任何动作
  console.log("\n=== 拿 Pod 的行去做动作");
  const pods = await list("pods");
  await refuses("Pod 行解不到可操作资源", "kubernetes-resource-unavailable", () =>
    sidecar.call("kubernetes.workload.action.plan", {
      bindingHandle: binding,
      snapshotHandle: pods.snapshotHandle,
      rowHandle: pods.rows[0].rowHandle,
      resourceName: pods.rows[0].name,
      action: { kind: "cordon" },
    }, 90_000));

  // --- 伪造句柄
  console.log("\n=== 伪造句柄");
  await refuses("伪造的行句柄名不到任何东西", "kubernetes-resource-unavailable", () =>
    sidecar.call("kubernetes.workload.action.plan", {
      bindingHandle: binding,
      snapshotHandle: deployments.snapshotHandle,
      rowHandle: "forged-row-handle-must-not-resolve",
      resourceName: "whatever",
      action: { kind: "scale-deployment", replicas: 2 },
    }, 90_000));
  await refuses("伪造的计划句柄", "kubernetes-action-plan-invalid", () =>
    sidecar.call("kubernetes.workload.action.confirm", {
      bindingHandle: binding, planHandle: "forged-plan-handle",
    }, 60_000));

  // --- 节点隔离，然后恢复
  console.log("\n=== 把节点标记为不可调度，再恢复");
  const nodes = await list("nodes");
  const node = nodes.rows[0];
  check("节点现在是可调度的", node.unschedulable, false);
  const cordon = await sidecar.call("kubernetes.workload.action.plan", {
    bindingHandle: binding,
    snapshotHandle: nodes.snapshotHandle,
    rowHandle: node.rowHandle,
    resourceName: node.name,
    action: { kind: "cordon" },
  }, 90_000);
  check("隔离动作也是危险操作", cordon.dangerous, true);
  await sidecar.call("kubernetes.workload.action.confirm", {
    bindingHandle: binding, planHandle: cordon.planHandle,
  }, 60_000);
  const cordonReceipt = await sidecar.call("kubernetes.workload.action.execute", {
    bindingHandle: binding, planHandle: cordon.planHandle,
  }, 180_000);
  check("隔离验证通过", cordonReceipt.verified, true);
  check(
    "集群里真的不可调度了",
    onCluster("kubectl get node -o jsonpath='{.items[0].spec.unschedulable}'"),
    "true",
  );

  const afterCordon = await list("nodes");
  const cordoned = afterCordon.rows[0];
  check("列表也读到了新状态", cordoned.unschedulable, true);
  const uncordon = await sidecar.call("kubernetes.workload.action.plan", {
    bindingHandle: binding,
    snapshotHandle: afterCordon.snapshotHandle,
    rowHandle: cordoned.rowHandle,
    resourceName: cordoned.name,
    action: { kind: "uncordon" },
  }, 90_000);
  await sidecar.call("kubernetes.workload.action.confirm", {
    bindingHandle: binding, planHandle: uncordon.planHandle,
  }, 60_000);
  const uncordonReceipt = await sidecar.call("kubernetes.workload.action.execute", {
    bindingHandle: binding, planHandle: uncordon.planHandle,
  }, 180_000);
  check("恢复验证通过", uncordonReceipt.verified, true);

  // --- 取消
  console.log("\n=== 取消一个计划");
  deployments = await list("deployments");
  const doomedRow = deployments.rows.find((row) => row.name === "ledger");
  const doomed = await sidecar.call("kubernetes.workload.action.plan", {
    bindingHandle: binding,
    snapshotHandle: deployments.snapshotHandle,
    rowHandle: doomedRow.rowHandle,
    resourceName: doomedRow.name,
    action: { kind: "scale-deployment", replicas: 5 },
  }, 90_000);
  const cancelled = await sidecar.call("kubernetes.workload.action.cancel", {
    bindingHandle: binding, planHandle: doomed.planHandle,
  }, 60_000);
  check("取消成功", cancelled.cancelled, true);
  await refuses("取消掉的计划确认不了", "kubernetes-action-plan-invalid", () =>
    sidecar.call("kubernetes.workload.action.confirm", {
      bindingHandle: binding, planHandle: doomed.planHandle,
    }, 60_000));

  // 把集群放回原样。开跑前也归位过一次，所以中途崩了也不影响下次。
  console.log("\n=== 复原集群");
  resetCluster();
  check(
    "ledger 回到 3 副本",
    onCluster("kubectl -n payments get deployment ledger -o jsonpath='{.spec.replicas}'"),
    "3",
  );
  check(
    "节点回到可调度",
    onCluster("kubectl get node -o jsonpath='{.items[0].spec.unschedulable}'"),
    "",
  );
} finally {
  // Restore this lab even if an RPC or assertion path throws midway through.
  try { resetCluster(); } finally { sidecar.close(); }
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exitCode = failures === 0 ? 0 : 1;
