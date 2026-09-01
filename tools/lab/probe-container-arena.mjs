// One machine, both pages.
//
// The single-purpose hosts each prove one thing, and between them they never
// exercise the case a real competition box actually is: Docker workloads and a
// Kubernetes cluster on the same host, reached through one SSH connection.
// This checks that both pages find real data on that one target.
//
//   node tools/lab/probe-container-arena.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 实际 ${String(actual)}`}`);
  return ok;
}

const target = labTarget("container-arena");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  console.log("=== Docker 侧");
  const snapshot = await sidecar.call(
    "docker.containers.refresh", { bindingHandle: binding }, 150_000,
  );
  const names = (snapshot.containers ?? []).map((item) => item.name);
  console.log(`  runtime=${snapshot.runtime}，${names.length} 个容器`);
  check("认出运行时是 docker", snapshot.runtime, "docker");
  check("读到了容器", names.length, (value) => value >= 12);
  check("特权容器在列表里", names.includes("legacy-agent"), true);

  const audit = await sidecar.call("docker.security.audit.get", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
  }, 180_000);
  check("安全审计有发现", (audit.findings ?? []).length, (value) => value >= 8);

  console.log("\n=== Kubernetes 侧（同一个 SSH 目标）");
  const availability = await sidecar.call(
    "kubernetes.availability.get", { bindingHandle: binding }, 60_000,
  );
  check("同一台机器上 kubectl 也在", availability.kubectlInstalled, true);
  check("集群 API 连得上", availability.apiReachable, true);

  const list = async (tab) => sidecar.call("kubernetes.resources.list", {
    bindingHandle: binding,
    input: { tab, namespaceScope: null },
  }, 120_000);

  const nodes = await list("nodes");
  check("节点读到了", nodes.rows.length, (value) => value >= 1);
  check("节点是 Ready 的", nodes.rows[0]?.ready, true);

  const pods = await list("pods");
  console.log(`  Pod ${pods.rows.length} 个`);
  check("Pod 读到了", pods.rows.length, (value) => value >= 8);
  // The states this lab plants on purpose; a list where everything reads
  // Running proves the column exists but not that it says anything.
  const states = new Set(pods.rows.map((row) => row.phase));
  console.log(`  状态种类：${[...states].join(" / ")}`);
  check("状态不是清一色 Running", states.size, (value) => value >= 2);
  const addressed = pods.rows.filter((row) => (row.podIp ?? "") !== "");
  check("Pod 有地址", addressed.length, (value) => value >= 6);

  const deployments = await list("deployments");
  check("Deployment 读到了", deployments.rows.length, (value) => value >= 4);
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exitCode = failures === 0 ? 0 : 1;
