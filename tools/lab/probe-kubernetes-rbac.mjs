// A kubeconfig that may look at one namespace and do nothing else.
//
// Competition boxes and real incident jump hosts often hand out exactly this:
// a service account bound to a Role in one namespace. What only a cluster can
// show is how each entry behaves when the API server says no:
//   1. the namespace list and the all-namespaces pod list are refused, and the
//      refusal is reported as a permission problem — never as an empty list;
//   2. the namespace the kubeconfig's current context names is still readable,
//      without the page ever sending a namespace name;
//   3. pods, deployments and logs in that namespace are read as usual;
//   4. a shell, a directory listing and a file read all need pods/exec, and
//      each is refused with that reason before anything runs in the pod;
//   5. a scaling plan can be made (it only reads), but executing it is
//      refused by the API server, nothing changes, and no success is claimed.
//
// The account, its namespace and its login come from
// kubernetes-rbac-fixture.mjs and are removed at the end.
//
//   node tools/lab/probe-kubernetes-rbac.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";
import { createRestrictedAccount, labKubectl } from "./kubernetes-rbac-fixture.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 200 ? `${actual.slice(0, 200)}…` : JSON.stringify(actual);
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

const account = await createRestrictedAccount();
const { namespace, login, password } = account;
const target = { ...labTarget("kubernetes"), username: login, password, id: "44444444-4444-4444-8444-444444444401", name: "lab-rbac" };
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  console.log(`建好了命名空间 ${namespace}（一个 Deployment、只读的 Role）和登录账号 ${login}`);
  check("账号本身确实只能看这个命名空间（kubectl auth can-i）", account.canI(), "no,no,yes,no");

  console.log(`\n以 ${login} 连接 ${target.host}:${target.port}`);
  const status = await connect(sidecar, target);
  check("连上了", status?.stage, "connected");
  const binding = status.bindingHandle;

  console.log("\n=== 可用性");
  const availability = await sidecar.call("kubernetes.availability.get", { bindingHandle: binding }, 60_000);
  check("kubectl 在、API 能连上", `${availability.kubectlInstalled},${availability.apiReachable}`, "true,true");
  check("当前上下文", availability.currentContext, "viewer@lab");
  check("报出了上下文指定的命名空间", availability.contextNamespace, namespace);

  const list = (tab, namespaceScope) => sidecar.call("kubernetes.resources.list", {
    bindingHandle: binding, input: { tab, namespaceScope },
  }, 90_000);

  console.log("\n=== 读不到的，说是权限，不说是空");
  await refuses("命名空间列表被拒，说的是权限", "kubernetes-forbidden", () => list("namespaces", null));
  await refuses("全部命名空间的 Pod 被拒，说的是权限", "kubernetes-forbidden", () => list("pods", null));
  await refuses("节点列表被拒，说的是权限", "kubernetes-forbidden", () => list("nodes", null));

  console.log("\n=== 上下文的命名空间照常能读");
  const pods = await list("pods", { context: true });
  check("按命名空间读的", pods.namespaceScoped, true);
  const pod = pods.rows.find((row) => row.namespace === namespace && row.name.startsWith("web-"));
  check("列出了 web 的 Pod", pod?.phase, "Running");
  check("只有这个命名空间的", pods.rows.every((row) => row.namespace === namespace), true);
  const deployments = await list("deployments", { context: true });
  const web = deployments.rows.find((row) => row.name === "web");
  check("列出了 Deployment web", web?.desiredReplicas, 1);

  const ask = (method, params) => sidecar.call(method, {
    bindingHandle: binding, snapshotHandle: pods.snapshotHandle, rowHandle: pod.rowHandle, ...params,
  }, 90_000);
  const logs = await ask("kubernetes.pod.logs.get", { previous: false, container: null });
  check("日志读得到（pods/log 有权限）", logs.text, (text) => text.includes("rbac-tick"));

  console.log("\n=== 要 pods/exec 的，都说缺这个权限");
  await refuses("终端打不开，说缺 exec 权限", "kubernetes-pod-exec-forbidden",
    () => ask("kubernetes.pod.terminal.open", { container: null, columns: 80, rows: 24 }));
  await refuses("目录列不出，说缺 exec 权限", "kubernetes-pod-exec-forbidden",
    () => ask("kubernetes.pod.directory.list", { path: "/tmp", container: null }));
  await refuses("文件读不了，说缺 exec 权限", "kubernetes-pod-exec-forbidden",
    () => ask("kubernetes.pod.file.read", { path: "/tmp/marker", container: null }));

  console.log("\n=== 扩缩容：计划能做，执行被集群拒绝");
  const plan = await sidecar.call("kubernetes.workload.action.plan", {
    bindingHandle: binding, snapshotHandle: deployments.snapshotHandle, rowHandle: web.rowHandle,
    resourceName: web.name, action: { kind: "scale-deployment", replicas: 2 },
  }, 90_000);
  check("计划写明了 1 → 2", plan.summary, (value) => (value ?? "").includes("1") && (value ?? "").includes("2"));
  await sidecar.call("kubernetes.workload.action.confirm", { bindingHandle: binding, planHandle: plan.planHandle }, 60_000);
  const receipt = await sidecar.call("kubernetes.workload.action.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 180_000);
  check("没有报成功", receipt.verified, false);
  check("回执说的是权限，并说明没有改动", receipt.detail,
    (value) => value.includes("没有这个权限") && value.includes("没有被改动"));
  check("没有声称恢复过", receipt.restored, false);
  check("集群里还是 1 副本", labKubectl(["get", "deployment", "web", "-n", namespace, "-o", "jsonpath={.spec.replicas}"]).trim(), "1");
} catch (error) {
  failures += 1;
  console.error(`\n失败：${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1200));
} finally {
  sidecar.close();
  const problems = account.remove();
  failures += problems.length;
  console.log(problems.length === 0 ? `\n已删除本次的命名空间 ${namespace} 和登录账号 ${login}` : `\n${problems.join("\n")}`);
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 项没对上`);
process.exitCode = failures === 0 ? 0 : 1;
