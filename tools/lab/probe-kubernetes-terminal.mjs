// Opens a real shell inside a real pod and types into it.
//
// What only a cluster can show:
//   1. the shell is the pod's, not the lab host's: a pod's hostname is its own
//      name, so `cat /etc/hostname` answers the question outright;
//   2. closing the window ends what the shell started — `kubectl exec` leaves
//      its processes running when the client goes away, so a background
//      `sleep` is planted and then looked for from outside, with kubectl;
//   3. the refusals say the right thing: a pod that is not running, a pod
//      whose image has no shell (coredns is distroless), a pod deleted and
//      recreated under a new UID since the list was read, a forged handle.
//
//   node tools/lab/probe-kubernetes-terminal.mjs
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

/** kubectl on the lab host, from outside the app: the independent look. */
function labKubectl(...args) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-kubernetes", "kubectl", ...args], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 60_000,
  });
}

const target = labTarget("kubernetes");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

async function readUntil(handle, needle, attempts = 40) {
  let text = "";
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const poll = await sidecar.call("terminal.poll", {
      handle, maximumEvents: 64, maximumBytes: 262_144,
    }, 30_000);
    for (const event of poll.events ?? []) {
      if (event.kind === "output") text += Buffer.from(event.bytes_base64, "base64").toString("utf8");
    }
    if (needle.test(text)) return text;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return text;
}

async function type(handle, text) {
  await sidecar.call("terminal.input", {
    handle, bytesBase64: Buffer.from(text, "utf8").toString("base64"),
  }, 30_000);
}

const list = async (binding) => sidecar.call("kubernetes.resources.list", {
  bindingHandle: binding, input: { tab: "pods", namespaceScope: null },
}, 90_000);

const open = (binding, snapshot, row) => sidecar.call("kubernetes.pod.terminal.open", {
  bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, rowHandle: row.rowHandle,
  columns: 100, rows: 30,
}, 90_000);

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  let snapshot = await list(binding);
  const rows = () => snapshot.rows ?? [];

  // --- 一个运行中的 Pod
  const ledger = rows().find((row) => row.name.startsWith("ledger-") && row.phase === "Running");
  console.log(`=== 进入 payments/${ledger?.name}（Alpine 镜像）`);
  check("靶机上有运行中的 ledger Pod", ledger?.phase, "Running");
  const terminal = await open(binding, snapshot, ledger);
  console.log(`  ${JSON.stringify(terminal)}`);
  check("挑中了 ash 或 sh，没有硬要 bash", terminal.shell, (value) => value === "ash" || value === "sh");
  check("回的是终端句柄，不是 Pod 名", terminal.handle, (value) => !value.includes("ledger"));

  console.log("\n=== 在里面敲命令");
  await type(terminal.handle, "echo lovelyhawk-pod-$$; cat /etc/hostname; echo done-hostname\n");
  const inside = await readUntil(terminal.handle, /done-hostname\s*\r?\n/u);
  check("命令的输出回来了", inside, (value) => /lovelyhawk-pod-\d+/u.test(value));
  check("确实在这个 Pod 里：主机名就是 Pod 名", inside, (value) => value.includes(ledger.name));

  // Something the shell leaves running, to be looked for after the close.
  await type(terminal.handle, "sleep 7771 & echo planted-$!\n");
  const planted = await readUntil(terminal.handle, /planted-\d+/u);
  check("后台进程起来了", planted, (value) => /planted-\d+/u.test(value));
  const before = labKubectl("exec", ledger.name, "-n", "payments", "--", "ps");
  check("关窗前从外面能看到它", before, (value) => value.includes("sleep 7771"));

  console.log("\n=== 关窗之后");
  await sidecar.call("terminal.close", { handle: terminal.handle }, 60_000);
  let after = "";
  for (let attempt = 0; attempt < 10; attempt += 1) {
    after = labKubectl("exec", ledger.name, "-n", "payments", "--", "ps");
    if (!after.includes("sleep 7771")) break;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  check("Shell 起的后台进程跟着结束了", after, (value) => !value.includes("sleep 7771"));

  // --- 没在运行的 Pod
  console.log("\n=== 拉不到镜像、一直 Pending 的 Pod");
  const pending = rows().find((row) => row.name.startsWith("nightly-report-"));
  check("靶机上有这个 Pod", pending?.phase, (value) => typeof value === "string" && value !== "Running");
  await refuses("说的是不在运行", "kubernetes-pod-not-running", () => open(binding, snapshot, pending));

  // --- 没有 shell 的镜像
  console.log("\n=== coredns（distroless，没有 shell）");
  const coredns = rows().find((row) => row.namespace === "kube-system" && row.name.startsWith("coredns-"));
  check("靶机上有运行中的 coredns", coredns?.phase, "Running");
  await refuses("说的是没有 shell，不是没在跑", "kubernetes-pod-shell-missing", () => open(binding, snapshot, coredns));

  // --- 列表之后被删掉重建的 Pod
  console.log("\n=== 列表读完之后被重建的 Pod");
  const victim = rows().find((row) => row.name.startsWith("storefront-") && row.phase === "Running");
  check("靶机上有运行中的 storefront Pod", victim?.phase, "Running");
  // The Deployment brings a replacement under a new name and UID; the old
  // row still names the one that is gone.
  labKubectl("delete", "pod", victim.name, "-n", "frontend", "--wait=true", "--timeout=60s");
  await refuses("旧的那一行打不开新的 Pod", "kubernetes-pod-not-running", () => open(binding, snapshot, victim));

  // --- 伪造的句柄
  console.log("\n=== 伪造的行句柄");
  await refuses("认不出来", "kubernetes-resource-unavailable", () =>
    open(binding, snapshot, { rowHandle: "a".repeat(32) }));

  // Fresh list: the replacement is a different row and opens normally.
  snapshot = await list(binding);
  const replacement = rows().find((row) => row.name.startsWith("storefront-") && row.phase === "Running" && row.name !== victim.name);
  if (replacement !== undefined) {
    const reopened = await open(binding, snapshot, replacement);
    check("刷新后新 Pod 能进", typeof reopened.handle, "string");
    await sidecar.call("terminal.close", { handle: reopened.handle }, 60_000);
  } else {
    failures += 1;
    console.log("  ✗ 替代的 storefront Pod 还没起来");
  }
} catch (error) {
  failures += 1;
  console.error(`\n失败：${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1200));
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 项没对上`);
process.exitCode = failures === 0 ? 0 : 1;
