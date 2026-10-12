// One pod, three containers: the logs, files and shell of each, by name.
//
// What only a cluster can show:
//   1. each container is reached by its own name: `app` and `sidecar` each
//      write their own marker file and their own log lines, and what comes
//      back names the one asked for and never the other;
//   2. with no name, the pod's default is used — the
//      `kubectl.kubernetes.io/default-container` annotation picks `sidecar`,
//      not the first container;
//   3. a container that keeps crashing (`crasher`) has its previous run's
//      logs readable, but no shell or files: it is not running;
//   4. a name that is not one of the pod's containers runs nothing;
//   5. closing a shell ends what it started in that container.
//
// The pod lives in a namespace this run creates on the lab's k3s cluster,
// labelled with the run's id, and the namespace is deleted at the end after
// that label is checked. alpine:3.20 is already in the cluster's image store.
//
//   node tools/lab/probe-kubernetes-containers.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const runId = randomUUID();
const namespace = `lh-containers-${runId.slice(0, 8)}`;
let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 160 ? `${actual.slice(0, 160)}…` : JSON.stringify(actual);
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
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** kubectl on the lab host, from outside the app: the independent look. */
function labKubectl(args, input) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "-i", "svc-kubernetes", "kubectl", ...args], {
    encoding: "utf8", windowsHide: true, timeout: 120_000, input,
  });
}

const container = (name, script) => ({
  name, image: "alpine:3.20", imagePullPolicy: "IfNotPresent",
  command: ["sh", "-c", script],
  resources: { limits: { cpu: "100m", memory: "32Mi" } },
});
const manifest = {
  apiVersion: "v1", kind: "List",
  items: [
    { apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, labels: { "lovelyres-test-run": runId } } },
    {
      apiVersion: "v1", kind: "Pod",
      metadata: {
        name: "duo", namespace, labels: { "lovelyres-test-run": runId },
        annotations: { "kubectl.kubernetes.io/default-container": "sidecar" },
      },
      spec: {
        terminationGracePeriodSeconds: 1,
        containers: [
          container("app", "echo app > /tmp/which; while true; do echo app-tick; sleep 2; done"),
          container("sidecar", "echo sidecar > /tmp/which; while true; do echo sidecar-tick; sleep 2; done"),
          container("crasher", "echo crasher-says-bye; sleep 1; exit 1"),
        ],
      },
    },
  ],
};

const target = labTarget("kubernetes");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
const list = (binding) => sidecar.call("kubernetes.resources.list", {
  bindingHandle: binding, input: { tab: "pods", namespaceScope: null },
}, 90_000);

async function readUntil(handle, needle, attempts = 40) {
  let text = "";
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const poll = await sidecar.call("terminal.poll", { handle, maximumEvents: 64, maximumBytes: 262_144 }, 30_000);
    for (const event of poll.events ?? []) {
      if (event.kind === "output") text += Buffer.from(event.bytes_base64, "base64").toString("utf8");
    }
    if (needle.test(text)) return text;
    await sleep(250);
  }
  return text;
}
const type = (handle, text) => sidecar.call("terminal.input", {
  handle, bytesBase64: Buffer.from(text, "utf8").toString("base64"),
}, 30_000);

try {
  console.log(`建一个命名空间 ${namespace}，里面一个三容器的 Pod`);
  labKubectl(["apply", "-f", "-"], JSON.stringify(manifest));
  // Wait for app and sidecar to run and the crasher to have crashed at least once.
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const state = JSON.parse(labKubectl(["get", "pod", "duo", "-n", namespace, "-o", "json"]));
    const statuses = Object.fromEntries((state.status.containerStatuses ?? []).map((s) => [s.name, s]));
    if (statuses.app?.state?.running && statuses.sidecar?.state?.running && (statuses.crasher?.restartCount ?? 0) >= 1 &&
      !statuses.crasher?.state?.running) break;
    await sleep(2_000);
  }

  console.log(`\n连接 ${target.host}:${target.port}`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const snapshot = await list(binding);
  const row = (snapshot.rows ?? []).find((item) => item.namespace === namespace && item.name === "duo");
  console.log("\n=== 列表");
  check("列出了这个 Pod", row?.name, "duo");
  check("三个容器按清单顺序", row?.containers?.map((c) => c.name).join(","), "app,sidecar,crasher");
  check("默认容器是注解指定的 sidecar，不是第一个", row?.defaultContainer, "sidecar");
  check("crasher 标为没在运行", row?.containers?.find((c) => c.name === "crasher")?.running, false);
  check("app 在运行", row?.containers?.find((c) => c.name === "app")?.running, true);

  const ask = (method, params) => sidecar.call(method, {
    bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, rowHandle: row.rowHandle, ...params,
  }, 90_000);

  console.log("\n=== 日志");
  const appLogs = await ask("kubernetes.pod.logs.get", { previous: false, container: "app" });
  check("app 的日志是 app 的", appLogs.text, (text) => text.includes("app-tick") && !text.includes("sidecar-tick"));
  const sideLogs = await ask("kubernetes.pod.logs.get", { previous: false, container: "sidecar" });
  check("sidecar 的日志是 sidecar 的", sideLogs.text, (text) => text.includes("sidecar-tick") && !text.includes("app-tick"));
  const defaultLogs = await ask("kubernetes.pod.logs.get", { previous: false, container: null });
  check("不点名时读的是默认容器 sidecar", defaultLogs.text, (text) => text.includes("sidecar-tick") && !text.includes("app-tick"));
  // The crashing container's own log, though it is not running.
  const crasherNow = await ask("kubernetes.pod.logs.get", { previous: false, container: "crasher" });
  check("crasher 自己的日志读得到，只有它的", crasherNow.text,
    (text) => text.includes("crasher-says-bye") && !text.includes("app-tick") && !text.includes("sidecar-tick"));
  // Its previous run's log: while the latest run still shows as terminated,
  // --previous names an older run the kubelet has already let go of, and
  // kubectl itself fails the same way (checked by hand on this cluster). The
  // page says to wait a few seconds and read again; so does this.
  let crashed = null;
  let notReady = 0;
  for (let attempt = 0; attempt < 25 && crashed === null; attempt += 1) {
    try {
      crashed = await ask("kubernetes.pod.logs.get", { previous: true, container: "crasher" });
    } catch (error) {
      if (!String(error.message).includes("kubernetes-logs-not-ready")) throw error;
      notReady += 1;
      await sleep(3_000);
    }
  }
  check(`crasher 上次运行的日志读得到（其间 kubelet 暂时交不出 ${notReady} 次）`, crashed?.text,
    (text) => typeof text === "string" && text.includes("crasher-says-bye"));
  await refuses("不是这个 Pod 的容器，不读", "kubernetes-pod-container-unavailable",
    () => ask("kubernetes.pod.logs.get", { previous: false, container: "nosuch" }));

  console.log("\n=== 文件");
  const appFile = await ask("kubernetes.pod.file.read", { path: "/tmp/which", container: "app" });
  check("在 app 里读到 app 写的文件", appFile.text, "app\n");
  const sideFile = await ask("kubernetes.pod.file.read", { path: "/tmp/which", container: "sidecar" });
  check("在 sidecar 里读到 sidecar 写的文件", sideFile.text, "sidecar\n");
  const listing = await ask("kubernetes.pod.directory.list", { path: "/tmp", container: "app" });
  check("在 app 里列出 /tmp", listing.entries?.some((entry) => entry.name === "which"), true);
  await refuses("没在运行的容器不读文件", "kubernetes-pod-container-not-running",
    () => ask("kubernetes.pod.file.read", { path: "/tmp/which", container: "crasher" }));
  await refuses("不存在的容器不读文件", "kubernetes-pod-container-unavailable",
    () => ask("kubernetes.pod.directory.list", { path: "/", container: "nosuch" }));

  console.log("\n=== 终端");
  const terminal = await ask("kubernetes.pod.terminal.open", { container: "app", columns: 100, rows: 30 });
  check("打开了 app 的 shell", typeof terminal.handle, "string");
  await type(terminal.handle, "cat /tmp/which; sleep 7772 & echo planted-$!\n");
  const inside = await readUntil(terminal.handle, /planted-\d+/u);
  check("shell 在 app 里", inside, (text) => /(^|\n)app\r?\n/u.test(text));
  const before = labKubectl(["exec", "duo", "-n", namespace, "-c", "app", "--", "ps"]);
  check("关窗前 app 里能看到 sleep 7772", before, (text) => text.includes("sleep 7772"));
  check("sidecar 里从来没有它", labKubectl(["exec", "duo", "-n", namespace, "-c", "sidecar", "--", "ps"]),
    (text) => !text.includes("sleep 7772"));
  await sidecar.call("terminal.close", { handle: terminal.handle }, 60_000);
  let after = "";
  for (let attempt = 0; attempt < 10; attempt += 1) {
    after = labKubectl(["exec", "duo", "-n", namespace, "-c", "app", "--", "ps"]);
    if (!after.includes("sleep 7772")) break;
    await sleep(1_000);
  }
  check("关窗后 app 里那个 sleep 跟着结束了", after, (text) => !text.includes("sleep 7772"));
  await refuses("没在运行的容器打不开终端", "kubernetes-pod-container-not-running",
    () => ask("kubernetes.pod.terminal.open", { container: "crasher", columns: 80, rows: 24 }));
  await refuses("不存在的容器打不开终端", "kubernetes-pod-container-unavailable",
    () => ask("kubernetes.pod.terminal.open", { container: "nosuch", columns: 80, rows: 24 }));
  await refuses("容器名的写法不对，什么都不执行", "kubernetes-pod-container-unavailable",
    () => ask("kubernetes.pod.terminal.open", { container: "app; id", columns: 80, rows: 24 }));
} catch (error) {
  failures += 1;
  console.error(`\n失败：${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1200));
} finally {
  sidecar.close();
  // Only the namespace this run made, and only while it still carries the run's label.
  try {
    const label = labKubectl(["get", "namespace", namespace, "-o", "jsonpath={.metadata.labels.lovelyres-test-run}"]).trim();
    if (label === runId) {
      labKubectl(["delete", "namespace", namespace, "--wait=true", "--timeout=120s"]);
      console.log(`\n已删除本次的命名空间 ${namespace}`);
    } else {
      failures += 1;
      console.log(`\n命名空间 ${namespace} 的标记不是本次的，没有删除`);
    }
  } catch (error) {
    failures += 1;
    console.log(`\n清理没有完成：${error.message}`);
  }
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 项没对上`);
process.exitCode = failures === 0 ? 0 : 1;
