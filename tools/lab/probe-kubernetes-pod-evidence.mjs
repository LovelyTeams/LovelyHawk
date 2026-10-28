// A file inside a pod kept as case evidence, against the k3s lab.
//
// What only a cluster can show:
//   1. the bytes saved locally are the pod's own: a 3 MiB random file is
//      digested inside the pod by kubectl (independently of the app) and the
//      local pod-file.bin, the manifest and the case record all agree;
//   2. the manifest says which pod (UID), container and path, and the file
//      the copy waited in on the SSH host is gone afterwards;
//   3. the container chosen is the one copied from;
//   4. a symlink, a missing file, a file being written to and one over the
//      512 MiB limit (sparse) are each refused with their own reason, and none
//      leaves a file on the host;
//   5. cancelling a copy in flight ends the kubectl doing it and removes its
//      file, and the folder gets no manifest.json.
//
// The pod lives in a namespace this run creates on the lab cluster, labelled
// with the run's id, deleted at the end after that label is checked.
// alpine:3.20 is already in the cluster's image store.
//
//   node tools/lab/probe-kubernetes-pod-evidence.mjs
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";
import { assertKubernetesLab, labKubectl, onClient } from "./kubernetes-rbac-fixture.mjs";

const runId = randomUUID();
const namespace = `lh-evidence-${runId.slice(0, 8)}`;
const folder = path.resolve("target", "lab-pod-evidence", runId);
let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 200 ? `${actual.slice(0, 200)}…` : JSON.stringify(actual);
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 实际 ${shown}`}`);
  return ok;
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** Files the copy left on the SSH host, as root sees them. */
const leftovers = () => onClient("ls /tmp/lovelyhawk-podfile-* 2>/dev/null | wc -l").trim();
/**
 * Starts watching the host for a copy's kubectl, before the copy is asked
 * for, so the watch is already running when it starts; resolves with how many
 * it saw (0 when none appeared within about a minute).
 */
const watchForMarkedCopy = () => new Promise((resolve) => {
  const loop = "for i in $(seq 1 3000); do n=$(grep -l 'LOVELYHAWK_PODFILE_STAGE=' /proc/[0-9]*/environ 2>/dev/null | wc -l); " +
    "if [ \"$n\" -gt 0 ]; then echo \"$n\"; exit 0; fi; sleep 0.02; done; echo 0";
  const child = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-kubernetes", "sh", "-c", loop],
    { windowsHide: true });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.on("close", () => resolve(output.trim()));
});
/** kubectl processes still carrying a copy's marker. */
const markedCopies = () => onClient("grep -l 'LOVELYHAWK_PODFILE_STAGE=' /proc/[0-9]*/environ 2>/dev/null | wc -l").trim();

assertKubernetesLab();
fs.mkdirSync(folder, { recursive: true });
const container = (name, script) => ({
  name, image: "alpine:3.20", imagePullPolicy: "IfNotPresent", command: ["sh", "-c", script],
  // A whole CPU: the evidence digests up to 512 MiB inside the container.
  resources: { limits: { cpu: "1", memory: "64Mi" } },
});
labKubectl(["apply", "-f", "-"], JSON.stringify({
  apiVersion: "v1", kind: "List", items: [
    { apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, labels: { "lovelyres-test-run": runId } } },
    {
      apiVersion: "v1", kind: "Pod",
      metadata: { name: "keeper", namespace, annotations: { "kubectl.kubernetes.io/default-container": "app" } },
      spec: {
        terminationGracePeriodSeconds: 1,
        containers: [
          container("app", [
            "mkdir -p /data",
            "head -c 3145728 /dev/urandom > /data/blob.bin",
            "echo planted > /data/note.txt",
            "ln -s note.txt /data/link",
            "truncate -s 600M /data/huge.bin",
            "head -c 471859200 /dev/urandom > /data/large.bin",
            "echo app > /tmp/which",
            "touch /data/ready",
            "while true; do echo tick >> /data/grow.log; sleep 0.05; done",
          ].join("; ")),
          container("sidecar", "echo sidecar > /tmp/which; while true; do sleep 5; done"),
        ],
      },
    },
  ],
}));
for (let attempt = 0; attempt < 90; attempt += 1) {
  const ready = labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.status.containerStatuses[*].ready}"]).trim();
  if (ready === "true true" && labKubectl(["exec", "keeper", "-n", namespace, "-c", "app", "--", "sh", "-c", "test -e /data/ready && echo yes || echo no"]).trim() === "yes") break;
  await sleep(2_000);
}

const target = labTarget("kubernetes");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  console.log(`连接 ${target.host}:${target.port}，命名空间 ${namespace}`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const pods = await sidecar.call("kubernetes.resources.list", { bindingHandle: binding, input: { tab: "pods", namespaceScope: null } }, 90_000);
  const row = pods.rows.find((item) => item.namespace === namespace && item.name === "keeper");
  check("列出了这个 Pod", row?.name, "keeper");
  const uid = labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.metadata.uid}"]).trim();

  const evidence = (params) => sidecar.call("kubernetes.pod.file-evidence", { bindingHandle: binding, ...params }, 120_000);
  const begin = (filePath, chosen, directory) => evidence({
    action: "begin", snapshotHandle: pods.snapshotHandle, rowHandle: row.rowHandle,
    container: chosen, path: filePath, selectedDirectory: directory,
  });
  async function settle(job, timeoutMs = 180_000) {
    const deadline = Date.now() + timeoutMs;
    let current = job;
    while (["copying", "collecting"].includes(current.state) && Date.now() < deadline) {
      await sleep(500);
      current = await evidence({ action: "poll", jobHandle: job.jobHandle });
    }
    return current;
  }
  const subfolder = (name) => {
    const directory = path.join(folder, name);
    fs.mkdirSync(directory, { recursive: true });
    return directory;
  };

  console.log("\n=== 3 MiB 随机文件，默认容器");
  const blobFolder = subfolder("blob");
  const started = await begin("/data/blob.bin", null, blobFolder);
  check("开始时是复制阶段", started.state, "copying");
  const blob = await settle(started);
  check("保存并登记到案件", blob.state, "completed");
  const podDigest = labKubectl(["exec", "keeper", "-n", namespace, "-c", "app", "--", "sha256sum", "/data/blob.bin"]).split(/\s+/u)[0];
  const evidenceDir = path.join(blobFolder, blob.folderName);
  const saved = fs.readFileSync(path.join(evidenceDir, "pod-file.bin"));
  const localDigest = createHash("sha256").update(saved).digest("hex");
  check("本地字节与 Pod 里独立算的 SHA-256 一致", localDigest, podDigest);
  check("页面上的摘要也是它", blob.sha256, podDigest);
  check("字节数 3 MiB", saved.length, 3_145_728);
  const manifest = JSON.parse(fs.readFileSync(path.join(evidenceDir, "manifest.json"), "utf8"));
  check("清单写明了样本文件名", manifest.sample_file, "pod-file.bin");
  check("清单写明了 Pod、UID 与路径", `${manifest.pod?.namespace}/${manifest.pod?.pod}/${manifest.pod?.pod_uid}${manifest.pod?.path}`,
    `${namespace}/keeper/${uid}/data/blob.bin`);
  check("清单里 Pod 内的摘要、两次读取的摘要一致", [manifest.pod?.pod_sha256, manifest.observation?.sha256].every((value) => value === podDigest), true);
  check("清单说主机临时文件已删除", manifest.pod?.host_temporary_removed, true);
  check("页面说主机临时文件已删除", blob.temporaryFile, "removed");
  check("主机上没有留下复制文件", leftovers(), "0");
  const cases = await sidecar.call("case.workspace", { action: "list", bindingHandle: binding }, 30_000);
  const view = await sidecar.call("case.workspace", { action: "view", bindingHandle: binding, caseId: cases.activeCaseId }, 30_000);
  const entries = await sidecar.call("case.workspace", {
    action: "items", bindingHandle: binding, snapshotHandle: view.snapshotHandle, section: "evidence", query: "", offset: 0,
  }, 30_000);
  const recorded = entries.items.find((entry) => entry.title === "Pod 文件留证");
  check("案件里有这条证据，定位到 pod-file.bin，摘要相同", recorded ?? null, (entry) =>
    entry !== null && entry.locator === `${blob.folderName}/pod-file.bin` && entry.sha256 === podDigest &&
    entry.hashScope === "external-artifact" && entry.text.includes(`UID ${uid}`));

  console.log("\n=== 所选容器");
  const sideFolder = subfolder("sidecar");
  const side = await settle(await begin("/tmp/which", "sidecar", sideFolder));
  check("从 sidecar 复制", side.state === "completed" &&
    fs.readFileSync(path.join(sideFolder, side.folderName, "pod-file.bin"), "utf8"), "sidecar\n");
  const sideManifest = JSON.parse(fs.readFileSync(path.join(sideFolder, side.folderName, "manifest.json"), "utf8"));
  check("清单写明容器 sidecar", sideManifest.pod?.container, "sidecar");

  console.log("\n=== 各自的拒绝原因，主机上都不留东西");
  for (const [label, filePath, wanted] of [
    ["符号链接", "/data/link", "不是普通文件"],
    ["不存在的文件", "/data/no-such-file", "不存在"],
    ["正在被写入的文件", "/data/grow.log", "有变化"],
    ["超过 512 MB（稀疏文件）", "/data/huge.bin", "512 MB"],
  ]) {
    const result = await settle(await begin(filePath, null, subfolder(label)));
    check(`${label}：没有保存，说明原因`, `${result.state}|${result.detail}`, (value) => value.startsWith("failed|") && value.includes(wanted));
    check(`${label}：主机上没有留下`, leftovers(), "0");
  }
  try {
    await begin("/data/blob.bin", "nosuch", subfolder("nosuch"));
    failures += 1;
    console.log("  ✗ 不属于这个 Pod 的容器居然开始了");
  } catch (error) {
    check("不属于这个 Pod 的容器，不开始", String(error.message), (value) => value.includes("kubernetes-pod-evidence-stale"));
  }

  console.log("\n=== 复制途中取消");
  // A copy can finish before the cancel lands; then that attempt says so and
  // a fresh job is tried, at most three times, and the count is reported.
  let cancelFolder = null;
  let large = null;
  let seen = "0";
  let cancelled = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    cancelFolder = subfolder(`cancel-${attempt}`);
    const watching = watchForMarkedCopy();
    await sleep(1_500);
    large = await begin("/data/large.bin", null, cancelFolder);
    seen = await watching;
    cancelled = await evidence({ action: "cancel", jobHandle: large.jobHandle });
    if (cancelled.state === "cancelled") {
      console.log(`  （第 ${attempt} 次取消落在复制途中）`);
      break;
    }
    console.log(`  （第 ${attempt} 次：取消前已经${cancelled.state === "completed" ? "完成" : cancelled.state}，换一个新任务再试）`);
  }
  check("复制进行中能看到带标记的 kubectl", seen, (value) => Number(value) >= 1);
  check("取消后状态是已取消", cancelled?.state, "cancelled");
  let after = cancelled;
  for (let attempt = 0; attempt < 30 && after.temporaryFile === "pending"; attempt += 1) {
    await sleep(500);
    after = await evidence({ action: "poll", jobHandle: large.jobHandle });
  }
  check("页面说主机临时文件已删除", after.temporaryFile, "removed");
  check("带标记的 kubectl 已结束", markedCopies(), "0");
  check("主机上没有留下复制文件", leftovers(), "0");
  check("取消的目录里没有 manifest.json", fs.existsSync(path.join(cancelFolder, large.folderName, "manifest.json")), false);
} catch (error) {
  failures += 1;
  console.error(`\n失败：${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1200));
} finally {
  sidecar.close();
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

console.log(`证据目录：${folder}`);
console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 项没对上`);
process.exitCode = failures === 0 ? 0 : 1;
