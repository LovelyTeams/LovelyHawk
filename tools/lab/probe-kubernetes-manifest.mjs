// A listed Pod, Deployment or Node's manifest, exported against the k3s lab.
//
// What only a cluster can show:
//   1. the YAML is the listed object's own — its UID as kubectl reads it
//      independently, every field kept as the cluster returned it (a clear-text
//      environment value included), under a header naming the host, context,
//      object, UID and time;
//   2. a Deployment and a Node export the same way, the Node with no namespace;
//   3. a namespace row, a forged handle, and a pod deleted and recreated under
//      the same name after it was listed are each refused, and the last one
//      with its own reason;
//   4. exporting changes nothing: the Deployment's generation and the Pod's
//      UID are what they were.
//
// The pod and deployment live in a namespace this run creates on the lab
// cluster, labelled with the run's id, deleted at the end after that label is
// checked. alpine:3.20 is already in the cluster's image store.
//
//   node tools/lab/probe-kubernetes-manifest.mjs
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";
import { assertKubernetesLab, labKubectl } from "./kubernetes-rbac-fixture.mjs";

const runId = randomUUID();
const namespace = `lh-manifest-${runId.slice(0, 8)}`;
const evidence = path.resolve("target", "lab-kubernetes-manifest", runId);
const checks = [];
let failures = 0;
/**
 * check(label, ok, detail) with a boolean, or check(label, actual, expected)
 * compared exactly. A non-boolean with nothing to compare against fails.
 */
function check(label, ok, ...rest) {
  const comparing = typeof ok !== "boolean";
  const detail = rest.length > 0 ? rest[0] : null;
  const passed = comparing ? rest.length > 0 && ok === detail : ok;
  const shown = comparing ? { actual: ok, expected: rest.length > 0 ? detail : "(nothing to compare with)" } : detail;
  checks.push({ label, passed, detail: shown });
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${label}${passed || shown === null ? "" : ` — ${JSON.stringify(shown).slice(0, 400)}`}`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function refused(label, code, run) {
  try {
    await run();
    check(label, false, "it was exported");
  } catch (error) {
    check(label, String(error.message).includes(code), String(error.message).slice(0, 200));
  }
}
const secretValue = `planted-${runId.slice(0, 8)}`;
const podSpec = (name) => ({
  apiVersion: "v1", kind: "Pod",
  metadata: { name, namespace, labels: { app: "keeper" } },
  spec: {
    terminationGracePeriodSeconds: 1,
    containers: [{
      name: "app", image: "alpine:3.20", imagePullPolicy: "IfNotPresent",
      command: ["sh", "-c", "while true; do sleep 5; done"],
      env: [{ name: "PROBE_SECRET", value: secretValue }],
      resources: { limits: { cpu: "100m", memory: "32Mi" } },
    }],
  },
});

assertKubernetesLab();
fs.mkdirSync(evidence, { recursive: true });
labKubectl(["apply", "-f", "-"], JSON.stringify({
  apiVersion: "v1", kind: "List", items: [
    { apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, labels: { "lovelyres-test-run": runId } } },
    podSpec("keeper"),
    {
      apiVersion: "apps/v1", kind: "Deployment",
      metadata: { name: "web", namespace },
      spec: {
        replicas: 1,
        selector: { matchLabels: { app: "web" } },
        template: {
          metadata: { labels: { app: "web" } },
          spec: {
            terminationGracePeriodSeconds: 1,
            containers: [{
              name: "web", image: "alpine:3.20", imagePullPolicy: "IfNotPresent",
              command: ["sh", "-c", "while true; do sleep 5; done"],
              resources: { limits: { cpu: "100m", memory: "32Mi" } },
            }],
          },
        },
      },
    },
  ],
}));
for (let attempt = 0; attempt < 90; attempt += 1) {
  if (labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.status.phase}"]).trim() === "Running") break;
  await sleep(2_000);
}

const target = labTarget("kubernetes");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  console.log(`连接 ${target.host}:${target.port}，命名空间 ${namespace}`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const list = (tab) => sidecar.call("kubernetes.resources.list", { bindingHandle: binding, input: { tab, namespaceScope: null } }, 90_000);
  const exportOf = (snapshot, row) => sidecar.call("kubernetes.manifest.export",
    { bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, rowHandle: row.rowHandle }, 90_000);
  const header = (contents) => contents.split("\n").filter((line) => line.startsWith("# "));
  const body = (contents) => contents.split("\n").filter((line) => !line.startsWith("# ")).join("\n");

  // 1. The pod.
  const pods = await list("pods");
  const pod = pods.rows.find((item) => item.namespace === namespace && item.name === "keeper");
  check("the pod is listed", pod?.name, "keeper");
  const podUid = labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.metadata.uid}"]).trim();
  const exported = await exportOf(pods, pod);
  fs.writeFileSync(path.join(evidence, "pod.yaml"), exported.contents);
  check("it is a pod's manifest, by name", exported.kind === "Pod" && exported.name === `${namespace}/keeper`, { kind: exported.kind, name: exported.name });
  check("the suggested file name names the pod and the time",
    /^pod-lh-manifest-[0-9a-f]{8}-keeper-\d{8}T\d{6}Z\.yaml$/u.test(exported.suggestedName), exported.suggestedName);
  check("the header names the object and its UID as kubectl reads it",
    header(exported.contents).includes(`# 对象：Pod ${namespace}/keeper`) &&
    header(exported.contents).some((line) => line.startsWith(`# UID：${podUid}  resourceVersion：`)), header(exported.contents));
  check("the header names the source host and the context",
    header(exported.contents).some((line) => line.startsWith(`# 来源 SSH 主机：${target.username}@`)) &&
    header(exported.contents).some((line) => line.startsWith("# kubeconfig 上下文：") && !line.endsWith("（未读到）")),
    header(exported.contents).slice(0, 3));
  check("the YAML is the pod's own: kind, name, namespace and UID",
    /^kind: Pod$/mu.test(body(exported.contents)) && body(exported.contents).includes(`\n  name: keeper\n`) &&
    body(exported.contents).includes(`\n  namespace: ${namespace}\n`) && body(exported.contents).includes(`\n  uid: ${podUid}\n`));
  check("every field is kept as the cluster returned it, a clear-text value included",
    body(exported.contents).includes(`value: ${secretValue}`));
  check("the header warns that clear-text secrets may be inside",
    header(exported.contents).some((line) => line.includes("明文口令")));

  // 2. A deployment and a node.
  const deployments = await list("deployments");
  const web = deployments.rows.find((item) => item.namespace === namespace && item.name === "web");
  const generation = labKubectl(["get", "deployment", "web", "-n", namespace, "-o", "jsonpath={.metadata.generation}"]).trim();
  const deployment = await exportOf(deployments, web);
  check("a deployment exports the same way",
    deployment.kind === "Deployment" && /^kind: Deployment$/mu.test(body(deployment.contents)) &&
    body(deployment.contents).includes(`\n  name: web\n`), deployment.name);
  const nodes = await list("nodes");
  const node = await exportOf(nodes, nodes.rows[0]);
  fs.writeFileSync(path.join(evidence, "node.yaml"), node.contents);
  check("a node exports with no namespace",
    node.kind === "Node" && !node.name.includes("/") && header(node.contents).includes(`# 对象：Node ${nodes.rows[0].name}`) &&
    node.suggestedName.startsWith(`node-${nodes.rows[0].name}-`), { name: node.name, suggestedName: node.suggestedName });

  // 3. Refusals.
  const namespaces = await list("namespaces");
  const own = namespaces.rows.find((item) => item.name === namespace);
  await refused("a namespace row is not exported", "kubernetes-resource-unavailable", () => exportOf(namespaces, own));
  await refused("a forged row handle is refused", "kubernetes-resource-unavailable",
    () => exportOf(pods, { rowHandle: "forged-row" }));
  labKubectl(["delete", "pod", "keeper", "-n", namespace, "--wait=true", "--timeout=60s"]);
  labKubectl(["apply", "-f", "-"], JSON.stringify(podSpec("keeper")));
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.metadata.uid}"]).trim() !== podUid) break;
    await sleep(1_000);
  }
  await refused("a pod recreated under the same name since the list is not exported as the listed one",
    "kubernetes-manifest-unavailable", () => exportOf(pods, pod));

  // 4. Nothing changed by exporting.
  check("the deployment's generation is what it was",
    labKubectl(["get", "deployment", "web", "-n", namespace, "-o", "jsonpath={.metadata.generation}"]).trim(), generation);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1200));
} finally {
  sidecar.close();
  try {
    const label = labKubectl(["get", "namespace", namespace, "-o", "jsonpath={.metadata.labels.lovelyres-test-run}"]).trim();
    if (label === runId) {
      labKubectl(["delete", "namespace", namespace, "--wait=true", "--timeout=120s"]);
      check("the run's own namespace was removed", true);
    } else {
      check("the run's own namespace was removed", false, "its label is not this run's; left in place");
    }
  } catch (error) {
    check("the run's own namespace was removed", false, error instanceof Error ? error.message : String(error));
  }
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-kubernetes-manifest-probe/v1", runId,
  status: failures === 0 ? "PASS" : "FAIL", generatedAt: new Date().toISOString(), checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.length - failures}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
