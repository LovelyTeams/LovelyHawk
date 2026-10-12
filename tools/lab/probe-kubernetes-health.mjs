// Exercises actual readiness and restoration through the finite sidecar API.
// Creates only this run's namespace in the verified, single-node k3s lab.
// HEALTH_UI=1 includes the desktop failure/restore UI; HEALTH_UI_ONLY=1 runs that UI case only.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const namespace = `lr-health-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-kubernetes-health", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-health-"));
fs.mkdirSync(evidence, { recursive: true });
const checks = [], outcomes = [];
let failures = 0, sidecar, binding, namespaceUid, clientId, failure, runningAction;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function docker(args, input) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", ...args],
    { encoding: "utf8", windowsHide: true, timeout: 30_000, ...(input === undefined ? {} : { input }) }).trim();
}
const kubectl = (...args) => docker(["exec", clientId, "kubectl", ...args]);
const deployment = name => JSON.parse(kubectl("-n", namespace, "get", "deployment", name, "-o", "json"));
function check(name, actual, expected = true) {
  const passed = actual === expected; checks.push({ name, passed }); if (!passed) failures++;
  console.log(`  ${passed ? "PASS" : "FAIL"} ${name}${passed ? "" : `: ${actual}`}`);
}
async function waitFor(predicate, label, limit = 60_000) {
  const until = Date.now() + limit;
  do { if (predicate()) return; await sleep(400); } while (Date.now() < until);
  throw new Error(`Timed out: ${label}`);
}
function createDeployment(name, replicas, ready) {
  const object = {
    apiVersion: "apps/v1", kind: "Deployment", metadata: { name, namespace, labels: { "lovelyres-test-run": runId } },
    spec: { replicas, progressDeadlineSeconds: 600, selector: { matchLabels: { app: name } },
      template: { metadata: { labels: { app: name } }, spec: { terminationGracePeriodSeconds: 1,
        containers: [{ name: "sample", image: "alpine:3.20", imagePullPolicy: "IfNotPresent",
          command: ["sh", "-c", "sleep 3600"],
          readinessProbe: { exec: { command: ["sh", "-c", ready ? "exit 0" : "exit 1"] }, periodSeconds: 1, failureThreshold: 1 },
          resources: { requests: { cpu: "10m", memory: "8Mi" }, limits: { cpu: "100m", memory: "32Mi" } },
        }],
      } },
    },
  };
  docker(["exec", "-i", clientId, "kubectl", "create", "-f", "-"], JSON.stringify(object));
}
async function plan(name, replicas) {
  const spaces = await sidecar.call("kubernetes.resources.list", {
    bindingHandle: binding, input: { tab: "namespaces", namespaceScope: null },
  });
  const space = spaces.rows.find(row => row.name === namespace);
  if (!space) throw new Error("The test namespace was not discovered");
  const list = await sidecar.call("kubernetes.resources.list", {
    bindingHandle: binding, input: { tab: "deployments", namespaceScope: { snapshotHandle: spaces.snapshotHandle, rowHandle: space.rowHandle } },
  });
  const row = list.rows.find(row => row.name === name);
  if (!row) throw new Error("The test Deployment was not discovered");
  const proposed = await sidecar.call("kubernetes.workload.action.plan", {
    bindingHandle: binding, snapshotHandle: list.snapshotHandle, rowHandle: row.rowHandle, resourceName: row.name,
    action: { kind: "scale-deployment", replicas },
  }, 60_000);
  check(`${name}: plan describes bounded verification`, proposed.summary.includes("45 秒"));
  await sidecar.call("kubernetes.workload.action.confirm", { bindingHandle: binding, planHandle: proposed.planHandle });
  return proposed;
}
async function execute(proposed, label) {
  const start = Date.now();
  runningAction = sidecar.call("kubernetes.workload.action.execute", {
    bindingHandle: binding, planHandle: proposed.planHandle,
  }, 210_000);
  const result = await runningAction;
  runningAction = undefined;
  outcomes.push({ label, elapsedMs: Date.now() - start, result });
  console.log(`  ${label}: ${result.detail}`);
  return result;
}

try {
  const client = JSON.parse(docker(["inspect", "svc-kubernetes"]))[0]; clientId = client.Id;
  const server = JSON.parse(docker(["inspect", "lab-k3s"]))[0];
  if (client.Config.Image !== "lovelyres-svc:kubernetes" || client.HostConfig.Privileged ||
    client.Mounts.length !== 1 || client.Mounts[0].Name !== "lab-k3s-config" || client.Mounts[0].RW ||
    server.Config.Image !== "docker.m.daocloud.io/rancher/k3s:v1.31.4-k3s1" ||
    !server.Mounts.some(mount => mount.Name === "lab-k3s-config") ||
    server.Mounts.some(mount => mount.Type === "bind" &&
      (mount.Source !== "/opt/lab-orchestration/k3s/registries.yaml" || mount.RW))) {
    throw new Error("Refusing a target outside the isolated k3s lab");
  }
  const nodes = JSON.parse(kubectl("get", "nodes", "-o", "json"));
  if (nodes.items.length !== 1 || nodes.items[0].metadata.name !== server.Id.slice(0, 12)) {
    throw new Error("The kubectl client points to another cluster");
  }
  kubectl("create", "namespace", namespace);
  namespaceUid = JSON.parse(kubectl("get", "namespace", namespace, "-o", "json")).metadata.uid;
  kubectl("label", "namespace", namespace, `lovelyres-test-run=${runId}`);
  createDeployment("healthy", 1, true); createDeployment("unready", 0, false);
  await waitFor(() => deployment("healthy").status.availableReplicas === 1, "initial healthy replica");
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  binding = (await connect(sidecar, labTarget("kubernetes"))).bindingHandle;
  console.log(`Testing ${namespace}`);

  if (process.env.HEALTH_UI_ONLY !== "1") {
  const healthy = await execute(await plan("healthy", 2), "healthy scaling");
  check("healthy scaling verified readiness", healthy.verified);
  check("all actual replicas are available", deployment("healthy").status.availableReplicas, 2);
  check("receipt distinguishes readiness from business health", healthy.detail.includes("业务接口仍需另行验证"));

  const unready = await execute(await plan("unready", 1), "persistent readiness failure");
  check("a patched replica count alone is never success", unready.verified, false);
  check("readiness timeout is explained", unready.detail.includes("就绪检查超时"));
  check("previous replica count was restored", unready.restored);
  check("independent read confirms restoration to zero", deployment("unready").spec.replicas, 0);
  check("readiness waiting is bounded", outcomes.at(-1).elapsedMs < 90_000);

  // Simulate another operator changing the configuration during the wait.
  const competing = await plan("unready", 1);
  const pending = execute(competing, "configuration changed during verification").catch(probeError => ({ probeError }));
  await waitFor(() => deployment("unready").spec.replicas === 1, "applied count before independent change");
  const beforeChange = deployment("unready").metadata.generation;
  kubectl("-n", namespace, "annotate", "deployment", "unready", `lovelyres-test-independent=${runId}`);
  check("independent change advances configuration generation", deployment("unready").metadata.generation > beforeChange);
  const changed = await pending;
  if (changed.probeError) throw changed.probeError;
  check("new configuration is not reported as this action's success", changed.verified, false);
  check("new configuration prevents automatic restoration", changed.restored, false);
  check("newer state was preserved", deployment("unready").spec.replicas, 1);
  check("receipt explains the changed configuration", changed.detail.includes("配置已再次变化"));

  // Stopping a faulty workload is an intentional IR action, not a rollout.
  const stopped = await execute(await plan("unready", 0), "stop faulty workload");
  check("zero replicas can be verified without ready Pods", stopped.verified);
  check("workload stays stopped", deployment("unready").spec.replicas, 0);
  check("stopping is not described as application availability", stopped.detail.includes("不代表应用可用"));
  }
  if (process.env.HEALTH_UI === "1" || process.env.HEALTH_UI_ONLY === "1") {
    sidecar.close(); sidecar = undefined;
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(repository, "tools/lab/probe-ui-orchestration.mjs")], {
        cwd: repository, env: { ...process.env, LAB: "kubernetes", LOVELYHAWK_HEALTH_FIXTURE: namespace },
        stdio: "inherit", windowsHide: true, shell: false,
      });
      child.on("error", reject); child.on("exit", code => resolve(code));
    });
    check("real desktop UI explains a failed readiness check and restoration", result, 0);
  }
} catch (error) {
  failure = error.message; failures++; console.log(`FAILED: ${failure}`);
} finally {
  if (runningAction) await runningAction.catch(() => {});
  sidecar?.close();
  if (namespaceUid !== undefined) {
    try {
      const current = JSON.parse(kubectl("get", "namespace", namespace, "-o", "json"));
      if (current.metadata.uid !== namespaceUid || current.metadata.labels["lovelyres-test-run"] !== runId) {
        throw new Error("Namespace ownership changed; cleanup refused");
      }
      kubectl("delete", "namespace", namespace, "--wait=false");
      await waitFor(() => JSON.parse(kubectl("get", "namespaces", "-o", "json")).items.every(item => item.metadata.uid !== namespaceUid), "namespace cleanup");
      check("only this run's namespace was removed", true);
    } catch (error) { failures++; failure = `${failure ?? ""} cleanup: ${error.message}`; }
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    generatedAt: new Date().toISOString(), status: failures === 0 ? "PASS" : "FAIL", namespace, namespaceUid,
    mode: process.env.HEALTH_UI_ONLY === "1" ? "ui-only" : process.env.HEALTH_UI === "1" ? "rpc-and-ui" : "rpc",
    checks, outcomes, failure,
  }, null, 2));
  if (path.dirname(dataRoot) === os.tmpdir() && !fs.lstatSync(dataRoot).isSymbolicLink()) fs.rmSync(dataRoot, { recursive: true, force: true });
  console.log(`Evidence: ${evidence}`);
  process.exitCode = failures === 0 ? 0 : 1;
}
