// Real desktop (Tauri / WebView2) CDP interactions against the isolated Docker / k3s lab.
//   $env:LAB='docker'; node tools/lab/probe-ui-orchestration.mjs
//   $env:LAB='kubernetes'; node tools/lab/probe-ui-orchestration.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { freePort, startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const backend = path.join(repository, "target/debug/lovelyhawk-backend.exe");
const which = process.env.LAB ?? "docker";
if (!["docker", "kubernetes"].includes(which)) throw new Error("Choose the Docker or Kubernetes lab");
const healthFixture = process.env.LOVELYHAWK_HEALTH_FIXTURE;
if (healthFixture !== undefined && (which !== "kubernetes" || !/^lr-health-[a-f0-9]{8}$/.test(healthFixture))) {
  throw new Error("Health UI cases require this probe's isolated namespace");
}
const deploymentNamespace = healthFixture ?? "payments";
const deploymentName = healthFixture === undefined ? "ledger" : "unready";
const initialReplicas = healthFixture === undefined ? 3 : 0;
const container = `svc-${which}`;
const runId = randomUUID();
const checks = [], consoleErrors = [];
let failures = 0;
function check(name, actual, expected = true) {
  const passed = actual === expected;
  checks.push({ name, passed });
  if (!passed) failures++;
  console.log(`  ${passed ? "PASS" : "FAIL"} ${name}`);
}
function wsl(...args) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", ...args],
    { encoding: "utf8", windowsHide: true, timeout: 60_000 }).trim();
}
const port = await freePort();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for a condition the page can answer, so no step races the render. */
async function waitFor(session, expression, label, attempts = 60) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const evidence = path.join(repository, "target", "lab-ui", `orchestration-${which}-${runId}`);
fs.mkdirSync(evidence, { recursive: true });

/** Saves what the operator would be looking at, as evidence for the change. */
async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-orchestration-ui-"));
let app, session, original, outerId;
let failure;
const onHost = (...args) => wsl("exec", outerId, ...args);
const readObject = () => JSON.parse(which === "docker"
  ? onHost("docker", "inspect", "stopped-worker")
  : onHost("kubectl", "-n", deploymentNamespace, "get", "deployment", deploymentName, "-o", "json"));
const readState = () => which === "docker" ? readObject()[0].State.Status : readObject().spec.replicas;
function restore() {
  if (original === undefined) return;
  const current = readObject();
  if (which === "docker") {
    if (current[0].Id !== original[0].Id) throw new Error("Fixture identity changed; restoration refused");
    if (current[0].State.Running) onHost("docker", "stop", original[0].Id);
  } else {
    if (current.metadata.uid !== original.metadata.uid) throw new Error("Fixture UID changed; restoration refused");
    if (current.spec.replicas !== original.spec.replicas) {
      onHost("kubectl", "-n", deploymentNamespace, "scale", "deployment", deploymentName, `--replicas=${original.spec.replicas}`);
    }
  }
  check("fixture restored after the probe", readState(), which === "docker" ? "exited" : initialReplicas);
}

try {
  const outer = JSON.parse(wsl("inspect", container))[0];
  outerId = outer.Id;
  if (outer.Config.Image !== `lovelyres-svc:${which}` || outer.Mounts.length !== 1 ||
    outer.Mounts[0].Type !== "volume" || outer.Mounts[0].Name !== (which === "docker" ? "lab-docker-lib" : "lab-k3s-config") ||
    outer.HostConfig.Privileged !== (which === "docker") || outer.Mounts[0].RW !== (which === "docker")) {
    throw new Error("Target does not match the isolated orchestration lab");
  }
  if (which === "kubernetes") {
    const server = JSON.parse(wsl("inspect", "lab-k3s"))[0];
    if (server.Config.Image !== "docker.m.daocloud.io/rancher/k3s:v1.31.4-k3s1" ||
      !server.Mounts.some((mount) => mount.Name === "lab-k3s-config") ||
      server.Mounts.some((mount) => mount.Type === "bind" &&
        (mount.Source !== "/opt/lab-orchestration/k3s/registries.yaml" || mount.RW))) {
      throw new Error("Cluster server does not match the k3s lab");
    }
    const nodes = JSON.parse(onHost("kubectl", "get", "nodes", "-o", "json"));
    if (nodes.items.length !== 1 || nodes.items[0].metadata.name !== server.Id.slice(0, 12)) {
      throw new Error("Client points at a different cluster");
    }
    if (healthFixture !== undefined) {
      const space = JSON.parse(onHost("kubectl", "get", "namespace", healthFixture, "-o", "json"));
      const owner = space.metadata.labels?.["lovelyres-test-run"];
      if (typeof owner !== "string" || `lr-health-${owner.slice(0, 8)}` !== healthFixture) {
        throw new Error("Health namespace ownership was not verified");
      }
    }
  }
  const candidate = readObject();
  if ((which === "docker" ? candidate[0].State.Status : candidate.spec.replicas) !== (which === "docker" ? "exited" : initialReplicas)) {
    throw new Error("Fixture is not in its expected starting state; no reset attempted");
  }
  original = candidate;
  const sidecar = new Sidecar(backend, dataRoot);
  try { await connect(sidecar, labTarget(which)); } finally { sidecar.close(); }
  app = await startDesktop({
    dataRoot, port,
    onConsoleError: (entry) => {
      if (consoleErrors.length < 20) consoleErrors.push(JSON.stringify(entry.params).slice(0, 2_000));
    },
  });
  session = app.session;
  await waitFor(session, "document.querySelector('.connection-card button') !== null", "saved lab connection");
  await session.evaluate("document.querySelector('.connection-card button').click()");
  await waitFor(session, "document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null", "connected lab", 120);
  const pageName = which === "docker" ? "Docker" : "Kubernetes";
  await session.evaluate(`(() => {
    const nav = [...document.querySelectorAll('.nav-item')].find(b => b.textContent.includes(${JSON.stringify(pageName)}));
    if (!nav) throw new Error('Missing navigation'); nav.click();
  })()`);
  await waitFor(session, `document.querySelector('.${which}-page table tbody tr') !== null`, "resource list", 120);
  check("real resources have visible action entry points", true);

  const dialogSelector = `[data-testid=${which}-action-dialog]`;
  const executeSelector = `[data-testid=${which}-action-execute]`;
  if (which === "docker") {
    await session.evaluate(`(() => {
      const input = document.querySelector('.docker-page input[type=search]');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'stopped-worker');
      input.dispatchEvent(new Event('input', {bubbles:true}));
    })()`);
    await waitFor(session, "document.querySelector('.docker-table tbody tr [data-testid=docker-action-start]') !== null", "stopped-worker action");
  } else {
    if (healthFixture !== undefined) {
      await waitFor(session, `[...document.querySelectorAll('.kubernetes-namespace-list button')].some(b => b.textContent === ${JSON.stringify(healthFixture)})`, "isolated health namespace");
      await session.evaluate(`[...document.querySelectorAll('.kubernetes-namespace-list button')].find(b => b.textContent === ${JSON.stringify(healthFixture)}).click()`);
    }
    await session.evaluate(`(() => {
      [...document.querySelectorAll('.kubernetes-tabs button')].find(b => b.textContent.includes('Deployment')).click();
    })()`);
    await waitFor(session, `[...document.querySelectorAll('.kubernetes-row-button')].some(b => b.textContent === ${JSON.stringify(deploymentName)})`, "test deployment");
    await session.evaluate(`[...document.querySelectorAll('.kubernetes-row-button')].find(b => b.textContent === ${JSON.stringify(deploymentName)}).click()`);
    await waitFor(session, "document.querySelector('[data-testid=kubernetes-action-scale-deployment]') !== null", "deployment action");
  }

  async function openPlan() {
    if (which === "docker") {
      await session.evaluate("document.querySelector('.docker-table tbody tr [data-testid=docker-action-start]').click()");
    } else {
      await session.evaluate("document.querySelector('[data-testid=kubernetes-action-scale-deployment]').click()");
      await waitFor(session, "document.querySelector('[data-testid=kubernetes-scale-submit]') !== null", "replica form");
      await session.evaluate("document.querySelector('[data-testid=kubernetes-scale-submit]').click()");
    }
    await waitFor(session, `document.querySelector('${executeSelector}:not([disabled])') !== null`, "reviewable action plan");
  }
  await openPlan();
  const planText = await session.evaluate(`document.querySelector('${dialogSelector}').textContent`);
  check("plan names the selected object", planText.includes(which === "docker" ? "stopped-worker" : deploymentName));
  check("plan explains restoration and requires confirmation", planText.includes("出错后如何还原") && planText.includes("确认并执行"));
  check("opening a plan leaves the real target unchanged", readState(), which === "docker" ? "exited" : initialReplicas);
  await shot(session, "plan-before-confirm");
  await session.evaluate(`document.querySelector('${dialogSelector} footer button').click()`);
  await waitFor(session, `document.querySelector('${dialogSelector}') === null`, "cancelled plan");
  check("cancelling a plan leaves the real target unchanged", readState(), which === "docker" ? "exited" : initialReplicas);

  await openPlan();
  await session.evaluate(`document.querySelector('${executeSelector}').click()`);
  const outcomeText = healthFixture === undefined ? "已完成，并" : "没有达到预期状态";
  await waitFor(session, `document.querySelector('${dialogSelector}')?.textContent.includes('${outcomeText}') === true`, "verified receipt", 180);
  check("confirmed UI outcome agrees with the actual object", readState(), which === "docker" ? "running" : (healthFixture === undefined ? 1 : 0));
  if (healthFixture !== undefined) {
    const text = await session.evaluate(`document.querySelector('${dialogSelector}').textContent`);
    check("UI explains readiness timeout instead of reporting success", text.includes("就绪检查超时"));
    check("UI identifies restored settings without claiming business recovery", text.includes("已恢复操作前的副本数或调度标记") && text.includes("继续检查工作负载状态"));
  }
  await shot(session, "verified-receipt");
  await session.evaluate(`document.querySelector('${dialogSelector} footer button').click()`);
  await waitFor(session, `document.querySelector('${dialogSelector}') === null`, "closed receipt");
  if (healthFixture !== undefined) {
    await waitFor(session, "document.querySelector('.kubernetes-table')?.textContent.includes('已设为 0 副本') === true", "zero replica status");
    check("zero replicas have an explicit status", true);
    await shot(session, "restored-zero-replicas");
  }
  if (which === "docker") {
    check("search survives the action and refresh", await session.evaluate("document.querySelector('.docker-page input[type=search]').value"), "stopped-worker");
    await waitFor(session, "document.querySelector('.docker-table tbody tr [data-testid=docker-action-stop]') !== null", "updated running state");
    await session.evaluate("document.querySelector('.docker-table tbody tr [data-testid=docker-action-stop]').click()");
  } else {
    // A new read-backed plan is enough to exercise cancellation on disconnect.
    await session.evaluate("[...document.querySelectorAll('.kubernetes-detail header button')].find(b => b.textContent.includes('关闭'))?.click()");
    await waitFor(session, `[...document.querySelectorAll('.kubernetes-row-button')].some(b => b.textContent === ${JSON.stringify(deploymentName)})`, "refreshed deployment");
    await session.evaluate(`[...document.querySelectorAll('.kubernetes-row-button')].find(b => b.textContent === ${JSON.stringify(deploymentName)}).click()`);
    await session.evaluate("document.querySelector('[data-testid=kubernetes-action-scale-deployment]').click()");
    await waitFor(session, "document.querySelector('[data-testid=kubernetes-scale-replicas]') !== null", "replica input");
    await session.evaluate(`(() => {
      const input = document.querySelector('[data-testid=kubernetes-scale-replicas]');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, '${healthFixture === undefined ? 3 : 1}');
      input.dispatchEvent(new Event('input', {bubbles:true}));
    })()`);
    await session.evaluate("document.querySelector('[data-testid=kubernetes-scale-submit]').click()");
  }
  await waitFor(session, `document.querySelector('${executeSelector}:not([disabled])') !== null`, "new pending plan");
  await session.evaluate("document.querySelector('[data-testid=disconnect-target]').click()");
  const prompt = which === "docker" ? ".docker-connect-prompt" : ".kubernetes-connect-state";
  await waitFor(session, `document.querySelector('${prompt}') !== null`, "disconnected page");
  check("disconnect clears the action dialog", await session.evaluate(`document.querySelector('${dialogSelector}') === null`));
  check("unconfirmed second action never ran", readState(), which === "docker" ? "running" : (healthFixture === undefined ? 1 : 0));
  await shot(session, "disconnected-page");
  check("desktop page produced no errors", consoleErrors.length, 0);
} catch (error) {
  failure = error.message; failures++;
  console.log(`FAILED: ${failure}`);
  if (session) { try { await shot(session, "failure"); } catch {} }
} finally {
  try { restore(); } catch (error) { failures++; failure = `${failure ?? ""} restoration: ${error.message}`; }
  await app?.close();
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    schema: "lovelyres-orchestration-ui/v1", generatedAt: new Date().toISOString(),
    target: { lab: which, container, outerId, healthFixture }, status: failures === 0 ? "PASS" : "FAIL",
    checks, consoleErrors, failure,
  }, null, 2));
  if (path.dirname(dataRoot) === os.tmpdir() && !fs.lstatSync(dataRoot).isSymbolicLink()) {
    fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
  console.log(`evidence: ${evidence}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

