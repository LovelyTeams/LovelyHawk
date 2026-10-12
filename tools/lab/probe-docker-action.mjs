// Drives a container action all the way through against a real daemon:
// plan, confirm, execute, verify — and the paths that must refuse.
//
// The core has had this pipeline for a long time and it has never once run
// against a container that actually exists. Everything below acts on
// `stopped-batch` and `cache-node`, which the lab plants for exactly this and
// which nothing else reads.
//
//   node tools/lab/probe-docker-action.mjs
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

/** Expects the call to fail, and reports the code it failed with. */
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

const target = labTarget("docker");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

/** Reads the host directly, so "it worked" is not the tool marking its own work. */
import { execFileSync } from "node:child_process";
function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc",
      `docker exec svc-docker sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const snapshotOf = async () =>
    sidecar.call("docker.containers.refresh", { bindingHandle: binding }, 90_000);

  let snapshot = await snapshotOf();
  const row = (name) => (snapshot.containers ?? []).find((item) => item.name === name);

  // --- 计划一个动作，先看它说了什么
  console.log("=== 计划：启动已停止的 stopped-worker");
  const stopped = row("stopped-worker");
  check("靶机上它确实是停着的", stopped?.state, (value) => value !== "running");
  const plan = await sidecar.call("docker.container.action.plan", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: stopped.containerHandle,
    containerName: stopped.name,
    action: "start",
  }, 90_000);
  console.log(`  ${JSON.stringify(plan)}`);
  check("说清了要做什么", plan.summary, (value) => (value ?? "").includes("启动容器"));
  check("摘要是中文，不是 docker 的命令动词", plan.summary, (value) => !/^start /u.test(value ?? ""));
  // A 64-character id in a line a person has to read is not a description.
  check("摘要里是短 id，不是 64 位全长", plan.summary, (value) => !/[0-9a-f]{20}/u.test(value ?? ""));
  check("标了这是危险操作", plan.dangerous, true);
  check("读回了当前状态", plan.beforeState, "exited");
  check("还没确认", plan.confirmed, false);
  check("计划有有效期", plan.expiresInSeconds, (value) => value > 0 && value <= 300);
  check("计划里没有容器 id", JSON.stringify(plan).includes(stopped.containerHandle), true);

  // --- 没确认不能执行
  console.log("\n=== 没确认就执行");
  await refuses("被拒绝", "docker-action-not-confirmed", () =>
    sidecar.call("docker.container.action.execute", {
      bindingHandle: binding, planHandle: plan.planHandle,
    }, 90_000));

  // --- 确认再执行
  console.log("\n=== 确认后执行");
  const confirmed = await sidecar.call("docker.container.action.confirm", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 60_000);
  check("确认状态回来了", confirmed.confirmed, true);

  const receipt = await sidecar.call("docker.container.action.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 180_000);
  console.log(`  ${JSON.stringify(receipt)}`);
  check("执行后验证通过", receipt.verified, true);
  check("没有触发回滚", receipt.restored, false);
  check("回执说得清是哪个容器哪个动作", receipt.actionLabel, "启动");
  // The host, not the tool, says whether it worked.
  check("主机上它真的在跑了", onHost("docker inspect -f '{{.State.Status}}' stopped-worker"), "running");

  // --- 达不到目标状态时，验证要发现并回滚
  console.log("\n=== 启动一个起来就退的容器（验证应该判失败并回滚）");
  snapshot = await snapshotOf();
  const flaky = (snapshot.containers ?? []).find((item) => item.name === "stopped-batch");
  const flakyPlan = await sidecar.call("docker.container.action.plan", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: flaky.containerHandle,
    containerName: flaky.name,
    action: "start",
  }, 90_000);
  await sidecar.call("docker.container.action.confirm", {
    bindingHandle: binding, planHandle: flakyPlan.planHandle,
  }, 60_000);
  const flakyReceipt = await sidecar.call("docker.container.action.execute", {
    bindingHandle: binding, planHandle: flakyPlan.planHandle,
  }, 180_000);
  console.log(`  ${JSON.stringify(flakyReceipt)}`);
  check("命令返回 0，但验证没有跟着说通过", flakyReceipt.verified, false);
  check("回滚跑了", flakyReceipt.restored, true);
  check("回执说了实际读回的状态", flakyReceipt.detail, (value) => (value ?? "").includes("exited"));

  // --- 同一个计划不能跑第二次
  console.log("\n=== 同一个计划再跑一次");
  await refuses("被拒绝", "docker-action-plan-invalid", () =>
    sidecar.call("docker.container.action.execute", {
      bindingHandle: binding, planHandle: plan.planHandle,
    }, 90_000));

  // --- 状态对不上的动作，计划阶段就该拒
  console.log("\n=== 对运行中的容器计划「启动」");
  snapshot = await snapshotOf();
  const running = (snapshot.containers ?? []).find((item) => item.name === "cache-node");
  await refuses("计划阶段就拒了", "docker-action-failed", () =>
    sidecar.call("docker.container.action.plan", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      containerHandle: running.containerHandle,
      containerName: running.name,
      action: "start",
    }, 90_000));

  // --- 伪造的句柄
  console.log("\n=== 伪造句柄");
  await refuses("伪造的容器句柄名不到任何东西", "docker-container-unavailable", () =>
    sidecar.call("docker.container.action.plan", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      containerHandle: "forged-container-handle-must-not-resolve",
      containerName: "whatever",
      action: "stop",
    }, 90_000));
  await refuses("伪造的计划句柄", "docker-action-plan-invalid", () =>
    sidecar.call("docker.container.action.confirm", {
      bindingHandle: binding, planHandle: "forged-plan-handle",
    }, 60_000));

  // --- 停一个运行中的容器，再放回去
  console.log("\n=== 停 cache-node（然后放回去）");
  const stopPlan = await sidecar.call("docker.container.action.plan", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: running.containerHandle,
    containerName: running.name,
    action: "stop",
  }, 90_000);
  check("停止有回滚说明", stopPlan.restoreDescription, (value) => (value ?? "").includes("重新启动"));
  await sidecar.call("docker.container.action.confirm", {
    bindingHandle: binding, planHandle: stopPlan.planHandle,
  }, 60_000);
  const stopReceipt = await sidecar.call("docker.container.action.execute", {
    bindingHandle: binding, planHandle: stopPlan.planHandle,
  }, 180_000);
  check("停止验证通过", stopReceipt.verified, true);
  check("主机上它真的停了", onHost("docker inspect -f '{{.State.Status}}' cache-node"), "exited");

  // --- 取消
  console.log("\n=== 取消一个计划");
  snapshot = await snapshotOf();
  const again = (snapshot.containers ?? []).find((item) => item.name === "cache-node");
  const doomed = await sidecar.call("docker.container.action.plan", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: again.containerHandle,
    containerName: again.name,
    action: "start",
  }, 90_000);
  const cancelled = await sidecar.call("docker.container.action.cancel", {
    bindingHandle: binding, planHandle: doomed.planHandle,
  }, 60_000);
  check("取消成功", cancelled.cancelled, true);
  await refuses("取消掉的计划确认不了", "docker-action-plan-invalid", () =>
    sidecar.call("docker.container.action.confirm", {
      bindingHandle: binding, planHandle: doomed.planHandle,
    }, 60_000));

  // 把靶机放回原样，下次跑还是同一个起点。
  console.log("\n=== 复原靶机");
  onHost("docker start cache-node >/dev/null 2>&1; docker stop stopped-worker stopped-batch >/dev/null 2>&1; true");
  check("cache-node 回到运行", onHost("docker inspect -f '{{.State.Status}}' cache-node"), "running");
  check("stopped-worker 回到停止", onHost("docker inspect -f '{{.State.Status}}' stopped-worker"), "exited");
  check("stopped-batch 回到停止", onHost("docker inspect -f '{{.State.Status}}' stopped-batch"), "exited");
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exitCode = failures === 0 ? 0 : 1;
