// Runs a catalogue check inside a real Kubernetes pod.
//
// The same trap as the container path, one layer further out: a pod's image is
// usually thinner than the node's, so a check whose program is absent must say
// so rather than return the empty page that reads as "clean". And the family
// has to be detected inside the pod — the node's answer says nothing about the
// image the pod is running.
//
//   node tools/lab/probe-workbench-pod.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 130
    ? `${actual.slice(0, 130)}…`
    : String(actual);
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 实际 ${shown}`}`);
  return ok;
}

// The combined host: one machine running both a Docker daemon and a k3s
// cluster, so one catalogue offers containers and pods together.
const target = labTarget("container-arena");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  console.log("=== 命令目录");
  const catalog = await sidecar.call(
    "emergency-command.catalog.load", { bindingHandle: binding }, 180_000,
  );
  const places = catalog.containers ?? [];
  const containers = places.filter((item) => item.kind === "container");
  const pods = places.filter((item) => item.kind === "pod");
  console.log(`  容器 ${containers.length} 个，Pod ${pods.length} 个`);
  check("容器和 Pod 在同一份清单里", containers.length > 0 && pods.length > 0, true);
  check("每一项都标了自己是什么", places.every((item) => item.kind === "container" || item.kind === "pod"), true);
  // A pod is named so an operator can tell two pods of the same deployment apart.
  check("Pod 名字带命名空间", pods.every((item) => item.name.includes("/")), true);
  check("清单里没有容器 id", /[0-9a-f]{32,}/u.test(JSON.stringify(places)), false);
  // Only running pods: the crash-looping and image-pull-failing ones have no
  // container to enter, so offering them would produce a refusal per command.
  check("没有列 CrashLoopBackOff 的 Pod", pods.some((item) => item.name.includes("flapping-worker")), false);
  check("没有列 ImagePullBackOff 的 Pod", pods.some((item) => item.name.includes("nightly-report")), false);

  const pod = pods.find((item) => item.name.includes("storefront")) ?? pods[0];
  console.log(`  选中 Pod：${pod.name}（${pod.image}）`);

  const run = async (title, placeHandle) => {
    const command = catalog.commands.find((item) => item.title === title);
    if (command === undefined) throw new Error(`目录里没有「${title}」`);
    return sidecar.call("emergency-command.run", {
      bindingHandle: binding,
      snapshotHandle: catalog.snapshotHandle,
      commandHandle: command.commandHandle,
      ...(placeHandle === undefined ? {} : { containerHandle: placeHandle }),
    }, 180_000);
  };

  console.log("\n=== Pod 里：SUID 扫描");
  const onNode = await run("SUID 可执行");
  const inPod = await run("SUID 可执行", pod.containerHandle);
  check("节点上跑出了东西", onNode.output.length, (value) => value > 0);
  check("Pod 里也跑出来了", inPod.resultKind, (value) => value !== "timeout");
  check("Pod 的结果和节点不一样", inPod.output === onNode.output, false);

  console.log("\n=== Pod 里：需要 systemctl 的那条");
  const services = await run("已启用服务", pod.containerHandle);
  console.log(`  → ${services.output.trim().slice(0, 90)}`);
  // The whole point: a sentence, not an empty page.
  check("说清了缺什么程序", services.output, (value) => /容器里没有 \S+，本项未执行/u.test(value ?? ""));
  check("不是空输出", services.output.trim().length, (value) => value > 0);

  console.log("\n=== 发行版按 Pod 探测");
  const podSystem = await run("系统与内核", pod.containerHandle);
  const nodeSystem = await run("系统与内核");
  console.log(`  Pod ：${podSystem.output.trim().split("\n")[0]}`);
  console.log(`  节点：${nodeSystem.output.trim().split("\n")[0]}`);
  check("Pod 读的是自己的发行版，不是节点的", podSystem.output === nodeSystem.output, false);

  console.log("\n=== 伪造的 Pod 句柄");
  try {
    await run("SUID 可执行", "b".repeat(36));
    failures += 1;
    console.log("  ✗ 居然接受了");
  } catch (error) {
    console.log(`  ✓ 被拒绝（${String(error.message).slice(0, 60)}）`);
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
