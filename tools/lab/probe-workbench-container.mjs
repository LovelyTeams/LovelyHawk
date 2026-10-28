// Runs a catalogue check inside a real container, and checks it told the truth.
//
// The trap this exists for: the catalogue is written for a host. On a busybox
// userland its real `ps` invocation prints nothing and exits zero, and nothing
// is what "no suspicious processes" looks like. So the interesting assertion is
// not that a check ran — it is that a check which *cannot* run says so.
//
//   node tools/lab/probe-workbench-container.mjs
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

const target = labTarget("docker");
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  console.log("=== 命令目录");
  const catalog = await sidecar.call(
    "emergency-command.catalog.load", { bindingHandle: binding }, 120_000,
  );
  check("拿到命令目录", catalog.commands?.length, (value) => value >= 140);
  const names = (catalog.containers ?? []).map((item) => item.name);
  console.log(`  容器 ${names.length} 个：${names.slice(0, 6).join(" ")}${names.length > 6 ? " …" : ""}`);
  check("目录带回了可选的容器", names.length, (value) => value >= 8);
  check("只列在跑的容器", names.includes("stopped-batch"), false);
  // The handles are UUIDs, which contain hex runs of their own — so look for
  // the runtime id form specifically rather than for any hex.
  check("容器条目里没有容器 id", /[0-9a-f]{32,}/u.test(JSON.stringify(catalog.containers)), false);

  const alpine = catalog.containers.find((item) => item.name === "ci-runner");
  const debian = catalog.containers.find((item) => item.name === "app-shell");
  check("找到 alpine 容器", alpine?.name, "ci-runner");
  check("找到 debian 容器", debian?.name, "app-shell");

  const run = async (title, containerHandle) => {
    const command = catalog.commands.find((item) => item.title === title);
    if (command === undefined) throw new Error(`目录里没有「${title}」`);
    return sidecar.call("emergency-command.run", {
      bindingHandle: binding,
      snapshotHandle: catalog.snapshotHandle,
      commandHandle: command.commandHandle,
      ...(containerHandle === undefined ? {} : { containerHandle }),
    }, 180_000);
  };

  // --- 宿主机上还是原来那样
  console.log("\n=== 不选容器时，跑在主机上");
  const onHost = await run("SUID 可执行");
  check("主机上跑出了东西", onHost.output.length, (value) => value > 0);
  check("没有报「容器里没有」", onHost.output.includes("容器里没有"), false);

  // --- 容器里：一个能跑的
  console.log("\n=== 容器里：SUID 扫描（容器里有意义，扫的是容器自己的文件系统）");
  const suid = await run("SUID 可执行", alpine.containerHandle);
  console.log(`  ${suid.output.split("\n").slice(0, 2).join(" / ")}`);
  check("跑出来了", suid.resultKind, (value) => value !== "missing-command");
  check("结果和主机那次不一样", suid.output === onHost.output, false);

  // --- 容器里：一个不能跑的
  console.log("\n=== 容器里：需要 systemctl 的那条");
  const systemd = catalog.commands.find((item) => item.title.includes("服务") || item.title.includes("systemd"));
  if (systemd !== undefined) {
    const result = await sidecar.call("emergency-command.run", {
      bindingHandle: binding,
      snapshotHandle: catalog.snapshotHandle,
      commandHandle: systemd.commandHandle,
      containerHandle: alpine.containerHandle,
    }, 180_000);
    console.log(`  「${systemd.title}」→ ${result.output.trim().slice(0, 80)}`);
    // This is the whole point: not an empty page, a sentence.
    check("说清了容器里没有这个程序", result.output, (value) => /容器里没有 \S+，本项未执行/u.test(value ?? ""));
    check("不是空输出", result.output.trim().length, (value) => value > 0);
  }

  // --- 发行版是按容器探的，不是按主机
  console.log("\n=== 发行版按容器探测");
  const alpineRelease = await run("系统与内核", alpine.containerHandle).catch(() => null);
  const debianRelease = await run("系统与内核", debian.containerHandle).catch(() => null);
  check("两个容器都读出来了", alpineRelease !== null && debianRelease !== null, true);
  if (alpineRelease !== null && debianRelease !== null) {
    console.log(`  alpine 容器：${alpineRelease.output.trim().split("\n")[0]}`);
    console.log(`  debian 容器：${debianRelease.output.trim().split("\n")[0]}`);
    check("两个容器读出的发行版不一样", alpineRelease.output === debianRelease.output, false);
  }

  // --- 伪造的容器句柄
  console.log("\n=== 伪造的容器句柄");
  try {
    await run("SUID 可执行", "a".repeat(36));
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
