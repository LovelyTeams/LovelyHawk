// Opens a real shell inside a real container and types into it.
//
// The three things worth proving, none of which a unit test can:
//   1. the shell probe picks bash where there is one and falls back where
//      there is not — `app-shell` is Debian and is in the lab for only this
//      reason; everything else there is busybox, which has no bash;
//   2. bytes typed in come back out, so the PTY is genuinely wired end to end
//      rather than merely opening without error;
//   3. a container that is not running is refused, and refused before any
//      terminal slot is taken.
//
//   node tools/lab/probe-docker-terminal.mjs
//   LAB=container-arena node tools/lab/probe-docker-terminal.mjs
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

const which = process.env.LAB ?? "docker";
const target = labTarget(which);
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

/** Drains the terminal until `needle` shows up, or gives up. */
async function readUntil(handle, needle, attempts = 40) {
  let text = "";
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const poll = await sidecar.call("terminal.poll", {
      handle, maximumEvents: 64, maximumBytes: 262_144,
    }, 30_000);
    for (const event of poll.events ?? []) {
      if (event.kind === "output") {
        text += Buffer.from(event.bytes_base64, "base64").toString("utf8");
      }
    }
    if (text.includes(needle)) return text;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return text;
}

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const snapshot = await sidecar.call(
    "docker.containers.refresh", { bindingHandle: binding }, 90_000,
  );
  const row = (name) => (snapshot.containers ?? []).find((item) => item.name === name);
  const opened = [];

  // --- 一个有 bash 的镜像
  console.log("=== 进入 app-shell（Debian 镜像，有 bash）");
  const debian = row("app-shell");
  check("靶机上有这个容器且在跑", debian?.state, "running");
  const bashTerminal = await sidecar.call("docker.container.terminal.open", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: debian.containerHandle,
    columns: 100,
    rows: 30,
  }, 90_000);
  opened.push(bashTerminal.handle);
  console.log(`  ${JSON.stringify(bashTerminal)}`);
  check("挑中了 bash", bashTerminal.shell, "bash");
  check("回的是终端句柄，不是容器 id", bashTerminal.handle, (value) => !/[0-9a-f]{20}/u.test(value));
  check("尺寸按要求给的", `${bashTerminal.columns}x${bashTerminal.rows}`, "100x30");

  // Typing into it and reading the answer back is the only way to know the
  // PTY is really attached; open succeeding proves only that open succeeded.
  console.log("\n=== 在里面敲一条命令");
  await sidecar.call("terminal.input", {
    handle: bashTerminal.handle,
    bytesBase64: Buffer.from("echo lovelyres-was-here-$$\n", "utf8").toString("base64"),
  }, 30_000);
  const echoed = await readUntil(bashTerminal.handle, "lovelyres-was-here-");
  check("命令的输出回来了", echoed, (value) => /lovelyres-was-here-\d+/u.test(value));
  // Whose filesystem it is, is the whole question: a shell that opened on the
  // target instead of in the container would look identical until you look.
  await sidecar.call("terminal.input", {
    handle: bashTerminal.handle,
    bytesBase64: Buffer.from("cat /etc/hostname; echo done-hostname\n", "utf8").toString("base64"),
  }, 30_000);
  const inside = await readUntil(bashTerminal.handle, "done-hostname");
  check("确实在容器里，不是在宿主机上", inside, (value) =>
    value.includes(debian.containerHandle) === false
    && !value.includes("svc-docker")
    && !value.includes("svc-arena"));

  // --- 一个只有 sh 的镜像
  console.log("\n=== 进入 ci-runner（Alpine 镜像，没有 bash）");
  const alpine = row("ci-runner");
  check("靶机上有这个容器且在跑", alpine?.state, "running");
  const shTerminal = await sidecar.call("docker.container.terminal.open", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    containerHandle: alpine.containerHandle,
    columns: 80,
    rows: 24,
  }, 90_000);
  opened.push(shTerminal.handle);
  console.log(`  ${JSON.stringify(shTerminal)}`);
  // BusyBox links sh to ash, and naming ash is what gets line editing.
  check("退到了 ash 或 sh，没有硬要 bash", shTerminal.shell, (value) => value === "ash" || value === "sh");

  // --- 停着的容器进不去
  console.log("\n=== 停着的容器");
  const stopped = (snapshot.containers ?? []).find((item) => item.state !== "running");
  check("靶机上确实有停着的容器", stopped?.name, (value) => typeof value === "string");
  // Not "这个容器里没有可用的 shell": both fail the same probe, and telling an
  // operator to go look at the image when the container is merely stopped is
  // the worse of the two wrong answers.
  await refuses("说的是没在跑，不是没有 shell", "docker-container-not-running", () =>
    sidecar.call("docker.container.terminal.open", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      containerHandle: stopped.containerHandle,
      columns: 80,
      rows: 24,
    }, 90_000));

  // --- 伪造的句柄
  console.log("\n=== 伪造的容器句柄");
  await refuses("认不出来", "docker", () =>
    sidecar.call("docker.container.terminal.open", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      containerHandle: "a".repeat(32),
      columns: 80,
      rows: 24,
    }, 60_000));

  console.log("\n=== 收尾");
  for (const handle of opened) {
    await sidecar.call("terminal.close", { handle }, 30_000);
  }
  check("开过的终端都关掉了", opened.length, 2);
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
