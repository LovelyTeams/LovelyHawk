// Lists directories inside real containers and pods, and reads a pod's file.
//
// What only real images can show:
//   1. the one listing script reads the same on BusyBox (Alpine) and GNU
//      (Debian), dotfiles included;
//   2. hostile names come back as data: a newline in a name stays one entry
//      and is marked as not openable, a space is kept, and setuid and
//      world-writable bits come through for the page to flag — planted in a
//      throwaway directory and removed afterwards;
//   3. a pod's file comes back with the length and SHA-256 it was checked
//      against, and a directory, a symlink, a missing file or a shell-less
//      image are each refused with their own reason.
//
//   node tools/lab/probe-container-files.mjs
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 110 ? `${actual.slice(0, 110)}…` : String(actual);
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

function wsl(...args) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", ...args], {
    encoding: "utf8", windowsHide: true, timeout: 60_000,
  });
}

// The throwaway directory, inside the lab's own Alpine container.
const PLANT = "/tmp/lovelyhawk-probe-files";
const plantScript = [
  `rm -rf ${PLANT}`, `mkdir -p ${PLANT}/sub`,
  `printf 'x' > "${PLANT}/a b"`,
  `printf 'x' > "${PLANT}/two`, `lines"`,
  `printf 'x' > ${PLANT}/.hidden`,
  `cp /bin/busybox ${PLANT}/suid && chmod 4755 ${PLANT}/suid`,
  `printf 'x' > ${PLANT}/open && chmod 666 ${PLANT}/open`,
  `ln -s /etc/passwd ${PLANT}/link`,
].join("\n");

async function dockerPart() {
  const target = labTarget("docker");
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  try {
    console.log(`=== Docker：连接 ${target.host}:${target.port}`);
    const status = await connect(sidecar, target);
    const binding = status.bindingHandle;
    const snapshot = await sidecar.call("docker.containers.refresh", { bindingHandle: binding }, 90_000);
    const row = (name) => (snapshot.containers ?? []).find((item) => item.name === name);
    const list = (container, path) => sidecar.call("docker.container.directory.list", {
      bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, containerHandle: container.containerHandle, path,
    }, 100_000);

    for (const [name, label] of [["ci-runner", "Alpine / BusyBox"], ["app-shell", "Debian / GNU"]]) {
      const listing = await list(row(name), "/etc");
      const names = listing.entries.map((entry) => entry.name);
      console.log(`\n--- ${name}（${label}）/etc：${names.length} 项`);
      check("列出来了", names.length, (value) => value > 10);
      check("passwd 是文件", listing.entries.find((entry) => entry.name === "passwd")?.kind, "file");
      check("有目录，且排在前面", listing.entries[0]?.kind, "directory");
      check("大小、时间、权限都读到了", listing.entries.find((entry) => entry.name === "passwd"),
        (entry) => entry?.size > 0 && entry?.modifiedUnix > 1_000_000_000 && entry?.mode === "644");
      check("没有被误报截断", listing.truncated, false);
    }
    const debianEtc = await list(row("app-shell"), "/etc");
    check("GNU 镜像里的点文件也在", debianEtc.entries.some((entry) => entry.name.startsWith(".")), true);
    const root = await list(row("ci-runner"), "/");
    check("根目录能列", root.entries.some((entry) => entry.name === "etc" && entry.kind === "directory"), true);

    console.log("\n--- 不怀好意的名字和权限位（临时目录，结束后删除）");
    wsl("docker", "exec", "svc-docker", "docker", "exec", "ci-runner", "sh", "-c", plantScript);
    try {
      const planted = await list(row("ci-runner"), PLANT);
      const byName = Object.fromEntries(planted.entries.map((entry) => [entry.name, entry]));
      check("带空格的名字原样保留，可以打开", byName["a b"]?.openable, true);
      check("带换行的名字仍是一项，标为不能打开", byName["two\nlines"]?.openable, false);
      check("点文件在", byName[".hidden"]?.kind, "file");
      check("setuid 位读到了", byName.suid?.mode, "4755");
      check("所有人可写读到了", byName.open?.mode, "666");
      check("符号链接认成链接，不跟过去", byName.link?.kind, "symlink");
      check("子目录排第一", planted.entries[0]?.name, "sub");
      check("一共 7 项，没多没少", planted.entries.length, 7);
    } finally {
      wsl("docker", "exec", "svc-docker", "docker", "exec", "ci-runner", "rm", "-rf", PLANT);
    }

    // What changed since the image, and what runs: both read from the host.
    // A cron file and a binary run from /tmp are planted as harmless markers;
    // the process is started by `docker exec -d`, so the runtime reaps it and
    // it ends on its own within a minute.
    console.log("\n--- 文件改动与进程（种下无害标记，结束后清掉）");
    const forensics = "/tmp/lovelyhawk-probe-diff";
    wsl("docker", "exec", "svc-docker", "docker", "exec", "ci-runner", "sh", "-c",
      `mkdir -p ${forensics} && cp /bin/busybox ${forensics}/sleep && echo '# lovelyhawk probe' > /etc/crontabs/lovelyhawk-probe`);
    wsl("docker", "exec", "svc-docker", "docker", "exec", "-d", "ci-runner", `${forensics}/sleep`, "45");
    try {
      const container = row("ci-runner");
      const changes = await sidecar.call("docker.container.changes.get", {
        bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, containerHandle: container.containerHandle,
      }, 90_000);
      const changed = (kind, path) => changes.items.some((item) => item.kind === kind && item.path === path);
      check("新增的计划任务文件在改动里", changed("added", "/etc/crontabs/lovelyhawk-probe"), true);
      check("新增的临时目录在改动里", changed("added", forensics), true);
      check("没有读不懂的行", changes.unreadableLines, 0);

      const processes = await sidecar.call("docker.container.processes.get", {
        bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, containerHandle: container.containerHandle,
      }, 90_000);
      const command = processes.titles.indexOf("CMD");
      console.log(`  进程表列：${processes.titles.join(" ")}`);
      check("进程表有命令列", command, (value) => value >= 0);
      check("从 /tmp 跑的进程连同完整命令行都在",
        processes.rows.some((fields) => fields[command] === `${forensics}/sleep 45`), true);
      check("每行列数和表头一致", processes.rows.every((fields) => fields.length === processes.titles.length), true);

      const stopped = (snapshot.containers ?? []).find((item) => item.state !== "running");
      await refuses("停着的容器没有进程可读", "docker", () => sidecar.call("docker.container.processes.get", {
        bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, containerHandle: stopped.containerHandle,
      }, 90_000));
    } finally {
      // Files first; then the process, by a pattern that cannot match this
      // cleanup shell's own command line (`[s]leep` does not contain `sleep`).
      wsl("docker", "exec", "svc-docker", "docker", "exec", "ci-runner", "sh", "-c",
        `rm -rf ${forensics} /etc/crontabs/lovelyhawk-probe; pkill -f '${forensics}/[s]leep 45' || true`);
    }

    console.log("\n--- 拒绝");
    await refuses("不存在的目录", "container-directory-missing", () => list(row("ci-runner"), "/no/such/place"));
    await refuses("带 .. 的路径在进容器前就被拒", "invalid-params", () => list(row("ci-runner"), "/etc/../root"));
    await refuses("伪造的容器句柄", "docker", () => list({ containerHandle: "a".repeat(32) }, "/"));
  } finally {
    sidecar.close();
  }
}

async function kubernetesPart() {
  const target = labTarget("kubernetes");
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  try {
    console.log(`\n=== Kubernetes：连接 ${target.host}:${target.port}`);
    const status = await connect(sidecar, target);
    const binding = status.bindingHandle;
    const snapshot = await sidecar.call("kubernetes.resources.list", {
      bindingHandle: binding, input: { tab: "pods", namespaceScope: null },
    }, 90_000);
    const rows = snapshot.rows ?? [];
    const ledger = rows.find((row) => row.name.startsWith("ledger-") && row.phase === "Running");
    const coredns = rows.find((row) => row.namespace === "kube-system" && row.name.startsWith("coredns-"));
    const call = (method, row, path) => sidecar.call(method, {
      bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, rowHandle: row.rowHandle, path,
    }, 100_000);

    const etc = await call("kubernetes.pod.directory.list", ledger, "/etc");
    console.log(`\n--- ${ledger.namespace}/${ledger.name} /etc：${etc.entries.length} 项`);
    check("Pod 里的目录列出来了", etc.entries.some((entry) => entry.name === "hostname"), true);
    check("kubectl 的提示没有混进条目", etc.entries.some((entry) => /Defaulted|kubectl/u.test(entry.name)), false);

    const hostname = await call("kubernetes.pod.file.read", ledger, "/etc/hostname");
    check("读到的是这个 Pod 的主机名", hostname.text.trim(), ledger.name);
    check("长度和内容一致", hostname.bytes, Buffer.byteLength(hostname.text));
    check("SHA-256 和内容一致", hostname.sha256, createHash("sha256").update(hostname.text).digest("hex"));

    console.log("\n--- 拒绝");
    await refuses("目录不当文件读", "kubernetes-pod-file-not-regular", () => call("kubernetes.pod.file.read", ledger, "/etc"));
    await refuses("符号链接不跟过去", "kubernetes-pod-file-not-regular", () => call("kubernetes.pod.file.read", ledger, "/etc/mtab"));
    await refuses("不存在的文件", "kubernetes-pod-file-missing", () => call("kubernetes.pod.file.read", ledger, "/etc/no-such-file"));
    await refuses("不存在的目录", "container-directory-missing", () => call("kubernetes.pod.directory.list", ledger, "/no/such"));
    await refuses("没有 shell 的镜像列不了目录", "kubernetes-pod-exec-failed", () => call("kubernetes.pod.directory.list", coredns, "/"));
    const pending = rows.find((row) => row.name.startsWith("nightly-report-"));
    await refuses("没在运行的 Pod", "kubernetes-pod-not-running", () => call("kubernetes.pod.directory.list", pending, "/"));
  } finally {
    sidecar.close();
  }
}

// Podman on cgroups v1 writes a warning to stderr on every command, and the
// transport appends stderr to the output: it once read as one more process and
// one unreadable change line. Every row here must be a real process.
async function podmanPart() {
  const target = labTarget("podman");
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  try {
    console.log(`\n=== Podman：连接 ${target.host}:${target.port}`);
    const status = await connect(sidecar, target);
    const binding = status.bindingHandle;
    const snapshot = await sidecar.call("docker.containers.refresh", { bindingHandle: binding }, 90_000);
    check("认出是 Podman", snapshot.runtime, "podman");
    const container = (snapshot.containers ?? []).find((item) => item.state === "running");
    const args = { bindingHandle: binding, snapshotHandle: snapshot.snapshotHandle, containerHandle: container.containerHandle };
    const processes = await sidecar.call("docker.container.processes.get", args, 90_000);
    console.log(`  进程表列：${processes.titles.join(" ")}`);
    check("用的是 Podman 自己的列", processes.titles.includes("COMMAND"), true);
    check("每一行都是进程，没有运行时的警告", processes.rows.every((fields) => /^\d+$/u.test(fields[processes.titles.indexOf("PID")] ?? "")), true);
    const changes = await sidecar.call("docker.container.changes.get", args, 90_000);
    check("改动里没有读不懂的行", changes.unreadableLines, 0);
    const listing = await sidecar.call("docker.container.directory.list", { ...args, path: "/etc" }, 90_000);
    check("目录能列，也没混进警告", listing.entries.some((entry) => entry.name === "passwd") &&
      !listing.entries.some((entry) => entry.name.includes("level=warning")), true);
    // Logs keep stderr (it is the container's), so the runtime's own warning
    // is switched off at the source instead.
    const logs = await sidecar.call("docker.container.logs.get", { ...args, tail: 50 }, 90_000);
    check("容器日志里没有运行时自己的警告", logs.text.includes("cgroups-v1"), false);
  } finally {
    sidecar.close();
  }
}

try {
  await dockerPart();
  await podmanPart();
  await kubernetesPart();
} catch (error) {
  failures += 1;
  console.error(`\n失败：${error.message}`);
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 项没对上`);
process.exitCode = failures === 0 ? 0 : 1;
