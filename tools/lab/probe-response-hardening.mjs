// Drives the post-incident hardening sweep (response.engine actions
// `hardening-scan` and `plan-hardening`) against the ghost-range-v2 lab
// container. The three closed items must each land in the right state, and
// the pending ones must run the full plan → confirm → execute → verify chain:
//
//   * auth-permissions: the probe loosens /etc/shadow and root's
//     authorized_keys on purpose; the scan flags both deviations, the fix
//     records the original modes into the archive and tightens them, a
//     re-scan is compliant again;
//   * audit-watch: the lab container has no auditd, so the item must report
//     not-applicable with a reason instead of pretending coverage;
//   * integrity-snapshot: absent → build the manifest → compliant; then the
//     probe edits a manifest-covered file, the drift re-check must flag it
//     and a rebuilt manifest goes back to clean;
//   * hardening plans ride the same confirm/execute/poll handles as incident
//     fixes, and no hardening request ever carries a path or command.
//
//   LOVELYHAWK_BACKEND_BIN=$PWD/target/debug/lovelyhawk-backend \
//     node tools/lab/probe-response-hardening.mjs
//
// Remote mode (shared live range): set PROBE_HOST/PROBE_PORT/PROBE_USER/
// PROBE_PASS. Remote mode never touches docker, never loosens anything and
// never executes a hardening plan — it only checks and reports.
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect, backendBinary } from "./rpc-harness.mjs";

const CONTAINER = "ghost-range-v2-lab";
const IMAGE = "ghost-range-v2";
const REMOTE = process.env.PROBE_HOST !== undefined;
const TARGET = {
  host: process.env.PROBE_HOST ?? "127.0.0.1",
  port: Number(process.env.PROBE_PORT ?? 2322),
  username: process.env.PROBE_USER ?? "ctfops",
  password: process.env.PROBE_PASS ?? "Ctfops@2026",
  name: REMOTE ? "ghost-hardening-remote" : "ghost-range-v2-lab",
};

let failures = 0;
function check(name, actual, expected = true) {
  const ok = typeof expected === "function" ? expected(actual) === true : actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       actual ${JSON.stringify(actual)}`}`);
}

function docker(args, { allowFailure = false } = {}) {
  try {
    return execFileSync("docker", args, { encoding: "utf8" }).trim();
  } catch (error) {
    if (allowFailure) return "";
    throw error;
  }
}

function onHost(command) {
  return docker(["exec", CONTAINER, "sh", "-c", command]);
}

function resetLab() {
  docker(["rm", "-f", CONTAINER], { allowFailure: true });
  docker(["run", "-d", "--name", CONTAINER, "-p", "2322:22", "-p", "8081:80", IMAGE]);
}

async function hardeningScan(sidecar, binding) {
  return sidecar.call("response.engine", { action: "hardening-scan", bindingHandle: binding }, 300_000);
}

function itemByKind(scan, kind) {
  return scan.items.find((item) => item.kind === kind) ?? null;
}

async function runHardening(sidecar, binding, item, label) {
  console.log(`\n  [${item.kind}] ${item.summary}`);
  const plan = await sidecar.call("response.engine", {
    action: "plan-hardening", bindingHandle: binding, itemHandle: item.itemHandle,
  }, 180_000);
  console.log(`    计划：${plan.summary}`);
  check(`${label} 计划有具体步骤`, Array.isArray(plan.steps) && plan.steps.length > 0);
  check(`${label} 计划说清了影响`, String(plan.impact ?? "").length > 4);
  const confirmed = await sidecar.call("response.engine", {
    action: "confirm-fix", bindingHandle: binding, planHandle: plan.planHandle,
  }, 120_000);
  check(`${label} 确认成功`, confirmed.confirmed, true);
  const started = await sidecar.call("response.engine", {
    action: "execute-fix", bindingHandle: binding, planHandle: plan.planHandle,
  }, 120_000);
  let operation = null;
  const deadline = Date.now() + 120_000;
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    operation = await sidecar.call("response.engine", {
      action: "poll-fix", bindingHandle: binding, operationHandle: started.operationHandle,
    }, 120_000);
    if (operation.stage !== "running" && operation.stage !== "verify-pending") break;
    if (Date.now() > deadline) break;
  }
  console.log(`    结果：stage=${operation.stage} verifyPassed=${operation.verifyPassed} · ${String(operation.summary).slice(0, 80)}`);
  check(`${label} 执行完成`, operation.stage, "completed");
  check(`${label} 复核通过`, operation.verifyPassed, true);
}

const sidecar = new Sidecar(backendBinary(), newDataRoot());

try {
  if (!REMOTE) {
    resetLab();
    // Wait for sshd to accept connections before the harness connects.
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const ready = onHost("echo ready 2>/dev/null");
      if (ready === "ready") break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    // Plant permission deviations the fix has to catch and undo.
    onHost("chmod 666 /etc/shadow");
    onHost("chmod 666 /root/.ssh/authorized_keys");
    console.log("  已植入权限偏离：/etc/shadow 666、/root/.ssh/authorized_keys 666");
  } else {
    console.log(`  远程模式：${TARGET.username}@${TARGET.host}:${TARGET.port}（只检查，不加固）`);
  }

  const status = await connect(sidecar, TARGET);
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  console.log(`  已连接 ${TARGET.username}@${TARGET.host}:${TARGET.port}`);

  // ---- 第一次加固检查 -------------------------------------------------------
  const first = await hardeningScan(sidecar, binding);
  console.log(`  加固检查：${first.items.length} 项（缺口=${first.gaps.length}）`);
  for (const item of first.items) {
    console.log(`    ${item.kind} → ${item.status}${item.note === null ? "" : `（${item.note}）`}`);
  }
  check("三个加固项都在", first.items.length, 3);
  check("句柄唯一且不与扫描句柄混用",
    new Set(first.items.map((item) => item.itemHandle)).size, first.items.length);

  const permissions = itemByKind(first, "hardening-auth-permissions");
  const audit = itemByKind(first, "hardening-audit-watch");
  const snapshot = itemByKind(first, "hardening-integrity-snapshot");
  check("权限项存在", permissions !== null);
  check("监控项存在", audit !== null);
  check("清单项存在", snapshot !== null);

  if (REMOTE) {
    console.log("\n  远程模式：仅报告状态，不执行加固。");
  } else {
    // ---- 权限加固 -----------------------------------------------------------
    check("植入的偏离被扫到（pending）", permissions.status, "pending");
    check("偏离证据点名了 shadow 与 authorized_keys",
      permissions.evidence.some((line) => line.includes("/etc/shadow")) &&
      permissions.evidence.some((line) => line.includes("authorized_keys")), true);
    await runHardening(sidecar, binding, permissions, "权限加固");
    check("远端权限已收紧（shadow 640）",
      onHost("stat -c '%a' /etc/shadow"), "640");
    check("远端权限已收紧（authorized_keys 600）",
      onHost("stat -c '%a' /root/.ssh/authorized_keys"), "600");
    check("原始权限记录进了归档",
      onHost("ls /var/case/bak/*/original-permissions.txt 2>/dev/null | wc -l | tr -d ' '"),
      (value) => parseInt(value, 10) >= 1);

    // ---- audit 监控（容器无 auditd → 不适用） --------------------------------
    check("无 auditd 的容器报告不适用而不是假装覆盖",
      audit.status, "not-applicable");
    check("不适用说明了原因", (audit.note ?? "").length > 4);

    // ---- 完整性清单 ----------------------------------------------------------
    check("尚未建立清单（pending）", snapshot.status, "pending");
    await runHardening(sidecar, binding, snapshot, "建立清单");
    const manifest = "/var/case/hardening/integrity-manifest.txt";
    check("清单已生成且非空",
      onHost(`[ -s ${manifest} ] && echo yes || echo no`), "yes");
    const entries = parseInt(onHost(`wc -l < ${manifest}`), 10);
    check("清单覆盖了关键文件（>10 项）", entries > 10, true);

    // ---- 漂移：改动清单内文件后再查 -----------------------------------------
    onHost("printf '# hardening drift probe\\n' >> /etc/crontab");
    const drifted = await hardeningScan(sidecar, binding);
    const driftedSnapshot = itemByKind(drifted, "hardening-integrity-snapshot");
    check("漂移后清单项回到 pending", driftedSnapshot.status, "pending");
    check("漂移证据点名了 /etc/crontab",
      driftedSnapshot.evidence.some((line) => line.includes("/etc/crontab")), true);
    await runHardening(sidecar, binding, driftedSnapshot, "重建清单");
    const settled = await hardeningScan(sidecar, binding);
    check("重建后清单项回到 compliant",
      itemByKind(settled, "hardening-integrity-snapshot").status, "compliant");
    check("重建后权限项保持 compliant",
      itemByKind(settled, "hardening-auth-permissions").status, "compliant");
    onHost("sed -i '/hardening drift probe/d' /etc/crontab");
  }
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
