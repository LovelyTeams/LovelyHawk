// Drives the whole incident-response engine against the ghost-range lab
// container: scan, then plan → confirm → execute → poll-verify every issue
// one at a time, then re-scan to zero and run the lab's own grader.
//
// This is the first time the full loop — seven issue kinds, password-sudo
// privilege escalation, the remove-account mode and the backdoor's delayed
// verification — runs against a real machine through the stdio harness:
//
//   * the scan has to find all seven planted shapes (three hijacked commands,
//     the uid-0 account, the empty-password account, the sudoers grant, both
//     cron persistence lines, the running backdoor and watcher's leaked
//     chpasswd line in .bash_history) and mint one opaque issue handle each;
//     a fresh container must NOT report any suspicious-account (watcher is
//     covered by empty-password, ctfops is the session user);
//   * ctfops is a sudoer WITH a password, so every privileged step exercises
//     the sudo-stdin credential path — the password must never appear in a
//     command line;
//   * the empty-password account is fixed in "remove" mode (the lab grader
//     requires the account gone from both passwd and shadow, not locked);
//   * cron issues are fixed before the backdoor: the backdoor plan cascades
//     over cron lines that reference it, and fixing the backdoor first would
//     leave the cron plans pointing at stale line hashes;
//   * the backdoor fix waits out one cron keep-alive period before verifying,
//     so its operation sits in verify-pending for about 70 seconds;
//   * when every fix verifies, a re-scan finds nothing and the lab grader
//     (docker exec ... python3 /opt/check.py) exits 0 with "3/3".
//
// The probe is idempotent: it recreates the container from the ghost-range
// image before touching anything.
//
//   LOVELYHAWK_BACKEND_BIN=$PWD/target/debug/lovelyhawk-backend \
//     node tools/lab/probe-response-engine.mjs
//
// Remote mode (shared live range): set PROBE_HOST/PROBE_PORT/PROBE_USER/
// PROBE_PASS to point at a real target. Remote mode never touches docker,
// never runs the local grader, and only fixes suspicious-account issues —
// everything else is reported but left alone.
//
//   PROBE_HOST=nc1.ctfplus.cn PROBE_PORT=49435 PROBE_USER=ctfops \
//   PROBE_PASS=Ctfops@2026 LOVELYHAWK_BACKEND_BIN=$PWD/target/debug/lovelyhawk-backend \
//     node tools/lab/probe-response-engine.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect, backendBinary } from "./rpc-harness.mjs";

const CONTAINER = "ghost-range-lab";
const IMAGE = "ghost-range";
const REMOTE = process.env.PROBE_HOST !== undefined;
const TARGET = {
  host: process.env.PROBE_HOST ?? "127.0.0.1",
  port: Number(process.env.PROBE_PORT ?? 2299),
  username: process.env.PROBE_USER ?? "ctfops",
  password: process.env.PROBE_PASS ?? "Ctfops@2026",
  name: REMOTE ? "ghost-range-remote" : "ghost-range-lab",
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
  docker(["run", "-d", "--name", CONTAINER, "-p", "2299:22", IMAGE]);
}

function grade() {
  try {
    return { exit: 0, output: docker(["exec", CONTAINER, "python3", "/opt/check.py"]) };
  } catch (error) {
    return { exit: error.status ?? 1, output: String(error.stdout ?? "") };
  }
}

async function scanFully(sidecar, binding) {
  const started = await scanFully(sidecar, binding);
  const deadline = Date.now() + 300_000;
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const status = await sidecar.call("response.engine", {
      action: "poll-scan", bindingHandle: binding, scanHandle: started.scanHandle,
    }, 120_000);
    if (status.stage === "completed" && status.scan !== null) return status.scan;
    if (status.stage === "failed") throw new Error(`扫描失败：${status.error ?? "未知原因"}`);
    if (Date.now() > deadline) throw new Error("扫描超时");
  }
}

const sidecar = new Sidecar(backendBinary(), newDataRoot());

try {
  if (!REMOTE) {
    resetLab();
    const before = grade();
    console.log(`  处置前评分：exit=${before.exit}`);
    check("起手就是失陷状态（评分脚本 exit 1）", before.exit, 1);
  } else {
    console.log(`  远程模式：${TARGET.username}@${TARGET.host}:${TARGET.port}（跳过 docker 重置与本地评分）`);
  }

  const status = await connect(sidecar, TARGET);
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  console.log(`  已连接 ${TARGET.username}@${TARGET.host}:${TARGET.port}`);

  // ---- 扫描 --------------------------------------------------------------
  const scan = await scanFully(sidecar, binding);
  console.log(`  扫描到 ${scan.issues.length} 个问题（截断=${scan.truncated}，缺口=${scan.gaps.length}）`);
  const byKind = new Map();
  for (const issue of scan.issues) {
    const list = byKind.get(issue.kind) ?? [];
    list.push(issue);
    byKind.set(issue.kind, list);
  }
  for (const [kind, list] of byKind) console.log(`    ${kind} × ${list.length}`);
  check("每个问题都带了处置句柄且可修复",
    scan.issues.every((issue) => issue.fixable === true && String(issue.issueHandle ?? "").length > 0));

  let queue;
  if (REMOTE) {
    // 共享靶场只允许处置可疑登录账户（如锁定态 watcher 残留），其他类别只报告。
    queue = byKind.get("suspicious-account") ?? [];
    check("远程目标命中 suspicious-account", queue.length, (value) => value >= 1);
    for (const issue of queue) console.log(`    待处置：${issue.summary}`);
  } else {
    check("七个类型全部扫到", [...byKind.keys()].sort(),
      (value) => JSON.stringify(value) === JSON.stringify([
        "backdoor-process", "cron-persistence", "empty-password",
        "hijacked-command", "history-credential-leak", "malicious-sudoers",
        "uid-zero-account",
      ]));
    check("fresh 容器 suspicious-account 0 命中（watcher 被空口令覆盖、ctfops 是会话用户）",
      (byKind.get("suspicious-account") ?? []).length, 0);
    check("至少 9 个问题（3 伪命令 + 账户 ×2 + sudoers + cron ×2 + 后门 + 历史密码）",
      scan.issues.length, (value) => value >= 9);

    // ---- 逐条修复 -----------------------------------------------------------
    // Order matters: the cron plans carry line hashes the backdoor's cascading
    // plan would invalidate, so the backdoor goes last; the empty-password
    // account must be removed (not locked) for the grader's gate 2; watcher's
    // history line must be fixed before the account removal deletes
    // /home/watcher (and with it the history file the line fix re-checks).
    queue = [
      ...byKind.get("hijacked-command") ?? [],
      ...byKind.get("uid-zero-account") ?? [],
      ...byKind.get("malicious-sudoers") ?? [],
      ...byKind.get("cron-persistence") ?? [],
      ...byKind.get("history-credential-leak") ?? [],
      ...byKind.get("empty-password") ?? [],
      ...byKind.get("backdoor-process") ?? [],
    ];
  }

  for (const issue of queue) {
    const mode = issue.kind === "empty-password" ? "remove" : null;
    console.log(`\n  [${issue.kind}] ${issue.summary}${mode === null ? "" : `（mode=${mode}）`}`);
    const plan = await sidecar.call("response.engine", {
      action: "plan-fix", bindingHandle: binding, issueHandle: issue.issueHandle, mode,
    }, 180_000);
    console.log(`    计划：${plan.summary}`);
    check("计划有具体步骤", Array.isArray(plan.steps) && plan.steps.length > 0);
    check("计划说清了影响", String(plan.impact ?? "").length > 4);

    const confirmed = await sidecar.call("response.engine", {
      action: "confirm-fix", bindingHandle: binding, planHandle: plan.planHandle,
    }, 120_000);
    check("确认成功", confirmed.confirmed, true);

    const started = await sidecar.call("response.engine", {
      action: "execute-fix", bindingHandle: binding, planHandle: plan.planHandle,
    }, 120_000);

    let operation = null;
    const deadline = Date.now() + 150_000; // the backdoor waits out one cron cycle
    for (;;) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      operation = await sidecar.call("response.engine", {
        action: "poll-fix", bindingHandle: binding, operationHandle: started.operationHandle,
      }, 120_000);
      if (operation.stage !== "running" && operation.stage !== "verify-pending") break;
      if (Date.now() > deadline) break;
    }
    console.log(`    结果：stage=${operation.stage} verifyPassed=${operation.verifyPassed} · ${String(operation.summary).slice(0, 80)}`);
    check("执行完成", operation.stage, "completed");
    check("复核通过", operation.verifyPassed, true);
  }

  // ---- 复扫与独立评分 -------------------------------------------------------
  console.log("\n  复扫");
  const rescan = await scanFully(sidecar, binding);
  if (REMOTE) {
    const remaining = rescan.issues.filter((issue) => issue.kind === "suspicious-account");
    console.log(`  复扫到 ${rescan.issues.length} 个问题，其中 suspicious-account × ${remaining.length}`);
    check("复扫 suspicious-account 清零", remaining.length, 0);
  } else {
    check("复扫没有任何遗留问题", rescan.issues.length, 0);

    const after = grade();
    console.log(`\n  处置后评分：exit=${after.exit}\n${after.output.split("\n").map((line) => `    ${line}`).join("\n")}`);
    check("评分脚本通过（exit 0）", after.exit, 0);
    check("评分输出确认 3/3", after.output.includes("3/3"));

    check("每条修复都留了独立证据（MANIFEST.sha256）",
      onHost("ls /var/case/bak/*/MANIFEST.sha256 2>/dev/null | wc -l | tr -d ' '"),
      (value) => parseInt(value, 10) >= queue.length);
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
