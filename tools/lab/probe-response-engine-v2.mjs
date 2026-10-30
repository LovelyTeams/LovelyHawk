// Drives the whole incident-response engine against the ghost-range-v2 lab
// container — the deep-compromise range: LD_PRELOAD readdir hook, PATH
// injection, forced-command ssh key, pam_permit, a loopback bind listener, a
// hidden stash dir, web sensitive files, a webshell, a PROMPT_COMMAND
// recorder and a cleartext password in root's history, on top of the classic
// account/sudoers/cron/backdoor shapes. Since the 2026-10-30 extension the
// scan must also catch a live login session still carrying the hook in its
// memory environment (planted via `bash -l sleep`), and after the fixes the
// re-scan may legitimately still list preload-residue guidance items — the
// deleted libsyslog.so stays mapped by nginx and friends until they restart.
//
// Expected flow:
//   * the scan finds all 17 planted kinds (suspicious-account stays silent:
//     watcher is covered by empty-password, ctfops is the session user) and
//     sorts the "eyes" first (ld-preload → path-injection → hijacked);
//   * the fix queue respects the cross-issue order: cron lines first (their
//     plans carry line hashes the backdoor's cascade would invalidate), the
//     eyes next, hooked sessions before the on-disk recorder fix, watcher-
//     type watchdog processes before their payload, the stash dir only once
//     nothing alive references it, and history lines in descending order per
//     file;
//   * web fixes freeze the plan-time business observation: the front page
//     answered 200 before the fix, so it must answer 200 after;
//   * when every fix verifies, a re-scan finds nothing except preload-
//     residue guidance, the lab grader (docker exec ... python3 /opt/check.py)
//     exits 0 with "5/5" — also after waiting out another cron cycle — and
//     the host-side front page on 127.0.0.1:8081 still answers 200.
//
// The probe is idempotent: it recreates the container from the ghost-range-v2
// image before touching anything.
//
//   LOVELYHAWK_BACKEND_BIN=$PWD/target/debug/lovelyhawk-backend \
//     node tools/lab/probe-response-engine-v2.mjs
//
// Remote mode (shared live range): set PROBE_HOST/PROBE_PORT/PROBE_USER/
// PROBE_PASS. Remote mode never touches docker and never runs the grader; it
// only scans and reports.
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect, backendBinary } from "./rpc-harness.mjs";

const CONTAINER = "ghost-range-v2-lab";
const IMAGE = "ghost-range-v2";
const REMOTE = process.env.PROBE_HOST !== undefined;
// Remote mode defaults to read-only; PROBE_REMOTE_FIX=1 additionally runs the
// whole fix queue against the shared live range (grading stays outside the
// probe: run `sudo python3 /opt/check.py` on the target yourself).
const REMOTE_FIX = process.env.PROBE_REMOTE_FIX === "1";
const TARGET = {
  host: process.env.PROBE_HOST ?? "127.0.0.1",
  port: Number(process.env.PROBE_PORT ?? 2322),
  username: process.env.PROBE_USER ?? "ctfops",
  password: process.env.PROBE_PASS ?? "Ctfops@2026",
  name: REMOTE ? "ghost-range-v2-remote" : "ghost-range-v2-lab",
};
const BUSINESS_URL = process.env.PROBE_BUSINESS_URL ?? "http://127.0.0.1:8081/";

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

function grade() {
  try {
    return { exit: 0, output: docker(["exec", CONTAINER, "python3", "/opt/check.py"]) };
  } catch (error) {
    return { exit: error.status ?? 1, output: String(error.stdout ?? "") };
  }
}

function businessStatus() {
  try {
    return execFileSync("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", BUSINESS_URL], { encoding: "utf8" }).trim();
  } catch {
    return "000";
  }
}

// `file:line` (history) and `file:line: text` (cron/pam/…) prefixes the
// first evidence line of every line-based issue; fixing a file top-down
// would shift the lines the later plans re-check.
function lineOf(issue) {
  const match = /^.*?:(\d+)(?::|$)/.exec(issue.evidence?.[0] ?? "");
  return match === null ? 0 : Number(match[1]);
}

function byLineDesc(issues) {
  return [...issues].sort((a, b) => lineOf(b) - lineOf(a));
}

/** 异步扫描：scan 返回句柄后轮询真实阶段直到拿到完整结果。 */
async function scanFully(sidecar, binding) {
  const started = await sidecar.call("response.engine", { action: "scan", bindingHandle: binding }, 300_000);
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
    // sshd/nginx need a moment after container start; wait for both instead
    // of racing the first grade and business probe.
    for (let attempt = 0; attempt < 30; attempt += 1) {
      if (businessStatus() === "200") break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    const before = grade();
    console.log(`  处置前评分：exit=${before.exit}`);
    check("起手就是失陷状态（评分脚本 exit 1）", before.exit, 1);
    check("起手业务首页 200", businessStatus(), "200");
    // Plant one live login shell so the session-env-hook detector has a real
    // in-memory hook to find: `bash -l` sources /etc/profile → profile.d
    // hooks land in its environment (the sleep never shows a prompt, so it
    // never re-creates the log file — the finding is the environment itself).
    docker(["exec", "-d", CONTAINER, "bash", "-l", "-c", "sleep 600"]);
  } else {
    console.log(`  远程模式：${TARGET.username}@${TARGET.host}:${TARGET.port}（${REMOTE_FIX ? "PROBE_REMOTE_FIX=1：执行完整修复队列；评分请在目标上手动跑 check.py" : "只扫描，不修复"}）`);
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
  if (!REMOTE) {
    // The shared live range may legitimately hold unfixable rows (a listener
    // whose owner cannot be pinned) and has no planted hooked session, so
    // these two closed-world checks only apply to the freshly reset lab.
    check("每个问题都带了处置句柄且可修复",
      scan.issues.every((issue) => issue.fixable === true && String(issue.issueHandle ?? "").length > 0));
  } else {
    check("每个问题都带了处置句柄",
      scan.issues.every((issue) => String(issue.issueHandle ?? "").length > 0));
  }

  const EXPECTED_KINDS = [
    "backdoor-process", "bind-listener", "command-recorder", "cron-persistence",
    "empty-password", "hijacked-command", "history-credential-leak",
    "ld-preload-hijack", "malicious-sudoers", "pam-backdoor", "path-injection",
    "session-env-hook", "ssh-key-backdoor", "stash-dir", "uid-zero-account",
    "web-sensitive-file", "webshell",
  ];
  if (!REMOTE) {
    check("十七个类型全部扫到", [...byKind.keys()].sort(),
      (value) => JSON.stringify(value) === JSON.stringify(EXPECTED_KINDS));
  } else {
    // session-env-hook needs a live hooked login session and preload-residue
    // only appears once the library is deleted; both are absent on an
    // untouched shared range.
    const remoteExpected = EXPECTED_KINDS.filter((kind) => kind !== "session-env-hook");
    check("远程实例如期扫到其余十六个类型", [...byKind.keys()].sort(),
      (value) => JSON.stringify(value) === JSON.stringify(remoteExpected));
  }
  check("fresh 容器 suspicious-account 0 命中（watcher 被空口令覆盖、ctfops 是会话用户）",
    (byKind.get("suspicious-account") ?? []).length, 0);
  check("至少 20 个问题", scan.issues.length, (value) => value >= 20);
  // 先修眼睛：动态链接库劫持、PATH 注入、命令劫持必须排在最前。
  check("排序把「眼睛」排在最前（ld-preload → path-injection → hijacked）",
    scan.issues.slice(0, 3).map((issue) => issue.kind),
    (value) => JSON.stringify(value) === JSON.stringify([
      "ld-preload-hijack", "path-injection", "hijacked-command",
    ]));

  let queue;
  if (REMOTE && !REMOTE_FIX) {
    queue = [];
  } else {
    // ---- 逐条修复 -----------------------------------------------------------
    // Order matters:
    //   * cron first, descending by line inside each file — the plans carry
    //     line hashes, and the backdoor cascade deletes cron lines too;
    //   * hijacked commands before the PATH injection that links them (the
    //     injection fix tolerates fakes already gone, not the reverse);
    //   * watcher-type processes before the payload they would respawn;
    //   * a bind listener whose body is also a backdoor-process body is fixed
    //     through the listener issue (its verify also demands the port shut),
    //     the duplicate backdoor issue is dropped;
    //   * the stash dir goes only once nothing alive references it;
    //   * the empty-password account is removed (the grader requires it gone),
    //     history lines last, descending per file.
    const listeners = (byKind.get("bind-listener") ?? []).filter((issue) => issue.fixable);
    const listenerBodies = new Set(listeners.map((issue) => {
      const match = /（(\/[^）]*)）/.exec(issue.summary);
      return match === null ? "" : match[1];
    }).filter((body) => body !== ""));
    const backdoors = (byKind.get("backdoor-process") ?? [])
      .filter((issue) => issue.fixable)
      .filter((issue) => {
        const body = (issue.evidence?.[0] ?? "").replace(/^后门本体：/, "");
        return !listenerBodies.has(body);
      })
      .sort((a, b) => Number(b.summary.includes("watcher")) - Number(a.summary.includes("watcher")));
    const fixableOnly = (kind) => (byKind.get(kind) ?? []).filter((issue) => issue.fixable);
    queue = [
      ...byLineDesc(fixableOnly("cron-persistence")),
      ...fixableOnly("hijacked-command"),
      ...fixableOnly("path-injection"),
      ...fixableOnly("ld-preload-hijack"),
      // Hooked sessions before the on-disk recorder fix: their environment is
      // the only place the hook still lives once sysstat.sh is gone.
      ...fixableOnly("session-env-hook"),
      ...fixableOnly("command-recorder"),
      ...backdoors,
      ...listeners,
      ...fixableOnly("stash-dir"),
      ...fixableOnly("ssh-key-backdoor"),
      ...fixableOnly("pam-backdoor"),
      ...fixableOnly("malicious-sudoers"),
      ...fixableOnly("uid-zero-account"),
      ...fixableOnly("empty-password"),
      ...fixableOnly("web-sensitive-file"),
      ...fixableOnly("webshell"),
      ...byLineDesc(fixableOnly("history-credential-leak")),
    ];
    check("修复队列覆盖了全部可修复问题（监听项已吸收同本体的后门项）", queue.length,
      scan.issues.filter((issue) => {
        if (!issue.fixable) return false;
        if (issue.kind !== "backdoor-process") return true;
        const body = (issue.evidence?.[0] ?? "").replace(/^后门本体：/, "");
        return !listenerBodies.has(body);
      }).length);
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
    const deadline = Date.now() + 150_000; // process fixes wait out one cron cycle
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
    console.log(`  复扫到 ${rescan.issues.length} 个问题（远程模式不修复，仅报告）`);
  } else {
    // The deleted libsyslog.so stays mapped (marked `(deleted)`) by the
    // long-running processes that loaded it — nginx, cron, sshd… Killing
    // them would take the business down, so those are guidance-only rows.
    const residue = rescan.issues.filter((issue) => issue.kind === "preload-residue");
    check("复扫除驻留库指导项外没有任何遗留问题",
      rescan.issues.filter((issue) => issue.kind !== "preload-residue").length, 0);
    check("驻留库指导项不可自动修复（防止误杀业务进程）",
      residue.every((issue) => issue.fixable === false), true);
    check("驻留库指导项给出了重启指引",
      residue.every((issue) => issue.evidence.some((line) => line.includes("重启"))), true);

    const after = grade();
    console.log(`\n  处置后评分：exit=${after.exit}\n${after.output.split("\n").map((line) => `    ${line}`).join("\n")}`);
    check("评分脚本通过（exit 0）", after.exit, 0);
    check("评分输出确认 5/5", after.output.includes("5/5"));

    // 再等一个 cron 保活周期后复评，确认没有任何东西复活。
    console.log("  等待 70 秒跨周期后复评…");
    await new Promise((resolve) => setTimeout(resolve, 70_000));
    const settled = grade();
    check("跨周期复评 exit 0", settled.exit, 0);
    check("跨周期复评仍是 5/5", settled.output.includes("5/5"));

    // The session-env-hook fix only terminates processes — nothing is
    // deleted, so it leaves no archive by design.
    const archiveExpect = queue.filter((issue) => issue.kind !== "session-env-hook").length;
    check("每条删除类修复都留了独立证据（MANIFEST.sha256）",
      onHost("ls /var/case/bak/*/MANIFEST.sha256 2>/dev/null | wc -l | tr -d ' '"),
      (value) => parseInt(value, 10) >= archiveExpect);
    check("业务首页仍是 200（修复没有打死业务）", businessStatus(), "200");
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
