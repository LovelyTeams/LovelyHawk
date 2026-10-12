// Acts on a file straight off a check's output line, the way somebody under
// time pressure actually does it.
//
// This is the shortest path in the whole tool between "I found something" and
// "it can no longer run": the operator runs a check, sees a line naming a file,
// and picks 去掉执行权限 or 隔离 from that line without ever typing the path.
// It shares the plan/confirm/execute machinery with the file manager but has
// its own capability handling — a path handle minted from one run's output —
// and none of that had been run against a real machine.
//
// What has to hold on a real target:
//   * a path handle only exists for a line that really named a file, and it
//     acts on that file and no other;
//   * 去掉执行权限 clears setuid, setgid and all three execute bits in one go,
//     and leaves the file readable, because it is still evidence;
//   * it refuses when the file changed between being listed and being acted on
//     — the file is not what the operator was looking at any more;
//   * 隔离 goes through the same recoverable removal as the file manager, so
//     the copy it leaves is inert (see probe-sftp-remove.mjs);
//   * every change leaves what it takes to undo it: the plan says how, and
//     隔离 keeps an inert, owner-only copy. Running the undo itself is not
//     exercised here.
//
//   node tools/lab/probe-emergency-path.mjs
//   LAB=rocky node tools/lab/probe-emergency-path.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
// Where a real one hides: a copy of the shell, setuid root, under a name that
// reads like something that belongs there.
const PLANTED = "/usr/local/bin/.systemd-helper";
const SECOND = "/usr/local/bin/.dbus-helper";

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
  ).split("\0").join("").trim();
}

const mode = (path) => onHost(`stat -c %a ${path} 2>/dev/null || echo gone`);
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  onHost(`mkdir -p /usr/local/bin;`
    + ` cp /bin/sh ${PLANTED}; chmod 4755 ${PLANTED};`
    + ` cp /bin/sh ${SECOND}; chmod 4755 ${SECOND}`);
  check("靶机上先种两个 setuid root 的后门", mode(PLANTED), "4755");

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("emergency-command.catalog.load",
    { bindingHandle: binding }, 180_000);
  const suid = catalog.commands.find((entry) => entry.title.includes("SUID"));
  check("命令清单里有 SUID 这一项", suid?.title, (value) => String(value).includes("SUID"));

  const run = await sidecar.call("emergency-command.run", {
    bindingHandle: binding,
    snapshotHandle: catalog.snapshotHandle,
    commandHandle: suid.commandHandle,
  }, 300_000);
  console.log(`  这台机器上找到 ${run.observedLineCount} 个 setuid 文件，界面显示 ${run.displayedLineCount} 行`
    + `，其中 ${run.paths.length} 行认出了文件`);
  check("扫出来的结果里有我们种的那个", run.output, (value) => String(value).includes(PLANTED));
  check("被标成了可疑", run.findingLines, (value) => Array.isArray(value) && value.length > 0);

  // Every path handle has to come from a line that really named a file.
  const lines = String(run.output).split("\n");
  const planted = run.paths.find((entry) => entry.path === PLANTED);
  const second = run.paths.find((entry) => entry.path === SECOND);
  check("那一行可以直接下手（拿到了句柄）", planted?.pathHandle, (value) => String(value ?? "").length > 0);
  check("句柄指的就是那一行显示的文件", lines[planted.line], (value) => String(value ?? "").includes(PLANTED));
  check("每个句柄都对得上自己那一行", run.paths,
    (value) => value.every((entry) => String(lines[entry.line] ?? "").includes(entry.path)));

  // ---- 去掉执行权限 ----------------------------------------------------
  console.log("\n  去掉执行权限");
  const inspected = await sidecar.call("emergency-command.path.inspect",
    { bindingHandle: binding, pathHandle: planted.pathHandle }, 180_000);
  console.log(`  先看一眼：${JSON.stringify(inspected).slice(0, 140)}`);
  check("看得出它现在是能跑的", inspected.executable, true);

  const disarm = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: planted.pathHandle, action: "disarm" }, 180_000);
  console.log(`  计划：${disarm.summary}`);
  check("计划说的就是这个文件", disarm.summary, (value) => String(value).includes(PLANTED));
  check("标了这是危险操作", disarm.dangerous, true);
  check("说了出问题怎么恢复", disarm.restoreDescription, (value) => String(value ?? "").length > 4);
  check("确认之前主机上还是 4755", mode(PLANTED), "4755");

  await sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle: disarm.planHandle }, 180_000);
  const disarmReceipt = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: disarm.planHandle }, 300_000);
  console.log(`  回执：passed=${disarmReceipt.passed} restored=${disarmReceipt.restored} · ${String(disarmReceipt.detail).slice(0, 60)}`);
  check("执行后复核通过", disarmReceipt.passed, true);
  check("没有触发回滚", disarmReceipt.restored, false);

  // The machine, not the receipt. setuid without execute is harmless, but a
  // file that still lists as setuid will still read as one to the next person
  // who looks — and to the next scanner.
  const after = mode(PLANTED);
  console.log(`  现在主机上是 ${after}`);
  check("setuid 位真的没了", after, (value) => (parseInt(String(value), 8) & 0o4000) === 0);
  check("三个执行位也都没了", after, (value) => (parseInt(String(value), 8) & 0o111) === 0);
  check("但文件还在、还读得了（还是证据）",
    onHost(`test -r ${PLANTED} && echo yes || echo no`), "yes");
  check("`find -perm -4000` 已经找不到它了",
    onHost(`find /usr/local/bin -perm -4000 -name '.systemd-helper' 2>/dev/null | wc -l | tr -d ' '`), "0");
  check("真的跑不动了",
    onHost(`${PLANTED} -c true >/dev/null 2>&1 && echo ran || echo blocked`), "blocked");

  // A second run of the same plan must not touch anything else.
  const twice = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: disarm.planHandle }, 180_000)
    .then(() => "又跑了一次").catch((error) => String(error.message).slice(0, 60));
  console.log(`  同一个计划再执行 → ${twice}`);
  check("同一个计划不能跑第二次", twice, (value) => value !== "又跑了一次");

  // ---- 撤销 ------------------------------------------------------------
  // Only a verified action is offered for undo, and the undo reads the file
  // again first: what it puts back is exactly what the action took away.
  console.log("\n  撤销去掉执行权限");
  check("回执说可以撤销", disarmReceipt.undoable, true);
  const disarmUndo = await sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle: disarm.planHandle }, 300_000);
  console.log(`  → undone=${disarmUndo.undone} · ${String(disarmUndo.detail).slice(0, 80)}`);
  check("撤销完成并复核通过", disarmUndo.undone, true);
  check("撤销结果说的是这个文件", disarmUndo.path, PLANTED);
  check("主机上权限回到了 4755（连 setuid 一起）", mode(PLANTED), "4755");
  const undoTwice = await sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle: disarm.planHandle }, 180_000)
    .then(() => "又撤销了一次").catch((error) => String(error.message).slice(0, 60));
  console.log(`  同一次操作再撤销 → ${undoTwice}`);
  check("同一次操作只能撤销一次", undoTwice, (value) => value !== "又撤销了一次");

  // ---- 变了就不动 ------------------------------------------------------
  console.log("\n  文件在计划之后被改过");
  const stalePlan = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: second.pathHandle, action: "disarm" }, 180_000);
  await sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle: stalePlan.planHandle }, 180_000);
  // Somebody else — or the intruder — changes it in between.
  onHost(`chmod 4700 ${SECOND}`);
  const staleReceipt = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: stalePlan.planHandle }, 300_000)
    .then((receipt) => ({ passed: receipt.passed, detail: String(receipt.detail), untouched: receipt.untouched, restored: receipt.restored, undoable: receipt.undoable }))
    .catch((error) => ({ passed: false, detail: String(error.message), untouched: null, restored: null, undoable: null }));
  console.log(`  → passed=${staleReceipt.passed} untouched=${staleReceipt.untouched} · ${staleReceipt.detail.slice(0, 80)}`);
  check("权限变过就不下手", staleReceipt.passed, false);
  check("说得出是为什么", staleReceipt.detail,
    (value) => /改过|变|权限/u.test(String(value)));
  // Nothing was written, so the receipt must not claim a failed restore.
  check("回执说明文件没被动过，而不是“没能还原”", staleReceipt.untouched === true && staleReceipt.restored === false, true);
  check("主机上就是没被动过", mode(SECOND), "4700");
  check("没动过的操作不提供撤销", staleReceipt.undoable, false);

  // ---- 隔离 ------------------------------------------------------------
  console.log("\n  隔离");
  onHost(`chmod 4755 ${SECOND}`);
  const rerun = await sidecar.call("emergency-command.run", {
    bindingHandle: binding,
    snapshotHandle: catalog.snapshotHandle,
    commandHandle: suid.commandHandle,
  }, 300_000);
  const fresh = rerun.paths.find((entry) => entry.path === SECOND);
  check("重新扫一遍还找得到它", fresh?.pathHandle, (value) => String(value ?? "").length > 0);

  const quarantine = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: fresh.pathHandle, action: "quarantine" }, 180_000);
  console.log(`  计划：${quarantine.summary}`);
  check("计划里写明了备份落在哪儿", quarantine.summary,
    (value) => String(value).includes(".lovelyres-backups/"));
  await sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle: quarantine.planHandle }, 180_000);
  const quarantineReceipt = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: quarantine.planHandle }, 300_000);
  console.log(`  回执：passed=${quarantineReceipt.passed} · ${String(quarantineReceipt.detail).slice(0, 60)}`);
  check("执行后复核通过", quarantineReceipt.passed, true);
  check("主机上原路径没了", mode(SECOND), "gone");

  const copy = onHost(`find /usr/local/bin/.lovelyres-backups -type f 2>/dev/null | head -1`);
  console.log(`  留底：${copy || "（没有）"}`);
  check("还留着可以还原的副本", copy.length > 0);
  // The same rules the file manager's removal follows.
  check("副本不带原来的名字结尾", copy, (value) => String(value).endsWith(".removed"));
  check("副本收成了只有属主能读写", mode(copy), "600");
  check("setuid 位在副本上也没了", mode(copy), (value) => (parseInt(String(value), 8) & 0o4000) === 0);

  // ---- 撤销隔离：原路径又有东西了就不动 ----------------------------------
  console.log("\n  隔离之后原路径又出现了文件，再撤销");
  check("隔离的回执也说可以撤销", quarantineReceipt.undoable, true);
  onHost(`printf 'later business change\\n' > ${SECOND}; chmod 0644 ${SECOND}`);
  const blockedUndo = await sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle: quarantine.planHandle }, 300_000);
  console.log(`  → undone=${blockedUndo.undone} · ${String(blockedUndo.detail).slice(0, 80)}`);
  check("后来的改动在，就不撤销", blockedUndo.undone, false);
  check("说得出是因为之后又有了变化", blockedUndo.detail, (value) => /又有了变化/u.test(String(value)));
  check("后来写进去的文件原样留着", onHost(`cat ${SECOND}`), "later business change");
  check("隔离的副本也原样留着", mode(copy), "600");

  // ---- 撤销隔离：原路径空着就放回去 --------------------------------------
  console.log("\n  隔离另一个，再撤销");
  const third = await sidecar.call("emergency-command.run", {
    bindingHandle: binding,
    snapshotHandle: catalog.snapshotHandle,
    commandHandle: suid.commandHandle,
  }, 300_000);
  const back = third.paths.find((entry) => entry.path === PLANTED);
  check("撤销过权限的那个又被扫出来了", back?.pathHandle, (value) => String(value ?? "").length > 0);
  const quarantineBack = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: back.pathHandle, action: "quarantine" }, 180_000);
  await sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle: quarantineBack.planHandle }, 180_000);
  const quarantineBackReceipt = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: quarantineBack.planHandle }, 300_000);
  check("隔离通过", quarantineBackReceipt.passed, true);
  check("原路径没了", mode(PLANTED), "gone");
  const restoredBack = await sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle: quarantineBack.planHandle }, 300_000);
  console.log(`  → undone=${restoredBack.undone} · ${String(restoredBack.detail).slice(0, 80)}`);
  check("撤销完成并复核通过", restoredBack.undone, true);
  check("文件回到了原路径，权限也还是 4755", mode(PLANTED), "4755");
  check("它的隔离副本不在了，另一个还在",
    onHost(`find /usr/local/bin/.lovelyres-backups -type f 2>/dev/null | wc -l | tr -d ' '`), "1");
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
  try { onHost(`rm -rf ${PLANTED} ${SECOND} /usr/local/bin/.lovelyres-backups`); } catch {}
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
