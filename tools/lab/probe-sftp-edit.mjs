// Reads a real file over SFTP, writes it back changed, and checks the machine.
//
// What only a real target can show:
//   1. the read hands out a hash of the whole file, and the write that quotes
//      it lands — verified by reading the file on the host, not by trusting the
//      receipt;
//   2. a write quoting a stale hash is refused, which is the whole point of
//      carrying one: two people editing the same file must not silently
//      overwrite each other;
//   3. the plan says what it is about to do in words an operator can act on,
//      and nothing is written before the plan is confirmed.
//
//   node tools/lab/probe-sftp-edit.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";
// The app's own validator, loaded from its TypeScript source through Node's
// built-in type stripping (Node 22.18 or later), not a copy of its rules.
//
// This probe talks straight to the backend, which is the whole point — but it
// also means it skips the host bridge, and the bridge and the SFTP page
// re-validate every reply before the operator sees it. A read that satisfies
// the backend and fails that check reaches the operator as "读不到这个文件",
// which is exactly what happened: the projection started keeping a file's
// trailing newline and the validator was still counting it as an extra line,
// so every ordinary text file was rejected. Running the real validator here
// closes that gap.
import { isSftpTextPreview } from "../../ui/src/shared/sftp-browser-contract.ts";

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

async function refuses(label, run) {
  try {
    await run();
    failures += 1;
    console.log(`  ✗ ${label} —— 居然成功了`);
  } catch (error) {
    console.log(`  ✓ ${label}（${String(error.message).slice(0, 70)}）`);
  }
}

const which = process.env.LAB ?? "arena";
const target = labTarget(which);
const container = which === "arena" ? "lab-arena" : `svc-${which}`;
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

/** Reads the target directly, so "it was written" is not the tool's own claim. */
function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc",
      `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const REMOTE = "/tmp/lovelyres-edit-probe.conf";
const ORIGINAL = "first = 1\nsecond = 2\nthird = 3\n";

/** Walks the browser down to /tmp and returns the listing. */
async function openTmp(binding) {
  let snapshot = await sidecar.call("sftp-browser.open", { bindingHandle: binding }, 60_000);
  const tmp = (snapshot.entries ?? []).find((entry) => entry.name === "tmp");
  if (tmp === undefined) throw new Error("靶机根目录下没有 tmp");
  return sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding,
    browserHandle: snapshot.browserHandle,
    directoryHandle: tmp.entryHandle,
  }, 60_000);
}

try {
  console.log(`连接 ${target.host}:${target.port}（${container}）\n`);
  // %b, not %s: the escapes have to become real newlines on the target.
  onHost(`printf '%b' ${JSON.stringify(ORIGINAL)} > ${REMOTE}`);
  check("靶机上先放好一个文件", onHost(`cat ${REMOTE}`), ORIGINAL.trim());

  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;

  // --- 读
  console.log("=== 读文件");
  let listing = await openTmp(binding);
  let file = (listing.entries ?? []).find((entry) => entry.name === "lovelyres-edit-probe.conf");
  check("目录里找得到它", file?.name, "lovelyres-edit-probe.conf");
  const read = await sidecar.call("sftp-browser.text.read", {
    bindingHandle: binding,
    browserHandle: listing.browserHandle,
    fileHandle: file.entryHandle,
  }, 60_000);
  // Byte for byte, trailing newline included. Reading a file and saving it
  // back unchanged must not change it, and the projection used to drop the
  // final newline — which every text file on a Unix machine has.
  check("界面自己的校验器认这份回复", isSftpTextPreview(read), true);
  check("读到的就是文件本身，一个字节不差", read.text, ORIGINAL);
  check("说清了这份内容可以原样写回", read.exact, true);
  check("带回了 64 位小写十六进制的摘要", read.sha256, (value) => /^[0-9a-f]{64}$/u.test(value ?? ""));
  check("摘要就是这个文件的摘要", read.sha256, onHost(`sha256sum ${REMOTE} | cut -d' ' -f1`));
  check("没有截断", read.truncated, false);

  // --- 计划
  console.log("\n=== 计划写回");
  const edited = "first = 1\nsecond = CHANGED\nthird = 3\nfourth = 4\n";
  const plan = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding,
    browserHandle: listing.browserHandle,
    kind: "write-text",
    entryHandles: [file.entryHandle],
    text: edited,
    expectedSha256: read.sha256,
  }, 60_000);
  console.log(`  ${plan.summary}`);
  check("计划说的是中文，不是实现术语", plan.summary, (value) =>
    (value ?? "").includes("写回") && !/atomically|SHA-256/u.test(value ?? ""));
  check("说清了要动哪个文件", plan.summary, (value) => (value ?? "").includes(REMOTE));
  check("标了这是危险操作", plan.dangerous, true);
  check("说了出问题怎么恢复", plan.restoreDescription, (value) => (value ?? "").length > 0);
  check("还没确认", plan.state, "planned");
  // Planning must not have touched anything.
  check("计划阶段主机上的文件没有动", onHost(`cat ${REMOTE}`), ORIGINAL.trim());

  // --- 未确认不能执行
  //
  // On its own plan, because a refused execute consumes the plan it was aimed
  // at — that is how every operation kind here behaves, and it is the safe
  // direction, but it does mean this check cannot share a plan with the one
  // below.
  console.log("\n=== 没确认就执行");
  const doomed = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding,
    browserHandle: listing.browserHandle,
    kind: "write-text",
    entryHandles: [file.entryHandle],
    text: "must not be written\n",
    expectedSha256: read.sha256,
  }, 60_000);
  await refuses("被拒绝", () => sidecar.call("sftp-browser.operation.execute", {
    bindingHandle: binding, planHandle: doomed.planHandle,
  }, 60_000));
  check("被拒之后主机上还是原样", onHost(`cat ${REMOTE}`), ORIGINAL.trim());
  await refuses("烧掉的计划不能再确认", () => sidecar.call("sftp-browser.operation.confirm", {
    bindingHandle: binding, planHandle: doomed.planHandle,
  }, 60_000));

  // --- 确认后执行
  console.log("\n=== 确认后执行");
  await sidecar.call("sftp-browser.operation.confirm", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 60_000);
  const receipt = await sidecar.call("sftp-browser.operation.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 120_000);
  check("执行后复核通过", receipt.passed, true);
  check("没有触发回滚", receipt.restored, false);
  // The host, not the receipt, says whether it worked.
  check("主机上的内容真的变了", onHost(`cat ${REMOTE}`), edited.trim());
  check("新内容是完整的，不是被截断的", onHost(`wc -l < ${REMOTE}`), "4");

  // --- 用过期的摘要写
  console.log("\n=== 拿旧摘要再写一次（别人已经改过了）");
  listing = await openTmp(binding);
  file = (listing.entries ?? []).find((entry) => entry.name === "lovelyres-edit-probe.conf");
  const stalePlan = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding,
    browserHandle: listing.browserHandle,
    kind: "write-text",
    entryHandles: [file.entryHandle],
    text: "clobbered\n",
    // The hash from before the write above: exactly the situation where a
    // second operator opened the file first and saved last.
    expectedSha256: read.sha256,
  }, 60_000);
  await sidecar.call("sftp-browser.operation.confirm", {
    bindingHandle: binding, planHandle: stalePlan.planHandle,
  }, 60_000);
  // This comes back as a receipt saying it failed, not as a thrown error: the
  // call completed, the write did not.
  let staleReceipt = null;
  try {
    staleReceipt = await sidecar.call("sftp-browser.operation.execute", {
      bindingHandle: binding, planHandle: stalePlan.planHandle,
    }, 120_000);
    check("回执说没通过", staleReceipt.passed, false);
  } catch (error) {
    console.log(`  ✓ 直接报错也可以（${String(error.message).slice(0, 60)}）`);
  }
  check("别人的改动没有被覆盖掉", onHost(`cat ${REMOTE}`), edited.trim());

  // --- 伪造的摘要
  console.log("\n=== 形状不对的摘要");
  await refuses("计划都建不出来", () => sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding,
    browserHandle: listing.browserHandle,
    kind: "write-text",
    entryHandles: [file.entryHandle],
    text: "x\n",
    expectedSha256: "not-a-digest",
  }, 60_000));

  console.log("\n=== 收尾");
  onHost(`rm -f ${REMOTE}`);
  check("清理干净", onHost(`test -e ${REMOTE} && echo yes || echo no`), "no");
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
