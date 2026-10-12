// Puts a file onto a real machine and packs real files up on it, then checks
// the machine rather than the receipt.
//
// These are the last two destructive paths in the file manager that had never
// been run against anything but an in-memory double. Both matter in the same
// way: an operator uploads a tool they need in a hurry, or packs up evidence
// they are about to be asked for, and a receipt that says "done" while the
// bytes are wrong is worse than an error — nobody checks a green tick.
//
// What each one has to get right on a real machine:
//   upload  — the bytes land byte-for-byte, under the name that was planned,
//             in the directory that was planned, and refusing to overwrite
//             something already sitting there.
//   archive — the pack really contains what was selected and nothing else,
//             and tar/gzip/zstd are named the way the machine has them (a
//             machine without zstd has to say so rather than write a
//             truncated pack).
//
//   node tools/lab/probe-sftp-upload-archive.mjs
//   LAB=alpine node tools/lab/probe-sftp-upload-archive.mjs
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
const DIRECTORY = "/tmp/lovelyres-upload-probe";
const UPLOADED = "incident-tool.sh";
// Big enough to cross a chunk boundary, and not compressible into nothing.
const PAYLOAD = Buffer.concat([
  Buffer.from("#!/bin/sh\n# planted by the upload probe\n", "utf8"),
  Buffer.from(Array.from({ length: 300_000 }, (_, index) => index % 251)),
]);

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

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
const staging = mkdtempSync(join(tmpdir(), "lovelyres-upload-probe-"));
const localFile = join(staging, UPLOADED);
writeFileSync(localFile, PAYLOAD);
const wanted = createHash("sha256").update(PAYLOAD).digest("hex");

async function walkTo(sidecar, binding, browser, path) {
  let listing = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding,
    browserHandle: browser.browserHandle,
    directoryHandle: browser.rootHandle ?? browser.directoryHandle ?? browser.currentHandle,
  }, 120_000);
  let handle = browser.rootHandle ?? browser.directoryHandle ?? browser.currentHandle;
  for (const segment of path.split("/").filter(Boolean)) {
    const next = listing.entries.find((entry) => entry.name === segment);
    if (next === undefined) {
      throw new Error(`no ${segment} in ${listing.entries.map((entry) => entry.name).join(",")}`);
    }
    handle = next.entryHandle;
    listing = await sidecar.call("sftp-browser.directory.list", {
      bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: handle,
    }, 120_000);
  }
  return { handle, listing };
}

try {
  onHost(`rm -rf ${DIRECTORY}; mkdir -p ${DIRECTORY}`);

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding }, 120_000);
  const browserHandle = browser.browserHandle;
  let { handle: directoryHandle } = await walkTo(sidecar, binding, browser, DIRECTORY);

  // ---- upload ----------------------------------------------------------
  console.log("\n  上传");
  const staged = await sidecar.call("sftp-browser.upload.stage", {
    bindingHandle: binding, localPath: localFile, name: UPLOADED,
  }, 120_000);
  check("本地文件先进了暂存区", staged.stagedHandle, (value) => String(value ?? "").length > 0);
  check("暂存区如实报出了文件大小", String(staged.bytes ?? staged.sizeBytes ?? ""), String(PAYLOAD.length));

  const uploadPlan = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding, browserHandle, kind: "upload",
    entryHandles: [directoryHandle], stagedHandle: staged.stagedHandle, name: UPLOADED,
  }, 120_000);
  console.log(`  计划：${String(uploadPlan.summary).slice(0, 100)}`);
  check("计划说清了要放哪个文件", uploadPlan.summary, (value) => String(value).includes(UPLOADED));
  check("说了出问题怎么恢复", uploadPlan.restoreDescription, (value) => String(value ?? "").length > 4);
  check("上传前主机上还没有这个文件",
    onHost(`test -e ${DIRECTORY}/${UPLOADED} && echo yes || echo no`), "no");

  await sidecar.call("sftp-browser.operation.confirm",
    { bindingHandle: binding, planHandle: uploadPlan.planHandle }, 120_000);
  const uploadReceipt = await sidecar.call("sftp-browser.operation.execute",
    { bindingHandle: binding, planHandle: uploadPlan.planHandle }, 300_000);
  console.log(`  回执：passed=${uploadReceipt.passed} restored=${uploadReceipt.restored} · ${String(uploadReceipt.detail).slice(0, 60)}`);
  check("执行后复核通过", uploadReceipt.passed, true);
  check("没有触发回滚", uploadReceipt.restored, false);

  // The machine, not the receipt: every byte, not just the size.
  const landed = onHost(`sha256sum ${DIRECTORY}/${UPLOADED} 2>/dev/null | cut -d' ' -f1`);
  console.log(`  主机上算出来的 sha256：${landed || "（没有这个文件）"}`);
  check("落到主机上的内容一字不差", landed, wanted);
  check("大小也对得上",
    onHost(`wc -c < ${DIRECTORY}/${UPLOADED} 2>/dev/null | tr -d " "`), String(PAYLOAD.length));

  // Uploading the same name again must not quietly replace what is there.
  const second = await sidecar.call("sftp-browser.upload.stage", {
    bindingHandle: binding, localPath: localFile, name: UPLOADED,
  }, 120_000);
  ({ handle: directoryHandle } = await walkTo(sidecar, binding, browser, DIRECTORY));
  const clash = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding, browserHandle, kind: "upload",
    entryHandles: [directoryHandle], stagedHandle: second.stagedHandle, name: UPLOADED,
  }, 120_000).then(async (plan) => {
    await sidecar.call("sftp-browser.operation.confirm",
      { bindingHandle: binding, planHandle: plan.planHandle }, 120_000);
    return sidecar.call("sftp-browser.operation.execute",
      { bindingHandle: binding, planHandle: plan.planHandle }, 300_000)
      .then((receipt) => `执行了：passed=${receipt.passed}`)
      .catch((error) => String(error.message).slice(0, 70));
  }).catch((error) => String(error.message).slice(0, 70));
  console.log(`  同名再传一次 → ${clash}`);
  check("同名文件不会被悄悄覆盖", clash, (value) => !String(value).startsWith("执行了：passed=true"));
  check("原来那份还是原来的内容",
    onHost(`sha256sum ${DIRECTORY}/${UPLOADED} 2>/dev/null | cut -d' ' -f1`), wanted);

  // ---- archive ---------------------------------------------------------
  console.log("\n  打包");
  onHost(`mkdir -p ${DIRECTORY}/evidence;`
    + ` printf 'alpha' > ${DIRECTORY}/evidence/one.log;`
    + ` printf 'beta' > ${DIRECTORY}/evidence/two.log;`
    + ` printf 'not selected' > ${DIRECTORY}/unrelated.txt`);
  ({ handle: directoryHandle } = await walkTo(sidecar, binding, browser, DIRECTORY));
  const listing = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding, browserHandle, directoryHandle,
  }, 120_000);
  const evidence = listing.entries.find((entry) => entry.name === "evidence");
  check("要打包的目录在列表里", evidence?.name, "evidence");

  // Ask the machine what it can actually do before demanding it do it. The
  // openSUSE Leap image has neither tar nor gzip, and an operator on that
  // machine has to be told so — a probe that insists on success there would be
  // testing its own assumptions, not the product.
  const can = (tool) => onHost(`command -v ${tool} >/dev/null 2>&1 && echo yes || echo no`) === "yes";
  const hasTar = can("tar");
  const hasGzip = can("gzip");
  const hasZstd = can("zstd");
  console.log(`  这台机器有：tar=${hasTar ? "有" : "没有"} gzip=${hasGzip ? "有" : "没有"} zstd=${hasZstd ? "有" : "没有"}`);

  async function pack(format, extension) {
    const name = `case.${extension}`;
    const plan = await sidecar.call("sftp-browser.operation.plan", {
      bindingHandle: binding, browserHandle, kind: "archive",
      entryHandles: [evidence.entryHandle], name, format,
    }, 120_000);
    check(`${format}：计划说清了打成什么`, plan.summary, (value) => String(value).includes(name));
    check(`${format}：说了出问题怎么恢复`, plan.restoreDescription, (value) => String(value ?? "").length > 4);
    await sidecar.call("sftp-browser.operation.confirm",
      { bindingHandle: binding, planHandle: plan.planHandle }, 120_000);
    const receipt = await sidecar.call("sftp-browser.operation.execute",
      { bindingHandle: binding, planHandle: plan.planHandle }, 300_000)
      .then((value) => ({ passed: value.passed, detail: String(value.detail) }))
      .catch((error) => ({ passed: false, detail: String(error.message) }));
    console.log(`  ${format} → passed=${receipt.passed} · ${receipt.detail.slice(0, 78)}`);
    return { name, ...receipt };
  }

  for (const [format, extension, reader, supported] of [
    ["tar", "tar", "tar tf", hasTar],
    ["tar-gzip", "tar.gz", "tar tzf", hasTar && hasGzip],
    ["tar-zstd", "tar.zst", "tar --zstd -tf", hasTar && hasZstd],
  ]) {
    const receipt = await pack(format, extension);
    if (supported) {
      check(`${format}：执行后复核通过`, receipt.passed, true);
      // A pack is only worth anything if the machine can open it again.
      const entries = onHost(`${reader} ${DIRECTORY}/${receipt.name} 2>&1 | sort | tr '\\n' ' '`);
      console.log(`  ${format} 里装着：${entries}`);
      check(`${format}：包里装的就是选中的那些`, entries,
        (value) => String(value).includes("one.log") && String(value).includes("two.log"));
      check(`${format}：没把没选的也装进去`, entries,
        (value) => !String(value).includes("unrelated.txt"));
      check(`${format}：包本身是完好的`, entries,
        (value) => !/error|cannot|unexpected/iu.test(String(value)));
    } else {
      // The one outcome that would be a lie: a green tick over a pack that is
      // not a pack.
      check(`${format}：打不了就不该说打好了`, receipt.passed, false);
      // "操作未能完成" is the same four words whether the machine is missing a
      // tool, out of disk, or refusing permission. Here it knows which, and
      // says what to do instead.
      check(`${format}：说得出是为什么、下一步该怎么办`, receipt.detail,
        (value) => /没有|打不出/u.test(String(value)) && /tar|下载/u.test(String(value)));
      const leftover = onHost(`test -e ${DIRECTORY}/${receipt.name} && echo yes || echo no`);
      check(`${format}：失败之后没在主机上留下半个包`, leftover, "no");
    }
  }
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
  rmSync(staging, { recursive: true, force: true });
  try { onHost(`rm -rf ${DIRECTORY}`); } catch {}
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
