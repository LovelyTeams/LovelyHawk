// Deletes a real file through the file manager, and checks the machine rather
// than the receipt.
//
// Deleting is the one action an operator cannot take back by hand, so the core
// does not really delete: it moves the file aside and the verification only
// passes when the original is gone *and* a recoverable copy exists. That design
// has never been run against a real target — which is the half that matters,
// because a backup that is not there is indistinguishable from one that is
// until someone needs it.
//
// The copy has to be kept somewhere, and it is kept beside the original —
// crossing a filesystem boundary would fail on machines where /var and /tmp are
// separate mounts, and a backup that cannot be written is a delete that cannot
// happen. That put the copy of a removed webshell inside the directory the web
// server serves, still named `.php` and still world-readable: fetching it
// returned 200 and the payload still ran. So the checks below are not only "is
// the copy there" but "is the copy inert" — right name, right permissions, and
// on a machine that serves the directory, no longer answering.
//
//   node tools/lab/probe-sftp-remove.mjs
//   LAB=rocky node tools/lab/probe-sftp-remove.mjs
//   LAB=arena node tools/lab/probe-sftp-remove.mjs   # the web-root scenario
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
const NAME = "webshell.php";
// Says so out loud if anything ever runs it.
const CONTENT = "<?php echo \"SHELL-RAN\"; system($_GET['c']); ?>";

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

/// A directory this machine actually answers HTTP requests out of, if it has
/// one. That is where a removal has to be judged: the copy it leaves behind
/// lands next to the original, so on these machines it lands somewhere the
/// internet can ask for.
function servedDirectory() {
  const answer = onHost(
    "for d in /var/www/html /var/www /usr/share/nginx/html /srv/http; do"
    + ' [ -d "$d" ] || continue;'
    + ' printf served > "$d/.lovelyres-probe-served";'
    + " code=$(curl -s -o /dev/null -w '%{http_code}'"
    + ' "http://127.0.0.1/.lovelyres-probe-served" 2>/dev/null);'
    + ' rm -f "$d/.lovelyres-probe-served";'
    + ' if [ "$code" = "200" ]; then echo "$d"; break; fi;'
    + " done; exit 0",
  );
  return answer.split("\n").map((line) => line.trim()).filter(Boolean).pop() ?? "";
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

const served = servedDirectory();
const DIRECTORY = served === "" ? "/tmp/lovelyres-remove-probe" : served;
const REMOTE = `${DIRECTORY}/${NAME}`;
const BACKUPS = `${DIRECTORY}/.lovelyres-backups`;
console.log(served === ""
  ? "  这台机器没有对外提供的目录，在 /tmp 里做删除验证"
  : `  这台机器真的在对外提供 ${served}，webshell 就放那儿`);

try {
  // Planted over base64: the content is a webshell, and every quoting layer
  // between here and the container wants to expand the `$_GET` in it.
  const encoded = Buffer.from(CONTENT, "utf8").toString("base64");
  onHost(`mkdir -p ${DIRECTORY}; printf '%s' ${encoded} | base64 -d > ${REMOTE}; chmod 644 ${REMOTE}`);
  check("靶机上先放好一个要删的文件", onHost(`cat ${REMOTE}`), CONTENT);
  if (served !== "") {
    const before = onHost(`curl -s "http://127.0.0.1/${NAME}" 2>/dev/null | head -c 200`);
    console.log(`  删之前网站给出的内容：${JSON.stringify(before.slice(0, 60))}`);
    check("删之前它确实是能被网站访问到的", before.length > 0);
  }

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding }, 120_000);
  const browserHandle = browser.browserHandle;

  // Walk to the directory the way the window does: by handle, never by path.
  let listing = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding,
    browserHandle,
    directoryHandle: browser.rootHandle ?? browser.directoryHandle ?? browser.currentHandle,
  }, 120_000);
  for (const segment of DIRECTORY.split("/").filter(Boolean)) {
    const next = listing.entries.find((entry) => entry.name === segment);
    if (next === undefined) throw new Error(`no ${segment} in ${listing.entries.map((e) => e.name).join(",")}`);
    listing = await sidecar.call("sftp-browser.directory.list", {
      bindingHandle: binding, browserHandle, directoryHandle: next.entryHandle,
    }, 120_000);
  }
  const target = listing.entries.find((entry) => entry.name === NAME);
  check("文件管理器里找得到它", target?.name, NAME);

  const plan = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding, browserHandle, kind: "remove", entryHandles: [target.entryHandle],
  }, 120_000);
  console.log(`  计划：${String(plan.summary)}`);
  check("计划说清了要删哪个文件", plan.summary, (value) => String(value).includes(NAME));
  check("标了这是危险操作", plan.dangerous, true);
  // Where the copy lands is the operator's business before they press the
  // button, not after: on these machines it lands in a directory the internet
  // can ask for, and only the plan text can tell them so.
  check("计划里写明了备份落在哪儿", plan.summary,
    (value) => String(value).includes(".lovelyres-backups/"));
  // A delete that could not be undone would be the one action worth refusing.
  check("说了出问题怎么恢复", plan.restoreDescription, (value) => String(value ?? "").length > 4);
  check("还没确认", plan.state, "planned");
  check("计划阶段主机上文件还在", onHost(`test -e ${REMOTE} && echo yes || echo no`), "yes");

  await sidecar.call("sftp-browser.operation.confirm", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 120_000);
  const receipt = await sidecar.call("sftp-browser.operation.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 180_000);
  console.log(`  回执：passed=${receipt.passed} restored=${receipt.restored} · ${String(receipt.detail).slice(0, 60)}`);
  check("执行后复核通过", receipt.passed, true);
  check("没有触发回滚", receipt.restored, false);

  // The machine, not the receipt.
  check("主机上文件真的没了", onHost(`test -e ${REMOTE} && echo yes || echo no`), "no");
  // The verification claims a recoverable copy exists; that claim is only worth
  // anything if the bytes are still findable on the machine.
  const found = onHost(
    `want=$(printf '%s' ${encoded} | base64 -d | sha256sum | cut -d" " -f1);`
    + ` find ${BACKUPS} -type f 2>/dev/null | while read -r f; do`
    + ` [ "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" = "$want" ] && echo "$f"; done | head -3`,
  );
  console.log(`  还能找回来的副本：${found || "（没有）"}`);
  check("备份真的在机器上，内容一字不差", found.length > 0);
  check("复核说的就是这件事", receipt.detail, (value) => String(value).length > 0);

  // Kept, but no longer live. The name is what stops it from being executed —
  // a web server picks its handler by the final extension — and the modes are
  // what stop it from being read at all.
  const backup = found.split("\n")[0].trim();
  check("副本不再叫原来的扩展名", backup, (value) => !String(value).endsWith(".php"));
  check("副本名字后面加了 .removed", backup, (value) => String(value).endsWith(".removed"));
  check("原来的文件名还看得出来，方便认", backup, (value) => String(value).includes(NAME));
  const fileMode = onHost(`stat -c %a ${backup} 2>/dev/null || echo unknown`);
  const directoryMode = onHost(`stat -c %a ${BACKUPS} 2>/dev/null || echo unknown`);
  console.log(`  副本权限 ${fileMode}，备份目录权限 ${directoryMode}`);
  check("副本收成了只有属主能读写", fileMode, "600");
  check("备份目录也只有属主进得去", directoryMode, "700");

  if (served !== "") {
    // The question the whole thing is for: the operator was told the file was
    // gone. Ask the web server whether it agrees.
    const name = backup.split("/").pop();
    const body = onHost(`curl -s "http://127.0.0.1/.lovelyres-backups/${name}" 2>/dev/null | head -c 200`);
    const code = onHost(
      "curl -s -o /dev/null -w '%{http_code}'"
      + ` "http://127.0.0.1/.lovelyres-backups/${name}" 2>/dev/null || echo none`,
    );
    console.log(`  网站现在对这个副本的回答：${code} ${JSON.stringify(body.slice(0, 60))}`);
    check("网站不再把副本原样交出来", body, (value) => !String(value).includes("system($_GET"));
    check("更不会去执行它", body, (value) => !String(value).includes("SHELL-RAN"));
    check("请求副本已经不是 200 了", code, (value) => String(value) !== "200");
    // And the original really is gone from the web root, not just renamed in
    // place under a name the server would still hand out.
    const original = onHost(`curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/${NAME}" 2>/dev/null || echo none`);
    check("原路径也不再有东西", original, (value) => String(value) !== "200");
  }

  // A plan is single-use: running it twice must not delete anything else.
  const again = await sidecar.call("sftp-browser.operation.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 120_000).then(() => "ran again").catch((error) => String(error.message).slice(0, 60));
  console.log(`  再执行一次 → ${again}`);
  check("同一个计划不能跑第二次", again, (value) => value !== "ran again");
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
  // Only what this probe put there: on a machine with a real web root the
  // directory itself is not ours to remove.
  try { onHost(`rm -rf ${BACKUPS} ${REMOTE}`); } catch {}
  if (served === "") {
    try { onHost(`rmdir ${DIRECTORY} 2>/dev/null || true`); } catch {}
  }
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
