// Checks that the configuration file behind a check comes back as it is on
// the host, with the line the host obeys marked.
//
// The marked line and the reported value have to agree: a verdict of 不合规
// with the wrong line highlighted is worse than no highlight at all.
//
//   node tools/lab/probe-baseline-file.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-baseline-file.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

/** Writes a file over an encoded payload, so no quoting layer eats a newline. */
function writeOnHost(path, content) {
  const encoded = Buffer.from(content, "utf8").toString("base64");
  onHost(`printf '%s' '${encoded}' | base64 -d > ${path}`);
}

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("baseline.catalog.get", {});
  const rootLogin = catalog.items.find((item) => item.title.includes("root 直接登录"));
  if (rootLogin === undefined) throw new Error("no root-login item in the catalogue");

  onHost("cp /etc/ssh/sshd_config /tmp/sshd_config.bak");

  // The shape the scan used to get wrong: an active line with the packaged
  // commented default underneath it.
  writeOnHost("/etc/ssh/sshd_config", [
    "Port 22",
    "PermitRootLogin yes",
    "#PermitRootLogin prohibit-password",
    "PasswordAuthentication yes",
    "PermitRootLogin no",
    "",
  ].join("\n"));

  const file = await sidecar.call("baseline.file.read", {
    bindingHandle: binding,
    itemHandle: rootLogin.itemHandle,
  }, 60_000);

  const lines = file.text.split("\n");
  console.log(`\n${file.path}  （这项检查读 ${file.key}）`);
  lines.forEach((line, index) => {
    const mention = file.mentions.find((entry) => entry.line === index);
    const mark = mention === undefined ? "   "
      : mention.effective ? "=> " : mention.commented ? " # " : " . ";
    console.log(`${mark}${String(index + 1).padStart(2)}  ${line}`);
  });

  check("文件内容跟主机上的一致", file.text, onHost("cat /etc/ssh/sshd_config").replace(/\r/gu, ""));
  check("三处提及全部标出来了", file.mentions.length, 3);
  check("注释那行标成注释", file.mentions[1]?.commented, true);
  check("注释那行不生效", file.mentions[1]?.effective, false);
  // sshd keeps the first value it is given, so line 2 wins over line 5.
  check("生效的是第 2 行", file.mentions[0]?.effective, true);
  check("后面那条同名设置不生效", file.mentions[2]?.effective, false);

  // The highlighted line and the scanned value have to be the same claim.
  const scan = await sidecar.call("baseline.scan", { bindingHandle: binding }, 90_000);
  const observed = scan.statuses.find((entry) => entry.itemHandle === rootLogin.itemHandle);
  const effectiveLine = lines[file.mentions.find((entry) => entry.effective).line];
  console.log(`\n扫描读到 "${observed.observed}"，标出的那行是 "${effectiveLine.trim()}"`);
  check("标出的行就是扫描读到的值", effectiveLine.trim().endsWith(observed.observed), true);
  check("放行 root 判为不合规", observed.compliant, false);

  // A forged handle names nothing.
  const forged = await sidecar
    .call("baseline.file.read", { bindingHandle: binding, itemHandle: "baseline-item-forged" })
    .then(() => "accepted", (error) => error.message);
  check("伪造的条目句柄被拒绝", /invalid|handle|参数/iu.test(forged), true);

  // A file that is not there says so rather than looking empty.
  onHost("mv /etc/security/faillock.conf /tmp/faillock.bak 2>/dev/null || true");
  const faillock = catalog.items.find((item) => item.title.includes("锁定"));
  if (faillock !== undefined) {
    const missing = await sidecar.call("baseline.file.read", {
      bindingHandle: binding,
      itemHandle: faillock.itemHandle,
    }, 60_000);
    console.log(`\n${missing.path}  exists=${missing.exists}`);
    check("文件不存在时明确说不存在", missing.exists, false);
    check("不存在的文件不带内容", missing.text, "");
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  process.exitCode = 1;
} finally {
  onHost("[ -f /tmp/sshd_config.bak ] && cp /tmp/sshd_config.bak /etc/ssh/sshd_config; rm -f /tmp/sshd_config.bak");
  onHost("[ -f /tmp/faillock.bak ] && mv /tmp/faillock.bak /etc/security/faillock.conf; true");
  sidecar.close();
}
