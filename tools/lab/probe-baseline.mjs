// Checks that the baseline scan reads what the host's own programs read.
//
// Every case below is first settled by asking the real daemon (`sshd -T`,
// `sysctl`), then the scan is run through the sidecar and has to agree. A
// disagreement here is a security check reporting a value the host is not
// using, which is worse than no check at all.
//
//   node tools/lab/probe-baseline.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-baseline.mjs
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

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

/** What sshd itself resolves the directive to, with the given file content. */
function sshdObeys(content, directive) {
  // The content goes over encoded: it has newlines and comment markers, and
  // every quoting layer between here and the container would eat one of them.
  const encoded = Buffer.from(content === "" ? "" : `${content}\n`, "utf8").toString("base64");
  onHost(
    `cp /etc/ssh/sshd_config /tmp/probe.conf` +
    ` && sed -i '/^[#[:space:]]*${directive}/Id' /tmp/probe.conf` +
    ` && printf '%s' '${encoded}' | base64 -d >> /tmp/probe.conf`,
  );
  // No `$2` here: this string passes through an outer shell that would expand
  // it to nothing and leave awk printing the whole line.
  return onHost(`sshd -T -f /tmp/probe.conf 2>/dev/null | grep -i '^${directive} ' | cut -d' ' -f2-`);
}

/** Replaces sshd_config with the probe copy, so the scan reads the same file. */
function installProbeConfig() {
  onHost("cp /etc/ssh/sshd_config /tmp/sshd_config.bak && cp /tmp/probe.conf /etc/ssh/sshd_config");
}

function restoreConfig() {
  onHost("[ -f /tmp/sshd_config.bak ] && cp /tmp/sshd_config.bak /etc/ssh/sshd_config; rm -f /tmp/probe.conf /tmp/sshd_config.bak");
}

const backend = "D:/LovelyRes/target/debug/lovelyres-backend.exe";
const sidecar = new Sidecar(backend, newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("baseline.catalog.get", {});
  const rootLogin = catalog.items.find((item) => item.title.includes("root 直接登录"));
  if (rootLogin === undefined) throw new Error("no root-login item in the catalogue");
  console.log(`目录 ${catalog.items.length} 项；用「${rootLogin.title}」核对读值\n`);

  /**
   * Runs one shaped sshd_config through both the daemon and the scan.
   *
   * `agrees` is false only where the file genuinely sets nothing: sshd still
   * answers with its compiled-in default, and the scan is right to say the
   * file does not set it rather than to report a value nobody wrote down.
   */
  async function compare(label, content, agrees = true) {
    const obeyed = sshdObeys(content, "PermitRootLogin");
    installProbeConfig();
    const scan = await sidecar.call("baseline.scan", { bindingHandle: binding }, 90_000);
    const observed = scan.statuses.find((entry) => entry.itemHandle === rootLogin.itemHandle);
    console.log(`${label}\n      sshd 生效: ${obeyed}   扫描读到: ${observed?.observed}   判定: ${observed?.compliant ? "合规" : "不合规"}`);
    if (agrees) check(`  ${label} — 扫描读到的就是 sshd 生效的`, observed?.observed, obeyed);
    return observed;
  }

  // The case that was reporting a wide-open host as compliant.
  const a = await compare(
    "A  生效行在前，发行版注释默认在后",
    "PermitRootLogin yes\n#PermitRootLogin no",
  );
  check("  A — 放行 root 必须判为不合规", a?.compliant, false);

  await compare(
    "B  注释默认在前，生效行在后",
    "#PermitRootLogin no\nPermitRootLogin yes",
  );

  // sshd keeps the first value it is given, not the last.
  const c = await compare(
    "C  两条生效行，先 no 后 yes",
    "PermitRootLogin no\nPermitRootLogin yes",
  );
  check("  C — 取第一条，所以判为合规", c?.compliant, true);

  const d = await compare(
    "D  两条生效行，先 yes 后 no",
    "PermitRootLogin yes\nPermitRootLogin no",
  );
  check("  D — 取第一条，所以判为不合规", d?.compliant, false);

  // Nothing set at all: the file says nothing, and the scan must say so
  // rather than borrowing a value from a comment.
  const e = await compare("E  整个文件里没有这条设置", "", false);
  check("  E — 报未设置，不是从注释里捡一个值", e?.observedKind, "missing");

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  process.exitCode = 1;
} finally {
  restoreConfig();
  sidecar.close();
}
