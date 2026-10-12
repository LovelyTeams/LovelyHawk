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

/**
 * Keeps the machine's own sshd_config aside, once, before any case runs.
 *
 * Each case used to build its file from whatever the previous case had
 * installed, so a case that wrote a `Match` line left it there for every case
 * after it — and the one that then disagreed with sshd looked like a bug in the
 * scan rather than in the harness. Every case now starts from the same file.
 */
function keepPristineConfig() {
  onHost("[ -f /tmp/sshd_config.pristine ] || cp /etc/ssh/sshd_config /tmp/sshd_config.pristine");
  // Some images ship a drop-in that sets the very directive under test — Alma
  // carries `25-permitrootlogin.conf` with `yes` in it. Both sshd and the scan
  // obey it, so they agree, and every case about the main file becomes a
  // statement about a file nothing reads. Moved aside for the run and put back
  // afterwards, so each case tests what it says it tests.
  onHost(
    "if [ -d /etc/ssh/sshd_config.d ] && [ ! -d /tmp/sshd_config.d.aside ]; then"
    + " mv /etc/ssh/sshd_config.d /tmp/sshd_config.d.aside && mkdir -p /etc/ssh/sshd_config.d;"
    // The Include cases need the directory; one made here is removed again.
    + " elif [ ! -e /etc/ssh/sshd_config.d ]; then mkdir /etc/ssh/sshd_config.d && touch /tmp/sshd_config.d.created; fi",
  );
}

/**
 * A directive spelled so any sed matches it whatever its case.
 *
 * busybox sed has no `I` address flag and fails the whole command on it, which
 * is why this probe had never once run on Alpine.
 */
function anyCase(directive) {
  return [...directive].map((letter) => `[${letter.toUpperCase()}${letter.toLowerCase()}]`).join("");
}

/** What sshd itself resolves the directive to, with the given file content. */
function sshdObeys(content, directive) {
  // The content goes over encoded: it has newlines and comment markers, and
  // every quoting layer between here and the container would eat one of them.
  const encoded = Buffer.from(content === "" ? "" : `${content}\n`, "utf8").toString("base64");
  onHost(
    `cp /tmp/sshd_config.pristine /tmp/probe.conf` +
    ` && sed -i '/^[#[:space:]]*${anyCase(directive)}/d' /tmp/probe.conf` +
    ` && printf '%s' '${encoded}' | base64 -d >> /tmp/probe.conf`,
  );
  // No `$2` here: this string passes through an outer shell that would expand
  // it to nothing and leave awk printing the whole line.
  return onHost(`sshd -T -f /tmp/probe.conf 2>/dev/null | grep -i '^${directive} ' | cut -d' ' -f2-`);
}

/** Replaces sshd_config with the probe copy, so the scan reads the same file. */
function installProbeConfig() {
  onHost("cp /tmp/probe.conf /etc/ssh/sshd_config");
}

/** Outside sshd_config.d, so the scan may read it but never name it. */
const OUTSIDE = "/etc/ssh/lovelyhawk-probe-outside.conf";

/**
 * A main file and its drop-ins, laid out as given, with every Include line of
 * the packaged file removed so the case decides where (and whether) one sits.
 */
function sshdObeysLayout(main, dropIns, outside = null) {
  const encode = (text) => Buffer.from(`${text}\n`, "utf8").toString("base64");
  let command = "rm -f /etc/ssh/sshd_config.d/*.conf " + OUTSIDE
    + " && cp /tmp/sshd_config.pristine /tmp/probe.conf"
    + ` && sed -i '/^[#[:space:]]*${anyCase("PermitRootLogin")}/d; /^[[:space:]]*${anyCase("Include")}/d' /tmp/probe.conf`
    + ` && printf '%s' '${encode(main)}' | base64 -d >> /tmp/probe.conf`;
  for (const [name, text] of Object.entries(dropIns)) {
    command += ` && printf '%s' '${encode(text)}' | base64 -d > /etc/ssh/sshd_config.d/${name}`;
  }
  if (outside !== null) command += ` && printf '%s' '${encode(outside)}' | base64 -d > ${OUTSIDE}`;
  onHost(command);
  return onHost("sshd -T -f /tmp/probe.conf 2>/dev/null | grep -i '^PermitRootLogin ' | cut -d' ' -f2-");
}

function restoreConfig() {
  onHost(
    "[ -f /tmp/sshd_config.pristine ] && cp /tmp/sshd_config.pristine /etc/ssh/sshd_config;"
    + " if [ -d /tmp/sshd_config.d.aside ]; then rm -rf /etc/ssh/sshd_config.d"
    + " && mv /tmp/sshd_config.d.aside /etc/ssh/sshd_config.d; fi;"
    + " if [ -f /tmp/sshd_config.d.created ]; then rm -rf /etc/ssh/sshd_config.d && rm -f /tmp/sshd_config.d.created; fi;"
    + ` rm -f /tmp/probe.conf /tmp/sshd_config.pristine /tmp/sshd_config.bak ${OUTSIDE}`,
  );
}

const backend = "D:/LovelyRes/target/debug/lovelyhawk-backend.exe";
const sidecar = new Sidecar(backend, newDataRoot());

try {
  keepPristineConfig();
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

  // A `Match` block sets the key for some connections and not others. `sshd -T`
  // without a connection spec answers with the global value, which is exactly
  // the point: the daemon itself says the Match line is not the machine's
  // setting, and reporting it as one is how a planted block goes unnoticed.
  const f = await compare(
    "F  全局 no，Match 块里改成 yes",
    "PermitRootLogin no\nMatch Address 10.0.0.0/8\n    PermitRootLogin yes",
    false,
  );
  check("  F — 报成条件设置，而不是全局值", f?.observedKind, "conditional");
  check("  F — 条件设置永远不算合规", f?.compliant, false);
  check("  F — 说明文字点出 Match", f?.observed?.includes("Match"), true);

  // Only inside the block, with nothing global: still conditional, never the
  // relaxed value read as though it applied to everyone.
  const g = await compare(
    "G  只在 Match 块里放行 root",
    "Match User deploy\n    PermitRootLogin yes",
    false,
  );
  check("  G — 同样报成条件设置", g?.observedKind, "conditional");
  check("  G — 不算合规", g?.compliant, false);

  // A commented-out Match opens no block, so the global line still counts.
  const h = await compare(
    "H  Match 被注释掉了",
    "#Match Address 10.0.0.0/8\nPermitRootLogin no",
  );
  check("  H — 注释掉的 Match 不开启条件块", h?.observedKind, "value");
  check("  H — 全局值照常判定", h?.compliant, true);

  // sshd reads a drop-in only where an Include line puts it, and keeps the
  // first value it sees. Each layout is settled by sshd before the scan runs.
  async function layout(label, main, dropIns, outside = null) {
    const obeyed = sshdObeysLayout(main, dropIns, outside);
    installProbeConfig();
    const scan = await sidecar.call("baseline.scan", { bindingHandle: binding }, 90_000);
    const observed = scan.statuses.find((entry) => entry.itemHandle === rootLogin.itemHandle);
    console.log(`${label}\n      sshd 生效: ${obeyed}   扫描读到: ${observed?.observed}   来源: ${observed?.fix?.file}`);
    return { obeyed, observed };
  }
  const dropIn = "/etc/ssh/sshd_config.d/25-probe.conf";

  const i = await layout("I  Include 在前，附加文件放行 root，主文件禁止",
    "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no", { "25-probe.conf": "PermitRootLogin yes" });
  check("  I — sshd 取附加文件的值", i.obeyed, "yes");
  check("  I — 扫描读到的就是 sshd 生效的", i.observed?.observed, i.obeyed);
  check("  I — 来源指向附加文件", i.observed?.fix?.file, dropIn);
  // The file pane shows that drop-in, with its line marked as the one sshd obeys.
  const fileI = await sidecar.call("baseline.file.read",
    { bindingHandle: binding, itemHandle: rootLogin.itemHandle }, 120_000);
  check("  I — 文件查看打开的是附加文件", fileI.path, dropIn);
  const markedI = fileI.mentions.find((entry) => entry.effective);
  check("  I — 标出的生效行就是放行 root 那行", markedI === undefined ? null : fileI.text.split("\n")[markedI.line].trim(),
    "PermitRootLogin yes");

  const j = await layout("J  主文件没有 Include，附加文件放行 root",
    "PermitRootLogin no", { "25-probe.conf": "PermitRootLogin yes" });
  check("  J — sshd 不读没被包含的附加文件", j.obeyed, "no");
  check("  J — 扫描读到的就是 sshd 生效的", j.observed?.observed, j.obeyed);
  check("  J — 来源是主文件", j.observed?.fix?.file, "/etc/ssh/sshd_config");

  const k = await layout("K  主文件先禁止，Include 在后",
    "PermitRootLogin no\nInclude /etc/ssh/sshd_config.d/*.conf", { "25-probe.conf": "PermitRootLogin yes" });
  check("  K — sshd 取先读到的主文件值", k.obeyed, "no");
  check("  K — 扫描读到的就是 sshd 生效的", k.observed?.observed, k.obeyed);
  check("  K — 来源是主文件", k.observed?.fix?.file, "/etc/ssh/sshd_config");

  const l = await layout("L  相对路径 Include",
    "Include sshd_config.d/*.conf", { "25-probe.conf": "PermitRootLogin yes" });
  check("  L — sshd 把相对路径当作 /etc/ssh 下", l.obeyed, "yes");
  check("  L — 扫描读到的就是 sshd 生效的", l.observed?.observed, l.obeyed);
  check("  L — 来源指向附加文件", l.observed?.fix?.file, dropIn);

  const m = await layout("M  只包含一个附加文件，它再包含另一个",
    "Include /etc/ssh/sshd_config.d/10-probe.conf",
    { "10-probe.conf": "Include /etc/ssh/sshd_config.d/25-probe.conf", "25-probe.conf": "PermitRootLogin yes",
      "50-probe.conf": "PermitRootLogin no" });
  check("  M — sshd 顺着嵌套 Include 读到", m.obeyed, "yes");
  check("  M — 扫描读到的就是 sshd 生效的", m.observed?.observed, m.obeyed);
  check("  M — 来源是嵌套包含的那个文件", m.observed?.fix?.file, dropIn);

  const n = await layout("N  生效值来自本工具不管理的位置",
    "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no",
    { "10-probe.conf": `Include ${OUTSIDE}` }, "PermitRootLogin yes");
  check("  N — sshd 读到了那个位置的值", n.obeyed, "yes");
  check("  N — 扫描不报一个会写错地方的值，只说无法判断", n.observed?.observedKind, "unverified");
  check("  N — 不算合规", n.observed?.compliant, false);
  // Undecided: the main file's own line is not claimed to be the one sshd uses.
  const fileN = await sidecar.call("baseline.file.read",
    { bindingHandle: binding, itemHandle: rootLogin.itemHandle }, 120_000);
  check("  N — 文件查看不把主文件那行标成生效", fileN.mentions.some((entry) => entry.effective), false);

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
