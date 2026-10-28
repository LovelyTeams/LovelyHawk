// Java hot update in the Tauri window against a real JVM, end to end.
//
// Everything happens in a container this probe creates from the local
// lovelyres-svc:tomcat image (JDK 17 included, nothing downloaded), labelled
// with this run's id, resource-limited, reachable only on the WSL address, and
// removed at the end after its identity is checked again. Inside it a tiny
// program is compiled twice (v1, v2), v1 is packed into a JAR and started; the
// page then scans the JVMs, opens that JAR, cancels a replacement once, replaces
// lh/probe/Probe.class with v2, and restores the original from the record.
//
// Checked on the host itself, not from the page: the JAR's and the class's
// SHA-256 before, after and after the restore; that the running JVM still
// prints v1 until it is restarted (the page says so); that a cancelled plan
// changes nothing.
//
//   node tools/lab/probe-java-hot-update.mjs

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-java-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-java-hot-update", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-java-"));
const root = "/opt/lh-java-probe";
const jarPath = `${root}/probe.jar`;
const entry = "lh/probe/Probe.class";
const checks = [];
let failures = 0;
let containerId = null;
let imageId = null;
let app = null;
fs.mkdirSync(evidence, { recursive: true });

function check(label, ok, detail = null) {
  checks.push({ label, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 300)}`}`);
}
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
/** The container must still be the one this run made, with the limits it was made with. */
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.Memory !== 512 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) {
    throw new Error("The Java fixture's identity or limits changed");
  }
  return target;
}
const onHost = (script) => { owned(); return docker("exec", containerId, "sh", "-c", script); };
function script(input) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000 }).trim();
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}
const jarSha = () => onHost(`sha256sum ${jarPath} | cut -d' ' -f1`);
const jarOwnerMode = () => onHost(`stat -c '%u:%g %a' ${jarPath}`);
const classShaInJar = () => onHost(`rm -rf /tmp/lh-x && mkdir /tmp/lh-x && cd /tmp/lh-x && jar xf ${jarPath} ${entry} && sha256sum ${entry} | cut -d' ' -f1`);
const lastPrinted = () => onHost(`tail -n 1 ${root}/run.log`);
function startJvm() {
  // Anchored on this JVM's own command so it never matches this very sh -c
  // line, nor the wildcard-classpath JVM.
  onHost(`pkill -f '^java -cp /opt/lh-java-probe/probe[.]jar ' || true; sleep 1; : > ${root}/run.log; nohup java -cp ${jarPath} lh.probe.Probe >> ${root}/run.log 2>&1 &`);
}
const setInput = (selector, value) => `(() => {
  const input = document.querySelector(${JSON.stringify(selector)});
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;

try {
  // 1. The fixture.
  imageId = docker("image", "inspect", "lovelyres-svc:tomcat", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  owned();
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  for (const version of ["v1", "v2"]) {
    script(`mkdir -p ${root}/${version}/src/lh/probe ${root}/${version}/out
cat > ${root}/${version}/src/lh/probe/Probe.java <<'EOF'
package lh.probe;
public final class Probe {
  public static void main(String[] args) throws Exception {
    while (true) { System.out.println("probe ${version}"); System.out.flush(); Thread.sleep(1000); }
  }
}
EOF
javac -d ${root}/${version}/out ${root}/${version}/src/lh/probe/Probe.java
`);
  }
  // An owner and mode no default would produce, so keeping them proves something.
  script(`cd ${root}/v1/out && jar cf ${jarPath} lh/probe/Probe.class && chown 4242:4243 ${jarPath} && chmod 0640 ${jarPath}`);
  startJvm();
  await until(() => lastPrinted() === "probe v1", "the v1 JVM");
  // A second JVM on a wildcard classpath: its command line names no JAR, so
  // only the files it holds open can say which one it runs. Next to them, a
  // JAR no JVM uses, and a symlink to the probe JAR.
  script(`mkdir -p ${root}/lib ${root}/spare
cp ${jarPath} ${root}/lib/wild.jar
(cd ${root}/v2/out && jar cf ${root}/spare/spare.jar lh/probe/Probe.class)
ln -s ${jarPath} ${root}/link.jar
nohup java -cp '${root}/lib/*' lh.probe.Probe > ${root}/wild.log 2>&1 &
`);
  await until(() => onHost(`tail -n 1 ${root}/wild.log`) === "probe v1", "the wildcard JVM");
  const wildPid = Number(script(`pgrep -f '^java -cp /opt/lh-java-probe/lib/[*] '`));
  const spareSha = onHost(`sha256sum ${root}/spare/spare.jar | cut -d' ' -f1`);
  const originalJar = jarSha();
  const v1Class = classShaInJar();
  // The replacement, copied out to this machine as the operator would have it.
  const v2Bytes = execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", containerId, "cat",
    `${root}/v2/out/${entry}`], { windowsHide: true, maxBuffer: 1024 * 1024 });
  const localClass = path.join(evidence, "replacement", "Probe.class");
  fs.mkdirSync(path.dirname(localClass), { recursive: true });
  fs.writeFileSync(localClass, v2Bytes);
  const v2Class = createHash("sha256").update(v2Bytes).digest("hex");
  check("the fixture runs v1 from a JAR, and v2 differs", v1Class !== v2Class && /^[a-f0-9]{64}$/u.test(originalJar));

  // Two ordinary accounts for section 8: ops, with a home and a JVM of its
  // own, and nohome, whose home is /. ops also has, in a folder it owns, a JAR
  // owned by another account that it may read but cannot give back its owner.
  const javaBinary = script('readlink -f "$(command -v java)"');
  script(`id ops >/dev/null 2>&1 || useradd -m -u 2001 -s /bin/sh ops
echo 'ops:OpsLab#2026' | chpasswd
id nohome >/dev/null 2>&1 || useradd -M -d / -u 2002 -s /bin/sh nohome
echo 'nohome:NoHome#2026' | chpasswd
mkdir -p /home/ops/app /home/ops/shared
(cd ${root}/v1/out && jar cf /home/ops/app/ops.jar lh/probe/Probe.class && jar cf /home/ops/shared/other.jar lh/probe/Probe.class)
chown -R ops:ops /home/ops/app /home/ops/shared
chmod 0640 /home/ops/app/ops.jar
chown 4242:4243 /home/ops/shared/other.jar && chmod 0644 /home/ops/shared/other.jar
su ops -s /bin/sh -c 'cd /home/ops/app && nohup ${javaBinary} -cp /home/ops/app/ops.jar lh.probe.Probe > /home/ops/app/run.log 2>&1 &'
`);
  await until(() => onHost("tail -n 1 /home/ops/app/run.log") === "probe v1", "the ops JVM");

  // 2. The desktop, connected to the fixture.
  const connectionName = (user) => `Java 靶机 ${runId.slice(0, 8)} ${user}`;
  const sidecar = new Sidecar(backendBinary(), dataRoot);
  try {
    for (const [id, username, password] of [
      ["33333333-3333-4333-8333-333333333301", "root", "LabRoot#2026"],
      ["33333333-3333-4333-8333-333333333302", "ops", "OpsLab#2026"],
      ["33333333-3333-4333-8333-333333333303", "nohome", "NoHome#2026"],
    ]) {
      const status = await connect(sidecar, { host, port: sshPort, username, password, id, name: connectionName(username) });
      if (status?.stage !== "connected") throw new Error(`fixture connect as ${username} failed: ${JSON.stringify(status)}`);
    }
  } finally { sidecar.close(); }
  const consoleErrors = [];
  let page = null;
  const evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs = 90_000) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  const click = (selector, text) => evaluate(`(() => { const button = [...document.querySelectorAll(${JSON.stringify(selector)})].find((b) => b.textContent.trim() === ${JSON.stringify(text)}); if (!button || button.disabled) return false; button.click(); return true; })()`);
  /** Opens the app on one account's stored connection and the Java page. */
  async function openAs(user) {
    app = await startDesktop({ dataRoot, evidence, dialogAnswers: [localClass],
      onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
    page = app.session;
    const name = connectionName(user);
    await uiWait(`[...document.querySelectorAll('.connection-card')].some((card) => card.textContent.includes(${JSON.stringify(name)}))`, "the connection card");
    await evaluate(`(() => { const card = [...document.querySelectorAll('.connection-card')].find((c) => c.textContent.includes(${JSON.stringify(name)})); (card.querySelector('button') ?? card).click(); return true; })()`);
    await uiWait("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null", "the connection");
    await evaluate("[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes('Java 热更新'))?.click(), true");
    await uiWait("document.querySelector('[data-testid=\"java-scan\"]') !== null", "the Java page");
  }
  await openAs("root");
  check("the page opens on a read-only scan and says it does not restart anything",
    await evaluate("document.querySelector('.java-hot-update-page')?.textContent.includes('不会重启进程') === true && document.querySelector('.placeholder-page') === null"));

  // 3. Scan and open the JAR.
  await evaluate("document.querySelector('[data-testid=\"java-scan\"]').click(), true");
  await uiWait("document.querySelector('.java-processes') !== null || document.querySelector('.java-error') !== null", "the scan");
  const scanned = await evaluate(`(() => ({
    rows: [...document.querySelectorAll('.java-processes tbody tr')].map((row) => row.textContent),
    jars: [...document.querySelectorAll('.java-jar-button')].map((button) => button.title),
    jarTool: [...document.querySelectorAll('.java-tools li')].find((item) => item.textContent.startsWith('jar'))?.textContent ?? null,
  }))()`);
  check("the scan lists the running JVM with its command line and offers its JAR",
    scanned.rows.some((row) => row.includes("lh.probe.Probe")) && scanned.jars.includes(jarPath) && scanned.jarTool === "jar可用", scanned);
  const wildJar = `${root}/lib/wild.jar`;
  check("a JAR named on no command line is found from the files its JVM holds open, and nothing it does not use",
    scanned.jars.includes(wildJar) && !scanned.jars.includes(`${root}/spare/spare.jar`) && !scanned.jars.includes(`${root}/link.jar`) &&
    scanned.rows.some((row) => row.includes(`${root}/lib/*`)), scanned.jars);
  // Narrow the list to the wildcard JVM, then show every JVM's again.
  await evaluate(`[...document.querySelectorAll('.java-process-jars')].find((button) => button.getAttribute('aria-label').startsWith('只看 PID ${wildPid} ')).click(), true`);
  await uiWait(`document.querySelector('.java-section[aria-label="JAR 文件"] .java-count')?.textContent.startsWith('只看 PID ${wildPid}') === true`, "the narrowed list");
  const narrowed = await evaluate("[...document.querySelectorAll('.java-jar-button')].map((button) => button.title)");
  check("narrowing to one JVM lists exactly the JAR it holds open", narrowed.length === 1 && narrowed[0] === wildJar, narrowed);
  await click(".java-jar-toolbar > button", "显示所有进程的 JAR");
  await uiWait(`document.querySelectorAll('.java-jar-button').length === ${scanned.jars.length}`, "the whole list again");

  // A JAR no JVM holds open, by its typed path: read like a listed one.
  const typedInput = ".java-typed-jar input";
  await evaluate(setInput(typedInput, "/opt/lh-java-probe/../etc/x.jar"));
  check("a typed path with .. is refused before anything is sent",
    await evaluate("document.querySelector('.java-typed-jar button').disabled && document.getElementById('java-typed-jar-hint').textContent.includes('不能含 ..')"));
  await evaluate(setInput(typedInput, `${root}/spare/spare.jar`));
  await uiWait("document.querySelector('.java-typed-jar button').disabled === false", "the typed path accepted");
  await evaluate("document.querySelector('.java-typed-jar').requestSubmit(), true");
  await uiWait(`document.querySelector('[data-testid="java-jar-sha256"]')?.textContent === ${JSON.stringify(spareSha)}`, "the typed JAR");
  check("a typed JAR path opens that JAR, with the hash the host computes", true);
  // A symlink is not opened, whatever it points at.
  await evaluate(setInput(typedInput, `${root}/link.jar`));
  await evaluate("document.querySelector('.java-typed-jar').requestSubmit(), true");
  await uiWait("document.querySelector('[data-testid=\"java-typed-jar-error\"]') !== null", "the refused symlink");
  const refusal = await evaluate(`(() => ({
    beside: document.querySelector('[data-testid="java-typed-jar-error"]').textContent,
    top: document.querySelectorAll('.java-hot-update-page > .java-error').length,
    sha: document.querySelector('[data-testid="java-jar-sha256"]')?.textContent,
  }))()`);
  check("a typed path that is a symlink is refused beside the field, saying why, and the JAR already open stays as it was",
    refusal.sha === spareSha && refusal.top === 0 && refusal.beside.includes("不是符号链接"), refusal);
  await page.shot("java-typed-jar.png");
  check("the typed JAR differs from the one the JVM runs, so the hashes above prove which was read", spareSha !== originalJar);
  await evaluate(`[...document.querySelectorAll('.java-jar-button')].find((button) => button.title === ${JSON.stringify(jarPath)}).click(), true`);
  await uiWait(`document.querySelector('.java-section[aria-label="JAR 里的类"] .java-facts dd')?.textContent === ${JSON.stringify(jarPath)} && document.querySelector('.java-hot-update-page').getAttribute('aria-busy') === 'false'`, "the probe JAR");
  await uiWait(`[...document.querySelectorAll('.java-classes button')].some((button) => button.textContent === ${JSON.stringify(entry)})`, "the class list");
  check("the opened JAR shows the hash the host computes", (await evaluate("document.querySelector('[data-testid=\"java-jar-sha256\"]').textContent")) === originalJar);
  await evaluate(`[...document.querySelectorAll('.java-classes button')].find((button) => button.textContent === ${JSON.stringify(entry)}).click(), true`);

  // 4. Choose the replacement, plan, and decline once.
  await evaluate("document.querySelector('[data-testid=\"java-choose-class\"]').click(), true");
  await uiWait(`document.querySelector('.java-hot-update-page')?.textContent.includes(${JSON.stringify(v2Class)}) === true`, "the staged class");
  check("the chosen file is shown by name, size and hash, never by its local location",
    !(await evaluate(`document.body.textContent.includes(${JSON.stringify(path.dirname(localClass))})`)));
  await evaluate("document.querySelector('[data-testid=\"java-plan\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-plan-dialog\"]') !== null", "the plan", 120_000);
  await sleep(300);
  const planView = await evaluate(`(() => ({ text: document.querySelector('[data-testid="java-plan-dialog"]').textContent, focus: document.activeElement?.dataset?.testid ?? null }))()`);
  check("the plan names the JAR, the class, the new hash and the way back, with focus on 取消",
    planView.text.includes(jarPath) && planView.text.includes(entry) && planView.text.includes(v2Class) && planView.text.includes("备份") && planView.focus === "java-plan-cancel", planView);
  check("making the plan changed nothing on the host", jarSha() === originalJar);
  await page.shot("java-plan.png");
  await evaluate("document.querySelector('[data-testid=\"java-plan-cancel\"]').click(), true");
  await uiWait("document.querySelector('.java-notice')?.textContent === '已取消，JAR 没有被改动。'", "the declined plan");
  check("declining the plan leaves the JAR exactly as it was", jarSha() === originalJar && classShaInJar() === v1Class);

  // 5. Replace.
  app.setDialogAnswers([localClass]);
  await evaluate("document.querySelector('[data-testid=\"java-choose-class\"]').click(), true");
  await uiWait(`document.querySelector('.java-hot-update-page')?.textContent.includes(${JSON.stringify(v2Class)}) === true`, "the staged class again");
  await evaluate("document.querySelector('[data-testid=\"java-plan\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-plan-execute\"]') !== null", "the second plan", 120_000);
  await evaluate("document.querySelector('[data-testid=\"java-plan-execute\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-receipt\"]') !== null", "the receipt", 300_000);
  const receipt = await evaluate("document.querySelector('[data-testid=\"java-receipt\"]').textContent");
  const replacedJar = jarSha();
  check("the receipt says the class was replaced and checked", receipt.includes("已替换，并核对过") && receipt.includes(replacedJar), receipt.slice(0, 200));
  check("on the host the JAR now holds exactly the chosen class, and nothing else changed name",
    classShaInJar() === v2Class && replacedJar !== originalJar && onHost(`jar tf ${jarPath} | grep -c '\\.class$'`) === "1");
  check("the replaced JAR keeps its owner and mode", jarOwnerMode() === "4242:4243 640", jarOwnerMode());
  check("the running JVM still prints v1: nothing was reloaded, as the page said", lastPrinted() === "probe v1");
  check("the receipt says the process will not load the new class by itself", receipt.includes("运行中的进程不会自动加载新类"));
  await page.shot("java-receipt.png");
  await evaluate(`[...document.querySelectorAll('[data-testid="java-plan-dialog"] footer button')].find((b) => b.textContent.trim() === '关闭').click(), true`);
  startJvm();
  await until(() => lastPrinted() === "probe v2", "the restarted JVM", 30_000).catch(() => undefined);
  check("after a restart the JVM runs the replaced class", lastPrinted() === "probe v2");

  // 6. Restore from the record.
  await uiWait("[...document.querySelectorAll('.java-records li')].some((item) => item.textContent.includes('已替换'))", "the record");
  await evaluate("[...document.querySelectorAll('.java-records button')].find((button) => button.textContent.trim() === '恢复原 JAR').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-plan-execute\"]')?.textContent.trim() === '确认恢复'", "the restore plan", 120_000);
  await evaluate("document.querySelector('[data-testid=\"java-plan-execute\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-receipt\"]') !== null", "the restore receipt", 300_000);
  const restored = await evaluate("document.querySelector('[data-testid=\"java-receipt\"]').textContent");
  check("restoring puts back the original JAR, byte for byte", restored.includes("已恢复，JAR 与替换前一致") && jarSha() === originalJar && classShaInJar() === v1Class, restored.slice(0, 200));
  check("the restored JAR has its original owner and mode", jarOwnerMode() === "4242:4243 640", jarOwnerMode());
  await evaluate(`[...document.querySelectorAll('[data-testid="java-plan-dialog"] footer button')].find((b) => b.textContent.trim() === '关闭').click(), true`);
  await uiWait("[...document.querySelectorAll('.java-records li')].some((item) => item.textContent.includes('已恢复原 JAR'))", "the restored record");
  check("the record now says the original JAR is back and offers no second restore",
    await evaluate("(() => { const items = [...document.querySelectorAll('.java-records li')]; return items.length === 1 && !items[0].querySelector('button'); })()"));
  await page.shot("java-restored.png");

  // 7. The JDK here is on no SSH login's PATH; jar was found beside the running
  //    JVM's own java. Once another account could write that JDK, it is not used.
  check("the fixture's JDK is not on an SSH login's PATH, so jar came from the running JVM",
    onHost("grep -c openjdk /etc/environment || true") === "0" && scanned.jarTool === "jar可用");
  const rescan = async () => {
    await evaluate("document.querySelector('[data-testid=\"java-scan\"]').click(), true");
    await uiWait("document.querySelector('[data-testid=\"java-scan\"]')?.textContent.trim() === '重新扫描' && document.querySelector('.java-hot-update-page')?.getAttribute('aria-busy') === 'false'", "a rescan");
    return evaluate(`[...document.querySelectorAll('.java-tools li')].find((item) => item.textContent.startsWith('jar'))?.textContent ?? null`);
  };
  const jdkBin = onHost(`dirname "$(readlink /proc/$(pgrep -f '^java .*lh[.]probe[.]Probe' | head -n 1)/exe)"`);
  const binMode = onHost(`stat -c %a ${jdkBin}`);
  onHost(`chmod g+w ${jdkBin}`);
  try {
    const refused = await rescan();
    check("a JDK another account can write is not trusted: jar shows as missing and the JAR cannot be opened",
      refused === "jar没有" && await evaluate("document.querySelector('.java-warning') !== null && [...document.querySelectorAll('.java-jar-button')].every((button) => button.disabled)"),
      { refused, jdkBin });
    await page.shot("java-untrusted-jdk.png");
  } finally {
    onHost(`chmod ${binMode} ${jdkBin}`);
  }
  check("with the JDK's mode put back, jar is found again", (await rescan()) === "jar可用");
  // The JVM stopped for the restart was never reaped (this container's PID 1 does not reap).
  const zombies = Number(script(`ps -eo stat=,comm= | awk '$1 ~ /^Z/ && $2 == "java"' | wc -l`));
  const listed = await evaluate("[...document.querySelectorAll('.java-processes tbody tr')].map((row) => row.textContent)");
  check("an exited, unreaped JVM is not listed as running; the restarted one is",
    zombies >= 1 && listed.length === 3 && listed.every((row) => row.includes("lh.probe.Probe") && !row.includes("defunct")), { zombies, listed });

  // 8. Ordinary logins. ops keeps its backups in its own home; a JAR another
  //    account owns is not swapped in, because its owner cannot be given back;
  //    an account whose home is / gets no plan at all.
  await app.close();
  app = null;
  const opsJar = "/home/ops/app/ops.jar";
  const otherJar = "/home/ops/shared/other.jar";
  const fileSha = (file) => onHost(`sha256sum ${file} | cut -d' ' -f1`);
  const ownerMode = (file) => onHost(`stat -c '%u:%g %a' ${file}`);
  const opsOriginal = fileSha(opsJar);
  const otherOriginal = fileSha(otherJar);
  await openAs("ops");
  await evaluate("document.querySelector('[data-testid=\"java-scan\"]').click(), true");
  await uiWait("document.querySelector('.java-processes') !== null && document.querySelector('.java-hot-update-page')?.getAttribute('aria-busy') === 'false'", "the scan as ops");
  const opsScan = await evaluate(`(() => ({
    rows: [...document.querySelectorAll('.java-processes tbody tr')].map((row) => row.textContent),
    jars: [...document.querySelectorAll('.java-jar-button')].map((button) => button.title),
  }))()`);
  check("as ops, every JVM is listed but other accounts' open files are not read: only the JARs their command lines name",
    opsScan.jars.includes(opsJar) && opsScan.jars.includes(jarPath) && !opsScan.jars.includes(wildJar) &&
      opsScan.rows.some((row) => row.includes("只列出命令行里写明的 JAR")), opsScan);
  const openJar = async (file) => {
    await evaluate(setInput(typedInput, file));
    await uiWait("document.querySelector('.java-typed-jar button').disabled === false", `the typed path ${file}`);
    await evaluate("document.querySelector('.java-typed-jar').requestSubmit(), true");
    await uiWait(`document.querySelector('[data-testid="java-jar-sha256"]')?.textContent === ${JSON.stringify(fileSha(file))} && document.querySelector('.java-hot-update-page').getAttribute('aria-busy') === 'false'`, `the JAR ${file}`);
    await uiWait(`[...document.querySelectorAll('.java-classes button')].some((button) => button.textContent === ${JSON.stringify(entry)})`, "the class list");
    await evaluate(`[...document.querySelectorAll('.java-classes button')].find((button) => button.textContent === ${JSON.stringify(entry)}).click(), true`);
    app.setDialogAnswers([localClass]);
    await evaluate("document.querySelector('[data-testid=\"java-choose-class\"]').click(), true");
    await uiWait(`document.querySelector('.java-hot-update-page')?.textContent.includes(${JSON.stringify(v2Class)}) === true`, "the staged class");
    await evaluate("document.querySelector('[data-testid=\"java-plan\"]').click(), true");
  };
  await openJar(opsJar);
  await uiWait("document.querySelector('[data-testid=\"java-plan-execute\"]') !== null", "the plan as ops", 120_000);
  await evaluate("document.querySelector('[data-testid=\"java-plan-execute\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-receipt\"]') !== null", "the receipt as ops", 300_000);
  const opsReceipt = await evaluate("document.querySelector('[data-testid=\"java-receipt\"]').textContent");
  const opsBackups = onHost("find /home/ops/.lovelyhawk-java-updates -mindepth 1 -maxdepth 1 -type d | wc -l");
  const opsBackupMode = onHost("stat -c '%U %a' /home/ops/.lovelyhawk-java-updates");
  check("as ops, its own JAR is replaced and checked, keeping owner and mode, with the original kept in its own home",
    opsReceipt.includes("已替换，并核对过") && fileSha(opsJar) !== opsOriginal && ownerMode(opsJar) === "2001:2001 640" &&
      opsBackups === "1" && opsBackupMode === "ops 700",
    { receipt: opsReceipt.slice(0, 160), owner: ownerMode(opsJar), opsBackups, opsBackupMode });
  await evaluate(`[...document.querySelectorAll('[data-testid="java-plan-dialog"] footer button')].find((b) => b.textContent.trim() === '关闭').click(), true`);
  await uiWait(`[...document.querySelectorAll('.java-records li')].some((item) => item.textContent.includes(${JSON.stringify(opsJar)}) && item.textContent.includes('已替换'))`, "the ops record");
  const opsRestoreButton = `[...document.querySelectorAll('.java-records li')].find((item) => item.textContent.includes(${JSON.stringify(opsJar)}) && item.textContent.includes('已替换'))?.querySelector('button')`;
  await uiWait(`(() => { const button = ${opsRestoreButton}; return button !== undefined && button !== null && !button.disabled; })()`, "the ops restore button");
  const opsRecordButtons = await evaluate(`[...document.querySelectorAll('.java-records li')].map((item) => [item.textContent.slice(0, 120), [...item.querySelectorAll('button')].map((b) => b.textContent.trim() + (b.disabled ? ' (off)' : ''))])`);
  await evaluate(`(${opsRestoreButton}).click(), true`);
  await uiWait("document.querySelector('[data-testid=\"java-plan-execute\"]')?.textContent.trim() === '确认恢复' || document.querySelector('.java-hot-update-page > .java-error') !== null", "the restore plan as ops", 120_000).catch(async (error) => { console.log(JSON.stringify(opsRecordButtons)); throw error; });
  const opsRestorePlan = await evaluate(`(() => ({
    error: document.querySelector('.java-hot-update-page > .java-error')?.textContent ?? null,
    records: [...document.querySelectorAll('.java-records li')].map((item) => item.textContent),
  }))()`);
  if (opsRestorePlan.error !== null) throw new Error(`the restore plan as ops was refused: ${JSON.stringify({ ...opsRestorePlan, opsRecordButtons })}`);
  await evaluate("document.querySelector('[data-testid=\"java-plan-execute\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-receipt\"]') !== null", "the restore receipt as ops", 300_000);
  const opsRestored = await evaluate("document.querySelector('[data-testid=\"java-receipt\"]').textContent");
  check("as ops, restoring puts its original JAR back byte for byte, owner and mode included",
    opsRestored.includes("已恢复，JAR 与替换前一致") && fileSha(opsJar) === opsOriginal && ownerMode(opsJar) === "2001:2001 640",
    { restored: opsRestored.slice(0, 160), owner: ownerMode(opsJar) });
  await evaluate(`[...document.querySelectorAll('[data-testid="java-plan-dialog"] footer button')].find((b) => b.textContent.trim() === '关闭').click(), true`);
  await page.shot("java-ops-restored.png");

  // A JAR in ops's own folder that another account owns: ops may read and
  // rename in that folder, but cannot give the new file the old owner.
  await openJar(otherJar);
  await uiWait("document.querySelector('[data-testid=\"java-plan-execute\"]') !== null", "the plan for another account's JAR", 120_000);
  await evaluate("document.querySelector('[data-testid=\"java-plan-execute\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"java-plan-dialog\"] .java-error') !== null || document.querySelector('.java-hot-update-page > .java-error') !== null || document.querySelector('[data-testid=\"java-receipt\"]') !== null", "the refused swap", 300_000);
  const otherOutcome = await evaluate(`(() => ({
    receipt: document.querySelector('[data-testid="java-receipt"]')?.textContent ?? null,
    error: [...document.querySelectorAll('.java-error')].map((item) => item.textContent).join(' | '),
  }))()`);
  const leftovers = onHost("ls -A /home/ops/shared");
  const backupsAfter = onHost("find /home/ops/.lovelyhawk-java-updates -mindepth 1 -maxdepth 1 -type d | wc -l");
  check("as ops, another account's JAR is not swapped in and the receipt says why; it keeps its bytes, owner and mode, and no copy is left behind",
    otherOutcome.receipt !== null && otherOutcome.receipt.includes("替换没有完成") && otherOutcome.receipt.includes("这个 JAR 属于其他账号") &&
      fileSha(otherJar) === otherOriginal && ownerMode(otherJar) === "4242:4243 644" && leftovers === "other.jar" && backupsAfter === opsBackups,
    { otherOutcome, owner: ownerMode(otherJar), leftovers, backupsAfter, opsBackups });
  await page.shot("java-ops-other-owner.png");
  await app.close();
  app = null;

  // An account whose home is /: nowhere of its own to keep the original. It
  // runs a JVM of its own, so jar is found beside it as for any login.
  onHost(`su nohome -s /bin/sh -c 'cd / && nohup ${javaBinary} -cp ${root}/spare/spare.jar lh.probe.Probe > /tmp/lh-nohome.log 2>&1 &'`);
  await until(() => onHost("tail -n 1 /tmp/lh-nohome.log") === "probe v2", "the nohome JVM");
  await openAs("nohome");
  await evaluate("document.querySelector('[data-testid=\"java-scan\"]').click(), true");
  await uiWait("document.querySelector('.java-processes') !== null && document.querySelector('.java-hot-update-page')?.getAttribute('aria-busy') === 'false'", "the scan as nohome");
  const spare = `${root}/spare/spare.jar`;
  const spareBefore = fileSha(spare);
  await openJar(spare);
  await uiWait("document.querySelector('.java-hot-update-page > .java-error') !== null || document.querySelector('[data-testid=\"java-plan-dialog\"]') !== null", "the refused plan", 120_000);
  const homeless = await evaluate(`(() => ({
    error: document.querySelector('.java-hot-update-page > .java-error')?.textContent ?? '',
    dialog: document.querySelector('[data-testid="java-plan-dialog"]') !== null,
  }))()`);
  check("an account whose home is / gets no plan and is told why; the JAR is untouched",
    !homeless.dialog && homeless.error.includes("没有自己的主目录") && fileSha(spare) === spareBefore &&
      onHost("ls -A /.lovelyhawk-java-updates 2>/dev/null | wc -l") === "0",
    homeless);
  await page.shot("java-nohome-refused.png");
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2));
} catch (error) {
  failures += 1;
  console.log(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
  try { await app?.session?.shot("failure.png"); } catch {}
} finally {
  try { await app?.close(); } catch {}
  if (containerId !== null) {
    try {
      owned();
      docker("rm", "-f", containerId);
      check("the run's own container was removed", !docker("ps", "-a", "--filter", `label=lovelyres-test-run=${runId}`, "--format", "{{.ID}}"));
    } catch (error) {
      failures += 1;
      console.log(`cleanup refused: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-java-hot-update-probe/v1",
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
