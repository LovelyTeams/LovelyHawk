// 网络抓包 in the Tauri window against a host that really has tcpdump.
//
// The shared lab hosts have no tcpdump (probe-packet-capture.mjs checks that
// case). This probe makes its own host instead: a container from the local
// lovelyres-lab image of one distribution (LAB=ubuntu by default), labelled
// with this run's id, resource-limited, reachable only on the WSL address,
// with tcpdump installed from that distribution's own package repository, and
// removed at the end after its identity is checked again.
//
// Checked on the host side, not only on the page: that the packets shown are
// the ones the host sent, that the packet limit ends tcpdump, that 停止抓包
// and leaving the page leave no tcpdump running, and that a filter carrying a
// shell command runs nothing. A capture kept as a file is read back here — its
// digest, its manifest and the packets inside it — and the host must keep no
// temporary copy, also after the capture is cancelled.
//
//   LAB=rocky node tools/lab/probe-ui-packet-capture.mjs

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { LAB_PORTS } from "./lab-target.mjs";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const lab = process.env.LAB ?? "ubuntu";
if (!Object.hasOwn(LAB_PORTS, lab)) throw new Error(`Unknown LAB ${lab}`);
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-pcap-${lab}-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-packet-capture", lab, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pcap-"));
const checks = [];
let failures = 0;
let containerId = null;
let imageId = null;
let app = null;
fs.mkdirSync(evidence, { recursive: true });

function check(label, ok, detail = null) {
  checks.push({ label, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.Memory !== 512 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) {
    throw new Error("The capture fixture's identity or limits changed");
  }
  return target;
}
/** Runs a script in the fixture through stdin, so nothing is re-quoted on the way. */
function script(input, timeout = 120_000) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout, maxBuffer: 8 * 1024 * 1024 }).trim();
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
/**
 * Running tcpdump processes on the host, by exact name (the probe's own sh
 * never matches). Exited ones are left out: this container's PID 1 does not
 * reap, so a tcpdump that ended stays listed as a zombie (state Z).
 */
const tcpdumps = () => script(`for p in /proc/[0-9]*; do
  [ "$(cat "$p/comm" 2>/dev/null)" = tcpdump ] || continue
  [ "$(sed 's/.*) //' "$p/stat" 2>/dev/null | cut -d' ' -f1)" = Z ] || echo "\${p#/proc/}"
done; true`).split(/\s+/u).filter(Boolean);

try {
  // 1. The fixture, with tcpdump from the distribution's own repository.
  imageId = docker("image", "inspect", `lovelyres-lab:${lab}`, "--format", "{{.Id}}");
  const wslAddress = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!wslAddress) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${wslAddress}::22`, imageId);
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  const installed = script(`set -e
if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null; apt-get install -y -qq tcpdump iproute2 iputils-ping >/dev/null
elif command -v dnf >/dev/null; then dnf -y -q install tcpdump iproute iputils >/dev/null
elif command -v yum >/dev/null; then yum -y -q install tcpdump iproute iputils >/dev/null
elif command -v apk >/dev/null; then apk add -q tcpdump iproute2 >/dev/null
elif command -v zypper >/dev/null; then zypper -n -q in tcpdump iproute2 iputils >/dev/null
fi
tcpdump --version 2>&1 | head -n 1`, 600_000);
  check("tcpdump is installed in this run's own container", /^tcpdump version /u.test(installed), installed);
  const gateway = script("ip route | awk '/^default/ {print $3; exit}'");
  const self = script("ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1");
  if (!/^\d+\.\d+\.\d+\.\d+$/u.test(gateway) || !/^\d+\.\d+\.\d+\.\d+$/u.test(self)) throw new Error(`No usable addresses: ${gateway} ${self}`);

  const sidecar = new Sidecar(backendBinary(), dataRoot);
  try {
    const status = await connect(sidecar, { host: wslAddress, port: sshPort, username: "root", password: "LabRoot#2026",
      id: "33333333-3333-4333-8333-333333333301", name: `抓包靶机 ${lab}` });
    if (status?.stage !== "connected") throw new Error(`fixture connect failed: ${JSON.stringify(status)}`);
  } finally { sidecar.close(); }

  const consoleErrors = [];
  app = await startDesktop({ dataRoot, evidence, dialogAnswers: [],
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs = 90_000) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  const setInput = (selector, value) => evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(selector)});
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(String(value))});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  const status = () => evaluate("document.querySelector('.packet-capture-status')?.textContent ?? ''");
  const button = (text) => evaluate(`(() => { const b = [...document.querySelectorAll('.packet-capture-actions button')].find((x) => x.textContent.trim() === ${JSON.stringify(text)}); if (!b || b.disabled) return false; b.click(); return true; })()`);
  const navigate = (title) => evaluate(`[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes(${JSON.stringify(title)}))?.click(), true`);
  const setForm = async (filter, limit, seconds) => {
    await setInput(".packet-capture-form label:nth-of-type(1) input", filter);
    await setInput(".packet-capture-form label:nth-of-type(2) input", limit);
    await setInput(".packet-capture-form label:nth-of-type(3) input", seconds);
  };
  await uiWait("document.querySelector('.connection-card button') !== null", "the connection card");
  await evaluate("document.querySelector('.connection-card button').click(), true");
  await uiWait("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null", "the connection");
  await navigate("网络抓包");
  await uiWait("[...document.querySelectorAll('.packet-capture-interface-list button')].some((b) => b.textContent.includes('eth0'))", "the interfaces");
  await evaluate("[...document.querySelectorAll('.packet-capture-interface-list button')].find((b) => b.textContent.includes('eth0')).click(), true");
  check("the interfaces come from the host and eth0 can be chosen",
    await evaluate("document.querySelector('.packet-capture-interface-list button[aria-pressed=\"true\"]')?.textContent.includes('eth0') === true"));

  // 2. Real traffic: six ICMP echoes to the gateway, captured with a limit of 6.
  await setForm(`icmp and host ${gateway}`, 6, 60);
  check("nothing captures before 开始抓包", tcpdumps().length === 0);
  await button("开始抓包");
  await until(async () => (await status()).includes("正在采集") && tcpdumps().length === 1, "the running capture", 60_000);
  check("开始抓包 starts exactly one tcpdump on the host", tcpdumps().length === 1);
  script(`ping -c 3 -i 0.3 ${gateway} >/dev/null 2>&1 || true`, 60_000);
  await until(async () => (await status()).includes("已停止"), "the capture to end at its limit", 60_000);
  const rows = await evaluate(`[...document.querySelectorAll('.packet-capture-table button[role="row"]')].map((row) => [...row.querySelectorAll('[role="cell"]')].map((cell) => cell.textContent))`);
  // The table shows the time of day; the full stamp is the cell's tooltip.
  const stamps = await evaluate(`[...document.querySelectorAll('.packet-capture-table button[role="row"]')].map((row) => row.querySelectorAll('[role="cell"]')[1]?.title ?? "")`);
  const total = Number(await evaluate("[...document.querySelectorAll('.packet-capture-metrics div')].find((d) => d.textContent.startsWith('累计数据包'))?.querySelector('strong')?.textContent ?? '-1'"));
  const requests = rows.filter((cells) => cells[2] === "ICMP" && cells[3] === self && cells[4] === gateway && /^ICMP echo request/u.test(cells[6] ?? ""));
  const replies = rows.filter((cells) => cells[2] === "ICMP" && cells[3] === gateway && cells[4] === self && /^ICMP echo reply/u.test(cells[6] ?? ""));
  check("exactly the six packets the limit allows: three echoes out, three back, with the host's addresses and a time each",
    rows.length === 6 && total === 6 && requests.length === 3 && replies.length === 3 &&
    rows.every((cells) => /^\d\d:\d\d:\d\d\.\d{3}$/u.test(cells[1] ?? "") && cells[5] === "64") &&
    stamps.length === 6 && stamps.every((stamp) => /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+$/u.test(stamp)), { rows: rows.slice(0, 6), total, stamps: stamps.slice(0, 2) });
  check("the totals are drawn in a colour that reads on their surface",
    await evaluate(`(() => {
      const strong = [...document.querySelectorAll('.packet-capture-metrics strong')][0];
      const box = strong.parentElement;
      return getComputedStyle(strong).color !== getComputedStyle(box).backgroundColor && getComputedStyle(strong).color !== 'rgb(255, 255, 255)';
    })()`));
  check("the capture that ended on its own lets the next one start, and says it was released",
    await evaluate("(() => { const b = [...document.querySelectorAll('.packet-capture-actions button')]; return b[0].disabled === false && b[1].disabled === true; })()") &&
    (await evaluate("document.querySelector('.packet-capture-notice')?.textContent ?? ''")).includes("已停止并释放"));
  check("reaching the packet limit ended tcpdump on the host", tcpdumps().length === 0);
  await evaluate("document.querySelector('.packet-capture-table button[role=\"row\"]').click(), true");
  check("a chosen packet shows its raw tcpdump line as text",
    await evaluate("(() => { const pre = [...document.querySelectorAll('.packet-capture-detail-content pre')]; return pre.length === 2 && pre[1].textContent.length > 0; })()"));
  await page.shot("packet-capture-echoes.png");

  // 3. 停止抓包 ends the remote tcpdump.
  await setForm("udp port 40999", 100, 120);
  await button("开始抓包");
  await until(async () => (await status()).includes("正在采集") && tcpdumps().length === 1, "the idle capture", 60_000);
  await button("停止抓包");
  await until(async () => (await status()).includes("已停止"), "the stop", 30_000);
  await until(() => tcpdumps().length === 0, "tcpdump to end after 停止抓包", 15_000).catch(() => undefined);
  check("停止抓包 leaves no tcpdump running on the host", tcpdumps().length === 0, tcpdumps());

  // 4. Leaving the page ends it too.
  await button("开始抓包");
  await until(async () => (await status()).includes("正在采集") && tcpdumps().length === 1, "the capture before leaving", 60_000);
  await navigate("主机全景");
  await until(() => tcpdumps().length === 0, "tcpdump to end after leaving the page", 20_000).catch(() => undefined);
  check("leaving the page leaves no tcpdump running on the host", tcpdumps().length === 0, tcpdumps());

  // 5. A filter that carries a shell command is one argument to tcpdump.
  await navigate("网络抓包");
  await uiWait("[...document.querySelectorAll('.packet-capture-interface-list button')].some((b) => b.textContent.includes('eth0'))", "the interfaces again");
  await evaluate("[...document.querySelectorAll('.packet-capture-interface-list button')].find((b) => b.textContent.includes('eth0')).click(), true");
  await setForm("udp port 1; touch /tmp/lh-pcap-pwned", 5, 10);
  await button("开始抓包");
  await until(async () => /已失败|已停止/u.test(await status()), "the refused filter", 60_000);
  // The network-card list reloads once the failed capture is released; that
  // reload used to wipe the explanation, on a slow host after the check above.
  await uiWait("[...document.querySelectorAll('.packet-capture-controls header button')].some((b) => b.textContent.trim() === '刷新网卡')", "the card list reload");
  const said = await evaluate("[...document.querySelectorAll('.packet-capture-notice, .packet-capture-info')].map((n) => n.textContent).join(' ')");
  check("a filter carrying a shell command runs nothing and the page says the capture did not run",
    script("test -e /tmp/lh-pcap-pwned && echo yes || echo no") === "no" && (await status()).includes("已失败") &&
    said.includes("tcpdump 以失败结束") && said.includes("can't parse filter expression"), { status: await status(), said });
  check("and nothing of it is left running", tcpdumps().length === 0);
  await page.shot("packet-capture-bad-filter.png");

  // 6. Keeping a capture as a file: the bytes tcpdump wrote on the host, kept
  //    in the folder the dialog chose, checked here against the host and the
  //    file itself, and the host's temporary copy gone.
  const kept = path.join(evidence, "kept");
  fs.mkdirSync(kept, { recursive: true });
  const panel = (expression) => evaluate(`(() => { const p = document.querySelector('[data-testid="packet-capture-evidence"]'); return ${expression}; })()`);
  const keptState = () => panel("p?.querySelector('[data-testid=\"packet-capture-evidence-result\"]')?.dataset.state ?? ''");
  const managedFiles = () => script("ls /tmp/lovelyres-pcap-*.pcap 2>/dev/null | wc -l");
  await uiWait("[...document.querySelectorAll('.packet-capture-interface-list button')].some((b) => b.textContent.includes('eth0') && !b.disabled)", "the interfaces before keeping");
  await evaluate("[...document.querySelectorAll('.packet-capture-interface-list button')].find((b) => b.textContent.includes('eth0')).click(), true");
  await setForm(`icmp and host ${gateway}`, 4, 60);
  check("before anything starts the panel says what keeping a capture does and needs",
    await panel("['capture.pcap', '/tmp', 'root 或能免密码 sudo', '离开本页会取消'].every((w) => p?.textContent.includes(w))"));
  app.setDialogAnswers([kept]);
  await panel("(p.querySelector('[data-testid=\"packet-capture-evidence-begin\"]').click(), true)");
  await until(async () => (await keptState()) === "capturing" && tcpdumps().length === 1 && managedFiles() === "1", "the kept capture to run", 60_000);
  check("抓包并保存 starts one tcpdump writing one managed file on the host",
    tcpdumps().length === 1 && managedFiles() === "1");
  check("while it runs the live capture and the parameters are held",
    await evaluate("(() => { const start = [...document.querySelectorAll('.packet-capture-actions button')][0]; const inputs = [...document.querySelectorAll('.packet-capture-form input')]; return start.disabled && inputs.every((i) => i.disabled); })()"));
  script(`ping -c 2 -i 0.3 ${gateway} >/dev/null 2>&1 || true`, 60_000);
  await until(async () => ["completed", "saved-unlinked", "failed"].includes(await keptState()), "the kept capture to finish", 120_000);
  const shownSha = await panel("p.querySelector('[data-testid=\"packet-capture-evidence-sha256\"]')?.textContent ?? ''");
  const folderName = await panel("p.querySelector('dd code')?.textContent ?? ''");
  const temporary = await panel("p.querySelector('[data-testid=\"packet-capture-evidence-temporary\"]')?.textContent ?? ''");
  check("the capture is saved and linked to the case", (await keptState()) === "completed", await panel("p.textContent"));
  check("the host keeps no temporary capture file and no tcpdump, and the page says the file was removed",
    managedFiles() === "0" && tcpdumps().length === 0 && temporary === "已删除", { files: managedFiles(), temporary });
  const folder = path.join(kept, folderName);
  const pcap = fs.existsSync(path.join(folder, "capture.pcap")) ? fs.readFileSync(path.join(folder, "capture.pcap")) : Buffer.alloc(0);
  const manifest = fs.existsSync(path.join(folder, "manifest.json")) ? JSON.parse(fs.readFileSync(path.join(folder, "manifest.json"), "utf8")) : {};
  const localSha = createHash("sha256").update(pcap).digest("hex");
  check("the kept file's SHA-256 is the one the page shows, the manifest records and the host computed",
    pcap.length > 24 && localSha === shownSha && manifest.observation?.sha256 === localSha &&
    manifest.capture?.target_sha256 === localSha && manifest.capture?.target_bytes === pcap.length &&
    manifest.sample_file === "capture.pcap", { localSha, shownSha, manifest: { observation: manifest.observation?.sha256, capture: manifest.capture } });
  check("the manifest says what was captured and that the host's copy is gone",
    manifest.capture?.tool === "tcpdump" && manifest.capture?.interface === "eth0" &&
    manifest.capture?.filter === `icmp and host ${gateway}` && manifest.capture?.packet_limit === 4 &&
    manifest.capture?.duration_seconds === 60 && manifest.capture?.target_temporary_removed === true &&
    /^\/tmp\/lovelyres-pcap-[0-9a-f-]{36}\.pcap$/u.test(manifest.capture?.target_temporary_path ?? "") &&
    typeof manifest.case_id === "string" && manifest.case_id.length > 0 &&
    fs.readFileSync(path.join(folder, "README.txt"), "utf8").includes("capture.pcap"), manifest.capture);
  // A PCAP read here, not by the program that wrote it: four ICMP packets
  // between this host and its gateway.
  const packets = [];
  if (pcap.length >= 24) {
    const magic = pcap.readUInt32LE(0);
    const little = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
    const u32 = (offset) => (little ? pcap.readUInt32LE(offset) : pcap.readUInt32BE(offset));
    const linkType = u32(20);
    for (let offset = 24; offset + 16 <= pcap.length;) {
      const length = u32(offset + 8);
      const data = pcap.subarray(offset + 16, offset + 16 + length);
      offset += 16 + length;
      if (linkType === 1 && data.length >= 34 && data.readUInt16BE(12) === 0x0800) {
        packets.push({ protocol: data[23], source: [...data.subarray(26, 30)].join("."), destination: [...data.subarray(30, 34)].join(".") });
      } else packets.push({ linkType, length });
    }
  }
  check("the file holds exactly the four ICMP packets between this host and its gateway",
    packets.length === 4 && packets.every((p) => p.protocol === 1 &&
      ((p.source === self && p.destination === gateway) || (p.source === gateway && p.destination === self))), packets);
  await page.shot("packet-capture-kept.png");
  await navigate("案件工作台");
  await uiWait("document.querySelector('.case-list-item') !== null", "the case list");
  await evaluate("document.querySelector('.case-list-item').click(), true");
  await uiWait("document.body.textContent.includes('抓包留证')", "the kept capture in the case", 30_000).catch(() => undefined);
  check("the case lists the capture as evidence with its file", await evaluate(`document.body.textContent.includes('抓包留证') && document.body.textContent.includes(${JSON.stringify(`${folderName}/capture.pcap`)})`));

  // 7. Cancelling a kept capture stops it on the host and removes its file.
  await navigate("网络抓包");
  await uiWait("[...document.querySelectorAll('.packet-capture-interface-list button')].some((b) => b.textContent.includes('eth0') && !b.disabled)", "the interfaces before cancelling");
  await evaluate("[...document.querySelectorAll('.packet-capture-interface-list button')].find((b) => b.textContent.includes('eth0')).click(), true");
  await setForm("udp port 40999", 100, 120);
  app.setDialogAnswers([kept]);
  await panel("(p.querySelector('[data-testid=\"packet-capture-evidence-begin\"]').click(), true)");
  await until(async () => (await keptState()) === "capturing" && tcpdumps().length === 1 && managedFiles() === "1", "the capture to cancel", 60_000);
  await panel("(p.querySelector('[data-testid=\"packet-capture-evidence-cancel\"]').click(), true)");
  await until(async () => (await keptState()) === "cancelled" &&
    (await panel("p.querySelector('[data-testid=\"packet-capture-evidence-temporary\"]')?.textContent ?? ''")) === "已删除", "the cancel to settle", 30_000);
  check("取消 stops tcpdump on the host at once and removes its file, and says so",
    tcpdumps().length === 0 && managedFiles() === "0", { tcpdumps: tcpdumps(), files: managedFiles() });
  const kepts = fs.readdirSync(kept).filter((entry) => entry.startsWith("LovelyHawk-evidence-"));
  const cancelledFolder = kepts.find((entry) => entry !== folderName);
  check("the cancelled capture's folder has no manifest, so it is not evidence",
    cancelledFolder !== undefined && !fs.existsSync(path.join(kept, cancelledFolder, "manifest.json")), kepts);
  await page.shot("packet-capture-kept-cancelled.png");
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
  schema: "lovelyhawk-packet-capture-probe/v1",
  lab,
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
