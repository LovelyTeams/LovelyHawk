// The journal as a log source, in the real window against a lab host, twice:
// first with no journald on the host (journalctl is installed but has no
// journal files), then with journald running and a few lines written to it.
//
// The lab image runs a plain sleep as PID 1, and systemd cannot be PID 1 in a
// container here without the WSL machine's cgroup tree mounted writable, so
// journald runs on its own: what is checked is reading a real journal with
// the host's journalctl — discovery, newest-first pages, keyword search, a
// calendar day — not units, which only systemd assigns.
//
//   LAB=alma node tools/lab/probe-ui-log-journal.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyhawk-backend.exe");
const which = process.env.LAB ?? "alma";
const container = `lab-${which}`;
const port = Number(process.env.LAB_UI_PORT ?? 9370);
const marker = `JOURNAL_PROBE_${randomUUID().slice(0, 8)}`;

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(session, expression, label, attempts = 360) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  const page = await session.evaluate("(document.querySelector('main')?.innerText ?? document.body.innerText).slice(0, 600)");
  throw new Error(`timed out waiting for ${label}; the page reads: ${JSON.stringify(page)}`);
}

const evidence = path.join(repository, "target", "lab-ui-log-journal", which);
fs.mkdirSync(evidence, { recursive: true });
async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

const sources = `[...document.querySelectorAll('.log-analysis-source')].map((button) => button.textContent.trim())`;
const warning = "document.querySelector('.log-analysis-list .log-analysis-warning')?.textContent ?? null";
const lines = "[...document.querySelectorAll('.log-analysis-lines > p')].map((line) => line.textContent)";
const discovered = "document.querySelector('.log-analysis-source') !== null || document.querySelector('.log-analysis-page [role=\"alert\"]') !== null || (document.querySelector('.log-analysis-page')?.textContent ?? '').includes('没有可读日志源')";

async function rediscover(session) {
  await session.evaluate("[...document.querySelectorAll('button')].find((button) => button.textContent.includes('刷新日志源'))?.click(), true");
  await sleep(500);
  await waitFor(session, `(${discovered}) && ![...document.querySelectorAll('button')].some((button) => button.textContent.includes('刷新中'))`, "the sources to be discovered again");
}

async function read(session, { keyword = "", date = "", unit = "" }) {
  await session.evaluate(`(() => {
    const set = (input, value) => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    };
    const labels = [...document.querySelectorAll('.log-analysis-query label')];
    const field = (text) => labels.find((label) => label.textContent.startsWith(text))?.querySelector('input');
    set(field('关键词'), ${JSON.stringify(keyword)});
    set(field('日期'), ${JSON.stringify(date)});
    const unit = field('Journal 单元');
    if (unit) set(unit, ${JSON.stringify(unit)});
    document.querySelector('.log-analysis-run').click();
    return true;
  })()`);
  await sleep(500);
  await waitFor(session, "document.querySelector('.log-analysis-run')?.textContent.includes('读取日志') === true", "the read to finish");
  return session.evaluate(`({
    lines: ${lines},
    empty: document.querySelector('.log-analysis-detail .log-analysis-empty, .log-analysis-detail [class*="empty"] strong')?.textContent ?? null,
    error: document.querySelector('.log-analysis-detail [role="alert"]')?.textContent ?? null,
  })`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-journal-"));
let app;
try {
  // Before: journalctl is there, journald is not, and there is no journal.
  const before = onHost("pgrep -x systemd-journal >/dev/null && echo running || echo stopped; journalctl --no-pager -n 1 2>&1");
  console.log(`  host before: ${before.replace(/\n/gu, " | ")}`);
  check("the host starts without journald and with no journal files", before.startsWith("stopped") && before.includes("No journal files were found"));

  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally { sidecar.close(); }

  app = await startDesktop({ dataRoot, port });
  const session = app.session;
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");
  await session.evaluate(`(() => { const c = document.querySelector('.connection-card'); c?.querySelector('button')?.click() ?? c?.click(); return true; })()`);
  await waitFor(session, "document.querySelector('.nav-item') !== null", "the connected shell");
  await session.evaluate(`(() => { [...document.querySelectorAll('.nav-item')].find(n => n.textContent?.includes('日志分析'))?.click(); return true; })()`);
  await waitFor(session, "document.querySelector('.log-analysis-page') !== null", "the log page");
  await waitFor(session, discovered, "the first discovery");

  const withoutJournal = await session.evaluate(`({ sources: ${sources}, warning: ${warning} })`);
  check("without a journal, no journal source is offered", withoutJournal.sources.some((text) => text.includes("journal")), false);
  check("and the list says the journal could not be read and why that may be",
    withoutJournal.warning?.includes("没有读到 journal") === true, true);
  await shot(session, "no-journal");

  // Now journald, on its own, and lines written to it through syslog and its stdout socket.
  onHost("mkdir -p /run/systemd/journal /var/log/journal; (setsid /usr/lib/systemd/systemd-journald </dev/null >/dev/null 2>&1 &); sleep 2; ln -sf /run/systemd/journal/dev-log /dev/log");
  onHost(`logger -t probe-sshd "Failed password for root from 198.51.100.7 port 4022 ssh2 ${marker}"; echo "${marker} application line" | systemd-cat -t probe-app; sleep 1`);
  const after = onHost(`pgrep -x systemd-journal >/dev/null && echo running || echo stopped; journalctl --no-pager | grep -c ${marker}`);
  console.log(`  host after: ${after.replace(/\n/gu, " | ")}`);
  check("journald runs and holds both probe lines", after, "running\n2");

  await rediscover(session);
  const withJournal = await session.evaluate(`({ sources: ${sources}, warning: ${warning} })`);
  check("with a journal, the journal source is offered", withJournal.sources.some((text) => text.includes("systemd journal")), true);
  check("and the list no longer says the journal could not be read", withJournal.warning?.includes("没有读到 journal") === true, false);
  await session.evaluate("[...document.querySelectorAll('.log-analysis-source')].find((button) => button.textContent.includes('systemd journal')).click(), true");
  await waitFor(session, "document.querySelector('.log-analysis-detail p')?.textContent.includes('systemd journal') === true", "the journal to become the open source");

  const searched = await read(session, { keyword: marker });
  console.log(`  searched: ${JSON.stringify(searched).slice(0, 400)}`);
  check("a keyword search finds both lines in the journal", searched.lines.filter((line) => line.includes(marker)).length, 2);
  check("each as the journal printed it, with its identifier", searched.lines.some((line) => line.includes("probe-sshd") && line.includes("198.51.100.7")) &&
    searched.lines.some((line) => line.includes("probe-app") && line.includes("application line")), true);
  await shot(session, "journal-search");

  const today = new Date().toISOString().slice(0, 10);
  const dated = await read(session, { keyword: marker, date: today });
  check("limited to today (the host's calendar day), they are still found", dated.lines.filter((line) => line.includes(marker)).length, 2);
  const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
  const earlier = await read(session, { keyword: marker, date: yesterday });
  check("limited to yesterday, nothing is found and nothing is made up", earlier.lines.length, 0);
  check("journalctl's own '-- No entries --' is not shown as a log line", earlier.lines.some((line) => line.includes("No entries")), false);

  const none = await read(session, { keyword: `${marker}-absent` });
  check("a search with no match shows no lines", none.lines.length, 0);
  const byUnit = await read(session, { keyword: "", unit: "probe-app.service" });
  check("a unit filter journald alone cannot match reads as empty, not as an error", byUnit.lines.length === 0 && byUnit.error === null, true);
  const newest = await read(session, { keyword: "", unit: "" });
  check("the newest page of the journal has the probe's lines", newest.lines.some((line) => line.includes(marker)), true);
  check("and no journalctl annotations among them", newest.lines.some((line) => /^-- .* --$/u.test(line.trim())), false);
  await shot(session, "journal-newest");
} catch (error) {
  failures += 1;
  console.error(`  FAIL ${error instanceof Error ? error.message : String(error)}`);
} finally {
  await app?.close?.();
}
console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exitCode = failures === 0 ? 0 : 1;
