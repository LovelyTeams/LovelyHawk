// Owned container only: real SSH, baseline plan/confirm/execute/restore and FIM.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";
import { startDesktop, waitFor } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lh-auth-baseline-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-auth-baseline", runId);
const dataRoot = path.join(evidence, "data");
fs.mkdirSync(dataRoot, { recursive: true });
const report = { runId, at: new Date().toISOString(), scope: "Owned Debian container, actual SSH. Kernel audit writes are refused in containers; this is not host auditd acceptance.", checks: [] };
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
let containerId, imageId, sidecar, app;
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` || target.Config.Labels?.["lovelyhawk-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" || target.Mounts.length !== 0 ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) throw new Error("Unverified lab identity, network, mounts or limits");
  return target;
}
function script(input) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 1024 * 1024 }).trim();
}
function check(label, ok, detail) {
  report.checks.push({ label, passed: Boolean(ok), detail }); console.log(`${ok ? "PASS" : "FAIL"} ${label}`);
  if (!ok) throw new Error(label);
}
async function refused(label, task) {
  try { await task(); } catch { check(label, true); return; }
  check(label, false);
}
try {
  imageId = docker("image", "inspect", "lovelyres-svc:baseline-deb", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\./u.test(ip));
  if (!host) throw new Error("No private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyhawk-test-run=${runId}`, "--memory", "256m", "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const target = owned();
  report.target = { id: target.Id, image: target.Image, name: target.Name, mounts: target.Mounts, network: target.HostConfig.NetworkMode };
  report.environment = script("cat /etc/os-release; uname -m; command -v getfacl || true");
  // The fixture needs ACL tools; installing in this verified, newly created
  // container is setup, never a detection side effect on a user's target.
  script("if ! command -v getfacl >/dev/null; then apt-get update -qq && apt-get install -y -qq acl >/dev/null; fi");
  script("chmod 0666 /etc/shadow; chown root:shadow /etc/shadow");
  script("cp -p /etc/shadow /tmp/lh-fixture-shadow-original; chmod 0600 /tmp/lh-fixture-shadow-original");
  const original = script("stat -c '%a:%u:%g:%d:%i:%h' /etc/shadow; sha256sum /etc/shadow | cut -d' ' -f1");
  sidecar = new Sidecar(backendBinary(), dataRoot);
  const connected = await connect(sidecar, { host, port: Number(target.NetworkSettings.Ports["22/tcp"][0].HostPort), username: "root", password: "LabRoot#2026", id: runId, name });
  check("owned SSH target connected", connected?.stage === "connected");
  const bindingHandle = connected.bindingHandle;
  const call = (method, rest = {}) => sidecar.call(method, { bindingHandle, ...rest }, 180_000);
  const catalog = await sidecar.call("baseline.catalog.get");
  const shadow = catalog.items.find(item => item.title === "口令文件权限");
  const audit = catalog.items.find(item => item.title === "认证文件的 auditd 监控");
  check("five additions reuse the baseline catalogue", catalog.items.length === 113 && shadow && audit);
  let scan = await call("baseline.scan");
  fs.writeFileSync(path.join(evidence, "baseline-scan.json"), JSON.stringify(scan, null, 2));
  check("unsafe shadow mode is a concrete failed observation", scan.statuses.some(item => item.itemHandle === shadow.itemHandle && !item.compliant && item.observed.includes("0666")));
  check("container audit limitations remain unverified", scan.statuses.find(item => item.itemHandle === audit.itemHandle)?.observedKind === "unverified");
  const action = item => ({ kind: "change", changes: [{ itemHandle: item.itemHandle, value: item.recommendation }], reload: "apply-now" });
  const plan = () => call("baseline.action.plan", { action: action(shadow) });
  const confirm = planHandle => call("baseline.action.confirm", { planHandle });
  const execute = planHandle => call("baseline.action.execute", { planHandle });
  const first = await plan();
  check("plan shows exact group-aware permissions and does not mutate", first.summary.includes("0640") && first.summary.includes("GID 42 → 42") && script("stat -c '%a:%u:%g:%d:%i:%h' /etc/shadow; sha256sum /etc/shadow | cut -d' ' -f1") === original);
  await refused("unconfirmed plan cannot execute", () => execute(first.planHandle));
  const approved = await plan(); await confirm(approved.planHandle);
  const applied = await execute(approved.planHandle);
  check("actual repair independently verified", applied.verified && !applied.restored, applied);
  const after = script("stat -c '%a:%u:%g:%d:%i:%h' /etc/shadow; sha256sum /etc/shadow | cut -d' ' -f1");
  check("only permissions changed; group, inode and content retained", after === original.replace(/^666:/u, "640:"));
  await refused("execution is single use", () => execute(approved.planHandle));
  await refused("a matching permission policy creates no extra change", plan);
  const view = await call("baseline.file.read", { itemHandle: shadow.itemHandle });
  check("view is metadata, with no password-file body", view.key === "文件属主与权限" && !view.text.includes("root:$") && !view.text.includes(original.split("\n")[1]));
  let history = await call("baseline.history.list");
  const record = history.entries.find(item => item.summary.includes("口令文件权限") && item.state === "applied");
  check("verified change has a recoverable history record", record?.restorable === true);
  const restore = await call("baseline.action.plan", { action: { kind: "restore", historyHandle: history.historyHandle, historyItemHandle: record.historyItemHandle } });
  await confirm(restore.planHandle);
  check("restore independently verified", (await execute(restore.planHandle)).verified);
  check("restore kept exact original content and identity", script("stat -c '%a:%u:%g:%d:%i:%h' /etc/shadow; sha256sum /etc/shadow | cut -d' ' -f1") === original);
  const beforeEdit = await plan(); await confirm(beforeEdit.planHandle); await execute(beforeEdit.planHandle);
  history = await call("baseline.history.list");
  const editedRecord = history.entries.find(item => item.state === "applied" && item.summary.includes("口令文件权限"));
  const editRestore = await call("baseline.action.plan", { action: { kind: "restore", historyHandle: history.historyHandle, historyItemHandle: editedRecord.historyItemHandle } });
  script("printf '\n' >> /etc/shadow");
  await confirm(editRestore.planHandle);
  const editedContent = script("sha256sum /etc/shadow | cut -d' ' -f1");
  const deniedRestore = await execute(editRestore.planHandle);
  check("restore refuses a later account-file edit without overwriting it", !deniedRestore.verified && script("stat -c %a /etc/shadow") === "640" && script("sha256sum /etc/shadow | cut -d' ' -f1") === editedContent);
  script("cat /tmp/lh-fixture-shadow-original > /etc/shadow; chmod 0666 /etc/shadow");
  const stale = await plan(); script("chmod 0600 /etc/shadow"); await confirm(stale.planHandle);
  const staleReceipt = await execute(stale.planHandle);
  check("permission change after planning refuses the old plan", !staleReceipt.verified && script("stat -c %a /etc/shadow") === "600");
  script("chmod 0666 /etc/shadow; mv /usr/bin/getfacl /tmp/lh-getfacl-disabled");
  scan = await call("baseline.scan");
  check("missing ACL tooling never becomes compliance", scan.statuses.find(item => item.itemHandle === shadow.itemHandle)?.observedKind === "unverified");
  await refused("no implicit install, escalation or guessed permission repair", plan);
  script("mv /tmp/lh-getfacl-disabled /usr/bin/getfacl; setfacl -m u:1000:r /etc/shadow");
  await refused("extended ACL refuses automatic chmod", plan);
  script("setfacl -b /etc/shadow; chmod 0666 /etc/shadow");
  await refused("host audit rules cannot be deployed from a container", () => call("baseline.action.plan", { action: action(audit) }));
  const presets = await sidecar.call("integrity.presets.get");
  check("four optional authentication presets reuse FIM", presets.presets.length === 10 && presets.presets.filter(item => item.id.startsWith("auth-")).length === 4);
  const created = await call("integrity.baseline.create.start", { presetIds: ["auth-passwd", "auth-group", "auth-shadow", "auth-gshadow"] });
  let creation;
  for (let i = 0; i < 60; i++) {
    creation = await call("integrity.baseline.create.poll", { operationHandle: created.operationHandle });
    if (creation.stage !== "running") break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  check("actual FIM creation records all four files", creation.stage === "completed" && creation.fileCount === 4, creation);
  const list = await call("integrity.baselines.list");
  const comparison = await call("integrity.comparison.start", { baselineHandle: list.items[0].baselineHandle });
  let result;
  for (let i = 0; i < 60; i++) {
    result = await call("integrity.comparison.poll", { operationHandle: comparison.operationHandle, afterEvent: 0, limit: 8 });
    if (result.stage !== "running") break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  check("unchanged authentication files compare without findings", result.stage === "completed" && result.comparison?.modified === 0 && result.comparison?.added === 0 && result.comparison?.removed === 0, result);
  script("mv /etc/gshadow /tmp/lh-fixture-gshadow");
  const missing = await call("integrity.baseline.create.start", { presetIds: ["auth-passwd", "auth-gshadow"] });
  let incomplete;
  for (let i = 0; i < 60; i++) {
    incomplete = await call("integrity.baseline.create.poll", { operationHandle: missing.operationHandle });
    if (incomplete.stage !== "running") break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  check("missing selected authentication file fails instead of saving a partial baseline", incomplete.stage === "failed" && (await call("integrity.baselines.list")).items.length === list.items.length, incomplete);
  script("mv /tmp/lh-fixture-gshadow /etc/gshadow");
  // The desktop reopens this run's isolated archive. All writes still use the
  // real in-app plan, confirmation and execution path against the owned target.
  await call("ssh.binding.disconnect");
  sidecar.close(); sidecar = null;
  app = await startDesktop({ dataRoot, evidence });
  report.desktopObservedAt = new Date().toISOString();
  report.desktopPort = app.port;
  report.desktopPid = app.child.pid;
  const page = app.session;
  const evaluate = expression => page.evaluate(expression);
  const wait = (expression, label) => waitFor(() => evaluate(expression), { timeoutMs: 120_000, label });
  const click = async expression => { if (!await evaluate(`(() => { const item = ${expression}; if (!item || item.disabled) return false; item.click(); return true; })()`)) throw new Error(`Missing active control: ${expression}`); };
  await wait(`[...document.querySelectorAll('.connection-card')].some(card => card.textContent.includes(${JSON.stringify(name)}))`, "owned connection card");
  // Keep this isolated automation window out of the operator's normal work.
  await click("document.querySelector('[data-testid=window-minimize]')");
  await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 960, deviceScaleFactor: 1, mobile: false });
  await click(`[...document.querySelectorAll('.connection-card')].find(card => card.textContent.includes(${JSON.stringify(name)})).querySelector('button')`);
  await wait("document.querySelector('[data-testid=sidebar-disconnect-target]') !== null", "desktop SSH connected");
  await click("[...document.querySelectorAll('.nav-item')].find(item => item.querySelector('strong')?.textContent === '配置')");
  await wait("document.querySelector('.configuration-modes') !== null", "configuration page");
  await click("[...document.querySelectorAll('.configuration-modes button')].find(item => item.textContent.includes('检查这台主机'))");
  await wait("[...document.querySelectorAll('.baseline-view-header button')].some(item => !item.disabled)", "baseline scan control");
  await click("[...document.querySelectorAll('.baseline-view-header button')].find(item => !item.disabled)");
  const card = title => `[...document.querySelectorAll('.baseline-card')].find(item => item.querySelector('strong')?.textContent === ${JSON.stringify(title)})`;
  await wait(`(${card("口令文件权限")})?.textContent.includes('0666') === true`, "actual unsafe permission observation");
  await click(card("口令文件权限"));
  await wait("document.querySelector('[data-testid=baseline-change-plan]') !== null", "permission change control");
  await wait("document.querySelector('[aria-label=状态核对]') !== null", "metadata read");
  check("configuration separates primary views from underlined baseline views", await evaluate(`(() => {
    const primary = document.querySelector('.configuration-modes');
    const secondary = document.querySelector('.baseline-tabs');
    const selected = secondary.querySelector('[aria-current=page]');
    return primary.classList.contains('view-tabs') && !secondary.contains(primary) &&
      secondary.classList.contains('view-tabs-underline') && getComputedStyle(selected, '::after').height === '2px' &&
      primary.getBoundingClientRect().bottom <= secondary.getBoundingClientRect().top;
  })()`));
  check("desktop reuses baseline metadata and immediate controls", await evaluate("document.querySelector('[aria-label=状态核对]').textContent.includes('正文不会显示') && !document.querySelector('.baseline-change input[type=radio]') && !document.querySelector('.baseline-file-pane').textContent.includes('程序自己的默认值')"));
  await page.shot("01-permission-panel.png");
  await click("document.querySelector('[data-testid=baseline-change-plan]')");
  await wait("document.querySelector('[role=dialog]') !== null", "permission confirmation");
  check("desktop confirmation exposes exact attributes and leaves target untouched", await evaluate("document.querySelector('[role=dialog]').textContent.includes('0640') && document.querySelector('[role=dialog]').textContent.includes('GID 42 → 42')") && script("stat -c %a /etc/shadow") === "666");
  await page.shot("02-permission-confirm.png");
  await click("[...document.querySelectorAll('[role=dialog] button')].find(item => item.textContent.trim() === '确认修改')");
  await wait("document.querySelector('[data-testid=baseline-action-receipt]')?.dataset.verified === 'true'", "desktop permission verification");
  await wait(`(${card("口令文件权限")})?.querySelector('.is-compliant') !== null && (${card("口令文件权限")})?.querySelector('.is-compliant') !== undefined`, "rescanned permission");
  check("desktop repair independently verified with no body replacement", script("stat -c '%a:%u:%g:%d:%i:%h' /etc/shadow; sha256sum /etc/shadow | cut -d' ' -f1") === original.replace(/^666:/u, "640:"));
  await page.shot("03-permission-completed.png");
  await click("[...document.querySelectorAll('.baseline-tabs button')].find(item => item.textContent.includes('历史'))");
  await wait("document.querySelector('[data-testid=baseline-restore-plan]') !== null", "history restoration");
  await click("document.querySelector('[data-testid=baseline-restore-plan]')");
  await wait("document.querySelector('[role=dialog]') !== null", "restore confirmation");
  await click("[...document.querySelectorAll('[role=dialog] button')].find(item => item.textContent.trim() === '确认放回')");
  await wait("document.querySelector('[data-testid=baseline-action-receipt]')?.dataset.verified === 'true'", "desktop restore verification");
  check("desktop restoration returns exact original attributes and content", script("stat -c '%a:%u:%g:%d:%i:%h' /etc/shadow; sha256sum /etc/shadow | cut -d' ' -f1") === original);
  await click("[...document.querySelectorAll('.baseline-tabs button')].find(item => item.textContent.trim() === '基线检查')");
  await wait(`(${card("认证文件的 auditd 监控")}) !== undefined`, "audit card");
  await click(card("认证文件的 auditd 监控"));
  await wait("document.querySelector('[data-testid=baseline-change-blocked]') !== null", "audit container refusal");
  check("desktop audit card exposes unsupported target without a write button", !await evaluate("document.querySelector('[data-testid=baseline-change-plan]') !== null"));
  await page.shot("04-audit-target-gap.png");
  await click("[...document.querySelectorAll('.nav-item')].find(item => item.querySelector('strong')?.textContent === '文件完整性')");
  await wait("document.querySelector('.integrity-auth-presets') !== null", "integrity presets");
  check("authentication presets are collapsed and optional", await evaluate("!document.querySelector('.integrity-auth-presets').open && document.querySelectorAll('.integrity-auth-presets input:checked').length === 0"));
  await evaluate("document.querySelector('.integrity-auth-presets summary').focus(); true");
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await wait("document.querySelector('.integrity-auth-presets').open", "keyboard expands authentication presets");
  await evaluate("[...document.querySelectorAll('.integrity-preset-grid > label input:checked')].forEach(input => input.click()); true");
  await evaluate("[...document.querySelectorAll('.integrity-auth-presets input')].forEach(input => input.click()); true");
  await wait("document.querySelector('.integrity-auth-presets summary').textContent.includes('已选 4 / 4')", "authentication selection summary");
  await page.shot("05-auth-integrity-presets.png");
  check("authentication presets use compact unboxed columns", await evaluate(`(() => {
    const options = [...document.querySelectorAll('.integrity-auth-options > label')];
    return options.length === 4 && getComputedStyle(options[0]).borderTopWidth === '0px' &&
      options[0].getBoundingClientRect().top === options[1].getBoundingClientRect().top &&
      options[0].getBoundingClientRect().width < document.querySelector('.integrity-presets').clientWidth / 2;
  })()`));
  await click("document.querySelector('[data-testid=integrity-create]')");
  await wait("document.querySelector('[role=dialog]') !== null", "integrity confirmation");
  check("integrity confirmation names four files and collection impact", await evaluate("['/etc/passwd','/etc/group','/etc/shadow','/etc/gshadow','访问时间'].every(value => document.querySelector('[role=dialog]').textContent.includes(value))"));
  await click("[...document.querySelectorAll('[role=dialog] button')].find(item => item.textContent.trim() === '新建基线')");
  await wait("document.querySelectorAll('.integrity-baseline-list > button').length === 2 && document.querySelector('[data-testid=integrity-create]')?.disabled === false", "new integrity baseline in the list");
  await click("document.querySelector('[data-testid=open-notifications]')");
  await wait("document.querySelector('.notification-center')?.textContent.includes('基线已建立：记录了 4 个文件（4 个位置）') === true", "creation receipt in the existing notification center");
  check("desktop records four authentication files and retains its receipt", await evaluate("document.querySelector('.integrity-baseline-list > button strong').textContent === '4 文件' && document.querySelector('.notification-center').textContent.includes('基线已建立：记录了 4 个文件（4 个位置）')"));
  await page.shot("06-auth-integrity-receipt.png");
  await click("document.querySelector('[aria-label=关闭通知中心]')");
  await page.send("Emulation.setDeviceMetricsOverride", { width: 900, height: 800, deviceScaleFactor: 1, mobile: false });
  check("integrity layout stays within narrow viewport", await evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"));
  await page.shot("07-auth-integrity-narrow.png");
  await evaluate("document.documentElement.dataset.theme = 'dark'; true");
  await page.shot("08-integrity-dark-narrow.png");
  await evaluate("document.documentElement.dataset.theme = 'light'; true");
  await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 960, deviceScaleFactor: 1, mobile: false });
  await click("[...document.querySelectorAll('.nav-item')].find(item => item.querySelector('strong')?.textContent === '命令审计')");
  await wait("document.querySelectorAll('.check-audit-command-list > button').length === 17", "real command audit rows");
  await wait("document.querySelector('[data-testid=check-audit-collect]')?.disabled === false", "command audit status and actions");
  check("audit tabs are soft text navigation and commands use flat aligned rows", await evaluate(`(() => {
    const tab = document.querySelector('.check-audit-tabs [aria-current=page]');
    const row = document.querySelector('.check-audit-command-list > button');
    const surface = getComputedStyle(document.documentElement).getPropertyValue('--surface-inset').trim();
    const color = document.createElement('span'); color.style.backgroundColor = surface; document.body.append(color);
    const sameFill = getComputedStyle(tab).backgroundColor === getComputedStyle(color).backgroundColor; color.remove();
    return sameFill && getComputedStyle(tab).borderTopWidth === '0px' &&
      getComputedStyle(row).borderRadius === '0px' && getComputedStyle(document.querySelector('.check-audit-content')).borderTopWidth === '0px' &&
      document.querySelector('.check-audit-command-columns').textContent.includes('执行位置');
  })()`));
  await page.shot("09-command-audit-flat.png");
  await click("[...document.querySelectorAll('.check-audit-command-list > button')].find(item => item.querySelector('strong')?.textContent === 'head')");
  check("row selection retains its collection action context", await evaluate("document.querySelector('.check-audit-actions-bar').textContent.includes('head') && document.querySelector('.check-audit-command-list > button[aria-pressed=true] strong').textContent === 'head'"));
  await evaluate(`(() => {
    const input = document.querySelector('.check-audit-command-tools > label input');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'no-such-command');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await wait("document.querySelector('.check-audit-empty')?.textContent.includes('没有匹配的命令')", "filtered empty state");
  await page.shot("10-audit-filter-empty.png");
  await evaluate(`(() => {
    const input = document.querySelector('.check-audit-command-tools > label input');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, '');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    [...document.querySelectorAll('.check-audit-tabs button')].find(item => item.textContent === '日志').focus();
  })()`);
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await wait("document.querySelector('.check-audit-tabs [aria-current=page]')?.textContent === '日志'", "keyboard changes audit view");
  check("audit keyboard navigation keeps visible focus", await evaluate("document.activeElement.textContent === '日志' && getComputedStyle(document.activeElement).outlineStyle !== 'none'"));
  await wait("document.querySelector('.check-audit-warning-panel, .check-audit-empty') !== null", "uncollected log state");
  await page.shot("11-audit-log-state.png");
  for (const title of ['周期分析', '建议', '命令']) {
    await click(`[...document.querySelectorAll('.check-audit-tabs button')].find(item => item.textContent === ${JSON.stringify(title)})`);
    await wait(`document.querySelector('.check-audit-tabs [aria-current=page]')?.textContent === ${JSON.stringify(title)}`, `audit ${title} view`);
  }
  await wait("document.querySelectorAll('.check-audit-command-list > button').length === 17", "audit list restored");
  await page.send("Emulation.setDeviceMetricsOverride", { width: 900, height: 800, deviceScaleFactor: 1, mobile: false });
  check("narrow audit content and actions fit the available page width", await evaluate(`(() => {
    const page = document.querySelector('.check-audit-page');
    return page.scrollWidth <= page.clientWidth + 1 && [...page.querySelectorAll('.check-audit-actions button')].every(item => item.getBoundingClientRect().right <= window.innerWidth);
  })()`));
  await page.shot("12-audit-narrow.png");
  await evaluate("document.documentElement.dataset.theme = 'dark'; true");
  await page.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 960, deviceScaleFactor: 1, mobile: false });
  await page.shot("13-audit-dark.png");
  await evaluate("document.documentElement.dataset.theme = 'light'; true");
  await click("[...document.querySelectorAll('.nav-item')].find(item => item.querySelector('strong')?.textContent === '日志分析')");
  await wait("document.querySelector('.log-analysis-views [aria-current=page]') !== null", "log analysis navigation");
  check("log analysis reuses soft view tabs with visible selection", await evaluate(`(() => {
    const tab = document.querySelector('.log-analysis-views [aria-current=page]');
    return document.querySelector('.log-analysis-views').classList.contains('view-tabs') &&
      getComputedStyle(tab).borderTopWidth === '0px' && getComputedStyle(tab).fontWeight === '600';
  })()`));
  await page.shot("14-log-analysis-tabs.png");
  check("desktop has no startup or runtime console, log or exception errors", app.errors.length === 0, app.errors);
} catch (error) {
  report.failure = String(error); process.exitCode = 1; console.error(report.failure);
  if (app) { report.desktopErrors = app.errors; await app.session.shot("failure.png").catch(() => {}); }
} finally {
  sidecar?.close();
  if (app) { fs.writeFileSync(path.join(evidence, "desktop.log"), app.log()); await app.close(); }
  if (containerId) { try { owned(); docker("rm", "-f", containerId); } catch (error) { report.cleanupFailure = String(error); process.exitCode = 1; } }
  keepalive.stdin.end();
  fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(`Evidence: ${evidence}`);
}
