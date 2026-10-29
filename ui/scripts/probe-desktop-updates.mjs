// Desktop regression: motion preferences, GitHub version check, and
// test-current-configuration -> save, using the existing isolated super lab.
// --panorama additionally creates and edits its own /home/lhprobe*/.bashrc
// fixture, then removes that owned directory; no existing startup file changes.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { attach, launchDesktop, listTargets, waitFor } from "./cdp.mjs";
import { labTarget } from "../../tools/lab/lab-target.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runRoot = path.join(root, "target/desktop-debug", `desktop-updates-${randomUUID()}`);
fs.mkdirSync(runRoot, { recursive: true });
const docker = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", ...args], { encoding: "utf8" });
const [container] = JSON.parse(docker("inspect", "lab-super"));
if (container.Name !== "/lab-super" || container.Config.Image !== "lovelyres-lab:super" ||
    container.HostConfig.Privileged || container.HostConfig.NetworkMode !== "bridge" ||
    container.Mounts.length !== 0 || !container.State.Running ||
    !container.NetworkSettings.Ports["22/tcp"]?.some((port) => port.HostPort === "2251")) {
  throw new Error("The running target does not match the documented, unprivileged, mount-free super lab.");
}
const fingerprint = docker("exec", container.Id, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256").split(/\s+/u)[1];
const lab = labTarget("super");
const panorama = process.argv.includes("--panorama");
const fixtureToken = randomUUID();
const fixtureDirectory = `/home/lhprobe${fixtureToken.replaceAll("-", "").slice(0, 12)}`;
const fixtureFile = `${fixtureDirectory}/.bashrc`;
const fixtureText = Array.from({ length: 1100 }, (_, index) => `# PANORAMA_ROW_${String(index + 1).padStart(4, "0")}\n`).join("");
let fixtureCreated = false;
const port = 10640 + Math.floor(Math.random() * 80);
const app = launchDesktop({
  executable: process.env.LOVELYHAWK_DESKTOP_BIN ?? path.join(root, "target/debug/lovelyhawk.exe"),
  archiveRoot: path.join(runRoot, "data"),
  port,
  extraEnv: { LOVELYHAWK_TEST_CLIPBOARD_FILE: path.join(runRoot, "clipboard.txt") },
});
const checks = [], errors = [];
let session;
const check = (name, ok, detail = null) => {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
  if (!ok) throw new Error(`${name}: ${JSON.stringify(detail)}`);
};
const click = async (selector, text) => waitFor(() => session.evaluate(`(() => {
  const b = [...document.querySelectorAll(${JSON.stringify(selector)})].find(e => ${text === undefined ? "true" : `e.textContent.trim() === ${JSON.stringify(text)}`});
  if (!b || b.disabled) return false; b.click(); return true;
})()`), { label: `click ${text ?? selector}` });
const field = async (label, value) => session.evaluate(`(() => {
  const label = [...document.querySelectorAll('.connection-field')].find(e => e.querySelector('span')?.textContent.startsWith(${JSON.stringify(label)}));
  const input = label?.querySelector('input'); if (!input) throw new Error('missing field');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', {bubbles:true})); return true;
})()`);

async function verifyPanorama() {
  fixtureCreated = true;
  execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "-i", container.Id, "sh", "-c",
    'set -eu; d=$1; token=$2; owner=$3; mkdir -m 700 -- "$d"; printf %s "$token" > "$d/.probe-owner"; cat > "$d/.bashrc"; chown -- "$owner:$(id -gn "$owner")" "$d" "$d/.bashrc"',
    "panorama-fixture", fixtureDirectory, fixtureToken, lab.username],
    { encoding: "utf8", input: fixtureText });
  fs.writeFileSync(path.join(runRoot, "fixture.json"), JSON.stringify({
    containerId: container.Id, image: container.Config.Image, mounts: container.Mounts,
    directory: fixtureDirectory, token: fixtureToken, lines: 1100,
  }, null, 2));
  await session.send("Emulation.setDeviceMetricsOverride", { width: 1100, height: 900, deviceScaleFactor: 1, mobile: false });
  await click(".system-info-tabs button", "Shell 配置");
  await waitFor(() => session.evaluate("document.querySelector('.system-info-filter-count')?.textContent.includes('500') && !!document.querySelector('.system-info-truncated')"), { timeoutMs: 60_000, label: "500-row bounded collection" });
  check("a real collection over 500 rows exposes its cutoff and an expansion action", await session.evaluate(
    "!!document.querySelector('.system-info-truncated button') && document.querySelectorAll('.system-info-file-line').length === 100"));
  await session.evaluate(`(() => { const select=document.querySelector('.system-info-row-limit select');
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(select,'2000');
    select.dispatchEvent(new Event('change',{bubbles:true})); return true; })()`);
  await waitFor(() => session.evaluate("Number(document.querySelector('.system-info-filter-count')?.textContent.match(/共 (\\d+)/)?.[1]) > 1100 && !document.querySelector('.system-info-truncated')"), { timeoutMs: 60_000, label: "expanded real snapshot" });
  const search = async value => {
    await session.evaluate(`(() => {const input=document.querySelector('.system-info-filter-search input');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});
      input.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
  };
  await search("PANORAMA_ROW_1100");
  await waitFor(() => session.evaluate("document.querySelectorAll('.system-info-file-line').length === 1 && document.querySelector('.system-info-file-number')?.textContent === '1100'"), { label: "search past row 500" });
  check("search reaches the 1100th line across the complete collected snapshot", true);
  await search(fixtureDirectory);
  await waitFor(() => session.evaluate("document.querySelector('.system-info-filter-count')?.textContent.includes('1100') && document.querySelectorAll('.system-info-file-line').length === 100"), { label: "paged fixture lines" });
  await click(".system-info-pagination button", "下一页");
  await waitFor(() => session.evaluate("document.querySelector('.system-info-file-number')?.textContent === '101'"), { label: "second page" });
  check("pagination renders 100 lines and reaches the next page", await session.evaluate("document.querySelectorAll('.system-info-file-line').length === 100"));
  await click(".system-info-panel-actions button", "复制表格");
  await waitFor(() => fs.existsSync(path.join(runRoot, "clipboard.txt")), { label: "full filtered copy" });
  const copied = fs.readFileSync(path.join(runRoot, "clipboard.txt"), "utf8");
  check("copy includes both first and last matching lines, beyond the visible page", copied.includes("PANORAMA_ROW_0001") && copied.includes("PANORAMA_ROW_1100"));
  await session.screenshot(path.join(runRoot, "shell-pagination.png"));

  await click(".system-info-file header button", "编辑文件");
  const { session: editor, target: editorTarget } = await attach(port, url => new URL(url).search === "?window=file-editor");
  const observe = async childSession => {
    childSession.onEvent((method, params) => {
      if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params.type === "error") ||
          (method === "Log.entryAdded" && params.entry.level === "error") ||
          method === "Inspector.targetCrashed") errors.push({ method, params });
    });
    await childSession.send("Runtime.enable"); await childSession.send("Log.enable"); await childSession.send("Inspector.enable");
  };
  await observe(editor);
  let terminal;
  try {
    await waitFor(() => editor.evaluate(`document.querySelector('.file-editor-text')?.value === ${JSON.stringify(fixtureText)} && !document.querySelector('.file-editor-text').readOnly`), { timeoutMs: 60_000, label: "full editable file in native child" });
    check("quick edit opens the full file, not the 100 displayed lines", true);
    const editedText = `${fixtureText}# saved-by-native-editor\n`;
    await editor.evaluate(`(() => {const input=document.querySelector('.file-editor-text');
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,${JSON.stringify(editedText)});
      input.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await click(".system-info-file header button", "编辑文件");
    const editors = (await listTargets(port)).filter(target => new URL(target.url).search === "?window=file-editor");
    check("reopening the same file reuses the editor and keeps its draft", editors.length === 1 && editors[0].id === editorTarget.id &&
      await editor.evaluate(`document.querySelector('.file-editor-text')?.value === ${JSON.stringify(editedText)}`));

    await click('[data-testid="open-ssh-terminal"]');
    ({ session: terminal } = await attach(port, url => new URL(url).search === "?window=terminal"));
    await terminal.send("Page.bringToFront");
    await observe(terminal);
    await waitFor(() => terminal.evaluate("!!document.querySelector('[data-testid=\"toggle-remote-files\"]')"), { label: "SSH file browser toggle" });
    await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"ssh-window-session\"]')?.textContent.includes('已连接')"), { timeoutMs: 60_000, label: "PTY connected before file browsing" });
    // The SSH window initially shows the file panes; its toggle would close them.
    await waitFor(() => terminal.evaluate("document.querySelector('.sftp-browser-actions button')?.disabled === false"), { timeoutMs: 60_000, label: "terminal file browser" });
    await terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]').click(); true");
    await waitFor(() => terminal.evaluate("!document.querySelector('.sftp-browser-actions')"), { label: "file browser closes" });
    await terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]').click(); true");
    await waitFor(() => terminal.evaluate("document.querySelector('.sftp-browser-actions button')?.disabled === false"), { timeoutMs: 60_000, label: "reopened terminal file browser" });
    await editor.send("Page.bringToFront");
    await waitFor(() => editor.evaluate("!document.querySelector('.file-editor-actions .file-editor-save')?.disabled"), { label: "dirty file can be saved" });
    await editor.evaluate("document.querySelector('.file-editor-actions .file-editor-save').click(); true");
    await waitFor(() => editor.evaluate("!!document.querySelector('.file-editor-dialog')"), { timeoutMs: 60_000, label: "real file save plan" });
    check("opening/reopening the terminal browser preserves the editor and its confirmation flow",
      docker("exec", container.Id, "cat", fixtureFile) === fixtureText);
    check("the confirmation freezes the draft until it is cancelled or completed",
      await editor.evaluate("document.querySelector('.file-editor-text').readOnly && document.querySelector('.file-editor-actions .file-editor-save').disabled"));
    await editor.screenshot(path.join(runRoot, "shell-edit-confirm.png"));
    await editor.evaluate("[...document.querySelectorAll('.file-editor-dialog-actions button')].find(b=>b.textContent==='取消').click(); true");
    await waitFor(() => editor.evaluate("!document.querySelector('.file-editor-dialog')"), { label: "save plan cancelled" });
    check("cancelling a save leaves the remote file unchanged and keeps the draft", docker("exec", container.Id, "cat", fixtureFile) === fixtureText &&
      await editor.evaluate(`document.querySelector('.file-editor-text').value === ${JSON.stringify(editedText)}`));
    await editor.evaluate("document.querySelector('.file-editor-actions .file-editor-save').click(); true");
    await waitFor(() => editor.evaluate("!!document.querySelector('.file-editor-dialog')"), { timeoutMs: 60_000, label: "new save plan" });
    await editor.evaluate("document.querySelector('.file-editor-dialog-actions .file-editor-save').click(); true");
    await waitFor(() => editor.evaluate("document.querySelector('.file-editor-notice')?.textContent.includes('已写回服务器并复核通过')"), { timeoutMs: 60_000, label: "verified save" });
    check("confirmed edit is independently visible on the isolated target", docker("exec", container.Id, "cat", fixtureFile) === editedText);
    await waitFor(() => editor.evaluate(`!document.querySelector('.file-editor-text').readOnly &&
      document.querySelector('.file-editor-text').value === ${JSON.stringify(editedText)}`), { label: "save readback finished" });
    await editor.screenshot(path.join(runRoot, "shell-edit-saved.png"));
    const staleDraft = `${editedText}# pending-local-edit\n`;
    await editor.evaluate(`(() => {const input=document.querySelector('.file-editor-text');
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,${JSON.stringify(staleDraft)});
      input.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    docker("exec", container.Id, "sh", "-c", 'printf "# external-edit\\n" >> "$1"', "external-edit", fixtureFile);
    await editor.evaluate("document.querySelector('.file-editor-actions .file-editor-save').click(); true");
    await waitFor(() => editor.evaluate("!!document.querySelector('.file-editor-dialog')"), { timeoutMs: 60_000, label: "guarded save plan" });
    await editor.evaluate("document.querySelector('.file-editor-dialog-actions .file-editor-save').click(); true");
    await waitFor(() => editor.evaluate("document.querySelector('.file-editor-error')?.textContent.includes('被改过了，所以没有动它')"), { timeoutMs: 60_000, label: "stale file rejected before writing" });
    check("an external file change refuses the old draft without overwriting either version",
      docker("exec", container.Id, "cat", fixtureFile) === `${editedText}# external-edit\n` &&
      await editor.evaluate(`document.querySelector('.file-editor-text').value === ${JSON.stringify(staleDraft)}`));
    await editor.evaluate("document.querySelector('[data-testid=\"file-editor-close\"]').click(); true");
    await waitFor(() => editor.evaluate("!!document.querySelector('.dialog-host')"), { label: "unsaved close confirmation" });
    await editor.evaluate("[...document.querySelectorAll('.dialog-host button')].find(b=>b.textContent==='取消').click(); true");
    check("cancelling close retains the unsaved draft", await editor.evaluate(`document.querySelector('.file-editor-text').value === ${JSON.stringify(staleDraft)}`));
    await editor.evaluate("document.querySelector('[data-testid=\"file-editor-close\"]').click(); true");
    await waitFor(() => editor.evaluate("!!document.querySelector('.dialog-host')"), { label: "discard confirmation" });
    await editor.evaluate("[...document.querySelectorAll('.dialog-host button')].find(b=>b.textContent==='放弃修改并关闭').click(); true");
  } finally {
    editor.close(); terminal?.close();
  }
}

try {
  const pageOrigin = process.env.LOVELYHAWK_DEV_SERVER ?? "https://tauri.localhost";
  ({ session } = await attach(port, url => {
    const page = new URL(url);
    return page.origin === pageOrigin && ["/", "/index.html"].includes(page.pathname);
  }));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" ||
      (method === "Runtime.consoleAPICalled" && params.type === "error") ||
      (method === "Log.entryAdded" && params.entry.level === "error")) errors.push({ method, params });
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  await session.send("Page.bringToFront");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"app-version\"]')?.textContent === 'v0.0.2'"), { label: "the native app version" });
  check("version is shown at the far right of the status bar", await session.evaluate("document.querySelector('.statusbar-end')?.lastElementChild?.dataset.testid === 'app-version'"));

  if (!panorama) {
  // Exercise the real CSS in the native WebView under both OS preferences.
  await session.evaluate(`(() => {
    const fixture = document.createElement('div'); fixture.id = 'motion-fixture';
    // Off-screen animations can be culled by WebView2's compositor. Sample
    // visible indicators and wait for rendering rather than a fixed delay.
    fixture.style.cssText = 'position:fixed;top:64px;left:24px;display:flex;gap:16px;z-index:1000';
    fixture.innerHTML = '<span class="ssh-spinner"></span><span class="loader"></span><span class="win-ir-spinner"></span><div class="docker-status-panel"><span></span></div><div class="log-analysis-status"><span></span></div><div class="check-audit-status-panel"><span></span></div><div class="emergency-command-status"><span></span></div>';
    for (const indicator of fixture.querySelectorAll('span')) {
      indicator.style.width = '24px'; indicator.style.height = '24px';
    }
    document.body.append(fixture); return true;
  })()`);
  const motion = () => session.evaluate(`[...document.querySelectorAll('#motion-fixture span')].map(e => {
    const c=getComputedStyle(e); return {name:c.animationName,duration:c.animationDuration,count:c.animationIterationCount,transform:c.transform,opacity:c.opacity,time:e.getAnimations()[0]?.currentTime ?? 0};
  })`);
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  const before = await motion();
  const after = await waitFor(async () => {
    const values = await motion();
    return values.every((value, index) => value.time > before[index].time + 50 && value.transform !== before[index].transform) ? values : null;
  }, { timeoutMs: 5000, intervalMs: 100, label: "visible activity rotation" });
  check("all seven activity indicators rotate with ordinary motion", after.length === 7 &&
    after.every((value, index) => value.name === "activity-spin" && value.count === "infinite" && value.transform !== before[index].transform), after);
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  const reduced = await motion();
  const reducedAfter = await waitFor(async () => {
    const values = await motion();
    return values.every((value, index) => value.time > reduced[index].time + 50 && value.transform !== reduced[index].transform) ? values : null;
  }, { timeoutMs: 5000, intervalMs: 100, label: "visible reduced-motion steps" });
  check("Windows reduced motion keeps slow discrete activity steps", reducedAfter.every((value, index) =>
    value.name === "activity-spin" && value.duration === "1.8s" && value.transform !== reduced[index].transform), reducedAfter);
  await session.evaluate("document.documentElement.dataset.motion = 'reduced'");
  const disabled = await motion();
  const disabledAfter = await waitFor(async () => {
    const values = await motion();
    return values.every((value, index) => value.time > disabled[index].time + 50 && value.opacity !== disabled[index].opacity) ? values : null;
  }, { timeoutMs: 5000, intervalMs: 100, label: "visible reduced-motion opacity" });
  check("disabling app animations uses opacity instead of rotation", disabledAfter.every((value, index) =>
    value.name === "activity-pulse" && value.transform === "none" && value.opacity !== disabled[index].opacity), disabledAfter);
  await session.evaluate("document.documentElement.dataset.motion = 'full'");
  await session.evaluate("document.querySelector('#motion-fixture').remove()");
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });

  await click('[data-testid="app-version"]');
  const update = await waitFor(() => session.evaluate("document.querySelector('#dialog-host-message')?.textContent"), { timeoutMs: 40_000, label: "GitHub release check" });
  check("native GitHub Release check reports the actual stable version", update.includes("GitHub 最新稳定版为 v0.0.1"), update);
  await session.screenshot(path.join(runRoot, "version-check.png"));
  await click(".dialog-host button", "知道了");
  check("version dialog restores keyboard focus", await session.evaluate("document.activeElement?.dataset.testid === 'app-version'"));
  }

  await click('[data-testid="open-connections"]');
  await click(".connection-manager-header button", "新建连接");
  for (const [label, value] of [
    ["连接名称", "测试后保存回归"], ["主机名或 IP", lab.host], ["端口", String(lab.port)],
    ["Linux 用户名", lab.username], ["SSH 密码", lab.password],
  ]) await field(label, value);
  await click(".connection-editor footer button", "测试当前配置");
  const shownFingerprint = await waitFor(() => session.evaluate("document.querySelector('.ssh-host-key-panel code')?.textContent"), { timeoutMs: 60_000, label: "SSH host key" });
  check("lab SSH host key matches independent container observation", shownFingerprint === fingerprint);
  await click('[data-testid="ssh-host-key-trust"]');
  await waitFor(() => session.evaluate("document.querySelector('.ssh-stage.probe-succeeded') !== null"), { timeoutMs: 60_000, label: "successful SSH probe" });
  await waitFor(() => session.evaluate("document.querySelector('.connection-notice:not(.error)')?.textContent.includes('验证通过并已保存')"), { label: "saved probe snapshot" });
  await click(".ssh-attempt-dialog > footer button");
  await waitFor(() => session.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]')?.disabled === false"), { label: "save enabled after readback" });
  check("probe success clears the draft password and shows it is stored", await session.evaluate(`(() => {
    const f=[...document.querySelectorAll('.connection-field')].find(e=>e.textContent.includes('SSH 密码'));
    return f?.textContent.includes('已有保存值') && f.querySelector('input').value === '';
  })()`));
  await session.screenshot(path.join(runRoot, "probe-saved.png"));
  await click('.connection-editor button[type="submit"]');
  await waitFor(() => session.evaluate("document.querySelector('.connection-details-view h2')?.textContent === '测试后保存回归'"), { label: "save after probe" });
  check("save after a successful new-connection probe updates without an error", await session.evaluate(
    "document.querySelector('.connection-notice.error') === null && document.querySelector('.connection-notice:not(.error)')?.textContent === '连接配置已更新。'"));
  check("probe then save creates exactly one stored connection", await session.evaluate("document.querySelectorAll('.connection-list .connection-list-row').length === 1"));
  await session.screenshot(path.join(runRoot, "save-after-probe.png"));
  if (process.argv.includes("--layout") || panorama) {
    for (const width of [1440, 1100]) {
      await session.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      const layout = await session.evaluate(`(() => {
        const pane=document.querySelector('.connection-detail');
        const footer=document.querySelector('.connection-details-view > footer');
        const buttons=[...footer.querySelectorAll('button')];
        return {
          headerHeight:document.querySelector('.connection-manager-header').getBoundingClientRect().height,
          headerButtons:document.querySelectorAll('.connection-details-view > header button').length,
          buttons:buttons.map(b=>b.textContent.trim()),
          visible:buttons.every(b=>{const r=b.getBoundingClientRect(), p=pane.getBoundingClientRect();return r.left>=p.left&&r.right<=p.right&&r.top>=p.top&&r.bottom<=p.bottom}),
          overflow:pane.scrollWidth>pane.clientWidth+1,
          cardBackgrounds:[...document.querySelectorAll('.connection-fact-grid > div')].map(e=>getComputedStyle(e).backgroundColor)
        };
      })()`);
      check(`compact connection layout at ${width}px`, layout.headerHeight < 75 &&
        layout.headerButtons === 0 && layout.buttons.join(",") === "编辑配置,永久删除,测试连接,连接目标" &&
        layout.visible && !layout.overflow && layout.cardBackgrounds.every(value => value === "rgba(0, 0, 0, 0)"), layout);
      await session.screenshot(path.join(runRoot, `connections-${width}.png`));
    }
    await click(".connection-connect-actions button", "连接目标");
    await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager') === null"),
      { timeoutMs: 90_000, label: "connection through the relocated action" });
    await session.evaluate("[...document.querySelectorAll('.nav-item')].find(e=>e.textContent.includes('主机全景')).click()");
    await waitFor(() => session.evaluate("document.querySelector('.system-info-summary strong')?.textContent !== '—' && document.querySelector('.system-info-summary') !== null"),
      { timeoutMs: 60_000, label: "the real lab system summary" });
    for (const width of [1440, 1100, 900]) {
      await session.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      const layout = await session.evaluate(`(() => {
        const s=document.querySelector('.system-info-summary'), rows=[...s.querySelectorAll('article')];
        return {columns:getComputedStyle(s).gridTemplateColumns.split(' ').length,
          overflow:s.scrollWidth>s.clientWidth+1 || rows.some(r=>r.scrollWidth>r.clientWidth+1),
          fields:rows.length, populated:rows.filter(r=>r.querySelector('strong').textContent!=='—').length};
      })()`);
      check(`system summary adapts at ${width}px without hiding values`, layout.columns === (width === 900 ? 1 : 2) &&
        !layout.overflow && layout.fields > 6 && layout.populated > 6, layout);
      await session.screenshot(path.join(runRoot, `summary-${width}.png`));
    }
    if (panorama) await verifyPanorama();
    await click('[data-testid="sidebar-disconnect-target"]');
    await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { label: "lab disconnect" });
  } else {
    await click('[aria-label="关闭连接管理"]');
  }
  check("no browser runtime or console errors", errors.length === 0, errors);
  await click('[data-testid="window-close"]');
  if (panorama) {
    await waitFor(() => app.child.exitCode !== null, { timeoutMs: 15_000, label: "clean desktop exit" });
    check("desktop exits cleanly", app.child.exitCode === 0);
  }
} catch (error) {
  checks.push({ name: "scenario completed", ok: false, detail: String(error) });
  console.error(error);
  if (session) {
    await session.screenshot(path.join(runRoot, "failure.png")).catch(() => {});
    const state = await session.evaluate(`({
      url:location.href, ready:document.readyState, title:document.title,
      version:document.querySelector('[data-testid="app-version"]')?.textContent,
      text:document.body.innerText.slice(0, 3000)
    })`).catch(reason => ({ error: String(reason) }));
    fs.writeFileSync(path.join(runRoot, "failure-state.json"), JSON.stringify({ state, output: app.output }, null, 2));
  }
} finally {
  session?.close();
  app.child.kill();
  if (fixtureCreated) {
    try {
      await waitFor(() => app.child.exitCode !== null || app.child.signalCode !== null, { timeoutMs: 10_000, label: "host stopped before fixture cleanup" });
      docker("exec", container.Id, "sh", "-c",
        'set -eu; d=$1; token=$2; printf "%s\\n" "$d" | grep -Eq "^/home/lhprobe[0-9a-f]{12}$"; [ ! -L "$d" ]; if [ -d "$d" ]; then [ "$(cat "$d/.probe-owner")" = "$token" ]; rm -rf -- "$d"; fi',
        "panorama-cleanup", fixtureDirectory, fixtureToken);
      checks.push({ name: "owned Shell fixture removed", ok: true });
    } catch (error) {
      checks.push({ name: "owned Shell fixture removed", ok: false, detail: String(error) });
    }
  }
  fs.writeFileSync(path.join(runRoot, "result.json"), JSON.stringify({
    schema: "lovelyhawk-desktop-updates-probe/v1", checks, errors,
    observationStart: "CDP attached after the main document loaded; Runtime and Log enabled before interaction",
    lab: { id: container.Id, image: container.Config.Image, network: container.HostConfig.NetworkMode, mounts: container.Mounts },
  }, null, 2));
  console.log(`Evidence: ${runRoot}`);
  process.exitCode = checks.some(item => !item.ok) ? 1 : 0;
}
