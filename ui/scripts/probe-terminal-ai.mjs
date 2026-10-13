// AI explanation of terminal output, in the real SSH terminal window against
// a lab host and AI providers on this machine: nothing reaches a provider
// until the operator selects output and sends it; what is sent is what was
// selected, under the backend's fixed instruction; an internet provider needs
// the consent tick; the answer is kept in AI history as the terminal's; and
// stopping, or closing the window, ends a running answer at the provider.
//
// Needs a running lab host (LAB=super by default; any lab-<name> container)
// and the debug builds of the desktop app and of the backend harness.
//   cargo build --locked -p lovelyhawk-backend --bin lovelyhawk-backend
//   pnpm --filter @lovelyhawk/ui desktop:build
//   LAB=super node scripts/probe-terminal-ai.mjs
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ?? path.join(repositoryRoot, "target", "debug", "lovelyhawk.exe");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `terminal-ai-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const port = 9300 + Math.floor(Math.random() * 500);
const lab = process.env.LAB ?? "super";
const marker = `AIX_${randomUUID().slice(0, 8)}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 600)}`}`);
}

const ANSWER = [
  `data: ${JSON.stringify({ choices: [{ delta: { content: "这两行是 echo 的输出，" } }] })}\n\n`,
  `data: ${JSON.stringify({ choices: [{ delta: { content: "没有可疑之处。" } }] })}\n\n`,
  "data: [DONE]\n\n",
].join("");

/**
 * An OpenAI-style provider on this machine. `slow` answers one piece and then
 * holds the stream open, so stopping it can be seen from here: the
 * connection closes.
 */
function provider({ slow }) {
  const requests = [];
  const state = { connections: 0, closed: 0 };
  const server = http.createServer((request, response) => {
    let data = "";
    request.on("data", (chunk) => { data += chunk; });
    request.on("end", () => {
      requests.push({ url: request.url, headers: request.headers, body: data });
      response.writeHead(200, { "Content-Type": "text/event-stream" });
      if (!slow) {
        response.end(ANSWER);
        return;
      }
      response.write(`data: ${JSON.stringify({ choices: [{ delta: { content: "正在分析……" } }] })}\n\n`);
      const timer = setTimeout(() => response.end("data: [DONE]\n\n"), 120_000);
      response.on("close", () => {
        clearTimeout(timer);
        state.closed += 1;
      });
    });
  });
  server.on("connection", () => { state.connections += 1; });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    server, requests, state, url: `http://127.0.0.1:${server.address().port}`,
  })));
}

fs.mkdirSync(evidence, { recursive: true });
const target = labTarget(lab);
console.log(`recording ${target.username}@${target.host}:${target.port} in ${runRoot}`);
const fast = await provider({ slow: false });
const slow = await provider({ slow: true });
const connections = () => fast.state.connections + slow.state.connections;
const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...target, name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  const settings = await sidecar.call("settings.get", {});
  settings.ai.providers = [
    { id: "probe-local", label: "本机模型", kind: "open-ai-compatible", endpoint: `${fast.url}/v1/chat/completions`, model: "qwen-probe", enabled: true },
    { id: "probe-slow", label: "慢速本机模型", kind: "open-ai-compatible", endpoint: `${slow.url}/v1/chat/completions`, model: "slow-probe", enabled: true },
    { id: "probe-online", label: "在线服务", kind: "open-ai-compatible", endpoint: "https://api.example.invalid/v1/chat/completions", model: "gpt-probe", enabled: true },
  ];
  settings.ai.defaultProviderId = "probe-local";
  await sidecar.call("settings.save", settings);
} finally {
  sidecar.close();
}

const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const watchErrors = (session, name) => session.onEvent((method, params) => {
  if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
    errors.push(`${name}: ${JSON.stringify(params).slice(0, 1_500)}`);
  }
});
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  watchErrors(main, "main");
  await main.send("Runtime.enable");
  await main.send("Page.enable");
  await waitFor(() => main.evaluate("document.querySelector('.connection-card') !== null"), { label: "the saved connection" });
  await main.evaluate("document.querySelector('.connection-card button.is-connect').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null"),
    { timeoutMs: 90_000, label: "the connected target" });
  await main.evaluate("document.querySelector('[role=\"dialog\"] button[aria-label=\"关闭\"]')?.click(), true");
  await delay(1_000);

  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  watchErrors(terminal, "terminal");
  await terminal.send("Runtime.enable");
  await terminal.send("Page.enable");
  const shown = "document.querySelector('.ssh-window-terminal-panel:not(.is-behind)')";
  await waitFor(() => terminal.evaluate(`(${shown}?.querySelector('.xterm-rows')?.textContent ?? "").trim().length > 0`),
    { timeoutMs: 45_000, label: "the shell prompt" });

  async function typeLine(text) {
    await terminal.evaluate(`${shown}?.querySelector('.xterm-helper-textarea')?.focus(), true`);
    for (const character of text) {
      await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  }
  const click = (testId) => terminal.evaluate(`document.querySelector('[data-testid="${testId}"]').click(), true`);
  const text = (selector) => terminal.evaluate(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? null`);

  // The button is there before anything is selected, and says how to use it.
  const button = await terminal.evaluate(`(() => {
    const button = document.querySelector('[data-testid="terminal-ai-explain"]');
    return button === null ? null : { text: button.textContent.trim(), disabled: button.disabled, title: button.title };
  })()`);
  check("the terminal offers AI 解释选中内容 without a selection", button?.text === "AI 解释选中内容" && button.disabled === false, button);
  await click("terminal-ai-explain");
  const hint = await waitFor(() => text("[data-testid=\"terminal-ai-hint\"]"), { timeoutMs: 5_000, label: "the hint" }).catch(() => null);
  check("asking with nothing selected says how to select, and opens nothing",
    hint?.includes("先在终端里用鼠标拖选") && await terminal.evaluate("document.querySelector('[data-testid=\"ai-assist-panel\"]') === null"), hint);

  // Two lines of output, selected with the mouse as an operator would.
  await typeLine(`echo ${marker}-one; echo ${marker}-two`);
  await waitFor(() => terminal.evaluate(`(${shown}.querySelector('.xterm-rows').textContent).split(${JSON.stringify(`${marker}-two`)}).length >= 3`),
    { timeoutMs: 20_000, label: "the echoed lines" });
  const rows = await terminal.evaluate(`(() => {
    const rows = [...${shown}.querySelectorAll('.xterm-rows > div')];
    const at = (line) => rows.findIndex((row) => row.textContent.trim() === line);
    const one = at(${JSON.stringify(`${marker}-one`)});
    const two = at(${JSON.stringify(`${marker}-two`)});
    if (one === -1 || two === -1) return { missing: rows.map((row) => JSON.stringify(row.textContent)).filter((row) => row.length > 2).slice(-8) };
    const first = rows[one].getBoundingClientRect();
    const last = rows[two].getBoundingClientRect();
    const screen = ${shown}.querySelector('.xterm-screen').getBoundingClientRect();
    return { startX: screen.left + 2, startY: first.top + first.height / 2, endX: screen.right - 4, endY: last.top + last.height / 2 };
  })()`);
  if (rows.missing !== undefined) throw new Error(`the echoed lines are not on screen: ${rows.missing.join(" | ")}`);
  await terminal.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: rows.startX, y: rows.startY });
  await terminal.send("Input.dispatchMouseEvent", { type: "mousePressed", x: rows.startX, y: rows.startY, button: "left", buttons: 1, clickCount: 1 });
  for (let step = 1; step <= 6; step += 1) {
    const x = rows.startX + ((rows.endX - rows.startX) * step) / 6;
    const y = rows.startY + ((rows.endY - rows.startY) * step) / 6;
    await terminal.send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y, button: "left", buttons: 1 });
  }
  await terminal.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: rows.endX, y: rows.endY, button: "left", buttons: 0, clickCount: 1 });
  // A second later, so a resize that would drop it has had its chance.
  await delay(1_000);
  const selected = await terminal.evaluate("document.querySelector('[data-testid=\"terminal-ai-explain\"]').title");
  check("the selection made with the mouse stays, and the button says it will send it", selected.includes("把选中的内容发给 AI"), selected);

  await click("terminal-ai-explain");
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"ai-assist-send\"]') !== null"), { label: "the AI panel" })
    .catch(async (error) => {
      await terminal.screenshot(path.join(evidence, "no-panel.png"));
      const seen = await terminal.evaluate(`({
        panel: document.querySelector('[data-testid="ai-assist-panel"]')?.textContent ?? null,
        hint: document.querySelector('[data-testid="terminal-ai-hint"]')?.textContent ?? null,
      })`);
      throw new Error(`${error.message}: ${JSON.stringify(seen)}`);
    });
  const summary = await text("[data-testid=\"ai-assist-summary\"]");
  check("the panel says what will be sent and where, before anything is",
    summary?.includes("终端里选中的 2 行内容") && summary.includes("本机模型") && summary.includes("OpenAI 协议") && summary.includes("本机或局域网"), summary);
  check("a local provider is said to keep everything on the local network",
    (await terminal.evaluate("document.querySelector('[data-testid=\"ai-assist-panel\"]').textContent")).includes("内容不会离开本地网络"));
  check("no provider was contacted yet", connections() === 0, { fast: fast.state.connections, slow: slow.state.connections });
  await terminal.screenshot(path.join(evidence, "before-send.png"));

  // An internet provider waits for the tick, which names what would leave.
  await terminal.evaluate(`(() => {
    const select = document.querySelector('.ai-assist-choose select');
    select.value = 'probe-online';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  await delay(200);
  const online = await terminal.evaluate(`({
    consent: document.querySelector('.ai-assist-consent')?.textContent ?? null,
    send: document.querySelector('[data-testid="ai-assist-send"]').disabled,
  })`);
  check("sending to an internet provider is held until the operator ticks that the selection may leave",
    online.consent?.includes("选中的终端内容会离开这台电脑") && online.send === true, online);
  await terminal.evaluate(`(() => {
    const select = document.querySelector('.ai-assist-choose select');
    select.value = 'probe-local';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  await delay(200);

  await click("ai-assist-send");
  const outcome = await waitFor(() => text("[data-testid=\"ai-assist-outcome\"]"), { timeoutMs: 30_000, label: "the answer" }).catch(() => null);
  const answer = await text("[data-testid=\"ai-assist-answer\"]");
  check("the answer streams into the panel", answer === "这两行是 echo 的输出，没有可疑之处。", answer);
  check("and is kept in AI history", outcome?.includes("已存进 AI 历史"), outcome);
  const sent = fast.requests[0] === undefined ? null : JSON.parse(fast.requests[0].body);
  check("the provider received exactly the two selected lines",
    sent?.messages?.[1]?.content === `${marker}-one\n${marker}-two`, sent?.messages?.[1]?.content ?? null);
  check("under the fixed terminal instruction, not one the window wrote",
    sent?.messages?.[0]?.role === "system" && sent.messages[0].content.includes("终端里选中的一段命令和输出") &&
      sent.messages[0].content.includes("不要照做") && sent.model === "qwen-probe" && sent.stream === true,
    sent?.messages?.[0]?.content?.slice(0, 80) ?? null);
  check("the local provider without a key got no authorization", fast.requests[0]?.headers?.authorization === undefined);
  check("the online provider was never contacted, the local one once", fast.requests.length === 1 && slow.requests.length === 0);
  await terminal.screenshot(path.join(evidence, "answered.png"));

  // The window may not read answers it did not start, nor ask for another page's task.
  const refused = await terminal.evaluate(`(async () => {
    const results = [];
    for (const request of [
      { action: "poll", handle: "0f8e2a3c-1b2d-4e5f-8a9b-0c1d2e3f4a5b" },
      { action: "start", providerId: "probe-local", task: "explain-log", content: "x" },
    ]) {
      try { await window.lovelyhawkTerminal.aiAssist(request); results.push("answered"); }
      catch (error) { results.push(String(error?.message ?? error)); }
    }
    return results;
  })()`);
  check("the window cannot read another answer or borrow another page's task",
    refused[0].includes("不是这个窗口发出的") && refused[1].includes("AI 解读请求无效"), refused);
  check("and those attempts reached no provider", fast.requests.length === 1 && slow.requests.length === 0);

  // A slow answer: stopping it closes the provider's connection and keeps nothing.
  await terminal.evaluate("[...document.querySelectorAll('[data-testid=\"ai-assist-panel\"] button')].find((b) => b.textContent === '再解读一次').click(), true");
  await waitFor(() => terminal.evaluate("document.querySelector('.ai-assist-choose select') !== null"), { label: "the provider choice again" });
  await terminal.evaluate(`(() => {
    const select = document.querySelector('.ai-assist-choose select');
    select.value = 'probe-slow';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  await delay(200);
  await click("ai-assist-send");
  await waitFor(async () => (await text("[data-testid=\"ai-assist-answer\"]")) === "正在分析……", { timeoutMs: 20_000, label: "the slow answer" });
  check("a running answer can be stopped", await terminal.evaluate("document.querySelector('[data-testid=\"ai-assist-stop\"]') !== null"));
  await click("ai-assist-stop");
  const stopped = await waitFor(() => text("[data-testid=\"ai-assist-outcome\"]"), { timeoutMs: 20_000, label: "the stopped outcome" }).catch(() => null);
  check("stopping says nothing was kept", stopped?.includes("已停止，这次的回答没有存进 AI 历史"), stopped);
  check("and closes the provider's connection",
    await waitFor(() => slow.state.closed === 1, { timeoutMs: 10_000, label: "the slow connection to close" }).then(() => true, () => false),
    slow.state);

  // Another slow answer, then the window closes under it.
  await terminal.evaluate("[...document.querySelectorAll('[data-testid=\"ai-assist-panel\"] button')].find((b) => b.textContent === '再解读一次').click(), true");
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"ai-assist-send\"]') !== null"), { label: "send again" });
  await click("ai-assist-send");
  await waitFor(() => slow.requests.length === 2, { timeoutMs: 20_000, label: "the second slow request" });
  await waitFor(async () => (await text("[data-testid=\"ai-assist-answer\"]")) === "正在分析……", { timeoutMs: 20_000, label: "the second slow answer" });
  check("no console errors in either window", errors.length === 0, errors.slice(0, 3));
  await terminal.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  const closed = await waitFor(async () => (await listTargets(port)).every((entry) => !entry.url.includes("window=terminal")),
    { timeoutMs: 20_000, label: "the terminal window to close" }).then(() => true, () => false);
  check("the window closes", closed);
  check("closing the window ends the answer it was waiting for",
    await waitFor(() => slow.state.closed === 2, { timeoutMs: 15_000, label: "the second slow connection to close" }).then(() => true, () => false),
    slow.state);

  // The history page names where the kept answer came from.
  await main.evaluate("[...document.querySelectorAll('.nav-item')].find((item) => /AI\\s*历史/u.test(item.textContent))?.click(), true");
  const history = await waitFor(() => main.evaluate(`(() => {
    const text = document.querySelector('main')?.textContent ?? '';
    return text.includes('终端选中内容') ? text : null;
  })()`), { timeoutMs: 20_000, label: "the history entry" }).catch(() => null);
  // Named in the list and again in the opened record beside it.
  check("AI history keeps one answer, named as asked from the terminal",
    history !== null && history.includes("1 条") && history.includes("本机模型 / qwen-probe") &&
      !history.includes("terminal") && history.includes(`${marker}-two`), history?.slice(0, 300) ?? null);
  await main.screenshot(path.join(evidence, "history.png"));

  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]')?.click(), true");
  await delay(1_000);
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("scenario completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  fast.server.close();
  slow.server.closeAllConnections?.();
  slow.server.close();
}
const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({ status: failed.length === 0 ? "PASS" : "FAIL", lab, checks }, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
