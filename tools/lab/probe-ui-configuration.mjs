// Looks at the configuration page the way the operator opens it: at the top,
// in both halves, with nothing connected.
//
//   node tools/lab/probe-ui-configuration.mjs
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const electronRoot = path.join(repository, "electron");
const port = 9338;

let failures = 0;
function check(name, actual, expected = true) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`}`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(session, expression, label, attempts = 160) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return true;
    await sleep(500);
  }
  throw new Error(`一直没等到 ${label}`);
}

function attach(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const pending = new Map();
    let nextId = 1;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      const waiting = pending.get(message.id);
      if (waiting === undefined) return;
      pending.delete(message.id);
      if (message.error !== undefined) waiting.reject(new Error(JSON.stringify(message.error)));
      else waiting.resolve(message.result);
    });
    socket.addEventListener("error", () => reject(new Error("附加调试端口失败")));
    socket.addEventListener("open", () => {
      const send = (method, params) => new Promise((res, rej) => {
        const id = nextId++;
        pending.set(id, { resolve: res, reject: rej });
        socket.send(JSON.stringify({ id, method, params }));
        setTimeout(() => { if (pending.delete(id)) rej(new Error(`${method} 超时`)); }, 30_000);
      });
      resolve({
        send,
        close: () => socket.close(),
        async evaluate(expression) {
          const result = await send("Runtime.evaluate", {
            expression, awaitPromise: true, returnByValue: true,
          });
          if (result.exceptionDetails !== undefined) {
            throw new Error(result.exceptionDetails.exception?.description ?? "求值抛出");
          }
          return result.result.value;
        },
      });
    });
  });
}

async function openSession() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json());
      const page = targets.find((target) =>
        target.type === "page" && String(target.url).startsWith("lovelyres://app/") &&
        !String(target.url).includes("window=terminal"));
      if (page !== undefined) return await attach(page.webSocketDebuggerUrl);
    } catch { /* not listening yet */ }
    await sleep(500);
  }
  throw new Error("窗口没有开出调试端口");
}

/** How far down the window the first real content starts. */
const FIRST_CONTENT_TOP = `(() => {
  const workspace = document.querySelector('.workspace, .content');
  const page = document.querySelector('.configuration-page');
  const first = page?.firstElementChild?.firstElementChild ?? null;
  return {
    headings: page?.querySelectorAll('h1').length ?? -1,
    switchTop: Math.round(document.querySelector('.configuration-modes')?.getBoundingClientRect().top ?? -1),
    switchHeight: Math.round(document.querySelector('.configuration-modes')?.getBoundingClientRect().height ?? -1),
    // The row the switch joined, so "costs no height" can be measured rather
    // than asserted against a number picked out of the air.
    rowHeight: Math.round(document.querySelector('.baseline-tabs')?.getBoundingClientRect().height ?? -1),
    tabHeight: Math.round(document.querySelector('.baseline-tabs button')?.getBoundingClientRect().height ?? -1),
    pageTop: Math.round(page?.getBoundingClientRect().top ?? -1),
    firstTop: Math.round(first?.getBoundingClientRect().top ?? -1),
    workspaceTop: Math.round(workspace?.getBoundingClientRect().top ?? -1)
  };
})()`;

const evidence = path.join(repository, "target", "lab-ui");
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-config-"));
let electron;
let session;

try {
  const executable = execFileSync(
    process.execPath, ["-e", "process.stdout.write(require('electron'))"],
    { cwd: electronRoot, encoding: "utf8" },
  ).trim();
  electron = spawn(executable, [".", `--remote-debugging-port=${port}`], {
    cwd: electronRoot,
    env: { ...process.env, LOVELYRES_ARCHIVE_ROOT: dataRoot, LOVELYRES_DEBUG: "1" },
    stdio: "ignore", shell: false, windowsHide: true,
  });

  session = await openSession();
  await session.send("Runtime.enable", {});
  await session.send("Page.enable", {});
  await waitFor(session, "document.querySelector('.nav-item') !== null", "主界面", 200);
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.nav-item')]
      .find(c => c.querySelector('strong')?.textContent === '配置')?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.configuration-modes') !== null", "配置页");

  console.log("\n=== 检查这台主机 ===");
  const inspect = await session.evaluate(FIRST_CONTENT_TOP);
  console.log(`  ${JSON.stringify(inspect)}`);
  check("页面里没有重复的大标题", inspect.headings, 0);
  check("切换开关没有把它加入的那一行撑高", inspect.rowHeight <= inspect.tabHeight, true);
  check("内容紧贴页面顶部", inspect.firstTop - inspect.pageTop <= 24, true);
  const one = await session.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(evidence, "configuration-inspect.png"), Buffer.from(one.data, "base64"));

  console.log("\n=== 生成新配置 ===");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.configuration-modes button')]
      .find(b => b.textContent?.includes('生成'))?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.config-product-list button') !== null", "生成器");
  const generate = await session.evaluate(`(() => {
    const list = document.querySelector('.config-product-list');
    const workbench = document.querySelector('.config-generator-workbench');
    const editor = document.querySelector('.config-editor');
    const preview = document.querySelector('.config-preview');
    const box = (node) => node === null ? null : {
      left: Math.round(node.getBoundingClientRect().left),
      width: Math.round(node.getBoundingClientRect().width),
    };
    return {
      products: list?.querySelectorAll('button').length ?? -1,
      families: [...(list?.querySelectorAll('.config-product-family') ?? [])].map(n => n.textContent),
      listScrolls: list === null ? false : getComputedStyle(list).overflowY === 'auto',
      columns: workbench === null ? '' : getComputedStyle(workbench).gridTemplateColumns,
      list: box(list), editor: box(editor), preview: box(preview),
      strips: document.querySelectorAll('.config-product-strip').length,
    };
  })()`);
  console.log(`  产品 ${generate.products} 个，分组 ${JSON.stringify(generate.families)}`);
  console.log(`  列宽 ${generate.columns}`);
  console.log(`  左列 ${JSON.stringify(generate.list)}  编辑 ${JSON.stringify(generate.editor)}  预览 ${JSON.stringify(generate.preview)}`);
  check("旧的横向产品条没有了", generate.strips, 0);
  check("九个产品都在左侧", generate.products, 9);
  check("按家族分组", generate.families.length >= 4, true);
  check("左列可以独立滚动", generate.listScrolls, true);
  check("编辑区在左列右边", generate.editor.left > generate.list.left + generate.list.width - 4, true);
  check("预览区在编辑区右边", generate.preview.left > generate.editor.left, true);
  const two = await session.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(evidence, "configuration-generate.png"), Buffer.from(two.data, "base64"));

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  session?.close();
  electron?.kill();
  await sleep(600);
  fs.rmSync(dataRoot, { recursive: true, force: true });
}
