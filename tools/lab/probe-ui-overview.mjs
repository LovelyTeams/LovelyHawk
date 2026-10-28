// Opens the real window on a lab host and reads the system-overview tabs the
// way an operator sees them: the shell configuration as text, the 详情 column
// only where a detail exists, and the network tabs with their columns lined up.
//
//   node tools/lab/probe-ui-overview.mjs [靶机名]
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
const port = 9337;
const lab = process.argv[2] ?? "arena";

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

/** Click a tab in the overview and wait for it to finish collecting. */
async function openTab(session, label) {
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.system-info-tabs button')]
      .find(b => b.textContent?.trim() === ${JSON.stringify(label)})?.click();
    return true;
  })()`);
  await waitFor(
    session,
    `(() => {
      const panel = document.querySelector('.system-info-table-panel');
      if (panel === null) return false;
      if (panel.querySelector('.system-info-table-state') !== null) {
        return panel.querySelector('.system-info-table-state.error') !== null;
      }
      return panel.querySelector('table tbody tr, .system-info-file') !== null;
    })()`,
    `${label} 标签页`,
  );
}

const evidence = path.join(repository, "target", "lab-ui");
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-overview-"));
let app;
let session;

try {
  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, { ...labTarget(lab), name: `实验靶机 ${lab}` });
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  } finally {
    sidecar.close();
  }

  app = await startDesktop({ dataRoot, port });
  session = app.session;

  await waitFor(session, "document.querySelector('[data-testid=open-connections]') !== null", "窗口");
  await session.evaluate("document.querySelector('[data-testid=open-connections]').click(); true");
  await waitFor(session, "document.querySelector('.connection-list-row') !== null", "连接列表");
  await session.evaluate("document.querySelector('.connection-list-row').click(); true");
  await waitFor(
    session,
    "[...document.querySelectorAll('.connection-detail button')].some(b => b.textContent?.trim() === '连接目标')",
    "连接详情",
  );
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.connection-detail button')]
      .find(b => b.textContent?.trim() === '连接目标')?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.nav-item') !== null", "主界面", 200);
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.nav-item')]
      .find(c => c.textContent?.includes('主机全景'))?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.system-info-tabs') !== null", "主机全景", 200);

  console.log(`\n=== Shell 配置：纯文本 ===`);
  await openTab(session, "Shell 配置");
  const shell = await session.evaluate(`(() => {
    const files = [...document.querySelectorAll('.system-info-file')];
    return {
      files: files.length,
      tables: document.querySelectorAll('.system-info-table-panel table').length,
      names: files.map(f => f.querySelector('header strong')?.textContent ?? ''),
      headers: files.map(f => [...f.querySelectorAll('header span')].map(s => s.textContent)),
      lines: files.reduce((total, f) => total + f.querySelectorAll('.system-info-file-line').length, 0),
      marked: [...document.querySelectorAll('.system-info-file-line.warning, .system-info-file-line.high')]
        .map(l => l.querySelector('.system-info-file-text')?.textContent?.trim().slice(0, 70)),
    };
  })()`);
  console.log(`  文件 ${shell.files} 个，共 ${shell.lines} 行；表格 ${shell.tables} 个`);
  for (const [index, name] of shell.names.entries()) {
    console.log(`    ${name} — ${(shell.headers[index] ?? []).join(" · ")}`);
  }
  for (const line of shell.marked) console.log(`    标红：${line}`);
  check("Shell 配置不再是表格", shell.tables, 0);
  check("Shell 配置按文件分组", shell.files > 0, true);
  check("每个文件都有时间而不是时间戳", shell.headers.every((h) => /\d{4}-\d{2}-\d{2}/u.test(h.join(" "))), true);
  check("危险行被标出来了", shell.marked.length > 0, true);
  const shot = await session.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(evidence, "shell-configs.png"), Buffer.from(shot.data, "base64"));

  console.log(`\n=== 详情列：只在真有详情时出现 ===`);
  const columns = {};
  for (const label of ["网络详情", "开放端口", "系统服务", "用户列表", "启动项汇总"]) {
    await openTab(session, label);
    columns[label] = await session.evaluate(`(() => {
      const panel = document.querySelector('.system-info-table-panel');
      const heads = [...panel.querySelectorAll('thead th')].map(t => t.textContent);
      return {
        heads,
        rows: panel.querySelectorAll('tbody tr').length,
        buttons: panel.querySelectorAll('tbody button').length,
        first: [...(panel.querySelector('tbody tr')?.querySelectorAll('td') ?? [])]
          .map(t => t.textContent).slice(0, 8),
      };
    })()`);
    const seen = columns[label];
    console.log(`  ${label}: ${seen.rows} 行，列 [${seen.heads.join(" | ")}]，查看按钮 ${seen.buttons} 个`);
    console.log(`    首行 ${JSON.stringify(seen.first)}`);
  }
  check("网络详情没有详情列", columns["网络详情"].heads.includes("详情"), false);
  check("网络详情没有查看按钮", columns["网络详情"].buttons, 0);
  check("开放端口没有查看按钮", columns["开放端口"].buttons, 0);
  check("启动项汇总没有查看按钮", columns["启动项汇总"].buttons, 0);
  check("系统服务保留查看按钮", columns["系统服务"].buttons > 0, true);
  check("用户列表保留查看按钮", columns["用户列表"].buttons > 0, true);
  check("系统服务采到了数据", columns["系统服务"].rows > 0, true);
  check("开放端口的用户列不再是空的", columns["开放端口"].first[5] !== "", true);

  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(evidence, "overview-tabs.png"), Buffer.from(data, "base64"));
  console.log(`\n截图：${path.join(evidence, "overview-tabs.png")}`);
  console.log(`${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  await app?.close();
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
