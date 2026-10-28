// Opens the baseline page against a real host, selects a failing check, and
// captures what the operator would be looking at.
//
//   node tools/lab/probe-ui-baseline.mjs            # ubuntu
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
const port = 9334;

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(session, expression, label, attempts = 90) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const evidence = path.join(repository, "target", "lab-ui");
fs.mkdirSync(evidence, { recursive: true });

async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-base-"));
let app;
let session;
try {
  onHost("cp /etc/ssh/sshd_config /tmp/sshd_config.bak");
  const seeded = Buffer.from(
    "Port 22\nPermitRootLogin yes\n#PermitRootLogin prohibit-password\nPasswordAuthentication yes\nPermitRootLogin no\n",
    "utf8",
  ).toString("base64");
  onHost(`printf '%s' '${seeded}' | base64 -d > /etc/ssh/sshd_config`);

  console.log(`preparing ${dataRoot} ...`);
  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally {
    sidecar.close();
  }

  console.log("launching the window ...");
  app = await startDesktop({ dataRoot, port });
  session = app.session;
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");
  await session.evaluate(`(() => {
    const card = document.querySelector('.connection-card');
    card?.querySelector('button')?.click() ?? card?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.nav-item') !== null", "the connected shell", 120);

  await session.evaluate(`(() => {
    [...document.querySelectorAll('.nav-item')]
      .find(candidate => candidate.textContent?.includes('配置'))?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.baseline-card') !== null", "the checks", 180);
  await waitFor(
    session,
    "document.querySelectorAll('.baseline-card-verdict.is-noncompliant').length > 0",
    "a scanned result",
    240,
  );

  const before = await session.evaluate(`(() => {
    const pane = document.querySelector('.baseline-file-pane');
    const empty = pane?.querySelector('.baseline-file-empty');
    const box = empty?.getBoundingClientRect();
    return {
      pane: pane !== null,
      text: pane?.textContent ?? "",
      emptyVisible: box !== undefined && box.height > 0 &&
        box.top >= 0 && box.bottom <= window.innerHeight
    };
  })()`);
  check("未选中时右侧说明它是干什么的", before.text.includes("右边会显示这项检查读的那个配置文件"));
  // Present in the DOM is not the same as on screen: the pane once grew past
  // the viewport and drew its centred message where nobody could see it.
  check("而且那段字真的在可视区里", before.emptyVisible, true);
  if (!before.emptyVisible) {
    console.log("      geometry:", JSON.stringify(await session.evaluate(`(() => {
      const box = (selector) => {
        const node = document.querySelector(selector);
        if (node === null) return null;
        const r = node.getBoundingClientRect();
        return { top: Math.round(r.top), h: Math.round(r.height), scrollH: node.scrollHeight };
      };
      return {
        viewport: window.innerHeight,
        workbench: box('.baseline-workbench'),
        cards: box('.baseline-card-grid'),
        pane: box('.baseline-file-pane'),
        empty: box('.baseline-file-empty'),
        content: box('.baseline-content'),
        page: box('.configuration-page')
      };
    })()`)));
  }

  const shell = await session.evaluate(`(() => ({
    title: document.querySelector('.window-titlebar small')?.textContent ?? null,
    modes: [...document.querySelectorAll('.configuration-modes button strong')].map(n => n.textContent),
    active: document.querySelector('.configuration-modes .is-active strong')?.textContent ?? null,
    baselineOwnHeader: document.querySelector('.baseline-header') !== null
  }))()`);
  check("标题只在标题栏上", shell.title, "配置");
  // 修补已有配置 joined the two original modes with the Nginx repair flow, and
  // 可视化编辑 the tree editor for Nginx files.
  check("四种模式都在", shell.modes.join(","), "检查这台主机,修补已有配置,生成新配置,可视化编辑");
  check("默认停在检查", shell.active, "检查这台主机");
  check("嵌进来的基线页不再自带标题", shell.baselineOwnHeader, false);
  await shot(session, "configuration-inspect");

  await session.evaluate(`(() => {
    const card = [...document.querySelectorAll('.baseline-card')]
      .find(candidate => candidate.textContent?.includes('禁止 root 直接登录'));
    card?.click();
    return true;
  })()`);
  await waitFor(
    session,
    "document.querySelector('.baseline-file-text') !== null",
    "the file",
    120,
  );

  const pane = await session.evaluate(`(() => {
    const lines = [...document.querySelectorAll('.baseline-file-text pre span')];
    return {
      path: document.querySelector('.baseline-file-path')?.textContent ?? null,
      verdict: document.querySelector('.baseline-file-verdict')?.textContent ?? null,
      effective: lines.filter(line => line.classList.contains('is-effective')).map(line => line.textContent.trim()),
      commented: lines.filter(line => line.classList.contains('is-commented')).map(line => line.textContent.trim()),
      inert: lines.filter(line => line.classList.contains('is-inert')).map(line => line.textContent.trim()),
      observed: document.querySelector('.baseline-file-facts')?.textContent ?? ""
    };
  })()`);
  console.log(`\n${pane.path}\n  ${pane.verdict}`);
  console.log(`  生效: ${JSON.stringify(pane.effective)}`);
  console.log(`  注释: ${JSON.stringify(pane.commented)}`);
  console.log(`  被压过: ${JSON.stringify(pane.inert)}`);
  check("右侧打开的是 sshd_config", pane.path, "/etc/ssh/sshd_config");
  check("生效行标的是放行 root 的那条", pane.effective.join(""), "PermitRootLogin yes");
  check("注释行单独标出来", pane.commented.join(""), "#PermitRootLogin prohibit-password");
  check("被压过的同名设置也标出来", pane.inert.join(""), "PermitRootLogin no");
  check("说明写清了第几行生效", pane.verdict.includes("第 2 行"));
  check("卡片上的观察值跟高亮一致", pane.observed.includes("yes"));
  await shot(session, "baseline-file-pane");

  // Density: how many checks fit without scrolling, and whether the bubble
  // that holds what the row had no room for opens on hover.
  const density = await session.evaluate(`(() => {
    const list = document.querySelector('.baseline-card-grid');
    const box = list.getBoundingClientRect();
    const cards = [...document.querySelectorAll('.baseline-card')];
    const inside = cards.filter(card => {
      const rect = card.getBoundingClientRect();
      return rect.top >= box.top && rect.bottom <= box.bottom;
    });
    return {
      groups: document.querySelectorAll('.baseline-check-group').length,
      cards: cards.length,
      visible: inside.length,
      cardHeight: Math.round(cards[0]?.getBoundingClientRect().height ?? 0),
      bubbleHidden: getComputedStyle(document.querySelector('.baseline-card-bubble')).opacity
    };
  })()`);
  console.log(`\n列表 ${density.cards} 项，分 ${density.groups} 组，不滚动看得到 ${density.visible} 项，单项高 ${density.cardHeight}px`);
  check("按分类分组", density.groups >= 5, true);
  // Guards against sliding back to the giant cards this replaced, where three
  // checks filled the column.
  check("一屏至少看得到 10 项", density.visible >= 10, true);
  check("单项高度压到 50px 以内", density.cardHeight <= 50, true);
  check("气泡默认不显示", density.bubbleHidden, "0");

  const at = await session.evaluate(`(() => {
    const rect = document.querySelector('.baseline-card').getBoundingClientRect();
    return {
      type: 'mouseMoved',
      x: Math.round(rect.left + 40),
      y: Math.round(rect.top + rect.height / 2)
    };
  })()`);
  await session.send("Input.dispatchMouseEvent", at);
  await sleep(400);
  const hovered = await session.evaluate(`(() => {
    const bubble = document.querySelector('.baseline-card-slot:hover .baseline-card-bubble');
    return {
      opacity: bubble === null ? null : getComputedStyle(bubble).opacity,
      text: bubble?.textContent ?? ''
    };
  })()`);
  check("悬停时气泡出来了", hovered.opacity, "1");
  check("气泡里带着说明和取值", hovered.text.includes("建议值") && hovered.text.includes("取值"), true);
  await shot(session, "baseline-card-bubble");

  // The other half of the same page.
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.configuration-modes button')]
      .find(candidate => candidate.querySelector('strong')?.textContent === '生成新配置')?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelectorAll('.config-product-list button').length > 0", "the generator", 180);
  const generator = await session.evaluate(`(() => ({
    products: document.querySelectorAll('.config-product-list button').length,
    preview: document.querySelector('.config-preview') !== null,
    ownTitle: [...document.querySelectorAll('.configuration-page h1')].map(n => n.textContent).join(","),
    active: document.querySelector('.configuration-modes .is-active strong')?.textContent ?? null
  }))()`);
  check("切到生成模式", generator.active, "生成新配置");
  check("生成器还在同一个页面里", generator.products > 0, true);
  check("右侧仍然是配置文件的位置", generator.preview, true);
  // The page carries no title of its own now; the title bar has it.
  check("整页没有重复的大标题", generator.ownTitle, "");
  await shot(session, "configuration-generate");

  // No page may tell an operator that something was hidden from them. Nothing
  // is: filtering by credential shape was removed because it swallowed the
  // shadow and auth-log lines these pages exist to surface. What stayed behind
  // was the wording, wired to flags nothing sets — a counter permanently
  // reading zero and a promise that credential-like fields had been hidden.
  // Read from the real window rather than the source, because the source can
  // be clean while a shared component still says it.
  for (const [label, nav] of [["配置", "配置"], ["命令审计", "命令审计"], ["文件完整性", "文件完整性"]]) {
    await session.evaluate(`(() => {
      [...document.querySelectorAll('.nav-item')]
        .find(candidate => candidate.textContent?.includes(${JSON.stringify(nav)}))?.click();
      return true;
    })()`);
    await sleep(1_200);
    const said = await session.evaluate(`(() => {
      const text = document.body.textContent ?? '';
      return { hides: text.includes('遮蔽'), zero: /0\\s*遮蔽字段/u.test(text) };
    })()`);
    check(`${label} 页没有说"已遮蔽"`, said.hides, false);
    check(`${label} 页没有恒为 0 的遮蔽计数`, said.zero, false);
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  await app?.close();
  onHost("[ -f /tmp/sshd_config.bak ] && cp /tmp/sshd_config.bak /etc/ssh/sshd_config; rm -f /tmp/sshd_config.bak");
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
