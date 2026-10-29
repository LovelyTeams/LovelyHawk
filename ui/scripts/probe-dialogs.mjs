// The shared in-app confirmation dialog, driven with the keyboard in the real
// window: it opens over unsaved settings with focus on the safe choice, Tab
// and Shift+Tab stay inside it and reach every button, the page behind is
// inert, Escape and Enter-on-取消 both back out and return focus, and only
// the explicit button discards. No target is involved; throwaway data root.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import react from "@vitejs/plugin-react";
import { contrastRatio, parseThemeTokenTable } from "../src/renderer/theme/theme-test-utils.ts";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `dialogs-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const port = 10_900 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];

const dialog = `(() => {
  const host = document.querySelector('.dialog-host');
  if (!host) return null;
  return {
    role: host.getAttribute('role'),
    title: host.querySelector('h2')?.textContent ?? null,
    eyebrow: host.querySelector('.dialog-host-eyebrow')?.textContent ?? null,
    focus: document.activeElement?.textContent?.trim() ?? null,
    focusInside: host.contains(document.activeElement),
    settingsInert: document.querySelector('.settings-panel')?.closest('[inert]') !== null,
  };
})()`;
async function key(session, name, { shift = false } = {}) {
  const codes = { Tab: 9, Escape: 27, Enter: 13 };
  const base = { key: name, code: name, windowsVirtualKeyCode: codes[name], modifiers: shift ? 8 : 0 };
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", ...base, ...(name === "Enter" ? { text: "\r" } : {}) });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  await delay(150);
}
async function openDiscard(session) {
  await key(session, "Escape");
  return waitFor(() => session.evaluate(dialog), { timeoutMs: 8_000, label: "the discard question" }).catch(() => null);
}

// Actual components and CSS inside the native WebView. The file/plan is a
// labelled visual fixture: every action callback is local and no target exists.
async function verifyButtonStates(session) {
  const ui = path.join(repositoryRoot, "ui");
  const outDir = path.join(runRoot, "button-fixture");
  const source = (name) => JSON.stringify(path.join(ui, "src/renderer", name).replaceAll("\\", "/"));
  const entry = `
    import React from "react";
    import {createRoot} from "react-dom/client";
    import {EmergencyPathMenu} from ${source("EmergencyPathMenu.tsx")};
    import {EmergencyPathDialog, EmergencyPathProperties} from ${source("EmergencyPathDialog.tsx")};
    import ${source("emergency-commands.css")};
    import ${source("log-analysis-page.css")};
    export function mount() {
      const app=document.getElementById("root"), previousTheme=document.documentElement.dataset.theme;
      app.hidden=true;
      const element=document.createElement("div"); element.id="button-states-preview"; document.body.append(element);
      const root=createRoot(element), path="/tmp/lovelyhawk-style-sample";
      const detail={pathHandle:"visual-only",path,kind:"file",size:"512",mode:"0755",ownerId:0,groupId:0,modifiedAt:"2026-10-29T00:00:00Z",executable:true};
      const plan={planHandle:"visual-only",pathHandle:"visual-only",path,action:"disarm",summary:"本地样式样例，不会修改任何文件。",dangerous:true,restoreDescription:"样例不执行，无需恢复。",state:"planned",expiresInSeconds:300};
      const noop=()=>{};
      return {
        show(page,kind,theme) {
          document.documentElement.dataset.theme=theme;
          const component=kind==="menu"
            ? React.createElement(EmergencyPathMenu,{position:{x:140,y:150},offer:{pathHandle:"visual-only",path},busy:false,onAction:noop,onDismiss:noop})
            : kind==="primary"
            ? React.createElement(EmergencyPathProperties,{path,detail,error:null,onClose:noop})
            : React.createElement(EmergencyPathDialog,{path,action:"disarm",detail,plan,receipt:null,busy:false,error:null,onConfirm:noop,onClose:noop});
          root.render(React.createElement("section",{className:page,key:page+kind+theme},
            React.createElement("h2",null,"按钮样式验证（本地样例，不连接目标）"),component));
        },
        unmount() {root.unmount();element.remove();app.hidden=false;document.documentElement.dataset.theme=previousTheme;}
      };
    }`;
  await build({
    root: ui, configFile: false, logLevel: "warn",
    plugins: [{ name: "button-state-fixture", resolveId: id => id.endsWith("virtual:button-states") ? "\0button-states-fixture" : null,
      load: id => id === "\0button-states-fixture" ? entry : null }, react()],
    define: { "process.env.NODE_ENV": JSON.stringify("production") },
    build: { outDir, emptyOutDir: false,
      lib: { entry: "virtual:button-states", name: "ButtonStatesFixture", formats: ["iife"], fileName: () => "fixture.js" } },
  });
  await session.send("DOM.enable"); await session.send("CSS.enable");
  const { frameTree } = await session.send("Page.getFrameTree");
  const { styleSheetId } = await session.send("CSS.createStyleSheet", { frameId: frameTree.frame.id });
  await session.send("CSS.setStyleSheetText", { styleSheetId,
    text: fs.readdirSync(outDir).filter(name => name.endsWith(".css")).map(name => fs.readFileSync(path.join(outDir, name), "utf8")).join("\n") });
  await session.evaluate(fs.readFileSync(path.join(outDir, "fixture.js"), "utf8"));
  await session.evaluate("window.__buttonStates = ButtonStatesFixture.mount(); true");
  await session.send("Emulation.setDeviceMetricsOverride", { width: 1100, height: 760, deviceScaleFactor: 1, mobile: false });
  const themes = [...parseThemeTokenTable(fs.readFileSync(path.join(ui, "src/renderer/theme/themes.css"), "utf8")).keys()];
  try {
    for (const theme of themes) {
      const ratios = [];
      for (const page of ["emergency-commands-page", "log-analysis-page"]) {
        for (const kind of ["menu", "primary", "danger"]) {
          await session.evaluate(`window.__buttonStates.show(${JSON.stringify(page)},${JSON.stringify(kind)},${JSON.stringify(theme)}); true`);
          const selector = kind === "menu" ? "#button-states-preview [role=menuitem]" :
            `#button-states-preview footer button.is-${kind === "primary" ? "primary" : "dangerous"}`;
          await waitFor(() => session.evaluate(`document.querySelector(${JSON.stringify(selector)}) !== null`), { label: `${theme} ${kind}` });
          // Rendering replaces nodes; wait for the committed theme/page/scene.
          await session.evaluate("new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))");
          const { root } = await session.send("DOM.getDocument");
          const { nodeIds } = await session.send("DOM.querySelectorAll", { nodeId: root.nodeId, selector });
          for (const [index, nodeId] of nodeIds.entries()) {
            for (const state of [[], ["hover"], ["focus-visible"]]) {
              await session.send("CSS.forcePseudoState", { nodeId, forcedPseudoClasses: state });
              const colors = await session.evaluate(`(() => {
                const b=document.querySelectorAll(${JSON.stringify(selector)})[${index}], c=getComputedStyle(b);
                const canvas=document.createElement('canvas');canvas.width=canvas.height=1;const ctx=canvas.getContext('2d');
                const rgba=value=>{ctx.clearRect(0,0,1,1);ctx.fillStyle=value;ctx.fillRect(0,0,1,1);return [...ctx.getImageData(0,0,1,1).data]};
                let parent=b, bg=rgba(c.backgroundColor);
                while(bg[3]===0 && parent.parentElement){parent=parent.parentElement;bg=rgba(getComputedStyle(parent).backgroundColor)}
                const hex=channels=>'#'+channels.slice(0,3).map(v=>v.toString(16).padStart(2,'0')).join('');
                return {foreground:hex(rgba(c.color)),background:hex(bg),alpha:bg[3],
                  border:c.borderTopWidth,height:b.getBoundingClientRect().height,notes:b.querySelectorAll('em').length};
              })()`);
              const ratio = contrastRatio(colors.foreground, colors.background);
              ratios.push(ratio);
              if (ratio < 4.5 || colors.alpha !== 255 || (kind === "menu" && (colors.border !== "0px" || colors.height > 34 || colors.notes))) {
                throw new Error(`${theme}/${page}/${kind}/${index}/${state}: contrast ${ratio.toFixed(2)} ${JSON.stringify(colors)}`);
              }
            }
            await session.send("CSS.forcePseudoState", { nodeId, forcedPseudoClasses: [] });
          }
          if (page === "emergency-commands-page" && ["light", "dark"].includes(theme)) {
            await session.send("CSS.forcePseudoState", { nodeId: nodeIds.at(-1), forcedPseudoClasses: ["hover"] });
            await session.screenshot(path.join(evidence, `${kind}-hover-${theme}.png`));
          }
        }
      }
      check(`${theme}: menu rows and normal/hover/focus button contrast`, true, { minimumContrast: Math.min(...ratios), samples: ratios.length });
    }
  } finally {
    await session.evaluate("window.__buttonStates.unmount(); delete window.__buttonStates; true");
  }
}

try {
  const origin = process.env.LOVELYHAWK_DEV_SERVER ?? "https://tauri.localhost";
  const { session } = await attach(port, url => new URL(url).origin === origin && ["/", "/index.html"].includes(new URL(url).pathname));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error") ||
      (method === "Log.entryAdded" && params?.entry?.level === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  await session.send("Page.bringToFront");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"open-settings\"]') !== null"), { label: "the title bar" });
  await session.evaluate("document.querySelector('[data-testid=\"open-settings\"]').click(), true");
  const toggled = await waitFor(() => session.evaluate(`(() => {
    const box = document.querySelector('.settings-panel .settings-toggle input[type="checkbox"]');
    if (!box) return false;
    box.click();
    box.focus();
    return true;
  })()`), { timeoutMs: 10_000, label: "a settings toggle" }).catch(() => false);
  check("settings has an unsaved change", toggled);

  let now = await openDiscard(session);
  check("Escape over unsaved settings asks first, with focus on 取消", now?.role === "dialog" && now.eyebrow === "请确认" && now.title === "放弃未保存的更改" && now.focus === "取消", now);
  check("the settings behind the question are inert", now?.settingsInert === true, now?.settingsInert);
  await session.screenshot(path.join(evidence, "discard-dialog.png"));

  await key(session, "Tab");
  now = await session.evaluate(dialog);
  check("Tab moves to the next button inside the dialog", now?.focus === "放弃更改" && now.focusInside, now?.focus);
  await key(session, "Tab");
  now = await session.evaluate(dialog);
  check("Tab from the last button wraps to the first", now?.focus === "取消" && now.focusInside, now?.focus);
  await key(session, "Tab", { shift: true });
  now = await session.evaluate(dialog);
  check("Shift+Tab from the first button wraps to the last", now?.focus === "放弃更改" && now.focusInside, now?.focus);
  await key(session, "Tab", { shift: true });
  now = await session.evaluate(dialog);
  check("Shift+Tab moves back to 取消", now?.focus === "取消" && now.focusInside, now?.focus);

  await key(session, "Escape");
  now = await session.evaluate(`({ dialog: ${dialog}, settings: document.querySelector('.settings-panel') !== null, focusInSettings: document.querySelector('.settings-panel')?.contains(document.activeElement) ?? false })`);
  check("Escape backs out, keeps settings open and returns focus there", now.dialog === null && now.settings && now.focusInSettings, now);

  now = await openDiscard(session);
  await key(session, "Enter");
  now = await session.evaluate(`({ dialog: ${dialog}, settings: document.querySelector('.settings-panel') !== null })`);
  check("Enter on the focused 取消 backs out instead of discarding", now.dialog === null && now.settings, now);

  now = await openDiscard(session);
  await session.evaluate(`[...document.querySelectorAll('.dialog-host button')].find((button) => button.textContent.trim() === '放弃更改').click(), true`);
  const closed = await waitFor(() => session.evaluate("document.querySelector('.settings-panel') === null && document.querySelector('.dialog-host') === null"), { timeoutMs: 8_000, label: "settings to close" }).catch(() => false);
  check("only the explicit 放弃更改 button discards and closes settings", closed);

  if (process.argv.includes("--buttons")) {
    check("titlebar has four actions and the statusbar theme picker remains", await session.evaluate(
      "document.querySelectorAll('.window-titlebar-actions button').length === 4 && !document.querySelector('[data-testid=\"cycle-theme\"]') && !!document.querySelector('[data-testid=\"open-theme-picker\"]')"));
    await verifyButtonStates(session);
  }
  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-dialogs-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
