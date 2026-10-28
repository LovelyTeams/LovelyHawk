// Negative self-test for the desktop smoke's accessibility audit: in the real
// debug window, the page as shipped is clean, and each kind of defect the
// audit claims to catch is caught once planted — an unnamed button, an unnamed
// field whose options would otherwise pass for a name, an image without alt,
// a duplicate id and a missing heading. A check that never fails proves
// nothing; this is the run that shows it can.
//
//   node scripts/check-accessibility-audit.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ACCESSIBILITY_AUDIT } from "./accessibility-audit.mjs";
import { attach, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `audit-self-test-${randomUUID()}`);
const port = 9800 + Math.floor(Math.random() * 150);
fs.mkdirSync(runRoot, { recursive: true });

let failures = 0;
function check(name, ok, detail = null) {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 300)}`}`);
}

const { child } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exited = false;
child.once("exit", () => { exited = true; });
try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  await session.send("Runtime.enable");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"),
    { label: "the welcome view" });
  const clean = await session.evaluate(ACCESSIBILITY_AUDIT);
  check("the shipped page is clean", clean.unnamed.length === 0 && clean.imagesWithoutAlt.length === 0 &&
    clean.duplicateIds.length === 0 && clean.heading === true, clean);

  // Each defect on its own, removed again before the next.
  const cases = [
    ["an unnamed button", `const e = document.createElement("button"); e.innerHTML = "<svg width='16' height='16'></svg>";`, (a) => a.unnamed.length === 1],
    ["an unnamed select whose options are not its name", `const e = document.createElement("select"); e.innerHTML = "<option>甲</option>";`, (a) => a.unnamed.length === 1],
    ["an image without alt", `const e = document.createElement("img"); e.width = 10; e.height = 10; e.src = "data:image/gif;base64,R0lGODlhAQABAAAAACw=";`, (a) => a.imagesWithoutAlt.length === 1],
    ["a duplicate id", `const e = document.createElement("span"); e.id = document.querySelector("[id]")?.id ?? "x"; if (!document.getElementById(e.id)) { const f = document.createElement("span"); f.id = e.id; f.dataset.selfTest = "1"; document.body.append(f); }`, (a) => a.duplicateIds.length === 1],
  ];
  for (const [label, create, caught] of cases) {
    const audit = await session.evaluate(`(() => { ${create} e.dataset.selfTest = "1"; e.style.display = "inline-block"; document.querySelector("main.content").append(e); return ${ACCESSIBILITY_AUDIT}; })()`);
    await session.evaluate(`document.querySelectorAll('[data-self-test]').forEach((e) => e.remove()), true`);
    check(`the audit catches ${label}`, caught(audit), audit);
  }
  const headless = await session.evaluate(`(() => {
    const headings = [...document.querySelectorAll("main.content h1, main.content h2, main.content [role='heading']")];
    headings.forEach((h) => { h.dataset.selfTestHidden = h.style.display; h.style.display = "none"; });
    const result = ${ACCESSIBILITY_AUDIT};
    headings.forEach((h) => { h.style.display = h.dataset.selfTestHidden; delete h.dataset.selfTestHidden; });
    return result;
  })()`);
  check("the audit catches a page without a visible heading", headless.heading === false, headless);
  const after = await session.evaluate(ACCESSIBILITY_AUDIT);
  check("the page is clean again afterwards", after.unnamed.length === 0 && after.heading === true, after);
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  session.close();
  await waitFor(() => exited, { timeoutMs: 15_000, label: "the app to exit" }).catch(() => undefined);
} catch (error) {
  check("self-test completed", false, error instanceof Error ? error.message : String(error));
} finally {
  if (!exited) child.kill();
}
console.log(`${failures === 0 ? "PASS" : "FAIL"}: accessibility audit self-test`);
process.exitCode = failures === 0 ? 0 : 1;
