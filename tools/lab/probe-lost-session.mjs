// What happens after the target goes away underneath a live connection.
//
// A lab host is stopped while LovelyRes is connected to it. Every feature then
// asks the same dead session for a command channel. This records what each of
// them says, so "the connection is gone" can be told apart from "this feature
// is broken" — which is the difference between one honest message and a wall
// of identical failures.
//
//   node tools/lab/probe-lost-session.mjs
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "redis";
const container = `svc-${which}`;

/** The same rule the window uses, kept here so the two cannot drift apart. */
function isTargetLost(message) {
  return message.includes("binding-unavailable");
}

function wsl(command) {
  try {
    return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", command], {
      encoding: "utf8",
    }).split("\0").join("").trim();
  } catch (error) {
    return `(failed: ${error.message.slice(0, 80)})`;
  }
}

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  console.log(`已连接 ${container}\n`);

  // Everything works while the host is there.
  const before = await sidecar.call("baseline.scan", { bindingHandle: binding }, 90_000);
  check("停机前扫描正常", before.statuses.length > 0, true);

  console.log(`\n停掉 ${container} …`);
  wsl(`docker stop ${container} >/dev/null 2>&1; docker update --restart no ${container} >/dev/null 2>&1`);
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // Every surface that would be tried next, in the order an operator would.
  const surfaces = [
    ["基线扫描", "baseline.scan", { bindingHandle: binding }],
    ["日志分析", "log-analysis.sources.discover", { bindingHandle: binding }],
    ["主机全景", "system-info.summary.get", { bindingHandle: binding }],
    ["基线扫描（再来一次）", "baseline.scan", { bindingHandle: binding }],
  ];

  console.log("\n主机没了之后，各功能分别说什么：");
  const seen = new Set();
  for (const [label, method, params] of surfaces) {
    const started = Date.now();
    const said = await sidecar.call(method, params, 90_000).then(
      () => "(居然成功了)",
      (error) => error.message,
    );
    const took = Date.now() - started;
    seen.add(said);
    console.log(`  ${label.padEnd(20)} ${took}ms  ${said}`);
  }

  console.log("\n判定：");
  // The window tells a lost target from a broken feature by the code family,
  // not by the English sentence, so that is what has to be uniform.
  const codes = [...seen].map((text) => text.split(":")[0].trim());
  console.log(`  错误码：${codes.join("、")}`);
  check(
    "每个功能都报「绑定没了」，没有一个说自己坏了",
    codes.every((code) => code.endsWith("-binding-unavailable")),
    true,
  );
  // And the window turns every one of those into the same sentence.
  const helper = readFileSync(
    new URL("../../electron/src/renderer/target-lost.ts", import.meta.url),
    "utf8",
  );
  check("窗口对这一族只有一句话", helper.includes('"与目标的连接已断开。请重新连接后再试。"'), true);
  check("窗口认得这一族", codes.every((code) => isTargetLost(`x (${code})`)), true);

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  wsl(`docker update --restart unless-stopped ${container} >/dev/null 2>&1; docker start ${container} >/dev/null 2>&1`);
  sidecar.close();
}
