// Disconnecting has to work when there is something to clean up.
//
// A connection whose transport has already gone is the case where the operator
// most needs the disconnect button, and it was the one case where it failed:
// the backend let the binding go and then reported an error, so the window
// went on showing a target it no longer had, with no way to let it go.
//
//   node tools/lab/probe-disconnect.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "arena";
const container = which === "arena" ? "lab-arena" : `svc-${which}`;

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

async function withConnection(run) {
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
    return await run(sidecar, status.bindingHandle);
  } finally {
    sidecar.close();
  }
}

try {
  // --- the ordinary case still works
  console.log("目标还在时断开：");
  await withConnection(async (sidecar, binding) => {
    const outcome = await sidecar
      .call("ssh.binding.disconnect", { bindingHandle: binding })
      .then((value) => value, (error) => ({ failed: error.message }));
    console.log(`  ${JSON.stringify(outcome)}`);
    check("断开成功", outcome.disconnected, true);
    check("目标守卫也清了", outcome.targetCleared, true);
    // And the binding really is gone afterwards.
    const after = await sidecar
      .call("baseline.scan", { bindingHandle: binding }, 30_000)
      .then(() => "still usable", (error) => error.message);
    check("断开后绑定确实不可用", /binding-unavailable|not-found/u.test(after), true);
  });

  // --- the case that mattered: the host went away first
  console.log(`\n主机先没了，再断开（停掉 ${container}）：`);
  await withConnection(async (sidecar, binding) => {
    wsl(`docker update --restart no ${container} >/dev/null 2>&1; docker stop ${container} >/dev/null 2>&1`);
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Confirm the transport really is gone before asking to disconnect.
    const dead = await sidecar
      .call("baseline.scan", { bindingHandle: binding }, 30_000)
      .then(() => "still alive", (error) => error.message);
    console.log(`  连接状态：${dead}`);

    const outcome = await sidecar
      .call("ssh.binding.disconnect", { bindingHandle: binding })
      .then((value) => value, (error) => ({ failed: error.message }));
    console.log(`  ${JSON.stringify(outcome)}`);
    check("断开仍然成功，而不是报错", outcome.disconnected, true);
    check("目标守卫也清了", outcome.targetCleared, true);
    check("没有把「已经断了」说成失败", outcome.failed, undefined);
  });

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  wsl(`docker update --restart unless-stopped ${container} >/dev/null 2>&1; docker start ${container} >/dev/null 2>&1`);
}
