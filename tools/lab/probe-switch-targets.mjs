// Switching from one lab to another while a page is open.
//
// The window replaces the active target without disconnecting the old one, so
// this walks the same path: connect A, read from it, connect B, and see what
// each of them says afterwards.
//
//   node tools/lab/probe-switch-targets.mjs
import { Sidecar, newDataRoot } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

/** Connects the way the window does: one stored connection per lab. */
async function connectTo(name, id) {
  const { host, port, username, password } = labTarget(name);
  try {
    await sidecar.call("connections.create", {
      connection: {
        id, name: `probe-${name}`, host, port, username,
        authMethod: "password", privateKeyPath: null, certificatePath: null,
        agentIdentityFingerprint: null, jumpHost: null, tags: [], notes: null,
        environment: null, role: null, group: null,
      },
      secrets: { password: { action: "replace", value: password } },
    });
  } catch {
    // Already created.
  }
  const started = await sidecar.call("ssh.connect.start", { connectionId: id });
  let status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
  for (let step = 0; step < 80; step += 1) {
    if (status.hostKeyPrompt?.promptHandle !== undefined) {
      status = await sidecar.call("ssh.host-key.confirm", {
        attemptHandle: started.attemptHandle,
        promptHandle: status.hostKeyPrompt.promptHandle,
      });
      continue;
    }
    if (status.stage === "connected" || status.stage === "failed") break;
    await new Promise((resolve) => setTimeout(resolve, 400));
    status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
  }
  return status;
}

/** What the system overview says for one binding right now. */
async function overview(binding) {
  return await sidecar
    .call("system-info.summary.get", { bindingHandle: binding }, 60_000)
    .then(() => "读到了", (error) => error.message.split(":")[0]);
}

try {
  const first = await connectTo("arena", "aaaaaaaa-0000-4000-8000-000000000001");
  if (first.stage !== "connected") {
    console.log(`  第一台连接失败，原因：${JSON.stringify(first).slice(0, 500)}`);
  }
  check("连上第一台", first.stage, "connected");
  console.log(`  第一台（arena:2250）主机全景 → ${await overview(first.bindingHandle)}`);

  console.log("\n不断开第一台，直接连第二台（模拟界面上点另一个连接）：");
  const second = await connectTo("nginx", "aaaaaaaa-0000-4000-8000-000000000002");
  check("连上第二台", second.stage, "connected");

  const secondSays = await overview(second.bindingHandle);
  const firstSays = await overview(first.bindingHandle);
  console.log(`  第二台（svc-nginx:2231）主机全景 → ${secondSays}`);
  console.log(`  第一台还剩什么 → ${firstSays}`);

  check("切过去之后新目标能用", secondSays, "读到了");
  check("旧目标明确失效，而不是含糊报错", firstSays.endsWith("-binding-unavailable"), true);

  console.log("\n再切回第一台：");
  const back = await connectTo("arena", "aaaaaaaa-0000-4000-8000-000000000001");
  check("切得回去", back.stage, "connected");
  const backSays = await overview(back.bindingHandle);
  console.log(`  第一台主机全景 → ${backSays}`);
  check("切回来之后能用", backSays, "读到了");

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-700));
  process.exitCode = 1;
} finally {
  sidecar.close();
}
