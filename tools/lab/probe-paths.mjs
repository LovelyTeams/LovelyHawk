// Drives the whole right-click path pipeline against a real lab host and
// checks the host afterwards, so a passing verification means the file on the
// target actually changed.
//
//   node tools/lab/probe-paths.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-paths.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;

/** Asks the container directly, so the check does not go through the sidecar. */
function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  )
    .split("\0")
    .join("")
    .trim();
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

  // Two files planted for this run, so the probe never touches the host's own.
  onHost("mkdir -p /usr/local/lib/pyshared && printf '#!/bin/sh\\nexit 0\\n' > /usr/local/lib/pyshared/.helper && chmod 4755 /usr/local/lib/pyshared/.helper");
  onHost("printf 'payload\\n' > /tmp/.probe-drop && chmod 755 /tmp/.probe-drop");

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const command = catalog.commands.find((entry) => entry.title.includes("SUID"));
  if (command === undefined) throw new Error("no SUID command in the catalogue");

  const result = await sidecar.call(
    "emergency-command.run",
    { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: command.commandHandle },
    90_000,
  );
  const lines = result.output.split("\n");
  console.log(`\n=== ${command.title} on ${container}: ${lines.length} lines, ${result.paths.length} paths ===`);

  const target = result.paths.find((entry) => entry.path === "/usr/local/lib/pyshared/.helper");
  if (target === undefined) {
    console.log(result.paths.map((entry) => `      ${entry.line} ${entry.path}`).join("\n"));
    throw new Error("the planted SUID file was not offered as a path");
  }
  check("the offered line is the line that printed it", lines[target.line].endsWith(target.path), true);

  // --- read-only inspection
  const detail = await sidecar.call("emergency-command.path.inspect", {
    bindingHandle: binding,
    pathHandle: target.pathHandle,
  });
  console.log(`\ninspect: ${detail.path} kind=${detail.kind} mode=${detail.mode} size=${detail.size} exec=${detail.executable}`);
  check("inspect reports the mode the host has", detail.mode, "4755");
  check("inspect reports it as runnable", detail.executable, true);

  // --- a forged handle names nothing
  const forged = await sidecar
    .call("emergency-command.path.inspect", { bindingHandle: binding, pathHandle: "00000000-0000-4000-8000-000000000000" })
    .then(() => "accepted", (error) => error.message);
  check("a forged path handle is refused", /missing, expired, or already used/.test(forged), true);

  // --- disarm
  const plan = await sidecar.call("emergency-command.path.plan", {
    bindingHandle: binding,
    pathHandle: target.pathHandle,
    action: "disarm",
  });
  console.log(`\nplan: ${plan.action} ${plan.path}\n  summary: ${plan.summary}\n  dangerous=${plan.dangerous} restore=${plan.restoreDescription ?? "-"}`);
  check("the plan starts unconfirmed", plan.state, "planned");

  const unconfirmed = await sidecar
    .call("emergency-command.path.execute", { bindingHandle: binding, planHandle: plan.planHandle }, 90_000)
    .then(() => "ran", (error) => error.message);
  check("an unconfirmed plan will not run", /missing, expired, or already used/.test(unconfirmed), true);
  check("the host is untouched before confirmation", onHost("stat -c %a /usr/local/lib/pyshared/.helper"), "4755");

  const confirmed = await sidecar.call("emergency-command.path.confirm", { bindingHandle: binding, planHandle: plan.planHandle });
  check("confirming records the approval", confirmed.state, "confirmed");

  const receipt = await sidecar.call(
    "emergency-command.path.execute",
    { bindingHandle: binding, planHandle: plan.planHandle },
    90_000,
  );
  console.log(`\nreceipt: passed=${receipt.passed} restored=${receipt.restored}\n  ${receipt.detail}`);
  check("the change verified", receipt.passed, true);
  check("the host lost every execute bit and the set-user-ID bit", onHost("stat -c %a /usr/local/lib/pyshared/.helper"), "644");
  check("the file is still there to examine", onHost("test -f /usr/local/lib/pyshared/.helper && echo yes"), "yes");

  const replay = await sidecar
    .call("emergency-command.path.execute", { bindingHandle: binding, planHandle: plan.planHandle }, 90_000)
    .then(() => "ran twice", (error) => error.message);
  check("a spent plan cannot run again", /missing, expired, or already used/.test(replay), true);

  const already = await sidecar
    .call("emergency-command.path.plan", { bindingHandle: binding, pathHandle: target.pathHandle, action: "disarm" })
    .then(() => "planned", (error) => error.message);
  check("disarming an already disarmed file is refused", /could not act on that path/.test(already), true);

  // --- quarantine, on a path from a second run
  const hidden = catalog.commands.find((entry) => entry.title.includes("临时目录"));
  if (hidden === undefined) throw new Error("no temporary-directory command in the catalogue");
  const second = await sidecar.call(
    "emergency-command.run",
    { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: hidden.commandHandle },
    90_000,
  );
  const drop = second.paths.find((entry) => entry.path === "/tmp/.probe-drop");
  if (drop === undefined) {
    console.log(`\n[${hidden.title}] offered:\n${second.paths.map((entry) => `      ${entry.path}`).join("\n")}`);
    throw new Error("the planted drop was not offered as a path");
  }
  check("the earlier run's handle is no longer live", await sidecar
    .call("emergency-command.path.inspect", { bindingHandle: binding, pathHandle: target.pathHandle })
    .then(() => "still live", (error) => /missing, expired, or already used/.test(error.message)), true);

  const removal = await sidecar.call("emergency-command.path.plan", {
    bindingHandle: binding,
    pathHandle: drop.pathHandle,
    action: "quarantine",
  });
  console.log(`\nplan: ${removal.action} ${removal.path}\n  summary: ${removal.summary}\n  dangerous=${removal.dangerous} restore=${removal.restoreDescription ?? "-"}`);
  check("removal is marked dangerous", removal.dangerous, true);
  await sidecar.call("emergency-command.path.confirm", { bindingHandle: binding, planHandle: removal.planHandle });
  const removalReceipt = await sidecar.call(
    "emergency-command.path.execute",
    { bindingHandle: binding, planHandle: removal.planHandle },
    90_000,
  );
  console.log(`\nreceipt: passed=${removalReceipt.passed} restored=${removalReceipt.restored}\n  ${removalReceipt.detail}`);
  check("the quarantine verified", removalReceipt.passed, true);
  check("the file is gone from where it ran", onHost("test -e /tmp/.probe-drop && echo there || echo gone"), "gone");
  const backup = onHost("ls -1 /tmp/.lovelyres-backup* 2>/dev/null | head -1; ls -1a /tmp | grep -i backup | head -3");
  console.log(`\nrecoverable copy on the host: ${backup === "" ? "(none found under /tmp)" : backup}`);

  // --- a cancelled plan runs nothing
  const cancelled = await sidecar.call("emergency-command.path.plan", {
    bindingHandle: binding,
    pathHandle: drop.pathHandle,
    action: "quarantine",
  }).then((entry) => entry, () => null);
  if (cancelled !== null) {
    await sidecar.call("emergency-command.path.cancel", { bindingHandle: binding, planHandle: cancelled.planHandle });
    const afterCancel = await sidecar
      .call("emergency-command.path.execute", { bindingHandle: binding, planHandle: cancelled.planHandle }, 90_000)
      .then(() => "ran", (error) => error.message);
    check("a cancelled plan will not run", /missing, expired, or already used/.test(afterCancel), true);
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log("\nFAILED:", error.message);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-800));
  process.exitCode = 1;
} finally {
  onHost("rm -f /usr/local/lib/pyshared/.helper /tmp/.probe-drop");
  sidecar.close();
}
