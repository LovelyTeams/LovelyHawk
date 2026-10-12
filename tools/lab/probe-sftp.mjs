import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
const step = async (label, run) => {
  try {
    const value = await run();
    console.log(`ok   ${label}`);
    return value;
  } catch (error) {
    console.log(`FAIL ${label}: ${error.message}`);
    return null;
  }
};

try {
  const status = await connect(sidecar, labTarget());
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const browser = await step("open browser at /", () =>
    sidecar.call("sftp-browser.open", { bindingHandle: binding }));
  if (browser === null) throw new Error("cannot browse");
  console.log(`  root: ${browser.displayedEntryCount}/${browser.observedEntryCount} entries`);
  for (const entry of browser.entries.slice(0, 6)) {
    console.log(`   ${entry.kind.padEnd(9)} ${entry.mode ?? "----"} ${String(entry.ownerId ?? "?").padStart(5)} ${entry.name}`);
  }

  const tmp = browser.entries.find((e) => e.name === "tmp");
  const listed = tmp === undefined ? null : await step("list /tmp", () =>
    sidecar.call("sftp-browser.directory.list", {
      bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: tmp.entryHandle,
    }));
  if (listed !== null) {
    console.log(`  /tmp: ${listed.displayedEntryCount} entries`);
    for (const entry of listed.entries.slice(0, 5)) {
      console.log(`   ${entry.kind.padEnd(9)} ${entry.mode ?? "----"} ${entry.name}`);
    }
  }

  // The whole point of the pipeline: create, verify, then remove again.
  const plan = await step("plan a directory under /tmp", () =>
    sidecar.call("sftp-browser.operation.plan", {
      bindingHandle: binding, browserHandle: browser.browserHandle,
      kind: "create-directory", entryHandles: [listed?.directoryHandle ?? browser.directoryHandle],
      name: "lovelyres-lab-check",
    }, 60_000));
  if (plan !== null) {
    console.log(`  plan: ${plan.summary}`);
    console.log(`  dangerous=${plan.dangerous} restore=${plan.restoreDescription ?? "none"} ttl=${plan.expiresInSeconds}s`);
    await step("confirm", () => sidecar.call("sftp-browser.operation.confirm", {
      bindingHandle: binding, planHandle: plan.planHandle,
    }));
    const receipt = await step("execute", () => sidecar.call("sftp-browser.operation.execute", {
      bindingHandle: binding, planHandle: plan.planHandle,
    }, 90_000));
    if (receipt !== null) {
      console.log(`  receipt: passed=${receipt.passed} restored=${receipt.restored} detail=${receipt.detail}`);
    }
    await step("execute again is refused", async () => {
      await sidecar.call("sftp-browser.operation.execute", {
        bindingHandle: binding, planHandle: plan.planHandle,
      });
      throw new Error("a spent plan ran a second time");
    }).catch(() => undefined);
  }

  const after = await step("re-list to verify", () =>
    sidecar.call("sftp-browser.directory.list", {
      bindingHandle: binding, browserHandle: browser.browserHandle,
      directoryHandle: listed?.directoryHandle ?? browser.directoryHandle,
    }));
  const made = after?.entries.find((e) => e.name === "lovelyres-lab-check");
  console.log(`  directory present after execute: ${made !== undefined}`);

  if (made !== undefined) {
    const removal = await step("plan removal", () =>
      sidecar.call("sftp-browser.operation.plan", {
        bindingHandle: binding, browserHandle: browser.browserHandle,
        kind: "remove", entryHandles: [made.entryHandle],
      }, 60_000));
    if (removal !== null) {
      console.log(`  plan: ${removal.summary} dangerous=${removal.dangerous}`);
      await step("confirm removal", () => sidecar.call("sftp-browser.operation.confirm", {
        bindingHandle: binding, planHandle: removal.planHandle,
      }));
      const receipt = await step("execute removal", () => sidecar.call("sftp-browser.operation.execute", {
        bindingHandle: binding, planHandle: removal.planHandle,
      }, 90_000));
      if (receipt !== null) console.log(`  receipt: passed=${receipt.passed} detail=${receipt.detail}`);
    }
  }
} catch (error) {
  console.log("FAILED:", error.message);
  console.log(sidecar.stderr.join("").slice(-900));
} finally {
  sidecar.close();
}
