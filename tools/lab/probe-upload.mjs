// The one path that writes bytes to a target: stage a local file, plan the
// upload, confirm it, run it, then verify what landed and take it away again.
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  const binding = status.bindingHandle;

  const local = path.join(mkdtempSync(path.join(tmpdir(), "lovelyres-upload-")), "evidence-note.txt");
  const body = "collected during the lab run\npassword=stays-visible\n";
  writeFileSync(local, body, "utf8");

  const staged = await sidecar.call("sftp-browser.upload.stage", {
    bindingHandle: binding, localPath: local, name: "evidence-note.txt",
  }, 60_000);
  console.log(`staged: name=${staged.name} bytes=${staged.bytes}`);

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding });
  const tmpEntry = browser.entries.find((e) => e.name === "tmp");
  const tmpDir = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: tmpEntry.entryHandle,
  });

  const plan = await sidecar.call("sftp-browser.operation.plan", {
    bindingHandle: binding, browserHandle: browser.browserHandle, kind: "upload",
    entryHandles: [tmpDir.directoryHandle], name: "evidence-note.txt", stagedHandle: staged.stagedHandle,
  }, 60_000);
  console.log(`plan: ${plan.summary}`);
  console.log(`  dangerous=${plan.dangerous} restore=${plan.restoreDescription ?? "none"}`);
  await sidecar.call("sftp-browser.operation.confirm", { bindingHandle: binding, planHandle: plan.planHandle });
  const receipt = await sidecar.call("sftp-browser.operation.execute", {
    bindingHandle: binding, planHandle: plan.planHandle,
  }, 90_000);
  console.log(`receipt: passed=${receipt.passed} restored=${receipt.restored} detail=${receipt.detail}`);

  const after = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: tmpDir.directoryHandle,
  });
  const landed = after.entries.find((e) => e.name === "evidence-note.txt");
  console.log(`landed: ${landed !== undefined} mode=${landed?.mode ?? "-"} bytes=${landed?.sizeBytes ?? "-"}`);
  if (landed !== undefined) {
    const preview = await sidecar.call("sftp-browser.text.read", {
      bindingHandle: binding, browserHandle: browser.browserHandle, fileHandle: landed.entryHandle,
    });
    console.log(`content matches: ${preview.text.includes("password=stays-visible")}`);
    const removal = await sidecar.call("sftp-browser.operation.plan", {
      bindingHandle: binding, browserHandle: browser.browserHandle, kind: "remove",
      entryHandles: [landed.entryHandle],
    }, 60_000);
    await sidecar.call("sftp-browser.operation.confirm", { bindingHandle: binding, planHandle: removal.planHandle });
    const cleanup = await sidecar.call("sftp-browser.operation.execute", {
      bindingHandle: binding, planHandle: removal.planHandle,
    }, 90_000);
    console.log(`cleaned up: passed=${cleanup.passed}`);
  }
} catch (error) {
  console.log("FAILED:", error.message);
  console.log(sidecar.stderr.join("").slice(-700));
} finally {
  sidecar.close();
}
