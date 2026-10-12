import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  const catalog = await sidecar.call("check-audit.catalog.get", {
    bindingHandle: status.bindingHandle, input: { customCommandNames: [] },
  }, 90_000);
  const state = await sidecar.call("check-audit.status.collect", {
    bindingHandle: status.bindingHandle, snapshotHandle: catalog.snapshotHandle,
  }, 180_000);
  console.log(`isRoot=${state.isRoot} truncated=${state.truncated} commands=${state.commands.length}`);
  for (const command of state.commands) {
    const mark = command.state === "original" ? "  " : "!!";
    console.log(`${mark} ${command.name.padEnd(10)} ${command.state.padEnd(14)} ${command.displayLocation ?? "-"}`);
  }
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
