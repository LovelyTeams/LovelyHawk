import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  const binding = status.bindingHandle;
  const catalog = await sidecar.call("check-audit.catalog.get", {
    bindingHandle: binding, input: { customCommandNames: [] },
  }, 90_000);
  console.log("catalog keys:", Object.keys(catalog).join(","));
  console.log("commands:", catalog.commands.map((c) => c.title ?? c.name ?? c.commandHandle).join(" | ").slice(0, 300));
  const state = await sidecar.call("check-audit.status.collect", {
    bindingHandle: binding, snapshotHandle: catalog.snapshotHandle,
  }, 180_000);
  console.log("\nstatus keys:", Object.keys(state).join(","));
  console.log(JSON.stringify(state).slice(0, 1500));
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
