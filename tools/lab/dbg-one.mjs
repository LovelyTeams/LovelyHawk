import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  console.log("stage:", status.stage);
  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: status.bindingHandle });
  console.log("catalog:", catalog.commands.length);
  const one = catalog.commands[0];
  console.log("running:", one.title);
  const run = await sidecar.call("emergency-command.run", {
    bindingHandle: status.bindingHandle, snapshotHandle: catalog.snapshotHandle, commandHandle: one.commandHandle,
  }, 90_000);
  console.log("kind:", run.resultKind, "exit:", run.exitCode);
} catch (error) {
  console.log("ERR:", error.message);
} finally {
  console.log("--- stderr ---");
  console.log(sidecar.stderr.join("").slice(-1200));
  sidecar.close();
}
