import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const wanted = process.argv.slice(2);
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: status.bindingHandle });
  for (const title of wanted) {
    const command = catalog.commands.find((entry) => entry.title === title);
    if (command === undefined) { console.log(`?? no command titled ${title}`); continue; }
    const result = await sidecar.call("emergency-command.run", {
      bindingHandle: status.bindingHandle,
      snapshotHandle: catalog.snapshotHandle,
      commandHandle: command.commandHandle,
    }, 90_000);
    const lines = result.output.split("\n");
    const flagged = new Set(result.findingLines ?? []);
    console.log(`\n===== ${command.category} / ${title} =====`);
    console.log(`kind=${result.resultKind} exit=${result.exitCode} lines=${lines.length} flagged=${flagged.size}`);
    lines.forEach((line, index) => {
      if (index > 60) return;
      console.log(`${flagged.has(index) ? "!!" : "  "} ${line.slice(0, 120)}`);
    });
  }
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
