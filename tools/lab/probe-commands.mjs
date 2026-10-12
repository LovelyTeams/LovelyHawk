import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  if (status.stage !== "connected") throw new Error(`connect: ${JSON.stringify(status)}`);
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  console.log(`catalog: ${catalog.commands.length} commands`);
  console.log("catalog keys:", Object.keys(catalog).join(","));

  const byCategory = new Map();
  for (const command of catalog.commands) {
    if (!byCategory.has(command.category)) byCategory.set(command.category, []);
    byCategory.get(command.category).push(command);
  }
  console.log("categories:", [...byCategory].map(([k, v]) => `${k}=${v.length}`).join(" "));

  const findings = [];
  const failures = [];
  let ran = 0;
  for (const command of catalog.commands) {
    try {
      const result = await sidecar.call("emergency-command.run", {
        bindingHandle: binding,
        snapshotHandle: catalog.snapshotHandle,
        commandHandle: command.commandHandle,
      }, 90_000);
      ran += 1;
      if (result.resultKind !== "success" && result.resultKind !== "empty") {
        failures.push(`${command.category}/${command.title}: ${result.resultKind} exit=${result.exitCode}`);
      }
      if ((result.findingLines?.length ?? 0) > 0) {
        findings.push({
          category: command.category,
          title: command.title,
          hits: result.findingLines.length,
          reason: result.findingReason,
          sample: result.output.split("\n")[result.findingLines[0]] ?? "",
        });
      }
    } catch (error) {
      failures.push(`${command.category}/${command.title}: ${error.message}`);
    }
  }
  console.log(`\nran ${ran}/${catalog.commands.length}`);
  console.log(`\n=== ${findings.length} commands flagged something ===`);
  for (const finding of findings) {
    console.log(`[${finding.category}] ${finding.title} (${finding.hits})`);
    console.log(`   why: ${finding.reason}`);
    console.log(`   e.g: ${finding.sample.slice(0, 130)}`);
  }
  console.log(`\n=== ${failures.length} did not succeed ===`);
  for (const failure of failures.slice(0, 40)) console.log(" -", failure);
} catch (error) {
  console.log("FAILED:", error.message);
  console.log(sidecar.stderr.join("").slice(-1200));
} finally {
  sidecar.close();
}
