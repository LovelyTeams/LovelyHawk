// Two real hosts, one sidecar: whatever was bound to the first target must stop
// answering the moment the operator moves to the second.
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
const expectRefusal = async (label, run) => {
  try {
    await run();
    console.log(`LEAK ${label}: answered after the target changed`);
  } catch (error) {
    console.log(`ok   ${label}: ${error.message.split(":")[0]}`);
  }
};

try {
  const first = await connect(sidecar, labTarget("ubuntu"));
  if (first.stage !== "connected") throw new Error(JSON.stringify(first));
  console.log("bound to ubuntu lab");

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: first.bindingHandle });
  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: first.bindingHandle });
  const sources = await sidecar.call("log-analysis.sources.discover", { bindingHandle: first.bindingHandle });
  console.log(`captured: catalog(${catalog.commands.length}) browser(${browser.entries.length}) sources(${sources.sources.length})`);

  // Same sidecar, different host: this is the operator switching targets.
  const second = await connect(sidecar, { ...labTarget("alpine"), });
  console.log(`bound to alpine lab: ${second.stage}`);

  await expectRefusal("emergency catalog on the old binding", () =>
    sidecar.call("emergency-command.run", {
      bindingHandle: first.bindingHandle,
      snapshotHandle: catalog.snapshotHandle,
      commandHandle: catalog.commands[0].commandHandle,
    }));
  await expectRefusal("sftp listing on the old browser", () =>
    sidecar.call("sftp-browser.directory.list", {
      bindingHandle: first.bindingHandle,
      browserHandle: browser.browserHandle,
      directoryHandle: browser.directoryHandle,
    }));
  await expectRefusal("log read on the old snapshot", () =>
    sidecar.call("log-analysis.source.read", {
      bindingHandle: first.bindingHandle,
      snapshotHandle: sources.snapshotHandle,
      sourceHandle: sources.sources[0].sourceHandle,
      input: { page: 1, pageSize: 10, keyword: null, date: null, journalUnit: null },
    }));
  await expectRefusal("system info on the old binding", () =>
    sidecar.call("system-info.summary.get", { bindingHandle: first.bindingHandle }));

  // The new binding has to work.
  const fresh = await sidecar.call("emergency-command.catalog.load", { bindingHandle: second.bindingHandle });
  console.log(`ok   new binding still works: ${fresh.commands.length} commands`);
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
