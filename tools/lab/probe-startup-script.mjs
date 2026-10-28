// Checks that a boot entry which is a script, not a systemd unit, can be
// investigated — on the hosts where every startup row is exactly that.
//
//   node tools/lab/probe-startup-script.mjs                    # ubuntu
//   LABS=ubuntu,debian,deepin,alpine node tools/lab/probe-startup-script.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

/** The questions worth showing output for; the rest are only counted. */
const SHOWN = ["startup.details", "startup.unit-file", "startup.startup-type", "startup.suspicious-path"];

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

for (const which of (process.env.LABS ?? "ubuntu").split(",")) {
  console.log(`\n=== ${which}`);
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
    const bindingHandle = status.bindingHandle;
    const table = await sidecar.call("system-info.table.collect", {
      bindingHandle, tab: "autostart", maximumRows: 200,
    }, 150_000);
    const rows = table.rows ?? [];
    check(`${which}: the autostart tab has rows`, rows.length > 0);
    if (rows.length === 0) continue;
    const kinds = [...new Set(rows.map((row) => row.cells[3]))];
    console.log(`  ${rows.length} rows, kinds: ${kinds.join(", ")}`);

    // The row an operator would actually open: the first one, whatever it is.
    const row = rows[0];
    console.log(`  row: ${JSON.stringify(row.cells)}`);
    const actions = await sidecar.call("system-info.row.actions.list", {
      bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id,
    }, 30_000);
    const keys = (actions.groups ?? []).flatMap((group) => group.actions.map((a) => a.key));
    check(`${which}: the row offers actions at all`, keys.length > 0);
    console.log(`  ${keys.length} actions offered`);
    // Two questions have no answer for a script and must not be offered.
    if (row.cells[3] === "init.d") {
      check(`${which}: boot timing is not offered for a script`, !keys.includes("startup.boot-time"));
      check(`${which}: resource usage is not offered for a script`, !keys.includes("startup.resource-usage"));
      check(`${which}: 16 of the 18 startup questions are offered`, keys.filter((k) => k.startsWith("startup.")).length, 16);
    }

    let answered = 0;
    const silent = [];
    for (const key of keys.filter((k) => k.startsWith("startup."))) {
      try {
        const result = await sidecar.call("system-info.row.inspect", {
          bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id, action: key,
        }, 60_000);
        if (result.output.trim().length > 0) answered += 1; else silent.push(key);
        if (SHOWN.includes(key)) {
          console.log(`  --- ${key} (${result.label})`);
          for (const line of result.output.split("\n").slice(0, 6)) {
            console.log(`      ${line.slice(0, 140)}`);
          }
        }
      } catch (error) {
        console.log(`  FAIL ${key}: ${error.message.slice(0, 90)}`);
        failures += 1;
      }
    }
    const asked = keys.filter((k) => k.startsWith("startup.")).length;
    if (silent.length > 0) console.log(`  silent: ${silent.join(" ")}`);
    if (row.cells[3] === "init.d") {
      // A script answers every question it is offered. An empty panel reads
      // as "nothing to see here", which is the wrong thing to say when the
      // truth is that the question was never answerable.
      check(`${which}: every offered question came back with something`, answered, asked);
    } else {
      // The systemd path is unchanged here, and in a container with no
      // running systemd its journal-backed questions have nothing to return.
      console.log(`  ${answered}/${asked} systemd questions answered (unchanged path)`);
    }
  } catch (error) {
    console.log(`  FAILED: ${error.message.slice(0, 120)}`);
    failures += 1;
  } finally {
    sidecar.close();
  }
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
