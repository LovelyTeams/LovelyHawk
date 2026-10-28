// Asks the sidecar, for one target, which right-click actions each tab's rows
// actually get. No window: this is the layer under it, so a gap shows up as
// "this tab offers nothing here" rather than as a menu that never fills.
//
//   node tools/lab/probe-row-actions.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-row-actions.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
/** The tabs that are supposed to have a row vocabulary behind them. */
const TABS = [
  "processes", "network", "established", "open-ports", "services", "users",
  "login-history", "autostart", "cron", "timers", "ssh-keys", "suid-files",
  "packages", "kernel-modules", "env-vars", "shell-configs", "sudoers",
];

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const bindingHandle = status.bindingHandle;
  console.log(`=== ${which}: row actions per tab ===`);

  for (const tab of TABS) {
    let table;
    try {
      table = await sidecar.call("system-info.table.collect", {
        bindingHandle, tab, maximumRows: 200,
      }, 90_000);
    } catch (error) {
      console.log(`  ${tab.padEnd(15)} collect failed: ${error.message.slice(0, 70)}`);
      continue;
    }
    const rows = table.rows ?? [];
    if (rows.length === 0) {
      console.log(`  ${tab.padEnd(15)} no rows`);
      continue;
    }
    // A few rows, not one: the first row of a table is often the least
    // typical (PID 1, the loopback socket, the root account).
    const sampled = rows.slice(0, 5);
    const perRow = [];
    for (const row of sampled) {
      try {
        const actions = await sidecar.call("system-info.row.actions.list", {
          bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id,
        }, 30_000);
        const count = (actions.groups ?? [])
          .reduce((total, group) => total + group.actions.length, 0);
        perRow.push({ count, subject: actions.subject, groups: actions.groups ?? [] });
      } catch (error) {
        perRow.push({ count: -1, subject: row.cells[0], error: error.message.slice(0, 60) });
      }
    }
    const best = perRow.reduce((a, b) => (b.count > a.count ? b : a));
    const counts = perRow.map((entry) => entry.count).join("/");
    const flag = best.count > 0 ? "ok  " : "GAP ";
    console.log(`  ${flag}${tab.padEnd(15)} ${rows.length} rows, actions per sampled row: ${counts}`);
    if (best.count > 0) {
      console.log(`       best row "${String(best.subject).slice(0, 60)}": ` +
        best.groups.map((group) => `${group.label}(${group.actions.length})`).join(" "));
    } else {
      for (const entry of perRow) {
        console.log(`       row "${String(entry.subject).slice(0, 60)}"` +
          (entry.error === undefined ? " offered nothing" : ` failed: ${entry.error}`));
      }
      console.log(`       first row cells: ${JSON.stringify(rows[0].cells).slice(0, 200)}`);
    }
  }
} catch (error) {
  console.log("FAILED:", error.message);
  process.exitCode = 1;
} finally {
  sidecar.close();
}
