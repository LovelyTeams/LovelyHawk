// Takes a boot script out of the boot sequence on a real host, and puts it
// back, through the same plan/confirm/execute path the window uses.
//
// The script is one this probe plants and removes. Nothing the target came
// with is ever enabled or disabled here.
//
//   node tools/lab/probe-boot-script-runtime.mjs
//   LABS=ubuntu,debian,deepin,alpine node tools/lab/probe-boot-script-runtime.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

/** A name nothing on the target uses, so no real service is ever touched. */
const NAME = "lovelyres-probe";

const SCRIPT = [
  "#!/bin/sh",
  "### BEGIN INIT INFO",
  `# Provides:          ${NAME}`,
  "# Required-Start:    $remote_fs",
  "# Required-Stop:     $remote_fs",
  "# Default-Start:     2 3 4 5",
  "# Default-Stop:      0 1 6",
  "# Short-Description: LovelyHawk probe placeholder, does nothing",
  "### END INIT INFO",
  'case "$1" in start|stop|restart|status) exit 0;; esac',
  "exit 0",
].join("\\n");

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(container, command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

/** The start links the host holds for the planted script, as the host sees them. */
function startLinks(container) {
  return onHost(
    container,
    `n=${NAME}; { for d in /etc/rc?.d /etc/rc.d/rc?.d; do [ -d "$d" ] || continue; for l in "$d"/*; do [ -e "$l" ] || continue; case "\${l##*/}" in S[0-9][0-9]"$n") printf '%s\\n' "$l";; esac; done; done; for l in /etc/runlevels/*/"$n"; do [ -e "$l" ] || continue; printf '%s\\n' "$l"; done; } | sort | tr '\\n' ' '`,
  );
}

/** Which boot-link tool this host has, if any. */
function hostManager(container) {
  return onHost(
    container,
    'if [ -d /etc/runlevels ] && command -v rc-update >/dev/null 2>&1; then echo rc-update; elif command -v update-rc.d >/dev/null 2>&1; then echo update-rc.d; elif command -v chkconfig >/dev/null 2>&1; then echo chkconfig; else echo none; fi',
  );
}

function plant(container) {
  // %b, not %s: the script is carried across as one line with escapes in it,
  // and only printf can turn those back into the lines the file needs.
  onHost(container, `printf '%b\\n' "${SCRIPT}" > /etc/init.d/${NAME}; chmod 755 /etc/init.d/${NAME}`);
  // Enable it with whatever this host manages boot links with, so the probe
  // starts from a script that is genuinely in the boot sequence.
  onHost(
    container,
    `if [ -d /etc/runlevels ] && command -v rc-update >/dev/null 2>&1; then rc-update add ${NAME} default >/dev/null 2>&1; elif command -v update-rc.d >/dev/null 2>&1; then update-rc.d ${NAME} defaults >/dev/null 2>&1; elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add ${NAME} >/dev/null 2>&1; chkconfig ${NAME} on >/dev/null 2>&1; else mkdir -p /etc/rc2.d && ln -sf ../init.d/${NAME} /etc/rc2.d/S99${NAME}; fi; true`,
  );
}

function unplant(container) {
  onHost(
    container,
    `if [ -d /etc/runlevels ] && command -v rc-update >/dev/null 2>&1; then rc-update del ${NAME} default >/dev/null 2>&1; elif command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f ${NAME} remove >/dev/null 2>&1; elif command -v chkconfig >/dev/null 2>&1; then chkconfig --del ${NAME} >/dev/null 2>&1; fi; rm -f /etc/rc?.d/[SK]??${NAME} /etc/rc.d/rc?.d/[SK]??${NAME} /etc/runlevels/*/${NAME} /etc/init.d/${NAME}; true`,
  );
}

/** Reads the autostart tab and returns the row for the planted script. */
async function plantedRow(sidecar, bindingHandle) {
  const table = await sidecar.call("system-info.table.collect", {
    bindingHandle, tab: "autostart", maximumRows: 200,
  }, 150_000);
  return { table, row: (table.rows ?? []).find((candidate) => candidate.cells[0] === NAME) };
}

/**
 * Takes the planted script out of the boot sequence through plan, confirm and
 * execute, and checks the host afterwards rather than believing the receipt.
 */
async function takeOutOfBootSequence(sidecar, bindingHandle, container) {
  const { table, row } = await plantedRow(sidecar, bindingHandle);
  if (row === undefined) {
    check("the planted script is listed on the autostart tab", false);
    return;
  }
  const actions = await sidecar.call("system-info.row.actions.list", {
    bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id,
  }, 30_000);
  const keys = (actions.groups ?? []).flatMap((group) => group.actions.map((a) => a.key));
  check("disabling is offered on the planted script", keys.includes("service.runtime.disable"));
  // This tab lists only what already starts at boot, so enabling one is a
  // no-op; and a script has nothing to hand a start to, or read back after.
  check("enabling is not offered", !keys.includes("service.runtime.enable"));
  check("starting a script is not offered", !keys.includes("service.runtime.start"));

  const plan = await sidecar.call("system-info.row.action.plan", {
    bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id,
    action: "service.runtime.disable",
  }, 90_000);
  console.log(`  plan: ${plan.summary.replace(/\s+/gu, " ").slice(0, 220)}`);
  console.log(`  restore: ${plan.restoreDescription}`);
  check("the plan is marked dangerous", plan.dangerous);
  check("the plan names the tool it will use", /rc-update|update-rc\.d|chkconfig/u.test(plan.summary));
  check("the plan says how it would be undone", typeof plan.restoreDescription === "string" && plan.restoreDescription.length > 0);
  check("nothing changed while the plan was pending", startLinks(container) !== "");

  await sidecar.call("system-info.row.action.confirm", { bindingHandle, planHandle: plan.planHandle }, 30_000);
  const receipt = await sidecar.call("system-info.row.action.execute", {
    bindingHandle, planHandle: plan.planHandle,
  }, 150_000);
  console.log(`  receipt: verified=${receipt.verified} ${receipt.detail.replace(/\s+/gu, " ").slice(0, 160)}`);
  check("the change reported itself verified", receipt.verified);

  const after = startLinks(container);
  console.log(`  host start links after: ${after === "" ? "(none)" : after}`);
  check("the host really has no start links left", after, "");

  // The tab is built from what starts at boot, so the row is gone from it.
  const { row: gone } = await plantedRow(sidecar, bindingHandle);
  check("the row has left the autostart tab", gone === undefined);

  // A plan is spent by one execution.
  await sidecar
    .call("system-info.row.action.execute", { bindingHandle, planHandle: plan.planHandle }, 60_000)
    .then(() => check("the spent plan cannot run twice", false))
    .catch((error) => check("the spent plan cannot run twice", error.message.includes("system-info-plan-unavailable")));
}

/**
 * On a host with no boot-link tool, the change has to be refused and the host
 * left exactly as it was — not attempted with something guessed.
 */
async function refuseWithoutManager(sidecar, bindingHandle, container) {
  const { table, row } = await plantedRow(sidecar, bindingHandle);
  if (row === undefined) {
    check("the planted script is listed on the autostart tab", false);
    return;
  }
  // The row can still be read: the menu is not empty just because nothing on
  // this host can change boot links.
  const actions = await sidecar.call("system-info.row.actions.list", {
    bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id,
  }, 30_000);
  const keys = (actions.groups ?? []).flatMap((group) => group.actions.map((a) => a.key));
  check("the row can still be investigated", keys.filter((k) => k.startsWith("startup.")).length, 16);

  const before = startLinks(container);
  await sidecar
    .call("system-info.row.action.plan", {
      bindingHandle, snapshotHandle: table.snapshotHandle, rowId: row.id,
      action: "service.runtime.disable",
    }, 90_000)
    .then(() => check("planning is refused when the host has no boot-link tool", false))
    .catch((error) => {
      console.log(`  refused: ${error.message.slice(0, 120)}`);
      check(
        "planning is refused when the host has no boot-link tool",
        error.message.includes("system-info-action-unavailable"),
      );
    });
  check("the host was left exactly as it was", startLinks(container), before);
}

for (const which of (process.env.LABS ?? "ubuntu").split(",")) {
  console.log(`\n=== ${which}`);
  const container = `lab-${which}`;
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  try {
    unplant(container);
    const manager = hostManager(container);
    plant(container);
    const planted = startLinks(container);
    console.log(`  boot-link tool on this host: ${manager}`);
    console.log(`  planted, start links: ${planted === "" ? "(none)" : planted}`);

    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
    const bindingHandle = status.bindingHandle;

    // A host whose startup inventory comes from systemd never lists boot
    // scripts at all, whatever is in its boot directories. There is nothing
    // for this probe to act on there, and saying so is not a failure.
    const { table } = await plantedRow(sidecar, bindingHandle);
    const kinds = [...new Set((table.rows ?? []).map((row) => row.cells[3]))];
    if (!kinds.includes("init.d")) {
      console.log(`  SKIP this host's startup inventory is ${kinds.join("/") || "empty"}; boot scripts are not listed`);
      continue;
    }
    check("the planted script starts out in the boot sequence", planted !== "");
    if (manager === "none") {
      await refuseWithoutManager(sidecar, bindingHandle, container);
    } else {
      await takeOutOfBootSequence(sidecar, bindingHandle, container);
    }
  } catch (error) {
    console.log(`  FAILED: ${error.message.slice(0, 200)}`);
    failures += 1;
  } finally {
    sidecar.close();
    unplant(container);
    const left = startLinks(container);
    check("the probe left nothing behind", left, "");
  }
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
