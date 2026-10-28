// When a page refuses, does it say what to do — or list what might have gone
// wrong and leave the operator to pick?
//
// They used to share a sentence: "this table is stale, refresh and try again".
// That is good advice for two of them and a loop with no end for the third — a
// row that has no further detail will say the same thing however many times it
// is asked, and the operator has no way to learn that from the window.
//
//   node tools/lab/probe-refusals.mjs
//   LAB=rocky node tools/lab/probe-refusals.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const collect = (tab) => sidecar.call(
    "system-info.table.collect",
    { bindingHandle: binding, tab, maximumRows: 20 },
    180_000,
  );
  const detail = (snapshotHandle, rowId) => sidecar.call(
    "system-info.detail.get",
    { bindingHandle: binding, snapshotHandle, rowId },
    180_000,
  ).then(() => null).catch((error) => String(error.message));

  const table = await collect("processes");
  const withDetail = table.rows.find((row) => row.detail) ?? table.rows[0];
  check("表里有行可以问", table.rows.length > 0);

  // The one that works, so the refusals below mean something.
  check("正常的一行问得到详情", await detail(table.snapshotHandle, withDetail.id), null);

  const gone = await detail(table.snapshotHandle, "no-such-row-0");
  console.log(`  表里没有这一行 → ${String(gone).slice(0, 80)}`);
  check("说的是这一行不在表里", gone?.includes("system-info-row-gone"), true);

  const stale = await detail("11111111-2222-4333-8444-555555555555", withDetail.id);
  console.log(`  旧快照       → ${String(stale).slice(0, 80)}`);
  check("说的是这份表旧了", stale?.includes("system-info-snapshot-stale"), true);

  // A tab whose rows carry nothing more to show. Refreshing will never change
  // that, which is exactly why it must not be reported as a stale table.
  const plain = await collect("env-vars");
  const plainRow = plain.rows.find((row) => row.detail === false);
  if (plainRow === undefined) {
    console.log("  SKIP 这台机器上没有『没有详情』的行");
  } else {
    const none = await detail(plain.snapshotHandle, plainRow.id);
    console.log(`  本来就没详情 → ${String(none).slice(0, 80)}`);
    check("说的是这一行本来就没有更多内容", none?.includes("system-info-detail-none"), true);
    check("而不是让人去刷新", none?.includes("system-info-snapshot-stale"), false);
  }

  // The old shared code is gone from every one of them.
  for (const [label, message] of [["不在表里", gone], ["旧快照", stale]]) {
    check(`${label}不再回退到笼统的旧码`, message?.includes("system-info-snapshot-invalid"), false);
  }

  // The log views take the opposite lesson: their four internal reasons all
  // mean the same thing to an operator — the source list has moved on, refresh
  // it — so they share one code on purpose, and the page turns that into one
  // action rather than a list of maybes.
  const snapshot = await sidecar.call(
    "log-analysis.sources.discover",
    { bindingHandle: binding },
    180_000,
  );
  const files = snapshot.sources.filter((source) => source.kind === "file");
  check("日志页有文件日志可用", files.length > 0);
  if (files.length > 0) {
    const staleHandle = "11111111-2222-4333-8444-555555555555";
    const attempts = {
      读一页: sidecar.call("log-analysis.source.read", {
        bindingHandle: binding,
        snapshotHandle: staleHandle,
        sourceHandle: files[0].sourceHandle,
        input: { page: 1, pageSize: 100, keyword: null, date: null, journalUnit: null },
      }, 180_000),
      多源关联: sidecar.call("log-analysis.sources.correlate", {
        bindingHandle: binding,
        snapshotHandle: staleHandle,
        input: {
          sourceHandles: files.slice(0, 2).map((file) => file.sourceHandle),
          lineLimit: 200,
        },
      }, 180_000),
      IOC搜索: sidecar.call("log-analysis.iocs.search", {
        bindingHandle: binding,
        snapshotHandle: snapshot.snapshotHandle,
        input: { sourceHandles: ["not-a-real-source"], indicators: ["203.0.113.7"] },
      }, 180_000),
    };
    for (const [label, pending] of Object.entries(attempts)) {
      const message = await pending.then(() => null).catch((error) => String(error.message));
      check(`${label}：清单旧了就说清单旧了`,
        message?.includes("log-analysis-snapshot-unavailable"), true);
    }
  }
  // The terminal's own ceiling. It used to report itself as "output read
  // failed", which reads like a hiccup worth retrying — but a session that has
  // produced every byte it may hold will never produce another, and the only
  // way forward is a new terminal.
  const opened = await sidecar.call(
    "terminal.open",
    { bindingHandle: binding, columns: 160, rows: 60 },
    120_000,
  );
  await sidecar.call("terminal.input", {
    handle: opened.handle,
    bytesBase64: Buffer.from("yes ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n", "utf8")
      .toString("base64"),
  }, 60_000);
  const deadline = Date.now() + 180_000;
  let refusal = null;
  while (Date.now() < deadline && refusal === null) {
    refusal = await sidecar.call("terminal.poll", {
      handle: opened.handle, maximumEvents: 64, maximumBytes: 262_144,
    }, 60_000).then(() => null).catch((error) => String(error.message));
    if (refusal === null) await new Promise((resolve) => setTimeout(resolve, 20));
  }
  console.log(`  终端灌满之后 → ${String(refusal).slice(0, 80)}`);
  check("说的是这个会话的输出量用满了", refusal?.includes("terminal-output-limit"), true);
  check("不再是笼统的『协议越界』", refusal?.includes("terminal-protocol-invalid"), false);
  await sidecar.call("terminal.close", { handle: opened.handle }, 60_000).catch(() => {});
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
