// Checks every one of the 90 protected config-generator test IDs against
// what actually ran on this snapshot: each completed entry in
// docs/CONFIG_GENERATOR_TEST_BACKLOG.md must name replacement tests, and each
// named test must have passed in the cargo test log, the vitest JSON report,
// or a real-window probe report. The ID list must equal the protected
// baseline's ordered inventory in docs/DESKTOP_UI_LEDGER.json, and the
// archived baseline must still hash to its recorded snapshot.
//
//   node scripts/config-generator-backlog-verify.mjs --cargo-log <file> --vitest-json <file> [--latest]
//   node scripts/config-generator-backlog-verify.mjs --self-test
//
// With --latest, real-window checks are read from the newest report of each
// probe (a fresh run on this snapshot) instead of the runs the entries cite.
//
// A missing test, a failed or skipped one, a probe check that did not pass,
// a pending item, a duplicate or an unlisted ID all fail the run.

import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** The completed and pending entries of the backlog, with what each names. */
export function parseBacklog(text) {
  const entries = [];
  for (const line of text.split("\n")) {
    const item = line.match(/^- \[( |x)\] `([a-z0-9_]+)`(.*)$/u);
    if (item === null) continue;
    const [, mark, id, rest] = item;
    const arrow = rest.indexOf("→");
    const mapping = arrow < 0 ? "" : rest.slice(arrow + 1, rest.indexOf("。", arrow) < 0 ? undefined : rest.indexOf("。", arrow));
    const quoted = [...mapping.matchAll(/`([^`]+)`/gu)].map((match) => match[1].trim());
    const refs = [];
    let probe = null;
    for (const ref of quoted) {
      if (/^(cargo|pnpm|node) /u.test(ref)) continue;
      const probeLabel = ref.match(/^tools\/lab\/(probe-[a-z0-9-]+)\.mjs › (.+)$/u);
      if (probeLabel !== null) {
        refs.push({ kind: "probe-label", probe: probeLabel[1], label: probeLabel[2] });
        continue;
      }
      if (/^tools\/lab\/probe-[a-z0-9-]+\.mjs$/u.test(ref)) {
        probe = ref.slice("tools/lab/".length, -".mjs".length);
        // A probe named by itself, with its check after › outside the quotes.
        const after = mapping.slice(mapping.indexOf(ref) + ref.length);
        const label = after.match(/^`?(?:（[^）]*）)?\s*›\s*([^`（、]+?)\s*$/u)?.[1];
        if (label !== undefined && !label.startsWith("desktop-cdp::")) {
          refs.push({ kind: "probe-label", probe: ref.slice("tools/lab/".length, -".mjs".length), label });
        }
        continue;
      }
      if (ref.startsWith("desktop-cdp::")) refs.push({ kind: "cdp", id: ref });
      else if (ref.includes(" > ")) refs.push({ kind: "vitest", name: ref });
      else if (/::tests::[a-z0-9_]+$/u.test(ref)) refs.push({ kind: "rust", name: ref.replace(/^lovelyhawk-[a-z]+::/u, "") });
    }
    const evidence = [...rest.matchAll(/`(target\/lab-[a-z-]+\/[0-9a-f-]{36})`/gu)].map((match) => match[1]);
    entries.push({ id, done: mark === "x", refs, evidence, probe });
  }
  return entries;
}

/** Every `test <name> ... <status>` line of a cargo test log. */
export function cargoResults(log) {
  const results = new Map();
  for (const match of log.matchAll(/^test (\S+) \.\.\. (ok|FAILED|ignored)\b/gmu)) {
    // The same name in two crates must pass in both.
    const previous = results.get(match[1]);
    results.set(match[1], previous === undefined || previous === "ok" ? match[2] : previous);
  }
  return results;
}

/** Every vitest assertion as "describe > … > title" with its status. */
export function vitestResults(report) {
  const results = new Map();
  for (const file of report.testResults ?? []) {
    for (const assertion of file.assertionResults ?? []) {
      const name = [...(assertion.ancestorTitles ?? []), assertion.title].join(" > ");
      results.set(name, assertion.status);
    }
  }
  return results;
}

function readProbeReport(directory) {
  const file = path.join(directory, "report.json");
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** The newest report of a probe, or the one an entry cites. */
function probeChecks(root, probe, evidence, latest = false) {
  const directories = {
    "probe-ui-config-visual": "lab-config-visual",
    "probe-ui-config-interactions": "lab-config-interactions",
    "probe-ui-config-layout": "lab-config-layout",
    "probe-ui-config-goals": "lab-config-goals",
  };
  const cited = latest ? [] : evidence.filter((item) => item.startsWith(`target/${directories[probe] ?? "-"}/`));
  const candidates = cited.length > 0 ? cited.map((item) => path.join(root, item)) : (() => {
    const base = path.join(root, "target", directories[probe] ?? "-");
    if (!fs.existsSync(base)) return [];
    return fs.readdirSync(base).map((name) => path.join(base, name))
      .filter((dir) => fs.existsSync(path.join(dir, "report.json")))
      .sort((a, b) => fs.statSync(path.join(b, "report.json")).mtimeMs - fs.statSync(path.join(a, "report.json")).mtimeMs)
      .slice(0, 1);
  })();
  return candidates.map((dir) => ({ dir, report: readProbeReport(dir) }));
}

/** One verdict per entry, and the run's. */
export function verify({ entries, protectedIds, cargo, vitest, root, latest = false }) {
  const problems = [];
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry.id)) problems.push(`duplicate ID ${entry.id}`);
    seen.add(entry.id);
  }
  const listed = entries.map((entry) => entry.id);
  for (const id of protectedIds) if (!seen.has(id)) problems.push(`protected ID ${id} has no backlog entry`);
  for (const id of listed) if (!protectedIds.includes(id)) problems.push(`backlog ID ${id} is not a protected test ID`);
  const verdicts = entries.map((entry) => {
    const sources = new Set();
    const failures = [];
    if (!entry.done) failures.push("still pending");
    if (entry.refs.length === 0) failures.push("names no replacement test");
    for (const ref of entry.refs) {
      if (ref.kind === "rust") {
        const hits = [...cargo.entries()].filter(([name]) => name === ref.name || name.endsWith(`::${ref.name}`));
        if (hits.length === 0) failures.push(`rust ${ref.name}: not in the cargo log`);
        else if (hits.some(([, status]) => status !== "ok")) failures.push(`rust ${ref.name}: ${hits.map(([, s]) => s).join("/")}`);
      } else if (ref.kind === "vitest") {
        const status = vitest.get(ref.name);
        if (status !== "passed") failures.push(`vitest ${ref.name}: ${status ?? "not in the report"}`);
      } else {
        const probe = ref.kind === "cdp" ? entry.probe ?? guessProbe(entry) : ref.probe;
        const reports = probeChecks(root, probe, entry.evidence, latest);
        for (const { dir } of reports) sources.add(path.relative(root, dir).replaceAll("\\", "/"));
        if (reports.length === 0 || reports.some(({ report }) => report === null)) {
          failures.push(`${probe}: no report`);
          continue;
        }
        const want = ref.kind === "cdp" ? ref.id : ref.label;
        const found = reports.some(({ report }) => (report.checks ?? []).some((item) =>
          (item.id ?? item.label) === want && item.passed === true) && report.status === "PASS");
        if (!found) failures.push(`${probe}: "${want}" did not pass in ${reports.map(({ dir }) => path.relative(root, dir)).join(", ")}`);
      }
    }
    return { id: entry.id, passed: failures.length === 0, refs: entry.refs.length, failures, sources: [...sources] };
  });
  return { passed: problems.length === 0 && verdicts.every((verdict) => verdict.passed), problems, verdicts };
}

function guessProbe(entry) {
  const evidence = entry.evidence[0] ?? "";
  if (evidence.startsWith("target/lab-config-goals/")) return "probe-ui-config-goals";
  if (evidence.startsWith("target/lab-config-layout/")) return "probe-ui-config-layout";
  if (evidence.startsWith("target/lab-config-interactions/")) return "probe-ui-config-interactions";
  return "probe-ui-config-interactions";
}

function protectedInventory(root) {
  const ledger = JSON.parse(fs.readFileSync(path.join(root, "docs", "DESKTOP_UI_LEDGER.json"), "utf8"));
  const baseline = ledger.protectedWorktree.find((item) => item.id === "dirty-config-generator-baseline");
  const ids = baseline.snapshot.testIds;
  const orderedHash = createHash("sha256").update(ids.join("\n"), "utf8").digest("hex");
  const archived = fs.readFileSync(path.join(root, "docs", "legacy", "config-generator-baseline.rs.txt"));
  return {
    ids,
    snapshotMatches: createHash("sha256").update(archived).digest("hex") === baseline.snapshot.sha256,
    inventoryMatches: orderedHash === baseline.snapshot.orderedTestIdSha256 && ids.length === baseline.snapshot.testCount,
  };
}

function selfTest() {
  const root = fs.mkdtempSync(path.join(repository, "target", "backlog-verify-self-"));
  try {
    const goals = path.join(root, "target", "lab-config-goals", "00000000-0000-4000-8000-000000000001");
    fs.mkdirSync(goals, { recursive: true });
    fs.writeFileSync(path.join(goals, "report.json"), JSON.stringify({ status: "PASS", checks: [
      { id: "desktop-cdp::config-generator::b_case", passed: true }, { id: "desktop-cdp::config-generator::c_case", passed: false },
    ] }));
    const evidence = "target/lab-config-goals/00000000-0000-4000-8000-000000000001";
    const backlog = [
      "- [x] `a_case`（2026-10-12）→ `lovelyhawk-core::m::tests::a_case`（`cargo test x`）。",
      `- [x] \`b_case\`（2026-10-12，证据 \`${evidence}\`）→ \`tools/lab/probe-ui-config-goals.mjs\`（\`pnpm x\`） › \`desktop-cdp::config-generator::b_case\`。`,
      "- [x] `d_case` → `suite > d case`。",
    ].join("\n");
    const cargo = cargoResults("test m::tests::a_case ... ok\n");
    const vitest = vitestResults({ testResults: [{ assertionResults: [{ ancestorTitles: ["suite"], title: "d case", status: "passed" }] }] });
    const ids = ["a_case", "b_case", "d_case"];
    const good = verify({ entries: parseBacklog(backlog), protectedIds: ids, cargo, vitest, root });
    const cases = {
      "a clean mapping passes": good.passed,
      "a duplicate ID fails": !verify({ entries: parseBacklog(`${backlog}\n- [x] \`a_case\` → \`m::tests::a_case\`。`), protectedIds: ids, cargo, vitest, root }).passed,
      "a pending item fails": !verify({ entries: parseBacklog(backlog.replace("- [x] `d_case`", "- [ ] `d_case`")), protectedIds: ids, cargo, vitest, root }).passed,
      "a missing rust test fails": !verify({ entries: parseBacklog(backlog), protectedIds: ids, cargo: cargoResults(""), vitest, root }).passed,
      "a failed rust test fails": !verify({ entries: parseBacklog(backlog), protectedIds: ids, cargo: cargoResults("test m::tests::a_case ... FAILED\n"), vitest, root }).passed,
      "an ignored rust test fails": !verify({ entries: parseBacklog(backlog), protectedIds: ids, cargo: cargoResults("test m::tests::a_case ... ignored\n"), vitest, root }).passed,
      "a skipped vitest test fails": !verify({ entries: parseBacklog(backlog), protectedIds: ids, cargo,
        vitest: vitestResults({ testResults: [{ assertionResults: [{ ancestorTitles: ["suite"], title: "d case", status: "skipped" }] }] }), root }).passed,
      "a probe check that did not pass fails": !verify({ entries: parseBacklog(backlog.replace(/b_case`。$/mu, "c_case`。")), protectedIds: ids, cargo, vitest, root }).passed,
      "missing probe evidence fails": !verify({ entries: parseBacklog(backlog.replace(evidence, "target/lab-config-goals/00000000-0000-4000-8000-0000000000ff")), protectedIds: ids, cargo, vitest, root }).passed,
      "an unlisted protected ID fails": !verify({ entries: parseBacklog(backlog), protectedIds: [...ids, "e_case"], cargo, vitest, root }).passed,
      "an entry with no replacement fails": !verify({ entries: parseBacklog(`${backlog.split("\n").slice(0, 2).join("\n")}\n- [x] \`d_case\` 已核对。`), protectedIds: ids, cargo, vitest, root }).passed,
    };
    for (const [name, ok] of Object.entries(cases)) console.log(`${ok ? "PASS" : "FAIL"} self-test: ${name}`);
    return Object.values(cases).every(Boolean);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1] ?? null;
}

if (process.argv.includes("--self-test")) {
  process.exitCode = selfTest() ? 0 : 1;
} else {
  const cargoLog = argument("--cargo-log");
  const vitestJson = argument("--vitest-json");
  if (cargoLog === null || vitestJson === null) {
    console.error("usage: --cargo-log <file> --vitest-json <file> | --self-test");
    process.exit(2);
  }
  const inventory = protectedInventory(repository);
  const entries = parseBacklog(fs.readFileSync(path.join(repository, "docs", "CONFIG_GENERATOR_TEST_BACKLOG.md"), "utf8"));
  const result = verify({
    entries,
    protectedIds: inventory.ids,
    cargo: cargoResults(fs.readFileSync(cargoLog, "utf8")),
    vitest: vitestResults(JSON.parse(fs.readFileSync(vitestJson, "utf8"))),
    root: repository,
    latest: process.argv.includes("--latest"),
  });
  if (!inventory.snapshotMatches) result.problems.push("the archived baseline no longer hashes to the recorded snapshot");
  if (!inventory.inventoryMatches) result.problems.push("the protected test inventory no longer matches its recorded hash");
  const passed = result.passed && inventory.snapshotMatches && inventory.inventoryMatches;
  const out = path.join(repository, "target", "config-generator-backlog", randomUUID());
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, "report.json"), `${JSON.stringify({
    schema: "lovelyhawk-config-generator-backlog-verify/v1",
    status: passed ? "PASS" : "FAIL",
    generatedAt: new Date().toISOString(),
    probeReports: process.argv.includes("--latest") ? "newest run of each probe" : "runs cited by each entry",
    inventory: { ids: inventory.ids.length, snapshotMatches: inventory.snapshotMatches, inventoryMatches: inventory.inventoryMatches },
    problems: result.problems,
    verdicts: result.verdicts,
  }, null, 2)}\n`);
  for (const problem of result.problems) console.log(`FAIL ${problem}`);
  for (const verdict of result.verdicts.filter((item) => !item.passed)) console.log(`FAIL ${verdict.id}: ${verdict.failures.join("; ")}`);
  const ok = result.verdicts.filter((item) => item.passed).length;
  console.log(`${passed ? "PASS" : "FAIL"}: ${ok}/${result.verdicts.length} entries, ${result.verdicts.reduce((n, v) => n + v.refs, 0)} replacement tests; report in ${out}`);
  process.exitCode = passed ? 0 : 1;
}
