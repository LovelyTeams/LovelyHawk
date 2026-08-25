import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const snapshot = await sidecar.call("log-analysis.sources.discover", { bindingHandle: binding });
  console.log(`sources: ${snapshot.sources.length} partial=${snapshot.partial} truncated=${snapshot.truncated}`);
  for (const source of snapshot.sources) {
    console.log(`  [${source.kind}] ${source.displayName} ${source.displayLocation} ${source.sizeBytes ?? "-"}`);
  }

  const auth = snapshot.sources.find((s) => s.displayName.includes("auth"));
  if (auth !== undefined) {
    const read = await sidecar.call("log-analysis.source.read", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      sourceHandle: auth.sourceHandle,
      input: { page: 1, pageSize: 100, keyword: null, date: null, journalUnit: null },
    }, 90_000);
    console.log(`\nauth.log: ${read.entryCount} entries, highlighted=${read.highlightedCount}, threat=${read.threatSummary.threatLevel}`);
    console.log(`  brute=${read.threatSummary.bruteForceCount} success=${read.threatSummary.successfulLoginCount} escalation=${read.threatSummary.privilegeEscalationCount} suspicious=${read.threatSummary.suspiciousActivityCount}`);
    console.log("  top ips:", read.threatSummary.topSourceIps.map((i) => `${i.ip}x${i.count}(${i.actionType})`).join(" "));
    console.log("  top users:", read.threatSummary.topTargetUsers.map((u) => `${u.username} ok=${u.successCount} fail=${u.failCount}`).join(" "));
    console.log("  first 4 entries:");
    for (const entry of read.entries.slice(0, 4)) {
      console.log(`   ${entry.highlighted ? "!!" : "  "} ${entry.rawText.slice(0, 110)}`);
    }
    const bearer = read.entries.find((e) => /Accepted password for root/u.test(e.rawText));
    console.log(`  successful-root-login entry present: ${bearer !== undefined}`);
  } else {
    console.log("!! auth.log was not discovered");
  }

  const files = snapshot.sources.filter((s) => s.kind === "file"
    && /auth\.log|access\.log|syslog/u.test(s.displayName));
  if (files.length > 0) {
    const ioc = await sidecar.call("log-analysis.iocs.search", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      input: { sourceHandles: files.map((f) => f.sourceHandle), indicators: ["198.51.100.7", "upload.php"] },
    }, 90_000);
    console.log(`\nIOC: ${ioc.totalMatches} matches across ${ioc.results.length} pairs`);
    for (const item of ioc.results) {
      console.log(`  ${item.indicator} in ${item.sourceName}: ${item.count}`);
      for (const sample of item.sampleLines.slice(0, 2)) console.log(`     ${sample.slice(0, 110)}`);
    }
  }
} catch (error) {
  console.log("FAILED:", error.message);
  console.log(sidecar.stderr.join("").slice(-800));
} finally {
  sidecar.close();
}
