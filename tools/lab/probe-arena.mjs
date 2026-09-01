// Walks the arena host with every page's own read, so "one host covers
// everything" is a measurement rather than a claim.
//
//   node tools/lab/probe-arena.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());

try {
  const status = await connect(sidecar, labTarget("arena"));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  console.log("已连接综合靶机\n");

  // --- baseline: the six files, and the shape that used to fool the scan
  const catalog = await sidecar.call("baseline.catalog.get", {});
  const scan = await sidecar.call("baseline.scan", { bindingHandle: binding }, 90_000);
  const failing = scan.statuses.filter((entry) => !entry.compliant).length;
  console.log(`基线：${catalog.items.length} 项检查，${failing} 项不符合`);
  check("基线检查绝大多数不合规（这台就是没加固的）", failing >= 30, true);

  const rootLogin = catalog.items.find((item) => item.title.includes("root 直接登录"));
  const observed = scan.statuses.find((entry) => entry.itemHandle === rootLogin.itemHandle);
  check("放行 root 被读成 yes，而不是被注释骗过去", observed.observed, "yes");
  check("并且判为不合规", observed.compliant, false);

  const file = await sidecar.call("baseline.file.read", {
    bindingHandle: binding,
    itemHandle: rootLogin.itemHandle,
  }, 60_000);
  const effective = file.mentions.find((entry) => entry.effective);
  const lines = file.text.split("\n");
  console.log(`  ${file.path} 第 ${effective.line + 1} 行生效：${lines[effective.line].trim()}`);
  check("标出的是生效那行", lines[effective.line].trim(), "PermitRootLogin yes");
  check("注释那行单独标出来", file.mentions.some((entry) => entry.commented), true);

  // --- the command workbench, and what it can act on
  const commands = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding }, 90_000);
  const suid = commands.commands.find((entry) => entry.title.includes("SUID"));
  const result = await sidecar.call("emergency-command.run", {
    bindingHandle: binding,
    snapshotHandle: commands.snapshotHandle,
    commandHandle: suid.commandHandle,
  }, 90_000);
  const planted = result.paths.filter((entry) =>
    entry.path.includes("/.helper") || entry.path.includes("/.sysd"));
  console.log(`\nSUID 扫描：${result.paths.length} 行可右键，其中种下的 ${planted.length} 个`);
  console.log(planted.map((entry) => `      ${entry.path}`).join("\n"));
  check("找到了种下的 SUID 后门", planted.length >= 2, true);
  check("标红的行数说得过去", result.findingLines.length > 0, true);

  // --- log analysis has real logs to read
  const sources = await sidecar
    .call("log-analysis.sources.discover", { bindingHandle: binding }, 90_000)
    .catch((error) => ({ failed: error.message }));
  const sourceCount = sources.failed === undefined ? (sources.sources ?? []).length : -1;
  if (sources.failed !== undefined) console.log(`  ${sources.failed}`);
  console.log(`\n日志源：${sourceCount} 个`);
  check("发现了日志源", sourceCount > 0, true);

  // --- and the system overview answers
  const summary = await sidecar
    .call("system-info.summary.get", { bindingHandle: binding }, 90_000)
    .catch((error) => ({ failed: error.message }));
  console.log(`\n主机全景：${summary.failed ?? `${Object.keys(summary).length} 项`}`);
  check("主机全景读到了东西", summary.failed === undefined, true);

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  process.exitCode = 1;
} finally {
  sidecar.close();
}
