const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { randomUUID } = require("node:crypto");

const electronPath = require("electron");
const projectRoot = path.resolve(__dirname, "..");
const repositoryRoot = path.resolve(projectRoot, "..");
const runRoot = path.join(repositoryRoot, "target", "electron-debug", randomUUID());
const outputDirectory = path.join(runRoot, "evidence");
const smokeRootId = randomUUID().replaceAll("-", "");
const smokeNonce = randomUUID().replaceAll("-", "");
const smokeRoot = path.join(os.tmpdir(), `lovelyres-electron-smoke-${smokeRootId}`);
const smokeMarker = path.join(smokeRoot, `ready-${smokeNonce}.json`);

fs.mkdirSync(outputDirectory, { recursive: true });
fs.mkdirSync(runRoot, { recursive: true });
fs.mkdirSync(smokeRoot, { recursive: false });

function cleanupSmokeRoot() {
  try {
    const root = fs.lstatSync(smokeRoot);
    if (!root.isDirectory() || root.isSymbolicLink()) return;
    const entries = fs.readdirSync(smokeRoot);
    if (entries.some((entry) => entry !== path.basename(smokeMarker))) return;
    if (fs.existsSync(smokeMarker)) {
      const marker = fs.lstatSync(smokeMarker);
      if (!marker.isFile() || marker.isSymbolicLink()) return;
      fs.unlinkSync(smokeMarker);
    }
    fs.rmdirSync(smokeRoot);
  } catch {
    // Failed debug runs keep their bounded temporary marker evidence for inspection.
  }
}

const child = spawn(electronPath, [projectRoot], {
  cwd: projectRoot,
  env: {
    ...process.env,
    ELECTRON_ENABLE_SECURITY_WARNINGS: "true",
    LOVELYRES_ARCHIVE_ROOT: runRoot,
    LOVELYRES_DEBUG_PROBE_DIR: outputDirectory,
    LOVELYRES_SMOKE_READY_ROOT: smokeRoot,
    LOVELYRES_SMOKE_READY_NONCE: smokeNonce,
  },
  shell: false,
  stdio: "inherit",
  windowsHide: true,
});

const timeout = setTimeout(() => {
  child.kill();
  process.stderr.write("Electron debug smoke timed out.\n");
  process.exitCode = 1;
}, 60_000);

child.once("error", (error) => {
  clearTimeout(timeout);
  cleanupSmokeRoot();
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

child.once("exit", (code, signal) => {
  clearTimeout(timeout);
  const reportPath = path.join(outputDirectory, "report.json");
  if (code !== 0 || signal !== null || !fs.existsSync(reportPath)) {
    process.stderr.write(
      `Electron debug smoke failed (${code ?? "no-code"}/${signal ?? "no-signal"}); evidence: ${outputDirectory}\n`,
    );
    process.exitCode = 1;
    cleanupSmokeRoot();
    return;
  }
  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  const marker = fs.existsSync(smokeMarker)
    ? JSON.parse(fs.readFileSync(smokeMarker, "utf8"))
    : null;
  if (
    report.status !== "PASS" ||
    marker?.schema !== "lovelyres-smoke-ready/v1" ||
    marker?.status !== "ready"
  ) {
    process.stderr.write(`Electron debug smoke did not pass; evidence: ${outputDirectory}\n`);
    process.exitCode = 1;
    cleanupSmokeRoot();
    return;
  }
  cleanupSmokeRoot();
  process.stdout.write(`Electron debug smoke passed; evidence: ${outputDirectory}\n`);
});
