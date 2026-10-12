// Starts the debug desktop build with its pages served by Vite, so edits under
// ui/src show in the open windows at once (React components keep their state).
// Rust changes still need this command run again.
//
// Debug builds only: the host reads LOVELYHAWK_DEV_SERVER and accepts nothing
// but a loopback origin. Release builds, `pnpm desktop:dev` and the CDP
// acceptance runs keep loading the embedded pages.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { build, createServer } from "vite";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
// Named explicitly: a stray vite.config.mjs next to it would otherwise win.
const configFile = path.join(uiRoot, "vite.config.mts");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: repositoryRoot, stdio: "inherit", windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${command} 退出码 ${code}`))));
  });
}

// The host embeds ui/dist at compile time even when it will not serve it.
if (!existsSync(path.join(uiRoot, "dist", "index.html"))) {
  await build({ configFile, root: uiRoot, logLevel: "warn" });
}
await run("cargo", ["build", "--locked", "--package", "lovelyhawk-desktop"]);

const server = await createServer({ configFile, root: uiRoot });
await server.listen();
const { host, port } = server.config.server;
const origin = `http://${host}:${port}/`;
console.log(`页面由 ${origin} 提供，改动 ui/src 后窗口会自动更新。`);

const child = spawn(executable, [], {
  stdio: "inherit",
  windowsHide: false,
  env: { ...process.env, LOVELYHAWK_DEV_SERVER: origin },
});
let stopping = false;
async function stop(code) {
  if (stopping) return;
  stopping = true;
  await server.close();
  process.exit(code);
}
child.once("error", (error) => {
  console.error(`无法启动 ${executable}：${error.message}`);
  void stop(1);
});
child.once("exit", (code) => void stop(code ?? 1));
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    child.kill();
    void stop(130);
  });
}
