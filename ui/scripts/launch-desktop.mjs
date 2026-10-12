// Starts the debug desktop build for development and waits for it to exit.
// Data goes to the repository's data/ unless LOVELYHAWK_ARCHIVE_ROOT points
// elsewhere (debug builds only). Extra arguments are not forwarded: the
// application takes none.

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");

const child = spawn(executable, [], { stdio: "inherit", windowsHide: false });
child.once("error", (error) => {
  console.error(`无法启动 ${executable}：${error.message}。先运行 pnpm desktop:build。`);
  process.exitCode = 1;
});
child.once("exit", (code) => {
  process.exitCode = code ?? 1;
});
