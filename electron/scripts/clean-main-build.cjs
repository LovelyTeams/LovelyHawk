const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");
const buildDirectory = path.resolve(projectRoot, "dist-electron");

if (
  path.dirname(buildDirectory) !== projectRoot ||
  path.basename(buildDirectory) !== "dist-electron"
) {
  throw new Error(`Refusing to clean unexpected build directory: ${buildDirectory}`);
}

fs.rmSync(buildDirectory, { force: true, recursive: true });
