// Copies the orchestration lab into the virtual machine and builds it.
//
// The copy is not a convenience: files edited on Windows carry CRLF, and a
// shell script with CRLF fails inside a container with errors that name the
// wrong line. Stripping happens here, once, rather than inside a nested
// quoting nightmare in package.json.
//
//   node tools/lab/orchestration/up.mjs
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
const inside = "/opt/lab-orchestration";

function wsl(command, options = {}) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc", command], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  });
}

/** Every file under the lab directory, relative to it. */
function walk(directory, prefix = "") {
  const found = [];
  for (const entry of fs.readdirSync(path.join(directory, prefix), { withFileTypes: true })) {
    const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) found.push(...walk(directory, relative));
    // The runner copies itself nowhere: it runs on this side.
    else if (relative !== "up.mjs") found.push(relative);
  }
  return found;
}

const files = walk(here);
const windowsPath = here.replace(/\\/gu, "/");
const source = `/mnt/${windowsPath[0].toLowerCase()}${windowsPath.slice(2)}`;

wsl(`rm -rf ${inside} && mkdir -p ${inside}`);
wsl(`cp -r ${source}/. ${inside}/ && rm -f ${inside}/up.mjs`);
// The arena runs the same Docker planting as the single-purpose host, and a
// Docker build context cannot reach outside its own directory — so the file is
// copied into place here rather than kept as a second copy in the tree. It was
// a second copy, byte for byte, and the first edit to one of them left the
// arena quietly missing a container the probes expected to find.
wsl(`cp ${inside}/docker/plant.sh ${inside}/arena/plant-docker.sh`);
// One sed per file, so a name with a space or a bracket cannot become two
// arguments the way a glob would.
for (const file of files) wsl(`sed -i 's/\\r$//' '${inside}/${file}'`);
wsl(`find ${inside} -name '*.sh' -exec chmod +x {} +`);
console.log(`已同步 ${files.length} 个文件到 ${inside}\n`);

process.stdout.write(wsl(`bash ${inside}/build.sh`, { stdio: ["ignore", "pipe", "inherit"] }));
