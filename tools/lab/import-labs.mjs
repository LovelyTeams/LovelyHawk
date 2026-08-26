// Writes the nine lab hosts into LovelyRes's own connection store, passwords
// included, so the window opens with all of them ready to connect.
//
// Re-running is the normal thing to do: the WSL virtual machine takes a new
// address every time it restarts, and this refreshes every entry in place
// rather than adding duplicates.
//
//   node tools/lab/import-labs.mjs            # into the development store
//   LOVELYRES_ARCHIVE_ROOT=D:/some/where node tools/lab/import-labs.mjs
//   node tools/lab/import-labs.mjs --remove   # take them all out again
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar } from "./rpc-harness.mjs";
import { LAB_PORTS } from "./lab-target.mjs";

const PASSWORD = "LabRoot#2026";
const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");

// The unpackaged app resolves its archive root to the directory above
// electron/, which is the repository root.
const archiveRoot = process.env.LOVELYRES_ARCHIVE_ROOT ?? repository;
const backend = path.join(repository, "target", "debug", "lovelyres-backend.exe");
const removing = process.argv.includes("--remove");

function wslAddress() {
  try {
    const output = execFileSync("wsl.exe", ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"], {
      encoding: "utf8",
    });
    const address = output.split("\0").join("").trim().split(/\s+/u)[0];
    if (address === undefined || address === "") throw new Error("no address");
    return address;
  } catch {
    throw new Error(
      "Could not read the WSL address. Start the distribution with `wsl -d Ubuntu -e true` and retry.",
    );
  }
}

/** A stable id per lab, so a second run updates rather than duplicates. */
function labId(index) {
  const suffix = String(index + 1).padStart(12, "0");
  return `1ab1ab1a-0000-4000-8000-${suffix}`;
}

function draft(name, host, port, id) {
  return {
    id,
    name: `实验靶机 ${name}`,
    host,
    port,
    username: "root",
    authMethod: "password",
    privateKeyPath: null,
    certificatePath: null,
    agentIdentityFingerprint: null,
    jumpHost: null,
    tags: ["lab"],
    notes: `WSL Docker 靶机 lab-${name}，故意做成被入侵的样子；见 tools/lab/README.md。`,
    environment: "lab",
    role: null,
    group: "实验靶机",
  };
}

const host = removing ? "127.0.0.1" : wslAddress();
const sidecar = new Sidecar(backend, archiveRoot);
let created = 0;
let updated = 0;
let removed = 0;

try {
  const existing = await sidecar.call("connections.list", {});
  const known = new Set(existing.map((entry) => entry.id));

  const names = Object.keys(LAB_PORTS);
  for (const [index, name] of names.entries()) {
    const id = labId(index);
    if (removing) {
      if (!known.has(id)) continue;
      const plan = await sidecar.call("connections.delete.plan", { id });
      await sidecar.call("connections.delete.confirm", { handle: plan.handle });
      removed += 1;
      continue;
    }
    const input = {
      connection: draft(name, host, LAB_PORTS[name], id),
      secrets: { password: { action: "replace", value: PASSWORD } },
    };
    if (known.has(id)) {
      await sidecar.call("connections.update", input);
      updated += 1;
    } else {
      await sidecar.call("connections.create", input);
      created += 1;
    }
  }

  if (removing) {
    console.log(`已移除 ${removed} 台实验靶机连接。`);
  } else {
    console.log(`靶机地址 ${host}，口令 ${PASSWORD}`);
    console.log(`已写入连接库：新建 ${created} 台，更新 ${updated} 台。`);
    console.log(`连接库位置：${path.join(archiveRoot, "data")}`);
    console.log("打开 LovelyRes 就能在连接管理里看到它们；WSL 重启换了地址后再跑一次即可。");
  }
} catch (error) {
  console.error(`失败：${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-600));
  process.exitCode = 1;
} finally {
  sidecar.close();
}
