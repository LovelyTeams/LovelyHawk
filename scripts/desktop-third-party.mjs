// Third-party inventory for a portable package: every Rust crate linked into
// the desktop executable for one target, every UI package bundled into the
// page, and every embedded asset, written as
//
//   THIRD_PARTY_LICENSES_RUST.txt  the license texts each crate ships, grouped
//                                  so identical texts appear once
//   SBOM.cdx.json                  a CycloneDX 1.5 bill of materials
//
// UI packages and fonts keep their notices in ui/THIRD_PARTY_NOTICES.md; the
// SBOM lists them with their declared licenses and the asset hashes.
//
//   node scripts/desktop-third-party.mjs --target x86_64-pc-windows-msvc --out <dir> --version 1.0.0
//
// Fails when a component has no declared license, when a retired GPUI crate
// appears, or when the output already exists. Crates that ship no license file
// are listed under their own heading for review rather than silently skipped.

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0 || index + 1 >= process.argv.length) throw new Error(`missing --${name}`);
  return process.argv[index + 1];
};
const target = argument("target");
const output = path.resolve(argument("out"));
const version = argument("version");
const licensesPath = path.join(output, "THIRD_PARTY_LICENSES_RUST.txt");
const sbomPath = path.join(output, "SBOM.cdx.json");
for (const file of [licensesPath, sbomPath]) {
  if (fs.existsSync(file)) throw new Error(`refusing to overwrite ${file}`);
}
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const problems = [];

// Rust: the normal-dependency closure of the desktop crate on this target.
const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--locked", "--format-version", "1", "--filter-platform", target], {
  cwd: repositoryRoot, encoding: "utf8", maxBuffer: 256 * 1024 * 1024,
}));
const packages = new Map(metadata.packages.map((entry) => [entry.id, entry]));
const nodes = new Map(metadata.resolve.nodes.map((entry) => [entry.id, entry]));
const desktop = metadata.packages.find((entry) => entry.name === "lovelyhawk-desktop");
const reachable = new Set();
const pending = [desktop.id];
while (pending.length > 0) {
  const id = pending.pop();
  if (reachable.has(id)) continue;
  reachable.add(id);
  for (const dependency of nodes.get(id)?.deps ?? []) {
    if (dependency.dep_kinds.some((kind) => kind.kind === null)) pending.push(dependency.pkg);
  }
}
const crates = [...reachable].map((id) => packages.get(id))
  .filter((entry) => entry.source !== null)
  .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
const texts = new Map(); // hash -> { text, crates[] }
const withoutFiles = [];
for (const entry of crates) {
  if (/^gpui/u.test(entry.name)) problems.push(`retired GPUI crate ${entry.name} is linked`);
  if (!entry.license && !entry.license_file) problems.push(`crate ${entry.name}@${entry.version} declares no license`);
  const directory = path.dirname(entry.manifest_path);
  const files = fs.readdirSync(directory)
    .filter((name) => /^(?:LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT)/iu.test(name))
    .filter((name) => fs.statSync(path.join(directory, name)).isFile())
    .sort();
  if (entry.license_file && !files.includes(path.basename(entry.license_file))) files.push(path.basename(entry.license_file));
  entry.licenseTexts = [];
  for (const name of files) {
    const text = fs.readFileSync(path.join(directory, name), "utf8").replace(/\r\n/gu, "\n").trim();
    const key = sha256(text);
    if (!texts.has(key)) texts.set(key, { text, users: [] });
    texts.get(key).users.push(`${entry.name} ${entry.version} (${name})`);
    entry.licenseTexts.push(key);
  }
  if (files.length === 0) withoutFiles.push(entry);
}

// A crate that ships no license file is covered only if the standard text of
// its license (or of one alternative in an OR expression) ships with another
// crate. Recognised by each license's own opening words.
const signatures = {
  "MIT": /Permission is hereby granted, free of charge/u,
  "Apache-2.0": /Apache License\s+Version 2\.0/u,
  "MPL-2.0": /Mozilla Public License Version 2\.0/u,
  "BSD-3-Clause": /Redistribution and use in source and binary forms[\s\S]*Neither the name/u,
  "BSD-2-Clause": /Redistribution and use in source and binary forms/u,
  "BSL-1.0": /Boost Software License - Version 1\.0/u,
  "ISC": /Permission to use, copy, modify, and\/or distribute this software/u,
  "Zlib": /This software is provided 'as-is', without any express or implied/u,
  "Unlicense": /This is free and unencumbered software released into the public domain/u,
};
const allTexts = [...texts.values()].map((entry) => entry.text);
for (const entry of withoutFiles) {
  const alternatives = (entry.license ?? "").split(/\s+OR\s+|\//u).map((part) => part.replace(/[()]/gu, "").trim());
  const covered = alternatives.some((alternative) => alternative.split(/\s+AND\s+/u).every((id) => {
    const signature = signatures[id.trim()];
    return signature !== undefined && allTexts.some((text) => signature.test(text));
  }));
  if (!covered) problems.push(`crate ${entry.name}@${entry.version} ships no license file and no standard text for "${entry.license}" is available`);
}

// UI packages: the production closure of ui/package.json, resolved in pnpm's layout.
const uiRoot = path.join(repositoryRoot, "ui");
const uiManifest = JSON.parse(fs.readFileSync(path.join(uiRoot, "package.json"), "utf8"));
function packageDirectory(name, from) {
  for (let directory = from; ; directory = path.dirname(directory)) {
    const candidate = path.join(directory, "node_modules", name);
    if (fs.existsSync(path.join(candidate, "package.json"))) return fs.realpathSync(candidate);
    const parent = path.dirname(directory);
    if (parent === directory) return null;
  }
}
const npm = new Map();
const npmPending = Object.keys(uiManifest.dependencies ?? {}).map((name) => [name, uiRoot]);
while (npmPending.length > 0) {
  const [name, from] = npmPending.pop();
  const directory = packageDirectory(name, from);
  if (directory === null) { problems.push(`UI package ${name} is not installed`); continue; }
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, "package.json"), "utf8"));
  const key = `${manifest.name}@${manifest.version}`;
  if (npm.has(key)) continue;
  const license = typeof manifest.license === "string" ? manifest.license : manifest.license?.type;
  if (!license) problems.push(`UI package ${key} declares no license`);
  npm.set(key, { name: manifest.name, version: manifest.version, license });
  for (const dependency of Object.keys(manifest.dependencies ?? {})) npmPending.push([dependency, directory]);
}

// Embedded assets with their recorded licenses.
const assets = [
  ["ui/assets/fonts/Inter-Regular.ttf", "OFL-1.1"],
  ["ui/assets/fonts/Inter-SemiBold.ttf", "OFL-1.1"],
  ["ui/assets/fonts/CascadiaMono.ttf", "OFL-1.1"],
  ["ui/assets/logo.png", "AGPL-3.0-only"],
  ["ui/assets/app.ico", "AGPL-3.0-only"],
  // Embedded into the executable as its file and window icons.
  ["crates/lovelyhawk-desktop/icons/icon.ico", "AGPL-3.0-only"],
  ["crates/lovelyhawk-desktop/icons/icon.png", "AGPL-3.0-only"],
  ["ui/assets/security_reference.json", "AGPL-3.0-only"],
].map(([file, license]) => ({ file, license, hash: sha256(fs.readFileSync(path.join(repositoryRoot, file))) }));

if (problems.length > 0) {
  console.error(`Third-party inventory failed:\n - ${problems.join("\n - ")}`);
  process.exit(1);
}

// THIRD_PARTY_LICENSES_RUST.txt
const numbered = [...texts.entries()].map(([key, value], index) => ({ key, number: index + 1, ...value }));
const numberOf = new Map(numbered.map((entry) => [entry.key, entry.number]));
const lines = [
  `LovelyHawk ${version} (${target}) — Rust crates linked into the executable`,
  "",
  `${crates.length} crates. Each line gives the crate, its declared license and the license texts it ships;`,
  "the texts follow once each, numbered. UI packages and fonts are in THIRD_PARTY_NOTICES.md.",
  "",
  "== Crates ==",
  ...crates.map((entry) => `${entry.name} ${entry.version} — ${entry.license ?? `see ${path.basename(entry.license_file)}`}` +
    (entry.repository ? ` — ${entry.repository}` : "") +
    (entry.licenseTexts.length > 0 ? ` — texts ${entry.licenseTexts.map((key) => `#${numberOf.get(key)}`).join(", ")}` : " — ships no license file")),
  "",
];
if (withoutFiles.length > 0) {
  lines.push("== Crates that ship no license file (for review) ==",
    "These crates declare the license below but include no license text; the standard text of",
    "each named license appears among the texts below, shipped by other crates.",
    ...withoutFiles.map((entry) => `${entry.name} ${entry.version} — ${entry.license} — authors: ${(entry.authors ?? []).join("; ") || "not declared"}` +
      (entry.repository ? ` — ${entry.repository}` : "")),
    "");
}
for (const entry of numbered) {
  lines.push(`== License text #${entry.number} ==`, `Shipped by: ${entry.users.join(", ")}`, "", entry.text, "");
}
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(licensesPath, `${lines.join("\n")}\n`, { flag: "wx" });

// SBOM.cdx.json
const licenseField = (expression) => (/\s(?:OR|AND|WITH)\s|\//u.test(expression)
  ? [{ expression: expression.replace(/\s*\/\s*/gu, " OR ") }]
  : [{ license: { id: expression } }]);
const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: { type: "application", "bom-ref": "lovelyhawk", name: "LovelyHawk", version, licenses: [{ license: { id: "AGPL-3.0-only" } }] },
    properties: [{ name: "lovelyhawk:target", value: target }],
  },
  components: [
    ...crates.map((entry) => ({
      type: "library",
      "bom-ref": `pkg:cargo/${entry.name}@${entry.version}`,
      name: entry.name,
      version: entry.version,
      purl: `pkg:cargo/${entry.name}@${entry.version}`,
      licenses: licenseField(entry.license ?? "LicenseRef-see-license-file"),
    })),
    ...[...npm.values()].sort((a, b) => a.name.localeCompare(b.name)).map((entry) => ({
      type: "library",
      "bom-ref": `pkg:npm/${entry.name}@${entry.version}`,
      name: entry.name,
      version: entry.version,
      purl: `pkg:npm/${entry.name.replace(/^@/u, "%40")}@${entry.version}`,
      licenses: licenseField(entry.license),
    })),
    ...assets.map((entry) => ({
      type: "file",
      "bom-ref": `file:${entry.file}`,
      name: entry.file,
      hashes: [{ alg: "SHA-256", content: entry.hash }],
      licenses: licenseField(entry.license),
    })),
  ],
};
fs.writeFileSync(sbomPath, `${JSON.stringify(bom, null, 2)}\n`, { flag: "wx" });
console.log(`Third-party inventory written: ${crates.length} crates (${numbered.length} distinct license texts, ${withoutFiles.length} without a shipped file), ${npm.size} UI packages, ${assets.length} assets.`);
