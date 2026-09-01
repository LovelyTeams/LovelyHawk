// Opens a real image's detail and checks it against what the daemon itself
// says, plus against what the lab deliberately baked into that image.
//
// The point of reading an image is to answer three questions a listing cannot:
// what will it run, as whom, and what got put in it along the way. Each of
// those is checked against ground truth read straight off the host, so "it
// matches" is never the tool agreeing with itself.
//
//   node tools/lab/probe-docker-image.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, backendBinary, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

let failures = 0;
function check(label, actual, expected) {
  const ok = typeof expected === "function" ? expected(actual) : actual === expected;
  if (!ok) failures += 1;
  const shown = typeof actual === "string" && actual.length > 90
    ? `${actual.slice(0, 90)}…`
    : String(actual);
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : ` —— 实际 ${shown}`}`);
  return ok;
}

const target = labTarget("docker");
const sidecar = new Sidecar(backendBinary(), newDataRoot());

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc",
      `docker exec svc-docker sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

try {
  console.log(`连接 ${target.host}:${target.port}\n`);
  const status = await connect(sidecar, target);
  const binding = status.bindingHandle;
  const snapshot = await sidecar.call("docker.containers.refresh", { bindingHandle: binding }, 90_000);

  console.log("=== 镜像清单");
  const images = await sidecar.call("docker.collection.get", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    kind: "images",
  }, 90_000);
  const rows = images.items ?? [];
  console.log(`  ${rows.length} 个：${rows.map((row) => `${row.repository}:${row.tag}`).slice(0, 6).join(" ")}`);
  check("镜像读到了", rows.length, (value) => value >= 2);
  check("每个镜像都有句柄", rows.every((row) => typeof row.imageHandle === "string" && row.imageHandle.length > 0), true);
  check("短 id 就是 12 位", rows.every((row) => /^[0-9a-f]{12}$/u.test(row.shortId)), true);

  // The short ids the runtime prints for itself. If ours disagree, ours are
  // not the ids anybody on that host would recognise.
  const hostShortIds = new Set(onHost("docker image ls --format '{{.ID}}'").split("\n").map((line) => line.trim()).filter(Boolean));
  check("短 id 和主机上 docker image ls 打的一致",
    rows.every((row) => hostShortIds.has(row.shortId)), true);

  // The invariant is that nothing addressable crosses as an id — not that no
  // sha256 does.
  //
  // Three fields are content digests, and they stay: layers and repo digests
  // are what an operator compares against a registry when an image looks
  // tampered with, and that is the reason to open this page at all. On a host
  // that pulled through a mirror the runtime prints a repo digest that is
  // textually equal to the image id, so they are excluded by name rather than
  // by shape — a check on "contains sha256" would either pass vacuously or
  // demand deleting the useful fields.
  const fullIds = onHost("docker image ls --no-trunc --format '{{.ID}}'")
    .split("\n").map((line) => line.trim()).filter(Boolean);
  const withoutDigests = (value) => JSON.stringify(value, (key, item) =>
    key === "digest" || key === "repoDigests" || key === "layers" ? undefined : item);
  const listing = withoutDigests(rows);
  check("摘要之外的字段没有带出完整 id", fullIds.some((id) => listing.includes(id)), false);

  // --- incident-tools:latest is the one plant.sh builds, so its Dockerfile is
  // known and the build steps are checkable rather than whatever a registry
  // happened to ship.
  console.log("\n=== 自建镜像的详情（incident-tools:latest）");
  const built = rows.find((row) => row.repository === "incident-tools");
  if (built === undefined) {
    failures += 1;
    console.log("  ✗ 找不到 incident-tools —— 靶机没按预期建镜像");
  } else {
    const detail = await sidecar.call("docker.resource.inspect", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      kind: "image",
      resourceHandle: built.imageHandle,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (detail.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ 详情读取失败 —— ${detail.failed}`);
    } else {
      console.log(`  平台 ${detail.os}/${detail.architecture} · 启动 ${[...detail.entrypoint, ...detail.command].join(" ")}`);
      check("是这个镜像，不是别的", detail.shortId, built.shortId);
      check("平台读到了", `${detail.os}/${detail.architecture}`, (value) => value.startsWith("linux/"));
      check("运行身份说清了", detail.user, (value) => (value ?? "") !== "");

      // Ground truth for the startup line, straight from the daemon.
      const hostStartup = onHost(
        `docker image inspect --format '{{join .Config.Entrypoint " "}}|{{join .Config.Cmd " "}}' ${built.shortId}`,
      );
      const [hostEntrypoint, hostCommand] = hostStartup.split("|");
      check("入口点和主机一致", detail.entrypoint.join(" "), hostEntrypoint);
      check("默认命令和主机一致", detail.command.join(" "), hostCommand);

      console.log(`  构建步骤 ${detail.history.length} 步`);
      check("构建步骤读到了", detail.history.length, (value) => value >= 1);
      check("构建指令不是空的",
        detail.history.some((step) => (step.createdBy ?? "").length > 0), true);
      // A pulled base layer has no local id, and the runtime says so rather
      // than inventing one; the field is text, so it survives either way.
      check("每一步都有大小",
        detail.history.every((step) => typeof step.size === "string"), true);
      // Same rule as the listing: everything but the three digest fields.
      const body = withoutDigests(detail);
      check("摘要之外的字段没有带出完整 id", fullIds.some((id) => body.includes(id)), false);
      check("句柄没有回流到正文",
        JSON.stringify(detail).split(built.imageHandle).length - 1, 1);
    }
  }

  // --- The base image everything else is built on, pulled rather than built:
  // it exercises the branch where history is thin and tags come from a
  // registry.
  console.log("\n=== 拉下来的镜像的详情（alpine）");
  const pulled = rows.find((row) => row.repository === "alpine");
  if (pulled === undefined) {
    failures += 1;
    console.log("  ✗ 找不到 alpine");
  } else {
    const detail = await sidecar.call("docker.resource.inspect", {
      bindingHandle: binding,
      snapshotHandle: snapshot.snapshotHandle,
      kind: "image",
      resourceHandle: pulled.imageHandle,
    }, 90_000).catch((error) => ({ failed: error.message }));
    if (detail.failed !== undefined) {
      failures += 1;
      console.log(`  ✗ 详情读取失败 —— ${detail.failed}`);
    } else {
      console.log(`  标签 ${detail.repoTags.join("、") || "（无）"} · 层 ${detail.layers.length}`);
      check("是 alpine，不是别的", detail.shortId, pulled.shortId);
      check("仓库标签读到了", detail.repoTags.some((tag) => tag.startsWith("alpine:")), true);
      check("层读到了", detail.layers.length, (value) => value >= 1);
      // An image that never set a user runs as root, and the page has to say
      // which of the two it is rather than leaving the field blank.
      const hostUser = onHost(`docker image inspect --format '{{.Config.User}}' ${pulled.shortId}`);
      if (hostUser === "") check("没设用户的镜像被说成 root", detail.user, (value) => value.startsWith("root"));
      else check("用户和主机一致", detail.user, hostUser);
    }
  }

  // --- 伪造的句柄
  console.log("\n=== 伪造的镜像句柄");
  const forged = await sidecar.call("docker.resource.inspect", {
    bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle,
    kind: "image",
    resourceHandle: "00000000-0000-4000-8000-000000000000",
  }, 30_000).then(() => null).catch((error) => error.message);
  check("认不出来", forged, (value) => typeof value === "string");
  if (typeof forged === "string") console.log(`  ${forged.slice(0, 80)}`);
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\n全部对上了" : `\n${failures} 处对不上`);
process.exit(failures === 0 ? 0 : 1);
