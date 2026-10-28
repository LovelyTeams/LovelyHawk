// Asks a machine that cannot capture packets to say why.
//
// The live capture command ends `2>&1`, so its own preflight complaints arrive
// on the same stream as the packets. "tcpdump unavailable" was parsed as one:
// protocol OTHER, empty source and destination, sitting in the packet list
// while the capture reported itself running. An operator then watched an empty
// table on a machine that was never going to produce a packet.
//
// None of the lab containers has tcpdump, which is what makes them the right
// place to check.
//
//   node tools/lab/probe-packet-capture.mjs
//   LAB=rocky node tools/lab/probe-packet-capture.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = ["docker", "kubernetes", "podman"].includes(which)
  ? `svc-${which}`
  : `lab-${which}`;

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  const hasTcpdump = onHost("command -v tcpdump >/dev/null 2>&1 && echo yes || echo no") === "yes";
  console.log(`  ${which}: 机器上${hasTcpdump ? "有" : "没有"} tcpdump`);

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  // Listing interfaces reads `ip`, not tcpdump, so it works either way — and a
  // capture has to be offered before the machine can say it cannot do one.
  const list = await sidecar.call(
    "packet-capture.interfaces.list",
    { bindingHandle: binding },
    120_000,
  );
  console.log(`  网卡 ${list.interfaces.length} 个：${list.interfaces.map((i) => i.name).join(" ")}`);
  check("列得出网卡", list.interfaces.length > 0);
  // Not the loopback: this probe's own SSH session is the traffic, and it
  // travels over the machine's real interface. Capturing `lo` on an idle
  // container would prove only that nothing crashed.
  const chosen = list.interfaces.find((entry) => entry.name !== "lo") ?? list.interfaces[0];
  console.log(`  抓 ${chosen.name}`);

  const started = await sidecar.call("packet-capture.start", {
    bindingHandle: binding,
    snapshotHandle: list.snapshotHandle,
    interfaceHandle: chosen.interfaceHandle,
    input: { filter: null, packetLimit: 5, durationSeconds: 5 },
  }, 120_000);
  check("能发起一次抓包", typeof started.captureHandle, "string");

  // On a machine that can capture, give it something to capture: an idle
  // container produces no traffic, and "it did not fail" is a much weaker
  // statement than "it saw the packets I made".
  if (hasTcpdump) {
    // The poll below travels over SSH to this very machine, so the capture has
    // something to see without needing a tool the container may not have —
    // these images have no `ping`, and the first version of this check passed
    // an empty capture off as a working one.
    await sidecar.call("packet-capture.poll", {
      bindingHandle: binding, captureHandle: started.captureHandle, afterSequence: 0,
    }, 120_000);
  }
  // Long enough for the preflight line to come back on a slow machine.
  await sleep(6_000);
  const polled = await sidecar.call("packet-capture.poll", {
    bindingHandle: binding,
    captureHandle: started.captureHandle,
    afterSequence: 0,
  }, 120_000);
  const failed = polled.events.find((event) => event.kind === "failed");
  const packets = polled.events.filter((event) => event.kind === "packet");
  console.log(`  状态 ${polled.status} · 事件 ${polled.events.map((e) => e.kind).join(",")}`);

  if (hasTcpdump) {
    check("有 tcpdump 时不该报预检失败", failed?.reason ?? null, null);
    console.log(`  抓到 ${polled.packets} 个包`);
    // The extra poll above is the traffic. If none of it reached the table then
    // the capture ran without capturing, which looks the same as success from
    // the outside.
    check("真的抓到了刚才制造的流量", polled.packets > 0);
    check("包也真的进了列表", packets.length > 0);
  } else {
    check("说清楚这次为什么抓不了", failed?.reason?.includes("没有 tcpdump"), true);
    check("并且把状态标成失败，而不是继续显示在采集", polled.status, "failed");
    // The line used to arrive as a packet: protocol OTHER, no source, no
    // destination, sitting in the table an operator reads for evidence.
    check("不把这句话伪装成一个数据包", packets.length, 0);
    check("也不混进包计数里", polled.packets, 0);
    for (const packet of packets) {
      check(`包列表里不该出现 ${JSON.stringify(packet.raw ?? "")}`, false);
    }
  }

  const stopped = await sidecar.call("packet-capture.stop", {
    bindingHandle: binding,
    captureHandle: started.captureHandle,
  }, 120_000);
  check("停得下来", stopped.stopped, true);

  // Leaving a capture running on a machine under investigation is its own
  // incident: it keeps writing, keeps CPU, and is a process the responder did
  // not mean to leave behind. Three ways out, all of which really happen.
  if (hasTcpdump) {
    const running = () => Number(onHost("ps -eo args= | grep -c '[t]cpdump' || true"));
    check("正常停止之后远端没有留下抓包进程", running(), 0);

    // Each of these leaves a capture behind on purpose. The duration is far
    // longer than the check, so anything still alive afterwards is a leak
    // rather than a capture that simply ran out on its own.
    const leaveOneRunning = async () => {
      await sidecar.call("packet-capture.start", {
        bindingHandle: binding,
        snapshotHandle: list.snapshotHandle,
        interfaceHandle: chosen.interfaceHandle,
        input: { filter: null, packetLimit: null, durationSeconds: 120 },
      }, 120_000);
      await sleep(2_500);
    };

    // The case nobody can send a signal for: the network drops and the machine
    // never hears that anyone wanted it to stop. What protects against that is
    // the capture's own `timeout` — so check the capture really does end on its
    // own, with nothing at all telling it to.
    const shortLived = await sidecar.call("packet-capture.start", {
      bindingHandle: binding,
      snapshotHandle: list.snapshotHandle,
      interfaceHandle: chosen.interfaceHandle,
      input: { filter: null, packetLimit: null, durationSeconds: 5 },
    }, 120_000);
    await sleep(2_000);
    check("到时限之前还在抓", running() > 0);
    await sleep(12_000);
    check("到了时限自己就停了，不用谁去通知它", running(), 0);

    // Draining matters: one poll returns at most a hundred events, so the
    // terminal one can still be queued behind a busy interface's packets and
    // the capture would look like it was running long after it had ended.
    let after = 0;
    let drained;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      drained = await sidecar.call("packet-capture.poll", {
        bindingHandle: binding, captureHandle: shortLived.captureHandle, afterSequence: after,
      }, 120_000);
      after = drained.latestSequence ?? after;
      if (!drained.hasMore) break;
    }
    check("读完事件之后状态就是已停止", drained?.status, "stopped");
    // And a capture that has ended must not be what stops the next one.
    const next = await sidecar.call("packet-capture.start", {
      bindingHandle: binding,
      snapshotHandle: list.snapshotHandle,
      interfaceHandle: chosen.interfaceHandle,
      input: { filter: null, packetLimit: null, durationSeconds: 5 },
    }, 120_000).catch((error) => ({ error: String(error.message).slice(0, 120) }));
    check("上一次自然结束后还能再开一次", typeof next.captureHandle, "string");
    if (next.captureHandle !== undefined) {
      // While one really is running, the refusal has to say *that* — not the
      // old shared "capacity reached", which read as "the tool is full" to an
      // operator whose only problem was a capture they could simply stop.
      const refused = await sidecar.call("packet-capture.start", {
        bindingHandle: binding,
        snapshotHandle: list.snapshotHandle,
        interfaceHandle: chosen.interfaceHandle,
        input: { filter: null, packetLimit: null, durationSeconds: 5 },
      }, 120_000).catch((error) => ({ error: String(error.message) }));
      console.log(`  已经在抓时再开一次 → ${JSON.stringify(refused.error ?? refused).slice(0, 90)}`);
      check("已经在抓时，拒绝的理由说的是这件事",
        refused.error?.includes("packet-capture-already-running"), true);
      check("不再是笼统的『已达上限』", refused.error?.includes("packet-capture-capacity"), false);

      await sidecar.call("packet-capture.stop", {
        bindingHandle: binding, captureHandle: next.captureHandle,
      }, 60_000);
    }

    await leaveOneRunning();
    check("断开连接前确实在抓", running() > 0);
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: binding }, 60_000);
    await sleep(4_000);
    check("主动断开之后远端没有留下抓包进程", running(), 0);

    // The harshest exit: the sidecar goes away without telling anyone, which is
    // what a crashed or force-quit application looks like from the machine.
    // Nothing can run after this, so it goes last.
    const reconnected = await connect(sidecar, labTarget(which));
    if (reconnected.stage === "connected") {
      const second = await sidecar.call(
        "packet-capture.interfaces.list",
        { bindingHandle: reconnected.bindingHandle },
        120_000,
      );
      await sidecar.call("packet-capture.start", {
        bindingHandle: reconnected.bindingHandle,
        snapshotHandle: second.snapshotHandle,
        interfaceHandle: (second.interfaces.find((entry) => entry.name !== "lo")
          ?? second.interfaces[0]).interfaceHandle,
        input: { filter: null, packetLimit: null, durationSeconds: 120 },
      }, 120_000);
      await sleep(2_500);
      check("应用消失前确实在抓", running() > 0);
      sidecar.close();
      await sleep(4_000);
      check("应用直接消失之后远端也没有留下抓包进程", running(), 0);
    }
  }
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
