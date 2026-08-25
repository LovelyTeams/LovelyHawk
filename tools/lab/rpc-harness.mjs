// Drives the real sidecar over its newline-delimited JSON protocol so the
// investigation code can be exercised against a live Linux host without the
// window in the way.
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const PROTOCOL = "lovelyres-backend/v1";

export class Sidecar {
  #child;
  #buffer = "";
  #pending = new Map();
  #next = 0;
  stderr = [];

  constructor(binaryPath, dataRoot) {
    this.#child = spawn(binaryPath, ["--archive-root", dataRoot], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? "info" },
    });
    this.#child.stdout.setEncoding("utf8");
    this.#child.stderr.setEncoding("utf8");
    this.#child.stdout.on("data", (chunk) => this.#consume(chunk));
    this.#child.stderr.on("data", (chunk) => this.stderr.push(chunk));
  }

  #consume(chunk) {
    this.#buffer += chunk;
    for (;;) {
      const newline = this.#buffer.indexOf("\n");
      if (newline < 0) return;
      const line = this.#buffer.slice(0, newline).replace(/\r$/u, "");
      this.#buffer = this.#buffer.slice(newline + 1);
      if (line.trim() === "") continue;
      let frame;
      try {
        frame = JSON.parse(line);
      } catch {
        continue;
      }
      const pending = this.#pending.get(frame.requestId);
      if (pending === undefined) continue;
      this.#pending.delete(frame.requestId);
      clearTimeout(pending.timer);
      if (frame.ok === true) pending.resolve(frame.result);
      else pending.reject(new Error(`${frame.error?.code ?? "error"}: ${frame.error?.message ?? line}`));
    }
  }

  call(method, params = {}, timeoutMs = 120_000) {
    const requestId = `req-${++this.#next}`;
    const encoded = JSON.stringify({ protocol: PROTOCOL, requestId, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(requestId);
        reject(new Error(`timeout: ${method}`));
      }, timeoutMs);
      this.#pending.set(requestId, { resolve, reject, timer });
      this.#child.stdin.write(`${encoded}\n`);
    });
  }

  close() {
    this.#child.kill();
  }
}

export function newDataRoot() {
  return mkdtempSync(path.join(tmpdir(), "lovelyres-lab-"));
}

export async function connect(sidecar, { host, port, username, password }, attempts = 6) {
  const connectionId = "11111111-1111-4111-8111-111111111111";
  try {
    await sidecar.call("connections.create", {
      connection: {
        id: connectionId, name: "lab-web", host, port, username,
        authMethod: "password", privateKeyPath: null, certificatePath: null,
        agentIdentityFingerprint: null, jumpHost: null, tags: [], notes: null,
        environment: null, role: null, group: null,
      },
      secrets: { password: { action: "replace", value: password } },
    });
  } catch {
    // Already created by an earlier attempt in this data root.
  }
  let last = null;
  // The WSL port forward settles a moment after the lab restarts, so a refused
  // attempt is retried rather than reported as the target being unreachable.
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const started = await sidecar.call("ssh.connect.start", { connectionId });
    let status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
    for (let step = 0; step < 80; step += 1) {
      if (status.hostKeyPrompt?.promptHandle !== undefined) {
        status = await sidecar.call("ssh.host-key.confirm", {
          attemptHandle: started.attemptHandle,
          promptHandle: status.hostKeyPrompt.promptHandle,
        });
        continue;
      }
      if (status.stage === "connected" || status.stage === "failed") break;
      await new Promise((resolve) => setTimeout(resolve, 400));
      status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
    }
    last = status;
    if (status.stage === "connected") return status;
    await new Promise((resolve) => setTimeout(resolve, 1200));
  }
  return last;
}
