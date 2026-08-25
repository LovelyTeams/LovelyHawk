// The WSL localhost relay drops connections intermittently, so the lab is
// reached on the VM's own address instead.
import { execFileSync } from "node:child_process";

export function labTarget() {
  const address = execFileSync("wsl.exe", ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"], {
    encoding: "utf8",
  }).replace(/\0/gu, "").trim().split(/\s+/u)[0];
  return { host: address, port: 2222, username: "root", password: "LabRoot#2026" };
}
