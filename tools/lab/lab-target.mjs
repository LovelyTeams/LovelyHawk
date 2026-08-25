// The WSL localhost relay drops connections intermittently, so the lab hosts
// are reached on the VM's own address instead.
import { execFileSync } from "node:child_process";

export const LAB_PORTS = {
  ubuntu: 2222, alpine: 2223, debian: 2224, rocky: 2225, alma: 2226,
  openeuler: 2227, anolis: 2228, deepin: 2229, suse: 2230,
};

export function labTarget(which = process.env.LAB ?? "ubuntu") {
  const output = execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"],
    { encoding: "utf8" },
  );
  const address = output.split("\0").join("").trim().split(/\s+/u)[0];
  const port = LAB_PORTS[which];
  if (port === undefined) {
    throw new Error(`unknown lab: ${which} (have ${Object.keys(LAB_PORTS).join(", ")})`);
  }
  return { host: address, port, username: "root", password: "LabRoot#2026" };
}
