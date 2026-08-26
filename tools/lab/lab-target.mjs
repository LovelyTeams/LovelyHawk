// The WSL localhost relay drops connections intermittently, so the lab hosts
// are reached on the VM's own address instead.
import { execFileSync } from "node:child_process";

export const LAB_PORTS = {
  ubuntu: 2222, alpine: 2223, debian: 2224, rocky: 2225, alma: 2226,
  openeuler: 2227, anolis: 2228, deepin: 2229, suse: 2230,
};

/** The service hosts: one product per host, each with a bad configuration. */
export const SERVICE_PORTS = {
  nginx: 2231, httpd: 2232, tomcat: 2233, mysql: 2234, mariadb: 2235,
  postgres: 2236, redis: 2237, mongo: 2238, opengauss: 2239, tidb: 2240,
  "baseline-deb": 2241, "baseline-el": 2242, haproxy: 2243,
};

/**
 * One Ubuntu server with several services on it, the way a competition box
 * actually looks. Start here: it is one container to keep alive instead of
 * twenty-one, and every page has something to find on it.
 */
export const ARENA_PORT = 2250;

export function labTarget(which = process.env.LAB ?? "ubuntu") {
  const output = execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"],
    { encoding: "utf8" },
  );
  const address = output.split("\0").join("").trim().split(/\s+/u)[0];
  const port = which === "arena" ? ARENA_PORT : LAB_PORTS[which] ?? SERVICE_PORTS[which];
  if (port === undefined) {
    const known = ["arena", ...Object.keys(LAB_PORTS), ...Object.keys(SERVICE_PORTS)].join(", ");
    throw new Error(`unknown lab: ${which} (have ${known})`);
  }
  return { host: address, port, username: "root", password: "LabRoot#2026" };
}
