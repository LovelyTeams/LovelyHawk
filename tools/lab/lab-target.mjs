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
 * The container-orchestration hosts, started by `pnpm lab:orchestration`.
 *
 * Kept apart from `SERVICE_PORTS` rather than appended to it: those are all
 * "one product with a deliberately bad configuration", and the connection
 * import labels the whole family that way. A Podman host filed as
 * "配置不合规 podman" would be wrong twice over — nothing is misconfigured on
 * it, and what it is for is not its configuration.
 */
export const ORCHESTRATION_PORTS = {
  // One host with its own Docker daemon; one with kubectl against the lab's
  // k3s cluster. Podman is here because most RHEL-family and domestic-distro
  // hosts have it and no docker at all, and the tool has to find that itself.
  docker: 2244, kubernetes: 2245, podman: 2246,
  // Both runtimes on one machine — the shape a real competition box has.
  "container-arena": 2247,
};

/**
 * One Ubuntu server with several services on it, the way a competition box
 * actually looks. Start here: it is one container to keep alive instead of
 * twenty-one, and every page has something to find on it.
 */
export const ARENA_PORT = 2250;

/**
 * The super arena: the ordinary arena and then some, on one host — a second
 * web server and an FTP server left open, more weak accounts and sudo, a
 * dangerous file capability, world-writable things on PATH, plaintext
 * credentials and tampered logs. One target that lights up every page.
 */
export const SUPER_PORT = 2251;

export function labTarget(which = process.env.LAB ?? "ubuntu") {
  const output = execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"],
    { encoding: "utf8" },
  );
  const address = output.split("\0").join("").trim().split(/\s+/u)[0];
  const port = which === "arena"
    ? ARENA_PORT
    : which === "super"
      ? SUPER_PORT
      : LAB_PORTS[which] ?? SERVICE_PORTS[which] ?? ORCHESTRATION_PORTS[which];
  if (port === undefined) {
    const known = [
      "arena",
      "super",
      ...Object.keys(LAB_PORTS),
      ...Object.keys(SERVICE_PORTS),
      ...Object.keys(ORCHESTRATION_PORTS),
    ].join(", ");
    throw new Error(`unknown lab: ${which} (have ${known})`);
  }
  return { host: address, port, username: "root", password: "LabRoot#2026" };
}
