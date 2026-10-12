// A login on the Kubernetes lab client whose kubeconfig may only read one
// namespace: pods, their logs and deployments, nothing else — no pods/exec,
// no namespace list, no writes. Shared by the RPC and desktop probes.
//
// Everything lives in a namespace the run creates, labelled with the run's
// id, on the lab's k3s cluster, plus one login account on svc-kubernetes whose
// name carries the run's id. `remove()` deletes both after that label and
// name are checked, and reports what it could not do.
import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";

/** A shell on the lab client host as root: the independent look, and the setup. */
export function onClient(script, input) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "-i", "svc-kubernetes", "sh", "-c", script], {
    encoding: "utf8", windowsHide: true, timeout: 120_000, input,
  });
}

/** kubectl as the cluster admin on the lab client host. */
export function labKubectl(args, input) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "-i", "svc-kubernetes", "kubectl", ...args], {
    encoding: "utf8", windowsHide: true, timeout: 120_000, input,
  });
}

function inspect(name) {
  return JSON.parse(execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "inspect", name], {
    encoding: "utf8", windowsHide: true,
  }))[0];
}

/** Refuses to touch anything that is not the isolated Kubernetes lab pair. */
export function assertKubernetesLab() {
  const client = inspect("svc-kubernetes");
  const server = inspect("lab-k3s");
  if (client.Config.Image !== "lovelyres-svc:kubernetes" || client.HostConfig.Privileged ||
    client.Mounts.length !== 1 || client.Mounts[0].Name !== "lab-k3s-config" || client.Mounts[0].RW ||
    server.Config.Image !== "docker.m.daocloud.io/rancher/k3s:v1.31.4-k3s1" ||
    !server.Mounts.some((mount) => mount.Name === "lab-k3s-config")) {
    throw new Error("svc-kubernetes / lab-k3s are not the isolated Kubernetes lab; nothing was changed");
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function createRestrictedAccount(prefix = "lh-rbac") {
  assertKubernetesLab();
  const runId = randomUUID();
  const short = runId.slice(0, 8);
  const namespace = `${prefix}-${short}`;
  const login = `lhrbac${short}`;
  const password = `Lab-${randomBytes(9).toString("base64url")}`;
  const labels = { "lovelyres-test-run": runId };
  const manifest = {
    apiVersion: "v1", kind: "List",
    items: [
      { apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, labels } },
      {
        apiVersion: "apps/v1", kind: "Deployment",
        metadata: { name: "web", namespace, labels },
        spec: {
          replicas: 1,
          selector: { matchLabels: { app: "web" } },
          template: {
            metadata: { labels: { app: "web", ...labels } },
            spec: {
              terminationGracePeriodSeconds: 1,
              containers: [{
                name: "web", image: "alpine:3.20", imagePullPolicy: "IfNotPresent",
                command: ["sh", "-c", "echo rbac-lab > /tmp/marker; while true; do echo rbac-tick; sleep 2; done"],
                resources: { limits: { cpu: "50m", memory: "16Mi" } },
              }],
            },
          },
        },
      },
      { apiVersion: "v1", kind: "ServiceAccount", metadata: { name: "viewer", namespace, labels } },
      {
        // Reading only: no pods/exec, no namespaces, no writes to deployments.
        apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role",
        metadata: { name: "viewer", namespace, labels },
        rules: [
          { apiGroups: [""], resources: ["pods", "pods/log", "events"], verbs: ["get", "list", "watch"] },
          { apiGroups: ["apps"], resources: ["deployments", "replicasets"], verbs: ["get", "list", "watch"] },
        ],
      },
      {
        apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding",
        metadata: { name: "viewer", namespace, labels },
        roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: "viewer" },
        subjects: [{ kind: "ServiceAccount", name: "viewer", namespace }],
      },
    ],
  };

  let accountMade = false;
  const remove = () => {
    const problems = [];
    try {
      const label = labKubectl(["get", "namespace", namespace, "-o", "jsonpath={.metadata.labels.lovelyres-test-run}"]).trim();
      if (label === runId) {
        labKubectl(["delete", "namespace", namespace, "--wait=true", "--timeout=120s"]);
      } else {
        problems.push(`命名空间 ${namespace} 的标记不是本次的，没有删除`);
      }
    } catch (error) {
      problems.push(`命名空间清理没有完成：${error.message}`);
    }
    if (accountMade) {
      try {
        // Only this run's account; its processes first, so userdel does not refuse.
        onClient(`pkill -KILL -u '${login}' || true; userdel -r '${login}' 2>/dev/null; ! id '${login}' >/dev/null 2>&1`);
      } catch (error) {
        problems.push(`登录账号清理没有完成：${error.message}`);
      }
    }
    return problems;
  };

  try {
    labKubectl(["apply", "-f", "-"], JSON.stringify(manifest));
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const ready = labKubectl(["get", "deployment", "web", "-n", namespace, "-o", "jsonpath={.status.readyReplicas}"]).trim();
      if (ready === "1") break;
      await sleep(2_000);
    }
    const token = labKubectl(["create", "token", "viewer", "-n", namespace, "--duration=30m"]).trim();
    const cluster = JSON.parse(labKubectl(["config", "view", "--raw", "--minify", "-o", "json"]));
    const kubeconfig = {
      apiVersion: "v1", kind: "Config",
      clusters: [{ name: "lab", cluster: cluster.clusters[0].cluster }],
      users: [{ name: "viewer", user: { token } }],
      contexts: [{ name: "viewer@lab", context: { cluster: "lab", user: "viewer", namespace } }],
      "current-context": "viewer@lab",
    };
    // The name is this run's and is checked to be unused, so nothing existing is touched.
    onClient(`set -e; ! id '${login}' >/dev/null 2>&1; useradd -m -s /bin/bash '${login}'; ` +
      `chpasswd; install -d -m 0700 -o '${login}' -g '${login}' '/home/${login}/.kube'`,
      `${login}:${password}\n`);
    accountMade = true;
    onClient(`umask 077; cat > '/home/${login}/.kube/config'; chown '${login}:${login}' '/home/${login}/.kube/config'`,
      JSON.stringify(kubeconfig));
  } catch (error) {
    const problems = remove();
    throw new Error(`${error.message}${problems.length > 0 ? `；${problems.join("；")}` : ""}`);
  }

  /** What the account itself may do, asked of the API server as that account. */
  const canI = () => onClient(`su - '${login}' -c 'kubectl auth can-i create pods/exec; kubectl auth can-i list namespaces; ` +
    `kubectl auth can-i list pods; kubectl auth can-i list pods -A' 2>/dev/null || true`)
    .split(/\s+/u).filter(Boolean).join(",");

  return { runId, namespace, login, password, canI, remove };
}
