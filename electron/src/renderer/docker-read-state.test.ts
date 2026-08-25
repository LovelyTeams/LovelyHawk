import { describe, expect, it } from "vitest";

import type {
  DockerContainerSnapshot,
  DockerLogs,
  DockerNetworksCollection,
  DockerReadInspection,
} from "../shared/docker-read-contract";
import { createDockerReadState, dockerReadReducer } from "./docker-read-state";

const snapshot: DockerContainerSnapshot = {
  snapshotHandle: "snapshot-a",
  expiresInSeconds: 300,
  containers: [{
    containerHandle: "container-a",
    name: "app",
    image: "app:1",
    state: "running",
    status: "Up",
    ports: "",
    createdAt: "now",
  }, {
    containerHandle: "container-b",
    name: "worker",
    image: "worker:1",
    state: "running",
    status: "Up",
    ports: "",
    createdAt: "now",
  }],
  truncated: false,
};

function loadedState() {
  let state = dockerReadReducer(createDockerReadState(), { type: "scope-changed", scope: "scope-a" });
  state = dockerReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 1 });
  return dockerReadReducer(state, { type: "snapshot-loaded", scope: "scope-a", request: 1, snapshot });
}

describe("Docker read reducer", () => {
  it("rejects a late snapshot after target scope changes", () => {
    let state = dockerReadReducer(createDockerReadState(), { type: "scope-changed", scope: "scope-a" });
    state = dockerReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 1 });
    state = dockerReadReducer(state, { type: "scope-changed", scope: "scope-b" });
    state = dockerReadReducer(state, { type: "snapshot-loaded", scope: "scope-a", request: 1, snapshot });
    expect(state.scope).toBe("scope-b");
    expect(state.snapshot).toBeNull();
  });

  it("refresh invalidates every prior resource, inspection, log and collection handle", () => {
    let state = loadedState();
    state = dockerReadReducer(state, {
      type: "logs-started", scope: "scope-a", snapshotHandle: "snapshot-a", handle: "container-a", request: 2,
    });
    state = dockerReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 3 });
    expect(state.snapshot).toBeNull();
    expect(state.collections).toEqual({});
    expect(state.selectedContainerHandle).toBeNull();
    expect(state.logsRequest).toBeNull();
    state = dockerReadReducer(state, {
      type: "logs-failed", scope: "scope-a", snapshotHandle: "snapshot-a", handle: "container-a", request: 2, error: "late",
    });
    expect(state.error).toBeNull();
  });

  it("binds collection responses to the current snapshot and request", () => {
    let state = loadedState();
    const networks: DockerNetworksCollection = {
      kind: "networks",
      snapshotHandle: "snapshot-a",
      items: [{ networkHandle: "network-a", name: "bridge", driver: "bridge", scope: "local", internal: false, ipv6: false }],
      truncated: false,
    };
    state = dockerReadReducer(state, {
      type: "collection-started", scope: "scope-a", snapshotHandle: "snapshot-a", kind: "networks", request: 2,
    });
    state = dockerReadReducer(state, {
      type: "collection-loaded", scope: "scope-a", snapshotHandle: "snapshot-old", kind: "networks", request: 2, collection: networks,
    });
    expect(state.collections.networks).toBeUndefined();
    state = dockerReadReducer(state, {
      type: "collection-loaded", scope: "scope-a", snapshotHandle: "snapshot-a", kind: "networks", request: 2, collection: networks,
    });
    expect(state.selectedNetworkHandle).toBe("network-a");
  });

  it("rejects late inspection after resource selection changes", () => {
    let state = loadedState();
    state = dockerReadReducer(state, {
      type: "inspection-started", scope: "scope-a", snapshotHandle: "snapshot-a", kind: "container", handle: "container-a", request: 2,
    });
    state = dockerReadReducer(state, { type: "container-selected", handle: "container-b" });
    const inspection: DockerReadInspection = {
      kind: "container",
      snapshotHandle: "snapshot-a",
      resourceHandle: "container-a",
      name: "old",
      fields: [],
      mounts: [],
      networks: [],
      truncated: false,
    };
    state = dockerReadReducer(state, {
      type: "inspection-loaded", scope: "scope-a", snapshotHandle: "snapshot-a", kind: "container", handle: "container-a", request: 2, inspection,
    });
    expect(state.inspection).toBeNull();
    expect(state.selectedContainerHandle).toBe("container-b");
  });

  it("rejects late logs after the selected container changes", () => {
    let state = loadedState();
    state = dockerReadReducer(state, {
      type: "logs-started", scope: "scope-a", snapshotHandle: "snapshot-a", handle: "container-a", request: 2,
    });
    state = dockerReadReducer(state, { type: "container-selected", handle: "container-b" });
    const logs: DockerLogs = {
      snapshotHandle: "snapshot-a",
      containerHandle: "container-a",
      tail: 200,
      text: "late output",
      truncated: false,
    };
    state = dockerReadReducer(state, {
      type: "logs-loaded", scope: "scope-a", snapshotHandle: "snapshot-a", handle: "container-a", request: 2, logs,
    });
    expect(state.logs).toBeNull();
    expect(state.logsStatus).toBe("idle");
    expect(state.selectedContainerHandle).toBe("container-b");
  });

  it("keeps filter state local without treating hostile text as control data", () => {
    let state = loadedState();
    state = dockerReadReducer(state, { type: "filter-changed", filter: "</input><script>x()</script>" });
    expect(state.filter).toBe("</input><script>x()</script>");
    expect(state.snapshot?.snapshotHandle).toBe("snapshot-a");
  });
});
