import { describe, expect, it } from "vitest";

import type {
  DockerContainerSnapshot,
  DockerImagesCollection,
  DockerLogs,
  DockerNetworksCollection,
  DockerReadInspection,
} from "../shared/docker-read-contract";
import { createDockerReadState, dockerReadReducer } from "./docker-read-state";

const snapshot: DockerContainerSnapshot = {
  snapshotHandle: "snapshot-a",
  expiresInSeconds: 300,
  containers: [{
    containerHandle: "container-a", shortId: "aaaaaaaaaaaa",
    name: "app",
    image: "app:1",
    state: "running",
    status: "Up",
    ports: "",
    createdAt: "now",
  }, {
    containerHandle: "container-b", shortId: "aaaaaaaaaaaa",
    name: "worker",
    image: "worker:1",
    state: "running",
    status: "Up",
    ports: "",
    createdAt: "now",
  }],
  truncated: false,
  runtime: "docker",
  installedRuntimes: ["docker"],
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

  /**
   * Loading a list is not choosing something from it.
   *
   * This used to select the first container, which was invisible while the
   * details were a column parked beside the table. Once they became a dialog
   * it meant arriving at the page with a modal already covering the very list
   * you came to read.
   */
  it("selects nothing when a snapshot arrives", () => {
    const state = loadedState();
    expect(state.snapshot?.containers.length).toBeGreaterThan(0);
    expect(state.selectedContainerHandle).toBeNull();
    expect(state.selectedNetworkHandle).toBeNull();
    expect(state.selectedVolumeHandle).toBeNull();
    // And a refresh does not quietly select one either.
    const refreshed = dockerReadReducer(
      dockerReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 9 }),
      { type: "snapshot-loaded", scope: "scope-a", request: 9, snapshot },
    );
    expect(refreshed.selectedContainerHandle).toBeNull();
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
    expect(state.collections.networks).toBe(networks);
    // A loaded list selects nothing. Details are a dialog, so selecting the
    // first row on arrival threw a modal over the list the operator came to
    // read, about a resource they never picked.
    expect(state.selectedNetworkHandle).toBeNull();
    state = dockerReadReducer(state, { type: "network-selected", handle: "network-a" });
    expect(state.selectedNetworkHandle).toBe("network-a");
  });

  it("opens no image detail until an image is picked", () => {
    let state = loadedState();
    const images: DockerImagesCollection = {
      kind: "images",
      snapshotHandle: "snapshot-a",
      items: [{
        imageHandle: "image-a", shortId: "abc123abc123", repository: "incident-tools",
        tag: "latest", digest: "<none>", createdAt: "now", size: "12MB",
      }],
      truncated: false,
    };
    state = dockerReadReducer(state, {
      type: "collection-started", scope: "scope-a", snapshotHandle: "snapshot-a", kind: "images", request: 2,
    });
    state = dockerReadReducer(state, {
      type: "collection-loaded", scope: "scope-a", snapshotHandle: "snapshot-a", kind: "images", request: 2, collection: images,
    });
    expect(state.selectedImageHandle).toBeNull();
    // A handle the listing never carried names nothing.
    state = dockerReadReducer(state, { type: "image-selected", handle: "image-b" });
    expect(state.selectedImageHandle).toBeNull();
    state = dockerReadReducer(state, { type: "image-selected", handle: "image-a" });
    expect(state.selectedImageHandle).toBe("image-a");
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
