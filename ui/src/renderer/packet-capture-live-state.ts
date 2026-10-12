import type {
  PacketCaptureInterfaceList,
  PacketCapturePacketEvent,
  PacketCapturePoll,
  PacketCaptureStarted,
} from "../shared/packet-capture-live-contract";
import {
  MAX_RENDERED_PACKETS,
  boundPacketCaptureText,
  type PacketCaptureForm,
} from "./packet-capture-live-helpers";

export type PacketCaptureLoadStatus = "idle" | "loading" | "ready" | "error";
export type PacketCaptureUiStatus =
  | "idle"
  | "starting"
  | "running"
  | "stopping"
  | "stopped"
  | "failed";

export interface PacketCaptureLiveState {
  scope: string | null;
  interfacesStatus: PacketCaptureLoadStatus;
  interfacesRequest: number;
  interfaces: PacketCaptureInterfaceList | null;
  selectedInterfaceHandle: string | null;
  form: PacketCaptureForm;
  captureStatus: PacketCaptureUiStatus;
  captureRequest: number;
  captureHandle: string | null;
  startInterfaceHandle: string | null;
  pollRequest: number;
  pollAfterSequence: number;
  afterSequence: number;
  packets: PacketCapturePacketEvent[];
  selectedPacketSequence: number | null;
  totalPackets: number;
  totalBytes: number;
  droppedEvents: number;
  truncated: boolean;
  search: string;
  info: string | null;
  /** tcpdump's last line from the host in this capture, kept across polls. */
  lastTcpdumpLine: string | null;
  notice: string | null;
  error: string | null;
}

export type PacketCaptureLiveAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "deactivated"; scope: string | null }
  | { type: "interfaces-started"; scope: string; request: number }
  | {
      type: "interfaces-loaded";
      scope: string;
      request: number;
      interfaces: PacketCaptureInterfaceList;
    }
  | { type: "interfaces-failed"; scope: string; request: number; error: string }
  | { type: "interface-selected"; scope: string; handle: string }
  | { type: "filter-changed"; value: string }
  | { type: "packet-limit-changed"; value: string }
  | { type: "duration-changed"; value: string }
  | {
      type: "start-started";
      scope: string;
      request: number;
      interfaceHandle: string;
    }
  | {
      type: "start-loaded";
      scope: string;
      request: number;
      interfaceHandle: string;
      capture: PacketCaptureStarted;
    }
  | { type: "start-failed"; scope: string; request: number; error: string }
  | {
      type: "poll-started";
      scope: string;
      request: number;
      captureHandle: string;
      afterSequence: number;
    }
  | {
      type: "poll-loaded";
      scope: string;
      request: number;
      captureHandle: string;
      afterSequence: number;
      result: PacketCapturePoll;
    }
  | {
      type: "poll-failed";
      scope: string;
      request: number;
      captureHandle: string;
      error: string;
    }
  | { type: "stop-started"; scope: string; request: number; captureHandle: string }
  | { type: "capture-released"; scope: string; captureHandle: string; failed: boolean }
  | { type: "packet-selected"; sequence: number }
  | { type: "search-changed"; value: string }
  | { type: "notice-cleared" }
  /** Another kind of capture starts: the last live one's verdict is not its. */
  | { type: "earlier-result-cleared" };

export function createPacketCaptureLiveState(
  scope: string | null = null,
): PacketCaptureLiveState {
  return {
    scope,
    interfacesStatus: "idle",
    interfacesRequest: 0,
    interfaces: null,
    selectedInterfaceHandle: null,
    form: { filter: "", packetLimit: "5000", durationSeconds: "60" },
    captureStatus: "idle",
    captureRequest: 0,
    captureHandle: null,
    startInterfaceHandle: null,
    pollRequest: 0,
    pollAfterSequence: 0,
    afterSequence: 0,
    packets: [],
    selectedPacketSequence: null,
    totalPackets: 0,
    totalBytes: 0,
    droppedEvents: 0,
    truncated: false,
    search: "",
    info: null,
    lastTcpdumpLine: null,
    notice: null,
    error: null,
  };
}

export function packetCaptureLiveReducer(
  state: PacketCaptureLiveState,
  action: PacketCaptureLiveAction,
): PacketCaptureLiveState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : createPacketCaptureLiveState(action.scope);
    case "deactivated":
      return action.scope === state.scope ? createPacketCaptureLiveState(action.scope) : state;
    case "interfaces-started":
      if (action.scope !== state.scope || captureBusy(state)) return state;
      return {
        ...state,
        interfacesStatus: "loading",
        interfacesRequest: action.request,
        // A capture that failed keeps saying why; reloading the list is not an answer to it.
        error: state.captureStatus === "failed" ? state.error : null,
      };
    case "interfaces-loaded": {
      if (action.scope !== state.scope || action.request !== state.interfacesRequest ||
        state.interfacesStatus !== "loading") return state;
      // Each reload hands out new handles, so the card chosen before is found
      // again by its name; with none chosen, the first real network card,
      // not the loopback, which carries none of the traffic worth capturing.
      const listed = action.interfaces.interfaces;
      const chosenName = state.interfaces?.interfaces.find((item) =>
        item.interfaceHandle === state.selectedInterfaceHandle)?.name ?? null;
      const selected = (listed.find((item) => item.interfaceHandle === state.selectedInterfaceHandle) ??
        (chosenName === null ? undefined : listed.find((item) => item.name === chosenName)) ??
        listed.find((item) => item.name !== "lo") ?? listed[0])?.interfaceHandle ?? null;
      return {
        ...state,
        interfacesStatus: "ready",
        interfaces: action.interfaces,
        selectedInterfaceHandle: selected,
        error: state.captureStatus === "failed" ? state.error : null,
      };
    }
    case "interfaces-failed":
      if (action.scope !== state.scope || action.request !== state.interfacesRequest) return state;
      return {
        ...state,
        interfacesStatus: "error",
        interfaces: null,
        selectedInterfaceHandle: null,
        error: action.error,
      };
    case "interface-selected":
      if (action.scope !== state.scope || captureBusy(state) ||
        !state.interfaces?.interfaces.some((item) => item.interfaceHandle === action.handle)) {
        return state;
      }
      return { ...state, selectedInterfaceHandle: action.handle, error: null };
    case "filter-changed":
      if (captureBusy(state)) return state;
      return {
        ...state,
        form: { ...state.form, filter: boundPacketCaptureText(action.value, 2_048) },
        error: null,
      };
    case "packet-limit-changed":
      if (captureBusy(state)) return state;
      return {
        ...state,
        form: { ...state.form, packetLimit: action.value.slice(0, 6) },
        error: null,
      };
    case "duration-changed":
      if (captureBusy(state)) return state;
      return {
        ...state,
        form: { ...state.form, durationSeconds: action.value.slice(0, 3) },
        error: null,
      };
    case "start-started":
      if (action.scope !== state.scope || captureBusy(state) || state.captureHandle !== null ||
        action.interfaceHandle !== state.selectedInterfaceHandle) return state;
      return {
        ...state,
        captureStatus: "starting",
        captureRequest: action.request,
        startInterfaceHandle: action.interfaceHandle,
        error: null,
        notice: "正在开始实时抓包…",
      };
    case "start-loaded":
      if (action.scope !== state.scope || action.request !== state.captureRequest ||
        state.captureStatus !== "starting" ||
        action.interfaceHandle !== state.startInterfaceHandle ||
        action.interfaceHandle !== state.selectedInterfaceHandle) return state;
      return {
        ...state,
        captureStatus: "running",
        captureHandle: action.capture.captureHandle,
        startInterfaceHandle: null,
        afterSequence: 0,
        packets: [],
        selectedPacketSequence: null,
        totalPackets: 0,
        totalBytes: 0,
        droppedEvents: 0,
        truncated: false,
        info: "抓包通道已建立，等待数据…",
        lastTcpdumpLine: null,
        notice: "实时抓包已开始。",
        error: null,
      };
    case "start-failed":
      if (action.scope !== state.scope || action.request !== state.captureRequest ||
        state.captureStatus !== "starting") return state;
      return {
        ...state,
        captureStatus: "failed",
        startInterfaceHandle: null,
        notice: null,
        error: action.error,
      };
    case "poll-started":
      if (!matchesCapture(state, action) || action.afterSequence !== state.afterSequence ||
        state.captureStatus !== "running") return state;
      return {
        ...state,
        pollRequest: action.request,
        pollAfterSequence: action.afterSequence,
      };
    case "poll-loaded": {
      if (!matchesPoll(state, action) || action.result.captureHandle !== action.captureHandle ||
        (!action.result.cursorReset && action.result.events.some((event) =>
          event.sequence <= action.afterSequence))) return state;
      const incoming = action.result.events.filter(
        (event): event is PacketCapturePacketEvent => event.kind === "packet",
      );
      const packets = action.result.cursorReset
        ? incoming.slice(-MAX_RENDERED_PACKETS)
        : mergePackets(state.packets, incoming);
      const selectedPacketSequence = state.selectedPacketSequence !== null &&
        packets.some((packet) => packet.sequence === state.selectedPacketSequence)
        ? state.selectedPacketSequence
        : null;
      const lastEvent = action.result.events.at(-1);
      const latestInfo = [...action.result.events].reverse().find((event) =>
        event.kind === "info" || event.kind === "failed" || event.kind === "stopped");
      // tcpdump's own last words, kept when it fails: they are usually why
      // (a filter it cannot parse). Shown as its output, never as our reason.
      // It may have arrived in an earlier poll than the failure itself.
      const newestLine = [...action.result.events].reverse().find((event) => event.kind === "info");
      const lastTcpdumpLine = newestLine?.kind === "info" ? newestLine.message : state.lastTcpdumpLine;
      const failed = action.result.status === "failed";
      return {
        ...state,
        captureStatus: action.result.status,
        afterSequence: lastEvent?.sequence ?? state.afterSequence,
        packets,
        selectedPacketSequence,
        totalPackets: action.result.packets,
        totalBytes: action.result.bytes,
        droppedEvents: action.result.droppedEvents,
        truncated: action.result.truncated,
        lastTcpdumpLine,
        info: failed && lastTcpdumpLine !== null
          ? `tcpdump 在目标机上的输出：${lastTcpdumpLine}`
          : latestInfo?.kind === "info"
            ? latestInfo.message
            // The status badge and the release notice already say it stopped.
            : latestInfo?.kind === "stopped"
              ? null
              : state.info,
        // A machine that cannot capture said why before it tried, and that
        // sentence was chosen on this side rather than read off the target.
        // Everything else stays behind the boundary: the rest of what a capture
        // prints is tcpdump's own stderr, on a machine that may be compromised.
        error: failed
          ? (latestInfo?.kind === "failed" ? latestInfo.reason : null)
            ?? (lastTcpdumpLine !== null
              ? "实时抓包没能进行下去：tcpdump 以失败结束。下面是它在目标机上的原样输出，常见原因是抓包条件（BPF filter）写错了。"
              : "实时抓包失败了，具体原因留在目标机上没有带回来。")
          : null,
      };
    }
    case "poll-failed":
      if (!matchesCapture(state, action) || action.request !== state.pollRequest) return state;
      return { ...state, captureStatus: "failed", error: action.error };
    case "stop-started":
      if (!matchesCapture(state, action) || state.captureStatus === "stopping") return state;
      return {
        ...state,
        captureStatus: "stopping",
        captureRequest: action.request,
        notice: "正在停止实时抓包…",
        error: null,
      };
    case "capture-released":
      if (action.scope !== state.scope || action.captureHandle !== state.captureHandle) return state;
      return {
        ...state,
        captureHandle: null,
        captureStatus: action.failed ? "failed" : "stopped",
        notice: action.failed ? null : "实时抓包已停止并释放。",
        error: action.failed ? state.error ?? "停止抓包时目标已断开。" : null,
      };
    case "packet-selected":
      return state.packets.some((packet) => packet.sequence === action.sequence)
        ? { ...state, selectedPacketSequence: action.sequence }
        : state;
    case "search-changed":
      return { ...state, search: boundPacketCaptureText(action.value, 256) };
    case "notice-cleared":
      return state.notice === null ? state : { ...state, notice: null };
    case "earlier-result-cleared":
      if (captureBusy(state)) return state;
      return {
        ...state,
        captureStatus: state.captureStatus === "failed" ? "idle" : state.captureStatus,
        info: null,
        lastTcpdumpLine: null,
        notice: null,
        error: null,
      };
  }
}

function captureBusy(state: PacketCaptureLiveState): boolean {
  return state.captureHandle !== null || state.captureStatus === "starting" ||
    state.captureStatus === "stopping";
}

function matchesCapture(
  state: PacketCaptureLiveState,
  action: { scope: string; captureHandle: string },
): boolean {
  return action.scope === state.scope && action.captureHandle === state.captureHandle;
}

function matchesPoll(
  state: PacketCaptureLiveState,
  action: {
    scope: string;
    request: number;
    captureHandle: string;
    afterSequence: number;
  },
): boolean {
  return matchesCapture(state, action) && action.request === state.pollRequest &&
    action.afterSequence === state.pollAfterSequence;
}

function mergePackets(
  current: readonly PacketCapturePacketEvent[],
  incoming: readonly PacketCapturePacketEvent[],
): PacketCapturePacketEvent[] {
  const bySequence = new Map(current.map((packet) => [packet.sequence, packet]));
  for (const packet of incoming) bySequence.set(packet.sequence, packet);
  return [...bySequence.values()]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-MAX_RENDERED_PACKETS);
}
