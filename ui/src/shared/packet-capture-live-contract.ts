export type PacketCaptureLiveStatus = "running" | "stopped" | "failed";

export interface PacketCaptureInterface {
  interfaceHandle: string;
  name: string;
  mac: string | null;
  addresses: string[];
  textTruncated: boolean;
}

export interface PacketCaptureInterfaceList {
  interfaces: PacketCaptureInterface[];
  displayed: number;
  truncated: boolean;
  expiresInSeconds: number;
}

export interface PacketCaptureStartInput {
  filter: string | null;
  packetLimit: number | null;
  durationSeconds: number;
}

export interface PacketCaptureStarted {
  captureHandle: string;
  status: "running";
  expiresInSeconds: number;
}

interface PacketCaptureEventBase {
  sequence: number;
  observedAt: string;
}

export interface PacketCaptureStartedEvent extends PacketCaptureEventBase {
  kind: "started";
}

export interface PacketCapturePacketEvent extends PacketCaptureEventBase {
  kind: "packet";
  timestamp: string;
  protocol: string;
  source: string;
  destination: string;
  length: string;
  info: string;
  raw: string;
  textTruncated: boolean;
}

export interface PacketCaptureInfoEvent extends PacketCaptureEventBase {
  kind: "info";
  message: string;
  textTruncated: boolean;
}

export interface PacketCaptureProgressEvent extends PacketCaptureEventBase {
  kind: "progress";
  packets: number;
  bytes: number;
  countersTruncated: boolean;
}

export interface PacketCaptureStoppedEvent extends PacketCaptureEventBase {
  kind: "stopped";
}

/**
 * Why a capture could not start, when the reason was one the tool itself knew.
 *
 * A capture's failure text is normally the target's own stderr and never
 * crosses. These few sentences are the exception: the core chose them from a
 * fixed list before the machine ran anything, so they are checked against that
 * list here too.
 */
export const PACKET_CAPTURE_FAILURE_REASONS = [
  "这台机器上没有 tcpdump，抓不了包。装上它再来，或者换一台机器抓。",
  "这台机器上没有 timeout 命令，没法给抓包设时限，所以没有开始。",
  "抓包要 root 或者能免密码的 sudo，这个账号两样都没有。换个账号连，或者给它配上 sudo。",
  "这个账号的 sudo 需要输密码，抓包用不了。给它配上免密码的 sudo 再试。",
] as const;
export type PacketCaptureFailureReason = (typeof PACKET_CAPTURE_FAILURE_REASONS)[number];

export interface PacketCaptureFailedEvent extends PacketCaptureEventBase {
  kind: "failed";
  code: "capture-failed";
  /** Null when the failure came from the machine rather than from this list. */
  reason: PacketCaptureFailureReason | null;
}

export type PacketCaptureLiveEvent =
  | PacketCaptureStartedEvent
  | PacketCapturePacketEvent
  | PacketCaptureInfoEvent
  | PacketCaptureProgressEvent
  | PacketCaptureStoppedEvent
  | PacketCaptureFailedEvent;

export interface PacketCapturePoll {
  captureHandle: string;
  status: PacketCaptureLiveStatus;
  oldestSequence: number;
  latestSequence: number;
  cursorReset: boolean;
  hasMore: boolean;
  truncated: boolean;
  droppedEvents: number;
  retainedPackets: number;
  packets: number;
  bytes: number;
  events: PacketCaptureLiveEvent[];
}

export interface PacketCaptureStopped {
  stopped: true;
}

export interface PacketCaptureLiveApi {
  listPacketCaptureInterfaces(bindingHandle: string): Promise<unknown>;
  startPacketCapture(
    bindingHandle: string,
    interfaceHandle: string,
    input: PacketCaptureStartInput,
  ): Promise<unknown>;
  pollPacketCapture(
    bindingHandle: string,
    captureHandle: string,
    afterSequence: number,
  ): Promise<unknown>;
  stopPacketCapture(bindingHandle: string, captureHandle: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const HANDLE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u001f]/u.test(value);
}

function unsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function jsonBytesAtMost(value: unknown, maximum: number): boolean {
  try {
    return encoder.encode(JSON.stringify(value)).byteLength <= maximum;
  } catch {
    return false;
  }
}

function observedAt(value: unknown): value is string {
  return text(value, 64, false) && !Number.isNaN(Date.parse(value));
}

/**
 * Bounded, control-character-free text. It does not judge the content: a
 * collected line that mentions a credential is the evidence, and refusing it
 * here would reject the whole response rather than one line.
 */
function publicText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return text(value, maximumBytes, allowEmpty);
}

function containsUriUserinfo(value: string): boolean {
  let remaining = value;
  for (;;) {
    const marker = remaining.indexOf("://");
    if (marker < 0) return false;
    remaining = remaining.slice(marker + 3);
    const authority = remaining.split(/[/?#\s]/u, 1)[0] ?? "";
    if (authority.includes("@")) return true;
  }
}

export function isPacketCaptureOpaqueHandle(value: unknown): value is string {
  return typeof value === "string" && HANDLE.test(value);
}

export function isPacketCaptureCursor(value: unknown): value is number {
  return unsigned(value);
}

export function isPacketCaptureStartInput(value: unknown): value is PacketCaptureStartInput {
  if (!record(value) || !exact(value, ["filter", "packetLimit", "durationSeconds"]) ||
    !(value.filter === null || (
      typeof value.filter === "string" && value.filter.length > 0 &&
      encoder.encode(value.filter).byteLength <= 2_048 &&
      value.filter.trim() === value.filter && !/[\u0000\n\r]/u.test(value.filter)
    )) || !(value.packetLimit === null || unsigned(value.packetLimit, 100_000) &&
      value.packetLimit > 0)) return false;
  return unsigned(value.durationSeconds, 300) && value.durationSeconds > 0;
}

export function isPacketCaptureInterfaceList(
  value: unknown,
): value is PacketCaptureInterfaceList {
  if (!record(value) || !exact(value, [
    "interfaces", "displayed", "truncated", "expiresInSeconds",
  ]) || !Array.isArray(value.interfaces) || value.interfaces.length > 128 ||
    !unsigned(value.displayed, 128) || value.displayed !== value.interfaces.length ||
    typeof value.truncated !== "boolean" || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds === 0) return false;
  const handles = new Set<string>();
  const valid = value.interfaces.every((item) => {
    if (!record(item) || !exact(item, [
      "interfaceHandle", "name", "mac", "addresses", "textTruncated",
    ]) || !isPacketCaptureOpaqueHandle(item.interfaceHandle) || handles.has(item.interfaceHandle) ||
      !publicText(item.name, 512, false) ||
      !(item.mac === null || publicText(item.mac, 512, false)) ||
      !Array.isArray(item.addresses) || item.addresses.length > 16 ||
      !item.addresses.every((address) => publicText(address, 512, false)) ||
      typeof item.textTruncated !== "boolean") return false;
    handles.add(item.interfaceHandle);
    return true;
  });
  return valid && jsonBytesAtMost(value, 256 * 1_024);
}

export function isPacketCaptureStarted(value: unknown): value is PacketCaptureStarted {
  return record(value) && exact(value, ["captureHandle", "status", "expiresInSeconds"]) &&
    isPacketCaptureOpaqueHandle(value.captureHandle) && value.status === "running" &&
    unsigned(value.expiresInSeconds, 390) && value.expiresInSeconds >= 91;
}

export function isPacketCaptureLiveEvent(value: unknown): value is PacketCaptureLiveEvent {
  if (!record(value) || !unsigned(value.sequence) || value.sequence === 0 ||
    !observedAt(value.observedAt)) return false;
  if (value.kind === "started" || value.kind === "stopped") {
    return exact(value, ["kind", "sequence", "observedAt"]);
  }
  if (value.kind === "failed") {
    return exact(value, ["kind", "sequence", "observedAt", "code", "reason"]) &&
      value.code === "capture-failed" &&
      (value.reason === null ||
        PACKET_CAPTURE_FAILURE_REASONS.includes(value.reason as PacketCaptureFailureReason));
  }
  if (value.kind === "info") {
    return exact(value, ["kind", "sequence", "observedAt", "message", "textTruncated"]) &&
      publicText(value.message, 8 * 1_024) && typeof value.textTruncated === "boolean" &&
      jsonBytesAtMost(value, 64 * 1_024);
  }
  if (value.kind === "progress") {
    return exact(value, [
      "kind", "sequence", "observedAt", "packets", "bytes", "countersTruncated",
    ]) && unsigned(value.packets) && unsigned(value.bytes) &&
      typeof value.countersTruncated === "boolean";
  }
  if (value.kind === "packet") {
    return exact(value, [
      "kind", "sequence", "observedAt", "timestamp", "protocol", "source",
      "destination", "length", "info", "raw", "textTruncated",
    ]) && publicText(value.timestamp, 4 * 1_024) &&
      publicText(value.protocol, 4 * 1_024, false) &&
      publicText(value.source, 4 * 1_024) && publicText(value.destination, 4 * 1_024) &&
      publicText(value.length, 4 * 1_024) && publicText(value.info, 16 * 1_024) &&
      publicText(value.raw, 16 * 1_024) && typeof value.textTruncated === "boolean" &&
      jsonBytesAtMost(value, 64 * 1_024);
  }
  return false;
}

export function isPacketCapturePoll(value: unknown): value is PacketCapturePoll {
  if (!record(value) || !exact(value, [
    "captureHandle", "status", "oldestSequence", "latestSequence", "cursorReset",
    "hasMore", "truncated", "droppedEvents", "retainedPackets", "packets", "bytes", "events",
  ]) || !isPacketCaptureOpaqueHandle(value.captureHandle) ||
    (value.status !== "running" && value.status !== "stopped" && value.status !== "failed") ||
    !unsigned(value.oldestSequence) || !unsigned(value.latestSequence) ||
    value.oldestSequence > value.latestSequence || typeof value.cursorReset !== "boolean" ||
    typeof value.hasMore !== "boolean" || typeof value.truncated !== "boolean" ||
    !unsigned(value.droppedEvents) || !unsigned(value.retainedPackets, 400) ||
    !unsigned(value.packets) || !unsigned(value.bytes) || !Array.isArray(value.events) ||
    value.events.length > 100 || !value.events.every(isPacketCaptureLiveEvent)) return false;
  const oldestSequence = value.oldestSequence;
  const latestSequence = value.latestSequence;
  const sequences = value.events.map((event) => event.sequence);
  const ordered = sequences.every((sequence, index) =>
    sequence >= oldestSequence && sequence <= latestSequence &&
    (index === 0 || sequence > (sequences[index - 1] ?? 0)));
  const emptyCoherent = value.latestSequence !== 0 ||
    (value.oldestSequence === 0 && value.events.length === 0 && value.packets === 0 && value.bytes === 0);
  return ordered && emptyCoherent &&
    value.truncated === (value.cursorReset || value.hasMore || value.droppedEvents > 0) &&
    jsonBytesAtMost(value, 512 * 1_024);
}

export function isPacketCaptureStopped(value: unknown): value is PacketCaptureStopped {
  return record(value) && exact(value, ["stopped"]) && value.stopped === true;
}
