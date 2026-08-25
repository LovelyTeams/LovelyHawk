import type {
  PacketCaptureInterface,
  PacketCapturePacketEvent,
  PacketCaptureStartInput,
} from "../shared/packet-capture-live-contract";

const encoder = new TextEncoder();
export const MAX_RENDERED_PACKETS = 400;

export interface PacketCaptureForm {
  filter: string;
  packetLimit: string;
  durationSeconds: string;
}

export function packetCaptureScope(bindingHandle: string): string {
  return bindingHandle;
}

export function boundPacketCaptureText(value: string, maximumBytes: number): string {
  if (encoder.encode(value).byteLength <= maximumBytes) return value;
  let output = "";
  for (const character of value) {
    if (encoder.encode(output + character).byteLength > maximumBytes) break;
    output += character;
  }
  return output;
}

export function packetCaptureStartInput(form: PacketCaptureForm): PacketCaptureStartInput | null {
  const filter = form.filter.trim();
  const packetLimit = parseBoundedInteger(form.packetLimit, 100_000);
  const durationSeconds = parseBoundedInteger(form.durationSeconds, 300);
  if (packetLimit === null || durationSeconds === null ||
    encoder.encode(filter).byteLength > 2_048 || /[\u0000\n\r]/u.test(filter)) return null;
  return {
    filter: filter === "" ? null : filter,
    packetLimit,
    durationSeconds,
  };
}

function parseBoundedInteger(value: string, maximum: number): number | null {
  const trimmed = value.trim();
  if (!/^[0-9]+$/u.test(trimmed)) return null;
  const parsed = Number(trimmed);
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= maximum ? parsed : null;
}

export function packetCaptureInterfaceLabel(value: PacketCaptureInterface): string {
  return value.addresses.length === 0
    ? value.name
    : `${value.name} · ${value.addresses.join(", ")}`;
}

export function filterPacketCapturePackets(
  packets: readonly PacketCapturePacketEvent[],
  query: string,
): PacketCapturePacketEvent[] {
  const normalized = query.trim().toLocaleLowerCase();
  if (normalized === "") return [...packets];
  return packets.filter((packet) => [
    packet.protocol,
    packet.source,
    packet.destination,
    packet.info,
    packet.raw,
  ].some((value) => value.toLocaleLowerCase().includes(normalized)));
}

export function packetCaptureProtocolSummary(
  packets: readonly PacketCapturePacketEvent[],
): Array<{ protocol: string; count: number }> {
  const counts = new Map<string, number>();
  for (const packet of packets) {
    const protocol = packet.protocol || "OTHER";
    counts.set(protocol, (counts.get(protocol) ?? 0) + 1);
  }
  return [...counts]
    .map(([protocol, count]) => ({ protocol, count }))
    .sort((left, right) => right.count - left.count || left.protocol.localeCompare(right.protocol))
    .slice(0, 8);
}

export function formatPacketCaptureBytes(value: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"] as const;
  let amount = value;
  let unit = 0;
  while (amount >= 1_024 && unit + 1 < units.length) {
    amount /= 1_024;
    unit += 1;
  }
  return unit === 0 ? `${value} ${units[unit]}` : `${amount.toFixed(1)} ${units[unit]}`;
}
