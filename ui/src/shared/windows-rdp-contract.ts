import { isWindowsFileId } from "./windows-incident-contract";

export interface WindowsRdpBounds { x: number; y: number; width: number; height: number }
/** A fixed remote desktop size; null fits the session to the embedded viewport. */
export interface WindowsRdpResolution { width: number; height: number }
export type WindowsRdpRequest = { action: "status" }
  | { action: "start"; server: string; clipboard: boolean; bounds: WindowsRdpBounds; resolution: WindowsRdpResolution | null }
  | { action: "place"; clientId: string; bounds: WindowsRdpBounds }
  | { action: "hide" | "disconnect"; clientId: string };
export interface WindowsRdpStatus { clientId: string | null; server: string; phase: "idle" | "waiting" | "embedded"; message: string }

/** The sizes the remote desktop client accepts: even widths, 640×480 up to 8192×8192. */
export const RDP_RESOLUTION_LIMITS = { minWidth: 640, minHeight: 480, max: 8192 } as const;

const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const keys = (v: Record<string, unknown>, names: string[]) => Object.keys(v).length === names.length && names.every((n) => Object.hasOwn(v, n));
function bounds(v: unknown): v is WindowsRdpBounds {
  return record(v) && keys(v, ["x", "y", "width", "height"]) && Object.values(v).every((n) => typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 16384) && (v.width as number) >= 160 && (v.height as number) >= 120 && (v.y as number) >= 40;
}
export function isWindowsRdpResolution(v: unknown): v is WindowsRdpResolution {
  return record(v) && keys(v, ["width", "height"]) && Number.isInteger(v.width) && Number.isInteger(v.height) &&
    (v.width as number) % 2 === 0 && (v.width as number) >= RDP_RESOLUTION_LIMITS.minWidth && (v.width as number) <= RDP_RESOLUTION_LIMITS.max &&
    (v.height as number) >= RDP_RESOLUTION_LIMITS.minHeight && (v.height as number) <= RDP_RESOLUTION_LIMITS.max;
}
export function isWindowsRdpRequest(v: unknown): v is WindowsRdpRequest {
  if (!record(v)) return false;
  if (v.action === "status") return keys(v, ["action"]);
  if (v.action === "start") return keys(v, ["action", "server", "clipboard", "bounds", "resolution"]) && typeof v.server === "string" && v.server.length <= 253 && /^[a-z\d\[][a-z\d.:[\]-]*$/iu.test(v.server) && typeof v.clipboard === "boolean" && bounds(v.bounds) && (v.resolution === null || isWindowsRdpResolution(v.resolution));
  if (v.action === "place") return keys(v, ["action", "clientId", "bounds"]) && isWindowsFileId(v.clientId) && bounds(v.bounds);
  return (v.action === "hide" || v.action === "disconnect") && keys(v, ["action", "clientId"]) && isWindowsFileId(v.clientId);
}
export function isWindowsRdpStatus(v: unknown): v is WindowsRdpStatus {
  return record(v) && keys(v, ["clientId", "server", "phase", "message"]) && typeof v.server === "string" && v.server.length <= 253 && typeof v.message === "string" && v.message.length <= 1024 &&
    (v.phase === "idle" ? v.clientId === null && v.server === "" : (v.phase === "waiting" || v.phase === "embedded") && isWindowsFileId(v.clientId));
}
