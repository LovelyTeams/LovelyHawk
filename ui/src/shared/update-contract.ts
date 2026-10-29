export type AppUpdateRequest =
  | { action: "info" | "check" }
  | { action: "download" | "progress" | "cancel"; handle: string };

export type AppUpdateResponse =
  | { kind: "info"; version: string }
  | { kind: "check"; version: string; available: boolean; handle: string | null; notes: string }
  | { kind: "download"; filename: string | null }
  | { kind: "progress"; received: number; total: number }
  | { kind: "cancel"; cancelled: boolean };

const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const keys = (value: Record<string, unknown>, expected: string[]) =>
  Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
const handle = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f-]{36}$/u.test(value);
const version = (value: unknown): value is string =>
  typeof value === "string" && value.length <= 64 && /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value);

export function isAppUpdateRequest(value: unknown): value is AppUpdateRequest {
  if (!record(value)) return false;
  if (value.action === "info" || value.action === "check") return keys(value, ["action"]);
  return ["download", "progress", "cancel"].includes(String(value.action)) &&
    keys(value, ["action", "handle"]) && handle(value.handle);
}

export function matchesAppUpdateResponse(request: AppUpdateRequest, value: unknown): value is AppUpdateResponse {
  if (!record(value) || value.kind !== request.action) return false;
  switch (value.kind) {
    case "info": return keys(value, ["kind", "version"]) && version(value.version);
    case "check": return keys(value, ["kind", "version", "available", "handle", "notes"]) &&
      version(value.version) && typeof value.available === "boolean" &&
      (value.handle === null || (value.available && handle(value.handle))) &&
      typeof value.notes === "string" && [...value.notes].length <= 8000;
    case "download": return keys(value, ["kind", "filename"]) && (value.filename === null ||
      (typeof value.filename === "string" && value.filename.length > 0 && value.filename.length <= 512 &&
        !/[\\/\u0000-\u001f\u007f]/u.test(value.filename)));
    case "progress": return keys(value, ["kind", "received", "total"]) &&
      Number.isSafeInteger(value.received) && Number.isSafeInteger(value.total) &&
      (value.received as number) >= 0 && (value.total as number) >= (value.received as number) &&
      (value.total as number) <= 128 * 1024 * 1024;
    case "cancel": return keys(value, ["kind", "cancelled"]) && value.cancelled === true;
    default: return false;
  }
}
