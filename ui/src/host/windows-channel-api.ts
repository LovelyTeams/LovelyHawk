import { isChannelAction, isChannelNotification, isChannelOwner, isChannelOwnerStatus, isChannelRead, isChannelTab, isChannelView, type WindowsChannelApi, type WindowsChannelOwnerApi } from "../shared/windows-channel-contract";
import { invokeHost, utf8ByteLength } from "./transport";

function check(condition: boolean): asserts condition { if (!condition) throw new Error("通道窗口请求或返回内容无效。"); }
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
async function call(child: boolean, request: object) { return invokeHost(child ? "windows_channel_child" : "windows_channel_owner", { request }, 15_000); }
async function empty(child: boolean, request: object) { check(await call(child, request) === null); }
export function createWindowsChannelOwnerApi(): WindowsChannelOwnerApi {
  return Object.freeze({
    async attach(...v: unknown[]) { check(v.length === 0); const r = await call(false, { kind: "attach" }); check(isChannelOwner(r)); return r; },
    async sync(...v: unknown[]) { check(v.length === 3 && isChannelOwner(v[0]) && (v[1] === null || isChannelOwner(v[1])) && isChannelView(v[2])); await empty(false, { kind: "sync", owner: v[0], sessionId: v[1], view: v[2] }); },
    async open(...v: unknown[]) { check(v.length === 2 && isChannelOwner(v[0]) && isChannelTab(v[1])); await empty(false, { kind: "open", owner: v[0], tab: v[1] }); },
    async poll(...v: unknown[]) { check(v.length === 2 && isChannelOwner(v[0]) && typeof v[1] === "boolean"); const r = await call(false, { kind: "poll", owner: v[0], take: v[1] }); check(isChannelOwnerStatus(r)); return r; },
    async finish(...v: unknown[]) { check(v.length === 3 && isChannelOwner(v[0]) && integer(v[1]) && typeof v[2] === "boolean"); await empty(false, { kind: "finish", owner: v[0], id: v[1], ok: v[2] }); },
    async release(...v: unknown[]) { check((v.length === 1 || v.length === 2) && isChannelOwner(v[0]) && (v.length === 1 || integer(v[1]))); await empty(false, { kind: "release", owner: v[0], expectedDraft: v[1] ?? null }); },
  });
}
export function createWindowsChannelApi(): WindowsChannelApi {
  return Object.freeze({
    async notify(...v: unknown[]) { check(v.length === 1 && isChannelNotification(v[0])); await empty(true, { kind: "notify", notification: v[0] }); },
    async read(...v: unknown[]) { check(v.length === 1 && integer(v[0])); const r = await call(true, { kind: "read", after: v[0] }); check(isChannelRead(r)); return r; },
    async act(...v: unknown[]) { check(v.length === 2 && integer(v[0]) && isChannelAction(v[1])); const r = await call(true, { kind: "act", binding: v[0], action: v[1] }); check(integer(r)); return r; },
    async dirty(...v: unknown[]) { check(v.length === 1 && typeof v[0] === "boolean"); await empty(true, { kind: "dirty", dirty: v[0] }); },
    async copy(...v: unknown[]) { check(v.length === 1 && typeof v[0] === "string" && utf8ByteLength(v[0]) <= 128 * 1024); await empty(true, { kind: "copy", text: v[0] }); },
  });
}
