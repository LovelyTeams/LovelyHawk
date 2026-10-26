import { describe, expect, it } from "vitest";
import { isWindowsRdpRequest, isWindowsRdpStatus } from "./windows-rdp-contract";

describe("native RDP boundary", () => {
  const bounds = { x: 200, y: 140, width: 800, height: 500 };
  const request = { action: "start", server: "server.example:3389", clipboard: false, bounds, resolution: null };
  it("rejects injected config, native handles, stale identity and invalid geometry", () => {
    expect(isWindowsRdpRequest(request)).toBe(true);
    expect(isWindowsRdpRequest({ ...request, resolution: { width: 1920, height: 1080 } })).toBe(true);
    for (const input of [
      { ...request, resolution: undefined }, { ...request, resolution: { width: 1921, height: 1080 } },
      { ...request, resolution: { width: 320, height: 240 } }, { ...request, resolution: { width: 9000, height: 1080 } },
      { ...request, resolution: { width: 1920.5, height: 1080 } }, { ...request, resolution: { width: 1920, height: 1080, bpp: 32 } },
      { ...request, server: "host\r\nredirectdrives:i:1" }, { ...request, server: "/admin" },
      { ...request, pid: 123 }, { ...request, bounds: { ...bounds, height: Infinity } },
      { ...request, bounds: { ...bounds, y: 0 } }, { action: "hide", clientId: "123" },
      { action: "status", hwnd: 1 }, { ...request, clipboard: "true" },
    ]) expect(isWindowsRdpRequest(input)).toBe(false);
  });
  it("does not accept an embedded claim without a valid client identity", () => {
    const idle = { clientId: null, server: "", phase: "idle", message: "" };
    expect(isWindowsRdpStatus(idle)).toBe(true);
    expect(isWindowsRdpStatus({ ...idle, phase: "embedded" })).toBe(false);
    expect(isWindowsRdpStatus({ ...idle, configPath: "C:\\data\\client.rdp" })).toBe(false);
  });
});
