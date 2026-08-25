import { describe, expect, it, vi } from "vitest";

import {
  createBeforeQuitHandler,
  createRendererCloseGate,
  resolveArchiveRootPath,
} from "./app-lifecycle";

describe("portable application lifecycle", () => {
  it("places a packaged macOS archive beside the app bundle", () => {
    expect(
      resolveArchiveRootPath({
        isPackaged: true,
        platform: "darwin",
        executablePath: "/Applications/LovelyRes.app/Contents/MacOS/LovelyRes",
        appPath: "/Applications/LovelyRes.app/Contents/Resources/app.asar",
      }),
    ).toBe("/Applications");
  });

  it("keeps packaged Windows and Linux archives beside the executable", () => {
    expect(
      resolveArchiveRootPath({
        isPackaged: true,
        platform: "win32",
        executablePath: "D:\\Portable\\LovelyRes\\LovelyRes.exe",
        appPath: "D:\\Portable\\LovelyRes\\resources\\app.asar",
      }),
    ).toBe("D:\\Portable\\LovelyRes");
    expect(
      resolveArchiveRootPath({
        isPackaged: true,
        platform: "linux",
        executablePath: "/opt/lovelyres/lovelyres",
        appPath: "/opt/lovelyres/resources/app.asar",
      }),
    ).toBe("/opt/lovelyres");
  });

  it("accepts only an absolute development override", () => {
    expect(
      resolveArchiveRootPath({
        isPackaged: false,
        platform: "win32",
        executablePath: "C:\\Electron\\electron.exe",
        appPath: "D:\\LovelyRes\\electron",
        developmentOverride: "E:\\LovelyResData",
      }),
    ).toBe("E:\\LovelyResData");
    expect(() =>
      resolveArchiveRootPath({
        isPackaged: false,
        platform: "win32",
        executablePath: "C:\\Electron\\electron.exe",
        appPath: "D:\\LovelyRes\\electron",
        developmentOverride: "relative-data",
      }),
    ).toThrow("must be an absolute path");
  });

  it("waits once, then allows the resumed quit without another stop", async () => {
    let finishStop: (() => void) | undefined;
    const stopBackend = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishStop = resolve;
        }),
    );
    const resumeQuit = vi.fn();
    const reportError = vi.fn();
    const handler = createBeforeQuitHandler(stopBackend, resumeQuit, reportError);
    const firstEvent = { preventDefault: vi.fn() };
    const repeatedEvent = { preventDefault: vi.fn() };

    handler(firstEvent);
    handler(repeatedEvent);
    expect(firstEvent.preventDefault).toHaveBeenCalledOnce();
    expect(repeatedEvent.preventDefault).toHaveBeenCalledOnce();
    expect(stopBackend).toHaveBeenCalledOnce();

    finishStop?.();
    await Promise.resolve();
    expect(resumeQuit).toHaveBeenCalledOnce();

    const resumedEvent = { preventDefault: vi.fn() };
    handler(resumedEvent);
    expect(resumedEvent.preventDefault).not.toHaveBeenCalled();
    expect(stopBackend).toHaveBeenCalledOnce();
    expect(reportError).not.toHaveBeenCalled();
  });

  it("closes only after the renderer save handshake succeeds", () => {
    const sendRequest = vi.fn();
    const closeWindow = vi.fn();
    const gate = createRendererCloseGate(sendRequest, closeWindow);
    const first = { preventDefault: vi.fn() };
    gate.request(first);
    gate.request({ preventDefault: vi.fn() });
    expect(first.preventDefault).toHaveBeenCalledOnce();
    expect(sendRequest).toHaveBeenCalledOnce();

    gate.resolve(false);
    expect(closeWindow).not.toHaveBeenCalled();
    const retry = { preventDefault: vi.fn() };
    gate.request(retry);
    expect(retry.preventDefault).toHaveBeenCalledOnce();
    gate.resolve(true);
    expect(closeWindow).toHaveBeenCalledOnce();

    const resumed = { preventDefault: vi.fn() };
    gate.request(resumed);
    expect(resumed.preventDefault).not.toHaveBeenCalled();
    gate.dispose();
  });

  it("keeps the window open when the renderer close handshake times out", () => {
    vi.useFakeTimers();
    const sendRequest = vi.fn();
    const closeWindow = vi.fn();
    const gate = createRendererCloseGate(sendRequest, closeWindow, 10);
    gate.request({ preventDefault: vi.fn() });
    vi.advanceTimersByTime(10);
    gate.resolve(true);
    expect(closeWindow).not.toHaveBeenCalled();
    gate.request({ preventDefault: vi.fn() });
    expect(sendRequest).toHaveBeenCalledTimes(2);
    gate.dispose();
    vi.useRealTimers();
  });
});
