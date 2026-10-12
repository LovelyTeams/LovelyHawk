import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it, vi } from "vitest";

import { createMainApi } from "./main-api";
import { createTerminalApi } from "./terminal-api";
import { setHostInvokerForTests } from "./transport";
import { isBrowserAccelerator } from "./window-chrome";

const backendBridge = readFileSync(
  new URL("../../../crates/lovelyhawk-desktop/src/backend_bridge.rs", import.meta.url),
  "utf8",
);
const allowedMethods = [...backendBridge
  .slice(backendBridge.indexOf("const MAIN_WINDOW_METHODS"), backendBridge.indexOf("];"))
  .matchAll(/"([a-z0-9.-]+)"/gu)].map((match) => match[1]);
const buildScript = readFileSync(new URL("../../../crates/lovelyhawk-desktop/build.rs", import.meta.url), "utf8");
const hostCommands = [...buildScript.matchAll(/^ {4}"([a-z_]+)",$/gmu)].map((match) => match[1] ?? "");
const capability = (name: string) => JSON.parse(readFileSync(
  new URL(`../../../crates/lovelyhawk-desktop/capabilities/${name}.json`, import.meta.url),
  "utf8",
)) as { windows: string[]; permissions: string[] };
const BINDING = "00000000-0000-4000-8000-000000000001";
const INTERFACE = "00000000-0000-4000-8000-000000000002";

function recordingHost(answer: (command: string, args: Record<string, unknown>) => unknown = () => null) {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  setHostInvokerForTests(async (command, args) => {
    calls.push({ command, args });
    return answer(command, args);
  });
  return calls;
}

afterEach(() => {
  setHostInvokerForTests(async () => {
    throw new Error("no host in tests");
  });
});

describe("main window API", () => {
  it("is frozen and keeps the method count the renderer was built against", () => {
    const api = createMainApi();
    expect(Object.isFrozen(api)).toBe(true);
    expect(Object.keys(api)).toHaveLength(164);
  });

  it("refuses bad arity and bad shapes before anything reaches the host", async () => {
    const calls = recordingHost();
    const api = createMainApi() as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
    for (const [method, args] of Object.entries({
      getConnection: [],
      startSshConnect: ["", "extra"],
      getSshAttempt: [42],
      collectSystemInfo: ["b", "not-a-tab", 50],
      readBaselineFile: ["b"],
      planDockerContainerAction: ["b", "s", "c", "name", "delete-everything"],
      runEmergencyCommand: ["b", "s"],
      exportDisposalReport: ["b", "r", "pdf"],
      // The object is the list's handles; a kind or a name is not a fourth argument.
      exportKubernetesManifest: ["b", "s", "r", "secret"],
      setWindowTheme: [{ theme: "neon", scrim: false }],
      writeClipboard: ["x".repeat(128 * 1_024 + 1)],
      nginxRepair: [{ action: "discover", bindingHandle: "b", command: "injected" }],
      caseLibrary: [{ action: "export", snapshotHandle: "s", selectedDestination: "C:\\x.json" }],
      fileEvidence: [{ action: "begin", bindingHandle: "b", pathHandle: "p", selectedDirectory: "C:\\" }],
      packetCaptureEvidence: [{
        action: "begin", bindingHandle: BINDING, interfaceHandle: INTERFACE,
        input: { filter: null, packetLimit: null, durationSeconds: 10 }, selectedDirectory: "C:\\",
      }],
      podFileEvidence: [{
        action: "begin", bindingHandle: BINDING, snapshotHandle: "s", rowHandle: "r", container: null,
        path: "/etc/hostname", selectedDirectory: "C:\\",
      }],
      // The page names a kind of file; it never hands the host a path.
      chooseConnectionCredentialFile: ["/home/ops/.ssh/id_ed25519"],
    })) {
      await expect(api[method]!(...args), method).rejects.toThrow();
    }
    expect(calls).toEqual([]);
  });

  it("sends only methods the host allows from the main window", async () => {
    const calls = recordingHost();
    const api = createMainApi();
    await api.bootstrap().catch(() => undefined);
    await api.getSystemInfoSummary("binding-1").catch(() => undefined);
    await api.listNotes("", 0, 20).catch(() => undefined);
    await api.caseLibrary({ action: "list" }).catch(() => undefined);
    await api.fileEvidence({ action: "poll", bindingHandle: "b", jobHandle: "j" }).catch(() => undefined);
    await api.packetCaptureEvidence({ action: "poll", bindingHandle: BINDING, jobHandle: "j" }).catch(() => undefined);
    await api.podFileEvidence({ action: "cancel", bindingHandle: BINDING, jobHandle: "j" }).catch(() => undefined);
    const methods = calls.map((call) => {
      expect(call.command).toBe("backend_call");
      return call.args.method as string;
    });
    expect(methods).toEqual([
      "app.bootstrap", "system-info.summary.get", "notes.list", "case.library", "emergency.file-evidence",
      "packet-capture.evidence", "kubernetes.pod.file-evidence",
    ]);
    for (const method of methods) expect(allowedMethods).toContain(method);
  });

  it("routes every local path and export through a host command, never the generic call", async () => {
    const calls = recordingHost((command) => command === "case_library_export" || command === "file_evidence_begin" ||
      command === "packet_capture_evidence_begin" || command === "pod_file_evidence_begin"
      ? null
      : command === "kubernetes_manifest_export"
        ? { saved: true, fileName: "pod-incident-api-20261012T101500Z.yaml" }
        : { saved: false, fileName: null, recordCount: 0 });
    const api = createMainApi();
    await expect(api.caseLibrary({ action: "export", snapshotHandle: "s" })).resolves.toBeNull();
    await expect(api.fileEvidence({ action: "begin", bindingHandle: "b", pathHandle: "p" })).resolves.toBeNull();
    await expect(api.packetCaptureEvidence({
      action: "begin", bindingHandle: BINDING, interfaceHandle: INTERFACE,
      input: { filter: "icmp", packetLimit: 6, durationSeconds: 20 },
    })).resolves.toBeNull();
    await expect(api.podFileEvidence({
      action: "begin", bindingHandle: BINDING, snapshotHandle: "s", rowHandle: "r", container: "app",
      path: "/var/log/app.log",
    })).resolves.toBeNull();
    await expect(api.exportAiHistory("json")).resolves.toEqual({ saved: false, fileName: null, recordCount: 0 });
    await expect(api.exportKubernetesManifest(BINDING, "s", "r"))
      .resolves.toEqual({ saved: true, fileName: "pod-incident-api-20261012T101500Z.yaml" });
    expect(calls.map((call) => call.command)).toEqual([
      "case_library_export", "file_evidence_begin", "packet_capture_evidence_begin", "pod_file_evidence_begin",
      "ai_history_export", "kubernetes_manifest_export",
    ]);
    expect(calls[0]!.args).toEqual({ request: { action: "export", snapshotHandle: "s" } });
    expect(calls[5]!.args).toEqual({ bindingHandle: BINDING, snapshotHandle: "s", rowHandle: "r" });
    for (const method of [
      "connections.import-file", "connections.export-file", "ai-history.export", "disposal-report.export",
      "application-log.export.prepare", "config.quick.copy", "config.quick.artifact", "config.quick.bundle.export",
      "kubernetes.manifest.export",
    ]) expect(allowedMethods).not.toContain(method);
  });

  it("exports a whole multi-file draft through its own host command, by handle and revision only", async () => {
    const answer = { saved: true, directoryName: "lovelyhawk-tomcat-new-empty-review-bundle", fileCount: 3 };
    const calls = recordingHost((command) => command === "config_bundle_export" ? answer : null);
    const api = createMainApi();
    await expect(api.exportConfigBundle("draft-1", 2)).resolves.toEqual(answer);
    expect(calls).toEqual([{ command: "config_bundle_export", args: { handle: "draft-1", revision: 2 } }]);
    // No folder, path or file list ever comes from the page.
    await expect((api.exportConfigBundle as (...values: unknown[]) => Promise<unknown>)("draft-1", 2, "C:/out"))
      .rejects.toThrow("Invalid configuration export request.");
    await expect(api.exportConfigBundle("../draft", 2)).rejects.toThrow("Invalid configuration export request.");
    await expect(api.exportConfigBundle("draft-1", 0)).rejects.toThrow("Invalid configuration export request.");
    expect(calls).toHaveLength(1);
    for (const bad of [
      { saved: true, directoryName: "../escape", fileCount: 3 },
      { saved: true, directoryName: "bundle", fileCount: 1 },
      { saved: false, directoryName: "bundle", fileCount: null },
      { ...answer, path: "C:/out" },
    ]) {
      recordingHost(() => bad);
      await expect(createMainApi().exportConfigBundle("draft-1", 2)).rejects.toThrow("export result is invalid");
    }
  });

  it("refuses a host answer that does not match the contract", async () => {
    recordingHost(() => ({ opened: true, reused: "yes" }));
    await expect(createMainApi().openSshTerminal()).rejects.toThrow("launch result is invalid");
  });

  it("turns a host sentence into an Error the pages can read", async () => {
    recordingHost(() => {
      throw "LovelyHawk could not complete the SSH controller operation. (ssh-binding-unavailable)";
    });
    await expect(createMainApi().getSystemInfoSummary("b")).rejects.toThrow("binding-unavailable");
  });

  it("answers each close request with the number the host gave it", async () => {
    const { listen } = await import("@tauri-apps/api/event");
    const calls = recordingHost();
    let deliver: ((event: { payload: unknown }) => void) | undefined;
    vi.mocked(listen).mockImplementationOnce(async (_name, handler) => {
      deliver = handler as unknown as (event: { payload: unknown }) => void;
      return () => undefined;
    });
    let answer!: (allowed: boolean) => void;
    const stop = createMainApi().onBeforeClose(() => new Promise<boolean>((resolve) => { answer = resolve; }));
    await vi.waitFor(() => expect(deliver).toBeDefined());

    deliver!({ payload: null });
    deliver!({ payload: { request: "7" } });
    expect(calls).toEqual([]);

    deliver!({ payload: { request: 7 } });
    answer(true);
    await vi.waitFor(() => expect(calls).toEqual([{ command: "close_decision", args: { request: 7, allowed: true } }]));
    stop();
  });

  /** Closing the main window closes the editors; an unreadable count still asks. */
  it("tells the close handler how many editor windows hold unsaved text", async () => {
    const { listen } = await import("@tauri-apps/api/event");
    recordingHost();
    let deliver: ((event: { payload: unknown }) => void) | undefined;
    vi.mocked(listen).mockImplementationOnce(async (_name, handler) => {
      deliver = handler as unknown as (event: { payload: unknown }) => void;
      return () => undefined;
    });
    const seen: number[] = [];
    const stop = createMainApi().onBeforeClose(async ({ unsavedEditors }) => {
      seen.push(unsavedEditors);
      return false;
    });
    await vi.waitFor(() => expect(deliver).toBeDefined());
    deliver!({ payload: { request: 1, unsavedEditors: 2 } });
    deliver!({ payload: { request: 2, unsavedEditors: 0 } });
    deliver!({ payload: { request: 3 } });
    deliver!({ payload: { request: 4, unsavedEditors: -1 } });
    await vi.waitFor(() => expect(seen).toEqual([2, 0, 1, 1]));
    stop();
  });

  it("accepts only a sane unsaved-editor count from the host", async () => {
    recordingHost((command) => command === "unsaved_editor_count" ? { count: 3 } : null);
    await expect(createMainApi().unsavedEditorCount()).resolves.toBe(3);
    recordingHost((command) => command === "unsaved_editor_count" ? { count: "3" } : null);
    await expect(createMainApi().unsavedEditorCount()).rejects.toThrow();
  });
});

describe("terminal-family window API", () => {
  it("never names a binding, a container or a local path", async () => {
    const calls = recordingHost((command) => command === "terminal_open" ? { columns: 80, rows: 24 } : null);
    const api = createTerminalApi();
    expect(Object.isFrozen(api)).toBe(true);
    await expect(api.open(80, 24)).resolves.toEqual({ columns: 80, rows: 24 });
    await api.listSftpDirectory("browser", "directory").catch(() => undefined);
    await api.downloadSftpEntry("browser", "file").catch(() => undefined);
    for (const call of calls) {
      expect(Object.keys(call.args)).not.toContain("bindingHandle");
      expect(JSON.stringify(call.args)).not.toMatch(/localPath|[A-Za-z]:\\\\/u);
    }
    expect(calls.map((call) => call.command)).toEqual(["terminal_open", "sftp_list", "sftp_download"]);
  });

  it("checks sizes, input and answers against the terminal contract", async () => {
    const calls = recordingHost((command) => command === "terminal_input" ? { acceptedBytes: 2 } : null);
    const api = createTerminalApi();
    await expect(api.open(0, 24)).rejects.toThrow("Invalid terminal open request.");
    await expect(api.input("not base64!")).rejects.toThrow("Invalid terminal input request.");
    // Three bytes sent, two acknowledged: the answer does not match the request.
    await expect(api.input("YWJj")).rejects.toThrow("response is invalid");
    expect(calls.map((call) => call.command)).toEqual(["terminal_input"]);
  });

  it("opens a folder terminal by the browser's handles and a display name only", async () => {
    const calls = recordingHost((command) =>
      command === "directory_terminal_open" ? { opened: true, reused: false } : null);
    const api = createTerminalApi() as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
    for (const args of [
      [],
      ["browser", "directory"],
      ["browser", "directory", "www", "/etc"],
      ["", "directory", "www"],
      ["browser", "dir\nectory", "www"],
      ["browser", "directory", ""],
      ["browser", "directory", "x".repeat(256)],
      ["browser", "directory", 42],
    ]) {
      await expect(api.openDirectoryTerminal!(...args), JSON.stringify(args))
        .rejects.toThrow("Invalid directory terminal request.");
    }
    expect(calls).toEqual([]);
    await expect(api.openDirectoryTerminal!("browser", "directory", "www")).resolves.toEqual({ opened: true, reused: false });
    expect(calls).toEqual([{
      command: "directory_terminal_open",
      args: { browserHandle: "browser", directoryHandle: "directory", name: "www" },
    }]);
    recordingHost(() => ({ opened: true, reused: false, path: "/etc" }));
    await expect(api.openDirectoryTerminal!("browser", "directory", "www")).rejects.toThrow("launch result is invalid");
  });

  it("is granted only to the child windows, and the main window's commands only to main", () => {
    const main = capability("main-window");
    const child = capability("child-windows");
    expect(main.windows).toEqual(["main"]);
    expect(child.windows).toEqual(["child-*"]);
    const commandPermission = (name: string) => `allow-${name.replaceAll("_", "-")}`;
    const mainCommands = hostCommands.slice(0, hostCommands.indexOf("terminal_open"));
    const childCommands = hostCommands.slice(hostCommands.indexOf("terminal_open"));
    expect(mainCommands).toContain("backend_call");
    for (const name of mainCommands) {
      expect(main.permissions).toContain(commandPermission(name));
      expect(child.permissions).not.toContain(commandPermission(name));
    }
    for (const name of childCommands) {
      expect(child.permissions).toContain(commandPermission(name));
      expect(main.permissions).not.toContain(commandPermission(name));
    }
    // No plugin reaches a page: dialogs, clipboard and files stay in the host.
    for (const permission of [...main.permissions, ...child.permissions]) {
      expect(permission).toMatch(/^(core:(event|window):allow-|allow-)/u);
    }
  });
});

describe("editor window close handshake", () => {
  it("reports unsaved text and answers the host's close question by its number", async () => {
    const { listen } = await import("@tauri-apps/api/event");
    const calls = recordingHost();
    const api = createTerminalApi();
    await api.setUnsavedChanges(true);
    await expect(api.setUnsavedChanges("yes" as unknown as boolean)).rejects.toThrow();
    expect(calls).toEqual([{ command: "file_editor_unsaved", args: { unsaved: true } }]);

    let deliver: ((event: { payload: unknown }) => void) | undefined;
    vi.mocked(listen).mockImplementationOnce(async (_name, handler) => {
      deliver = handler as unknown as (event: { payload: unknown }) => void;
      return () => undefined;
    });
    const stop = api.onBeforeClose(async () => true);
    await vi.waitFor(() => expect(deliver).toBeDefined());
    deliver!({ payload: { request: 0 } });
    deliver!({ payload: { request: 3 } });
    await vi.waitFor(() => expect(calls.at(-1)).toEqual({ command: "child_close_decision", args: { request: 3, allowed: true } }));
    expect(calls.filter((call) => call.command === "child_close_decision")).toHaveLength(1);
    stop();
  });
});

describe("page hardening", () => {
  it("takes reload, print and history keys only", () => {
    const key = (value: string, modifiers: Partial<KeyboardEvent> = {}) => ({
      key: value, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...modifiers,
    });
    expect(isBrowserAccelerator(key("F5"))).toBe(true);
    expect(isBrowserAccelerator(key("r", { ctrlKey: true }))).toBe(true);
    expect(isBrowserAccelerator(key("P", { ctrlKey: true, shiftKey: true }))).toBe(true);
    expect(isBrowserAccelerator(key("ArrowLeft", { altKey: true }))).toBe(true);
    expect(isBrowserAccelerator(key("r"))).toBe(false);
    expect(isBrowserAccelerator(key("c", { ctrlKey: true }))).toBe(false);
    expect(isBrowserAccelerator(key("v", { ctrlKey: true }))).toBe(false);
    expect(isBrowserAccelerator(key("Enter"))).toBe(false);
  });

  it("only acts on keys a page left unhandled, so a terminal keeps Ctrl+R and Ctrl+U", () => {
    const source = readFileSync(new URL("./window-chrome.ts", import.meta.url), "utf8");
    expect(source).toContain("if (!event.defaultPrevented && (isBrowserAccelerator(event) || isFindAccelerator(event)))");
    expect(source).not.toContain("capture: true }); // keys");
    expect(source.match(/addEventListener\("keydown"/gu)).toHaveLength(1);
  });
});

vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => undefined) }));
