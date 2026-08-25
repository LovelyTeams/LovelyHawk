import path from "node:path";

export interface ArchiveRootInput {
  isPackaged: boolean;
  platform: NodeJS.Platform;
  executablePath: string;
  appPath: string;
  developmentOverride?: string | undefined;
}

export function resolveArchiveRootPath(input: ArchiveRootInput): string {
  const pathApi = input.platform === "win32" ? path.win32 : path.posix;
  if (!input.isPackaged && input.developmentOverride !== undefined) {
    if (!pathApi.isAbsolute(input.developmentOverride)) {
      throw new Error("LOVELYRES_ARCHIVE_ROOT must be an absolute path.");
    }
    return pathApi.resolve(input.developmentOverride);
  }

  if (!input.isPackaged) return pathApi.resolve(input.appPath, "..");
  if (input.platform !== "darwin") {
    return pathApi.dirname(pathApi.resolve(input.executablePath));
  }

  let candidate = pathApi.dirname(pathApi.resolve(input.executablePath));
  for (;;) {
    if (pathApi.basename(candidate).toLowerCase().endsWith(".app")) {
      return pathApi.dirname(candidate);
    }
    const parent = pathApi.dirname(candidate);
    if (parent === candidate) {
      throw new Error("Packaged macOS executable must be inside an .app bundle.");
    }
    candidate = parent;
  }
}

interface PreventableQuitEvent {
  preventDefault(): void;
}

export interface RendererCloseGate {
  request(event: PreventableQuitEvent): void;
  resolve(allowed: boolean): void;
  dispose(): void;
}

export function createRendererCloseGate(
  sendRequest: () => void,
  closeWindow: () => void,
  timeoutMillis = 15_000,
): RendererCloseGate {
  let allowed = false;
  let pending = false;
  let timer: NodeJS.Timeout | null = null;

  return {
    request(event) {
      if (allowed) return;
      event.preventDefault();
      if (pending) return;
      pending = true;
      sendRequest();
      timer = setTimeout(() => {
        pending = false;
        timer = null;
      }, timeoutMillis);
    },
    resolve(result) {
      if (!pending) return;
      pending = false;
      if (timer !== null) clearTimeout(timer);
      timer = null;
      if (!result) return;
      allowed = true;
      closeWindow();
    },
    dispose() {
      pending = false;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
  };
}

export function createBeforeQuitHandler(
  stopBackend: () => Promise<void>,
  resumeQuit: () => void,
  reportError: (error: unknown) => void,
): (event: PreventableQuitEvent) => void {
  let backendStopped = false;
  let stopInProgress: Promise<void> | null = null;

  return (event) => {
    if (backendStopped) return;
    event.preventDefault();
    if (stopInProgress !== null) return;

    stopInProgress = stopBackend().then(
      () => {
        backendStopped = true;
        resumeQuit();
      },
      (error: unknown) => {
        stopInProgress = null;
        reportError(error);
      },
    );
  };
}
