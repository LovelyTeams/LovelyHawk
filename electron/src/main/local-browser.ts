import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  LOCAL_BROWSER_LIMITS,
  type LocalBrowserEntry,
  type LocalBrowserEntryKind,
  type LocalDirectorySnapshot,
} from "../shared/local-browser-contract.js";

/**
 * Reads the operator's own machine for the SSH window's local pane.
 *
 * The renderer never holds a filesystem path: every directory it can open came
 * back from here as an opaque handle, and a handle only ever names a directory
 * this registry produced. That keeps a compromised renderer from asking for an
 * arbitrary path, and keeps the local pane in the same shape as the remote one.
 */
const MAX_DIRECTORIES = 512;
const READ_DEADLINE_MS = 10_000;

interface StoredDirectory {
  readonly handle: string;
  readonly directory: string;
}

export class LocalBrowser {
  readonly #byHandle = new Map<string, StoredDirectory>();
  readonly #byDirectory = new Map<string, string>();
  readonly #home: string;

  constructor(home: string = os.homedir()) {
    this.#home = home;
  }

  /** Opens the operator's home directory, the one fixed entry point. */
  async open(): Promise<LocalDirectorySnapshot> {
    return this.#read(await realDirectory(this.#home));
  }

  async list(directoryHandle: string): Promise<LocalDirectorySnapshot> {
    const stored = this.#byHandle.get(directoryHandle);
    if (stored === undefined) throw new Error("The local directory capability is unknown or expired.");
    return this.#read(stored.directory);
  }

  #handleFor(directory: string): string {
    const existing = this.#byDirectory.get(directory);
    if (existing !== undefined) return existing;
    if (this.#byHandle.size >= MAX_DIRECTORIES) this.#evictOldest();
    const handle = randomUUID();
    this.#byHandle.set(handle, { handle, directory });
    this.#byDirectory.set(directory, handle);
    return handle;
  }

  #evictOldest(): void {
    const oldest = this.#byHandle.keys().next();
    if (oldest.done === true) return;
    const stored = this.#byHandle.get(oldest.value);
    this.#byHandle.delete(oldest.value);
    if (stored !== undefined) this.#byDirectory.delete(stored.directory);
  }

  async #read(directory: string): Promise<LocalDirectorySnapshot> {
    const names = await withDeadline(fs.readdir(directory), READ_DEADLINE_MS);
    const observed = Math.min(names.length, LOCAL_BROWSER_LIMITS.maximumObservedEntries);
    const visible = names.slice(0, LOCAL_BROWSER_LIMITS.maximumDisplayedEntries);
    const entries: LocalBrowserEntry[] = [];
    for (const name of visible) {
      const entry = await this.#describe(directory, name);
      if (entry !== null) entries.push(entry);
    }
    entries.sort(byDirectoryThenName);
    const parent = path.dirname(directory);
    return {
      directoryHandle: this.#handleFor(directory),
      parentDirectoryHandle: parent === directory ? null : this.#handleFor(parent),
      directoryLabel: bounded(directory, LOCAL_BROWSER_LIMITS.maximumLabelBytes).text,
      directoryLabelTruncated: bounded(directory, LOCAL_BROWSER_LIMITS.maximumLabelBytes).truncated,
      observedEntryCount: observed,
      displayedEntryCount: entries.length,
      truncated: observed > entries.length,
      entries,
    };
  }

  async #describe(directory: string, name: string): Promise<LocalBrowserEntry | null> {
    const full = path.join(directory, name);
    let kind: LocalBrowserEntryKind = "other";
    let sizeBytes = "0";
    let modifiedAt: string | null = null;
    try {
      // A symbolic link is described by what it is, never followed blindly.
      const stats = await fs.lstat(full);
      if (stats.isDirectory()) kind = "directory";
      else if (stats.isFile()) {
        kind = "file";
        sizeBytes = String(Math.max(0, Math.trunc(stats.size)));
      }
      const modified = stats.mtime.toISOString();
      modifiedAt = Number.isFinite(Date.parse(modified)) ? modified : null;
    } catch {
      // An entry that cannot be described is still worth listing by name.
    }
    const label = bounded(name, LOCAL_BROWSER_LIMITS.maximumNameBytes);
    if (label.text.length === 0) return null;
    return {
      entryHandle: kind === "directory" ? this.#handleFor(full) : randomUUID(),
      name: label.text,
      nameTruncated: label.truncated,
      kind,
      sizeBytes,
      modifiedAt,
    };
  }
}

function byDirectoryThenName(left: LocalBrowserEntry, right: LocalBrowserEntry): number {
  if (left.kind !== right.kind) return left.kind === "directory" ? -1 : 1;
  return left.name.localeCompare(right.name);
}

/** Keeps display text renderable: no control characters, bounded bytes. */
export function bounded(value: string, maximumBytes: number): { text: string; truncated: boolean } {
  const encoder = new TextEncoder();
  const plain = [...value].filter((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code >= 0x20 && code !== 0x7f;
  }).join("");
  if (encoder.encode(plain).byteLength <= maximumBytes) {
    return { text: plain, truncated: plain.length !== value.length };
  }
  let text = plain;
  while (text.length > 0 && encoder.encode(text).byteLength > maximumBytes) {
    text = [...text].slice(0, -1).join("");
  }
  return { text, truncated: true };
}

async function realDirectory(candidate: string): Promise<string> {
  const resolved = path.resolve(candidate);
  const stats = await fs.stat(resolved);
  if (!stats.isDirectory()) throw new Error("The local path is not a directory.");
  return resolved;
}

async function withDeadline<T>(work: Promise<T>, milliseconds: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("The local directory read exceeded its deadline.")), milliseconds);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
