import { describe, expect, it } from "vitest";

import {
  isExecDirectoryListing,
  isExecDirectoryPath,
  isExecFilePath,
  isPodFile,
  joinExecPath,
  MAX_EXEC_DIRECTORY_ENTRIES,
  parentExecPath,
} from "./exec-files-contract";

const entry = {
  name: "nginx.conf",
  kind: "file",
  size: 2_048,
  modifiedUnix: 1_700_000_000,
  mode: "644",
  openable: true,
};

describe("paths inside a container or pod", () => {
  it("takes the same paths the backend does, and nothing that climbs or hides", () => {
    for (const good of ["/", "/etc", "/etc/nginx/nginx.conf", "/tmp/a b", "/dev/shm/.x"]) {
      expect(isExecDirectoryPath(good), good).toBe(true);
    }
    for (const bad of ["", "etc", "/etc/", "//etc", "/etc/../root", "/./etc", "/etc\\x", "/etc/\nx", 7, null, `/${"a".repeat(4_096)}`]) {
      expect(isExecDirectoryPath(bad), String(bad)).toBe(false);
    }
    expect(isExecFilePath("/")).toBe(false);
    expect(isExecFilePath("/etc/hosts")).toBe(true);
  });

  it("joins and climbs without doubling or losing the root", () => {
    expect(joinExecPath("/", "etc")).toBe("/etc");
    expect(joinExecPath("/etc", "hosts")).toBe("/etc/hosts");
    expect(parentExecPath("/etc/nginx")).toBe("/etc");
    expect(parentExecPath("/etc")).toBe("/");
    expect(parentExecPath("/")).toBeNull();
  });
});

describe("a directory listing", () => {
  it("is exactly the backend's shape, with unknowns as null", () => {
    const listing = { path: "/etc", entries: [entry, { ...entry, name: "conf.d", kind: "directory", size: null, modifiedUnix: null, mode: null }], truncated: false };
    expect(isExecDirectoryListing(listing)).toBe(true);
    expect(isExecDirectoryListing({ ...listing, extra: 1 })).toBe(false);
    expect(isExecDirectoryListing({ ...listing, path: "etc" })).toBe(false);
    expect(isExecDirectoryListing({ ...listing, entries: [{ ...entry, kind: "socket" }] })).toBe(false);
    // A name with a slash would make the joined path name something else.
    expect(isExecDirectoryListing({ ...listing, entries: [{ ...entry, name: "../root" }] })).toBe(false);
    expect(isExecDirectoryListing({ ...listing, entries: [{ ...entry, mode: "rwx" }] })).toBe(false);
    expect(isExecDirectoryListing({ ...listing, entries: [{ ...entry, size: -1 }] })).toBe(false);
    expect(isExecDirectoryListing({ ...listing, entries: [{ ...entry, size: 2 ** 60 }] })).toBe(false);
    // A name with a newline is still a listing entry: data, shown escaped.
    expect(isExecDirectoryListing({ ...listing, entries: [{ ...entry, name: "two\nlines", openable: false }] })).toBe(true);
    expect(isExecDirectoryListing({
      ...listing,
      entries: Array.from({ length: MAX_EXEC_DIRECTORY_ENTRIES + 1 }, (_, index) => ({ ...entry, name: `f${index}` })),
    })).toBe(false);
  });
});

describe("a pod file", () => {
  it("must carry text whose length is the one stated and a real digest", () => {
    const file = { path: "/etc/hosts", text: "127.0.0.1 localhost\n", bytes: 20, sha256: "a".repeat(64) };
    expect(isPodFile(file)).toBe(true);
    expect(isPodFile({ ...file, bytes: 19 })).toBe(false);
    expect(isPodFile({ ...file, text: "中文", bytes: 6 })).toBe(true);
    expect(isPodFile({ ...file, sha256: "A".repeat(64) })).toBe(false);
    expect(isPodFile({ ...file, path: "/" })).toBe(false);
    expect(isPodFile({ ...file, handle: "x" })).toBe(false);
  });
});
