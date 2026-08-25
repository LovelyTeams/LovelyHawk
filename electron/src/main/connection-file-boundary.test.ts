import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  cancelledConnectionExport,
  cancelledConnectionImport,
  completedConnectionExport,
  completedConnectionImport,
  isSelectedConnectionJsonPath,
} from "./connection-file-boundary";

describe("connection file main-process boundary", () => {
  it("accepts only bounded absolute JSON selections", () => {
    const selected = path.resolve("selected-connections.json");
    expect(isSelectedConnectionJsonPath(selected)).toBe(true);
    expect(isSelectedConnectionJsonPath(path.resolve("selected.txt"))).toBe(false);
    expect(isSelectedConnectionJsonPath("relative.json")).toBe(false);
    expect(isSelectedConnectionJsonPath(`${selected}\0hostile`)).toBe(false);
  });

  it("returns explicit cancellation without a path or mutation count", () => {
    expect(cancelledConnectionImport()).toEqual({
      cancelled: true,
      imported: 0,
      skippedExisting: 0,
      skippedDuplicate: 0,
    });
    expect(cancelledConnectionExport()).toEqual({
      cancelled: true,
      count: 0,
      fileName: null,
    });
  });

  it("projects only counts and the export basename to the renderer", () => {
    expect(
      completedConnectionImport({
        imported: 2,
        skippedExisting: 3,
        skippedDuplicate: 4,
      }),
    ).toEqual({
      cancelled: false,
      imported: 2,
      skippedExisting: 3,
      skippedDuplicate: 4,
    });
    const selected = path.resolve("private", "incident-connections.json");
    const exported = completedConnectionExport({ count: 5 }, selected);
    expect(exported).toEqual({
      cancelled: false,
      count: 5,
      fileName: "incident-connections.json",
    });
    expect(JSON.stringify(exported)).not.toContain(path.dirname(selected));
  });
});
