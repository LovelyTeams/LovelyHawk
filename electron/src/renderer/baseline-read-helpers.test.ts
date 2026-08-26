import { describe, expect, it } from "vitest";

import type { BaselineCatalogItem, BaselineScan } from "../shared/baseline-read-contract";
import {
  baselineCategoryLabel,
  baselineComplianceLabel,
  baselineHistoryStateLabel,
  baselineRiskLabel,
  baselineScope,
  baselineValueKindLabel,
  filterBaselineItems,
} from "./baseline-read-helpers";

const hostile = "</div><script>plain()</script>";
const items: BaselineCatalogItem[] = [{
  itemHandle: "item-ssh",
  category: "ssh",
  component: "ssh",
  risk: "critical",
  valueKind: { kind: "choice", options: ["yes", "no"] },
  title: "关闭密码认证",
  description: hostile,
  recommendation: "no",
  writable: true,
}, {
  itemHandle: "item-kernel",
  category: "kernel",
  component: "system",
  risk: "high",
  valueKind: { kind: "integer", minimum: 0, maximum: 2 },
  title: "启用 ASLR",
  description: "内核地址随机化",
  recommendation: "2",
  writable: true,
}];

const scan: BaselineScan = {
  scanHandle: "scan-a",
  capturedAt: "2026-08-24T01:02:03Z",
  expiresInSeconds: 300,
  statuses: [{
    itemHandle: "item-ssh",
    observedKind: "value",
    observed: hostile,
    compliant: false,
    redacted: false,
    textTruncated: false,
  }],
  displayed: 1,
  compliantCount: 0,
  nonCompliantCount: 1,
  redactedFieldCount: 0,
  truncated: false,
};

describe("baseline read helpers", () => {
  it("filters by category, compliance and hostile search text without interpreting it", () => {
    expect(filterBaselineItems(items, scan, "script", "all", "all").map(({ item }) => item.itemHandle))
      .toEqual(["item-ssh"]);
    expect(filterBaselineItems(items, scan, "", "ssh", "non-compliant").length).toBe(1);
    expect(filterBaselineItems(items, scan, "", "kernel", "unscanned").length).toBe(1);
    expect(filterBaselineItems(items, scan, "", "kernel", "compliant").length).toBe(0);
  });

  it("uses only the opaque binding handle as lifecycle scope", () => {
    expect(baselineScope("binding-a")).toBe("binding-a");
    expect(baselineScope("binding-a")).not.toBe(baselineScope("binding-b"));
  });

  it("provides only closed display labels and value descriptions", () => {
    expect(baselineCategoryLabel("file-permissions")).toBe("文件权限");
    expect(baselineRiskLabel("critical")).toBe("严重");
    expect(baselineHistoryStateLabel("restored")).toBe("已恢复");
    expect(baselineComplianceLabel(null)).toBe("尚未扫描");
    expect(baselineComplianceLabel(scan.statuses[0]!)).toBe("不符合");
    expect(baselineValueKindLabel(items[0]!.valueKind)).toBe("选项：yes / no");
    expect(baselineValueKindLabel(items[1]!.valueKind)).toBe("整数范围：0–2");
  });
});
