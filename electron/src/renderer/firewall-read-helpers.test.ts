import { describe, expect, it } from "vitest";

import type { FirewallInspection } from "../shared/firewall-read-contract";
import {
  MAX_FIREWALL_RULE_VIEW_BYTES,
  MAX_FIREWALL_CLIPBOARD_BYTES,
  boundFirewallText,
  firewallBackendLabel,
  firewallChangeKindLabel,
  firewallChangeStateLabel,
  firewallCopyText,
  firewallEngineLabel,
  firewallReadScope,
  firewallRuleView,
} from "./firewall-read-helpers";

describe("firewall read helpers", () => {
  it("uses only the opaque binding handle as the target scope", () => {
    expect(firewallReadScope("binding-one")).toBe("binding-one");
    expect(firewallReadScope("binding-one")).not.toBe(firewallReadScope("binding-two"));
  });

  it("filters hostile plain-text rules and independently bounds the visible window", () => {
    const hostile = "</pre><script>steal()</script>";
    const rules = [`allow 22`, hostile, ...Array.from({ length: 2_100 }, (_, index) => `drop ${index}`)]
      .join("\n");
    const filtered = firewallRuleView(rules, "SCRIPT");
    expect(filtered.text).toBe(hostile);
    expect(filtered.matchedLines).toBe(1);
    const all = firewallRuleView(rules, "");
    expect(all.displayedLines).toBe(2_000);
    expect(all.truncated).toBe(true);
    expect(new TextEncoder().encode(all.text).byteLength)
      .toBeLessThanOrEqual(MAX_FIREWALL_RULE_VIEW_BYTES);
    expect(firewallRuleView("", "")).toEqual({
      text: "",
      totalLines: 0,
      matchedLines: 0,
      displayedLines: 0,
      truncated: false,
    });
  });

  it("bounds UTF-8 without splitting a scalar", () => {
    expect(boundFirewallText("界".repeat(100), 256)).toBe("界".repeat(85));
  });

  it("copies only the already-bounded inspection rules", () => {
    const inspection: FirewallInspection = {
      snapshotHandle: "11111111-1111-4111-8111-111111111111",
      backend: "iptables",
      engine: "iptables",
      active: true,
      rules: "bounded rules",
      rulesTruncated: false,
      capturedAt: "2026-08-24T00:00:00Z",
      expiresInSeconds: 300,
    };
    expect(firewallCopyText(inspection)).toEqual({ text: "bounded rules", truncated: false });
    const oversized = {
      ...inspection,
      rules: `${"a".repeat(MAX_FIREWALL_CLIPBOARD_BYTES - 1)}界`,
    };
    const copy = firewallCopyText(oversized);
    expect(new TextEncoder().encode(copy.text).byteLength)
      .toBeLessThanOrEqual(MAX_FIREWALL_CLIPBOARD_BYTES);
    expect(copy.text.endsWith("界")).toBe(false);
    expect(copy.truncated).toBe(true);
  });

  it("maps only closed display labels", () => {
    expect(firewallBackendLabel("unknown")).toBe("未探测到");
    expect(firewallEngineLabel("unavailable")).toBe("仅查看");
    expect(firewallChangeKindLabel("isolate-inbound")).toContain("历史");
    expect(firewallChangeStateLabel("awaiting-keep")).toContain("只读记录");
  });
});
