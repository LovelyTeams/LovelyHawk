import type {
  FirewallBackend,
  FirewallChangeKind,
  FirewallChangeState,
  FirewallEngine,
  FirewallInspection,
} from "../shared/firewall-read-contract";

const encoder = new TextEncoder();
export const MAX_FIREWALL_RULE_VIEW_BYTES = 128 * 1_024;
export const MAX_FIREWALL_RULE_VIEW_LINES = 2_000;
export const MAX_FIREWALL_CLIPBOARD_BYTES = 128 * 1_024;

export interface FirewallRuleView {
  text: string;
  totalLines: number;
  matchedLines: number;
  displayedLines: number;
  truncated: boolean;
}

export function firewallReadScope(bindingHandle: string): string {
  return bindingHandle;
}

export function boundFirewallText(value: string, maximumBytes: number): string {
  if (encoder.encode(value).byteLength <= maximumBytes) return value;
  const output: string[] = [];
  let bytes = 0;
  for (const character of value) {
    const characterBytes = encoder.encode(character).byteLength;
    if (bytes + characterBytes > maximumBytes) break;
    output.push(character);
    bytes += characterBytes;
  }
  return output.join("");
}

export function firewallRuleView(rules: string, query: string): FirewallRuleView {
  const lines = rules === "" ? [] : rules.split("\n");
  const normalized = query.trim().toLocaleLowerCase();
  const matched = normalized === ""
    ? lines
    : lines.filter((line) => line.toLocaleLowerCase().includes(normalized));
  const displayed: string[] = [];
  let bytes = 0;
  for (const line of matched) {
    if (displayed.length >= MAX_FIREWALL_RULE_VIEW_LINES) break;
    const lineBytes = encoder.encode(line).byteLength + (displayed.length === 0 ? 0 : 1);
    if (bytes + lineBytes > MAX_FIREWALL_RULE_VIEW_BYTES) break;
    displayed.push(line);
    bytes += lineBytes;
  }
  return {
    text: displayed.join("\n"),
    totalLines: lines.length,
    matchedLines: matched.length,
    displayedLines: displayed.length,
    truncated: displayed.length < matched.length,
  };
}

export function firewallCopyText(inspection: FirewallInspection): {
  text: string;
  truncated: boolean;
} {
  const text = boundFirewallText(inspection.rules, MAX_FIREWALL_CLIPBOARD_BYTES);
  return { text, truncated: text !== inspection.rules };
}

export function firewallBackendLabel(value: FirewallBackend): string {
  switch (value) {
    case "iptables": return "iptables";
    case "nftables": return "nftables";
    case "ufw": return "UFW";
    case "firewalld": return "firewalld";
    case "unknown": return "未探测到";
  }
}

export function firewallEngineLabel(value: FirewallEngine): string {
  switch (value) {
    case "iptables": return "iptables isolated chain";
    case "nftables": return "nftables isolated table";
    case "unavailable": return "仅查看";
  }
}

export function firewallChangeKindLabel(value: FirewallChangeKind): string {
  switch (value) {
    case "block-ipv4": return "历史 IPv4 封禁";
    case "temporary-block-ipv4": return "历史临时 IPv4 封禁";
    case "allow-tcp-port": return "历史 TCP 端口放行";
    case "isolate-inbound": return "历史入站隔离";
  }
}

export function firewallChangeStateLabel(value: FirewallChangeState): string {
  switch (value) {
    case "awaiting-keep": return "等待保留确认（只读记录）";
    case "kept": return "已保留";
    case "restored": return "已恢复";
    case "auto-restored": return "已自动恢复";
  }
}
