import { describe, expect, it } from "vitest";

import type { MiddlewareInstanceSummary } from "../shared/middleware-read-contract";
import {
  filterMiddlewareInstances,
  formatMiddlewareBytes,
  middlewareHistoryStateLabel,
  middlewareNodeKindLabel,
  middlewareProductLabel,
  middlewareRawReasonLabel,
  middlewareRoleLabel,
  middlewareScope,
  middlewareStatusLabel,
} from "./middleware-read-helpers";

const hostile = "</div><script>plain()</script>";
const instances: MiddlewareInstanceSummary[] = [{
  instanceHandle: "nginx-a",
  title: "Nginx 实例 1",
  product: "nginx",
  version: hostile,
  status: "active",
  statusText: "active / running",
  active: true,
  redacted: false,
  textTruncated: false,
}, {
  instanceHandle: "redis-a",
  title: "Redis 实例 1",
  product: "redis",
  version: "8.0",
  status: "failed",
  statusText: "failed / exit-code",
  active: false,
  redacted: false,
  textTruncated: false,
}];

describe("middleware read helpers", () => {
  it("filters safe remote text by search, product and closed status", () => {
    expect(filterMiddlewareInstances(instances, "script", "all", "all").map((item) => item.instanceHandle))
      .toEqual(["nginx-a"]);
    expect(filterMiddlewareInstances(instances, "", "redis", "failed").length).toBe(1);
    expect(filterMiddlewareInstances(instances, "", "nginx", "failed").length).toBe(0);
  });

  it("scopes renderer state only by the opaque binding handle", () => {
    expect(middlewareScope("binding-a")).toBe("binding-a");
    expect(middlewareScope("binding-a")).not.toBe(middlewareScope("binding-b"));
  });

  it("provides only closed labels and bounded byte summaries", () => {
    expect(middlewareProductLabel("apache-httpd")).toBe("Apache HTTPD");
    expect(middlewareStatusLabel("failed")).toBe("失败");
    expect(middlewareRoleLabel("included")).toBe("包含配置");
    expect(middlewareNodeKindLabel("opaque")).toBe("不透明区域");
    expect(middlewareRawReasonLabel("not-safe-text")).toContain("core");
    expect(middlewareHistoryStateLabel("automatically-restored")).toBe("已自动恢复");
    expect(formatMiddlewareBytes("2048")).toBe("2 KiB");
  });
});
