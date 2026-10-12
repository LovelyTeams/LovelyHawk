import { describe, expect, it } from "vitest";

import { configFamilyLabel } from "./ConfigGeneratorPage";

describe("configuration product family labels", () => {
  it("names every catalogue family in words rather than its key", () => {
    for (const family of ["web", "proxy", "database", "cache", "application-server"]) {
      const label = configFamilyLabel(family);
      expect(label).not.toBe(family);
      expect(label).toMatch(/\p{Script=Han}/u);
    }
  });

  it("shows a family it does not know yet as it came instead of dropping it", () => {
    expect(configFamilyLabel("message-queue")).toBe("message-queue");
  });
});
