import { describe, expect, it } from "vitest";

import { filterSnippets, securityReferenceCatalog } from "./catalog";

describe("security-reference search", () => {
  it("keeps the frozen catalog complete", () => {
    expect(securityReferenceCatalog.schema).toBe("lovelyres-security-reference/v1");
    expect(securityReferenceCatalog.snippets).toHaveLength(107);
  });

  it("searches CVE, tags and fix content while pinning favorites", () => {
    const favorites = new Set(["py-sqli"]);
    const sql = filterSnippets(
      securityReferenceCatalog.snippets,
      "参数化查询",
      "all",
      favorites,
      false,
    );
    expect(sql.some((snippet) => snippet.id === "py-sqli")).toBe(true);
    const favoriteOnly = filterSnippets(
      securityReferenceCatalog.snippets,
      "",
      "all",
      favorites,
      true,
    );
    expect(favoriteOnly.map((snippet) => snippet.id)).toEqual(["py-sqli"]);
  });
});
