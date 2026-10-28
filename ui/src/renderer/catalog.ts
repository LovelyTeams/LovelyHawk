import rawCatalog from "../../assets/security_reference.json";

export interface CatalogLanguage {
  key: string;
  label: string;
}

export interface SecuritySnippet {
  id: string;
  lang: string;
  vuln: string;
  title: string;
  desc: string;
  bad: string | null;
  fix: string | null;
  oneliner: string | null;
  verify: string | null;
  cve: string | null;
  affected: string | null;
  tags: string[];
}

export interface SecurityReferenceCatalog {
  schema: "lovelyres-security-reference/v1";
  languages: CatalogLanguage[];
  snippets: SecuritySnippet[];
}

function isText(value: unknown, maximum = 64 * 1024): value is string {
  return typeof value === "string" && value.length <= maximum;
}

function optionalText(value: unknown): value is string | null {
  return value === null || isText(value);
}

export function validateCatalog(value: unknown): SecurityReferenceCatalog {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Invalid security-reference catalog.");
  }
  const candidate = value as Record<string, unknown>;
  if (
    candidate.schema !== "lovelyres-security-reference/v1" ||
    !Array.isArray(candidate.languages) ||
    candidate.languages.length > 64 ||
    !candidate.languages.every(
      (language) =>
        typeof language === "object" &&
        language !== null &&
        isText((language as Record<string, unknown>).key, 64) &&
        isText((language as Record<string, unknown>).label, 128),
    ) ||
    !Array.isArray(candidate.snippets) ||
    candidate.snippets.length > 512
  ) {
    throw new Error("Invalid security-reference catalog shape.");
  }
  for (const snippet of candidate.snippets) {
    if (typeof snippet !== "object" || snippet === null || Array.isArray(snippet)) {
      throw new Error("Invalid security-reference snippet.");
    }
    const item = snippet as Record<string, unknown>;
    if (
      ![item.id, item.lang, item.vuln, item.title, item.desc].every((field) => isText(field)) ||
      ![item.bad, item.fix, item.oneliner, item.verify, item.cve, item.affected].every(optionalText) ||
      !Array.isArray(item.tags) ||
      item.tags.length > 64 ||
      !item.tags.every((tag) => isText(tag, 128))
    ) {
      throw new Error("Invalid security-reference snippet fields.");
    }
  }
  return value as SecurityReferenceCatalog;
}

export const securityReferenceCatalog = validateCatalog(rawCatalog);

export function filterSnippets(
  snippets: SecuritySnippet[],
  query: string,
  language: string,
  favorites: ReadonlySet<string>,
  favoritesOnly: boolean,
): SecuritySnippet[] {
  const normalized = query.trim().toLocaleLowerCase("zh-CN");
  return snippets
    .filter((snippet) => language === "all" || snippet.lang === language)
    .filter((snippet) => !favoritesOnly || favorites.has(snippet.id))
    .filter((snippet) => {
      if (normalized.length === 0) return true;
      return [
        snippet.title,
        snippet.vuln,
        snippet.desc,
        snippet.cve,
        snippet.affected,
        ...snippet.tags,
        snippet.fix,
        snippet.oneliner,
      ]
        .filter((value): value is string => value !== null)
        .some((value) => value.toLocaleLowerCase("zh-CN").includes(normalized));
    })
    .sort((left, right) => {
      const favoriteOrder = Number(favorites.has(right.id)) - Number(favorites.has(left.id));
      return favoriteOrder || left.title.localeCompare(right.title, "zh-CN");
    });
}
