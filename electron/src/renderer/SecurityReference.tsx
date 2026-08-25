import { useMemo, useState } from "react";

import {
  filterSnippets,
  securityReferenceCatalog,
  type SecuritySnippet,
} from "./catalog";

interface SecurityReferenceProps {
  favoriteIds: string[];
  onFavoriteIdsChange(ids: string[]): Promise<string[]>;
}

export function SecurityReference({
  favoriteIds,
  onFavoriteIdsChange,
}: SecurityReferenceProps) {
  const [query, setQuery] = useState("");
  const [language, setLanguage] = useState("all");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const favorites = useMemo(() => new Set(favoriteIds), [favoriteIds]);
  const filtered = useMemo(
    () =>
      filterSnippets(
        securityReferenceCatalog.snippets,
        query,
        language,
        favorites,
        favoritesOnly,
      ),
    [favorites, favoritesOnly, language, query],
  );

  async function toggleFavorite(id: string) {
    if (saving) return;
    const next = new Set(favorites);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSaving(true);
    setNotice(null);
    try {
      await onFavoriteIdsChange([...next]);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "收藏保存失败。 ");
    } finally {
      setSaving(false);
    }
  }

  async function copy(text: string | null) {
    if (text === null) return;
    try {
      await window.lovelyres.writeClipboard(text);
      setNotice("已复制到剪贴板。");
    } catch {
      setNotice("复制失败。");
    }
  }

  return (
    <section className="page security-reference">
      <header className="page-heading">
        <div>
          <p className="eyebrow">离线知识库</p>
          <h1>安全速查</h1>
          <p>搜索本地随包分发的修复片段；任何内容都只按纯文本显示。</p>
        </div>
        <div className="result-count"><strong>{filtered.length}</strong><span>条结果</span></div>
      </header>

      <div className="reference-toolbar">
        <label className="search-field">
          <span>⌕</span>
          <input
            aria-label="搜索安全速查目录"
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
            placeholder="搜索漏洞、CVE、标签或修复内容"
            maxLength={256}
          />
        </label>
        <button
          className={favoritesOnly ? "chip active" : "chip"}
          type="button"
          onClick={() => setFavoritesOnly((value) => !value)}
        >
          ★ 仅收藏
        </button>
      </div>

      <div className="language-strip" role="list" aria-label="语言筛选">
        {securityReferenceCatalog.languages.map((item) => (
          <button
            className={language === item.key ? "language-pill active" : "language-pill"}
            key={item.key}
            type="button"
            onClick={() => setLanguage(item.key)}
          >
            {item.label}
          </button>
        ))}
      </div>

      {notice === null ? null : <div className="inline-notice">{notice}</div>}
      <div className="snippet-grid">
        {filtered.map((snippet) => (
          <SnippetCard
            expanded={expandedId === snippet.id}
            favorite={favorites.has(snippet.id)}
            key={snippet.id}
            onCopy={copy}
            onExpand={() => setExpandedId((current) => (current === snippet.id ? null : snippet.id))}
            onFavorite={() => void toggleFavorite(snippet.id)}
            snippet={snippet}
          />
        ))}
      </div>
      {filtered.length === 0 ? <div className="empty-state">没有匹配的本地速查条目。</div> : null}
    </section>
  );
}

interface SnippetCardProps {
  snippet: SecuritySnippet;
  expanded: boolean;
  favorite: boolean;
  onExpand(): void;
  onFavorite(): void;
  onCopy(text: string | null): Promise<void>;
}

function SnippetCard({
  snippet,
  expanded,
  favorite,
  onExpand,
  onFavorite,
  onCopy,
}: SnippetCardProps) {
  return (
    <article className={expanded ? "snippet-card expanded" : "snippet-card"}>
      <div className="snippet-topline">
        <span className="snippet-language">{snippet.lang}</span>
        <button
          aria-label={favorite ? "取消收藏" : "收藏"}
          className={favorite ? "favorite-button active" : "favorite-button"}
          type="button"
          onClick={onFavorite}
        >
          ★
        </button>
      </div>
      <button className="snippet-summary" type="button" onClick={onExpand}>
        <span>{snippet.vuln}</span>
        <strong>{snippet.title}</strong>
        <small>{snippet.desc}</small>
      </button>
      <div className="tag-row">
        {snippet.tags.slice(0, 4).map((tag) => <span key={tag}>{tag}</span>)}
      </div>
      {expanded ? (
        <div className="snippet-detail">
          <CodeBlock label="错误示例" text={snippet.bad} tone="bad" onCopy={onCopy} />
          <CodeBlock label="修复建议" text={snippet.fix} tone="good" onCopy={onCopy} />
          <CodeBlock label="排查命令" text={snippet.oneliner} tone="neutral" onCopy={onCopy} />
          <CodeBlock label="验证" text={snippet.verify} tone="neutral" onCopy={onCopy} />
        </div>
      ) : null}
    </article>
  );
}

function CodeBlock({
  label,
  text,
  tone,
  onCopy,
}: {
  label: string;
  text: string | null;
  tone: "bad" | "good" | "neutral";
  onCopy(text: string | null): Promise<void>;
}) {
  if (text === null || text.length === 0) return null;
  return (
    <div className={`code-block ${tone}`}>
      <div><span>{label}</span><button type="button" onClick={() => void onCopy(text)}>复制</button></div>
      <pre>{text}</pre>
    </div>
  );
}
