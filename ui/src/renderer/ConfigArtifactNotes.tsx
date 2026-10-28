import { useMemo } from "react";

import type { ConfigVisualProduct } from "../shared/config-visual-contract";
import { configVisualFileItems } from "./config-visual-glossary";
import { configVisualKindLabel } from "./config-visual-helpers";

/**
 * What each directive in a generated draft means, in Chinese, under its
 * preview. The draft's bytes are not touched: the notes sit beside it.
 */
export function ConfigArtifactNotes({ product, text }: { product: ConfigVisualProduct; text: string }) {
  const items = useMemo(() => configVisualFileItems(product, text), [product, text]);
  if (items.length === 0) return null;
  return (
    <details className="config-artifact-notes" data-testid="config-artifact-notes">
      <summary>这份文件用到的 {items.length} 个配置项分别是什么意思</summary>
      <p className="config-artifact-notes-hint">说明是内置的固定文字，帮助理解每一项的作用；具体写法以目标上产品版本的官方文档为准。</p>
      <dl>
        {items.map((item) => (
          <div key={`${item.kind}:${item.name}`} className="config-artifact-note">
            <dt><code>{item.name}</code><span>{configVisualKindLabel(item.kind, product)}</span></dt>
            <dd>
              {item.help?.summary ?? "不在内置说明里，请对照官方文档。"}
              {item.help?.caution !== undefined ? <small>注意：{item.help.caution}</small> : null}
            </dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
