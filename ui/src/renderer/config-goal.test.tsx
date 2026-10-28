import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ConfigGoalAssignment, ConfigGoalGap, ConfigGoalTarget } from "../shared/config-visual-contract";
import {
  ConfigGoalAssignmentCard,
  configGoalAssignmentSentence,
  configGoalBlockText,
  configGoalGapExplanation,
  configGoalGapLabel,
  configGoalRejectionText,
} from "./ConfigGoalPanel";

const target: ConfigGoalTarget = {
  product: "postgresql", productLabel: "PostgreSQL", artifactKey: "postgresql-main", fileLabel: "postgresql.conf",
  schema: { index: 3, label: "PostgreSQL 16.x", version: "16.0.0 及以上、低于 17.0.0", complete: false },
  parameterIndex: 4, key: "max_connections", group: null, valueDomain: "文本（1 到 32 字节，去掉首尾空白）",
  activation: "restart", risk: "high",
};
const lease = "00000000-0000-4000-8000-0000000000aa";
const noop = { onChoose: () => undefined, onConfirm: () => undefined };

describe("configuration goals", () => {
  it("shows a resolved assignment with where it lands, its version and an editable value", () => {
    const ready: ConfigGoalAssignment = { lease, state: "ready", target, value: "250", landing: "new-draft", blocked: null, candidates: [], rejection: null };
    const html = renderToStaticMarkup(<ConfigGoalAssignmentCard assignment={ready} working={false} {...noop} />);
    expect(html).toContain('data-testid="config-goal-assignment-ready"');
    expect(html).toContain("把 max_connections 写入 PostgreSQL 的 postgresql.conf");
    expect(html).toContain("PostgreSQL 16.x（16.0.0 及以上、低于 17.0.0） · 部分参数");
    expect(html).toContain("重启后生效");
    expect(html).toContain('value="250"');
    expect(html).toContain("新建一份只含这一项的草稿");
    const confirmButton = (markup: string) => markup.match(/<button[^>]*data-testid="config-goal-assignment-confirm"[^>]*>/u)?.[0] ?? "";
    expect(confirmButton(html)).not.toContain("disabled");

    const open = renderToStaticMarkup(<ConfigGoalAssignmentCard assignment={{ ...ready, landing: "open-draft" }} working={false} {...noop} />);
    expect(open).toContain("写进当前打开的文件");

    // Blocked before confirming: the reason is shown and confirming is off.
    const blocked = renderToStaticMarkup(<ConfigGoalAssignmentCard assignment={{ ...ready, landing: null, blocked: "duplicate" }}
      working={false} {...noop} />);
    expect(blocked).toContain('data-testid="config-goal-assignment-preflight-blocked"');
    expect(blocked).toContain("出现了多次");
    expect(confirmButton(blocked)).toContain("disabled=\"\"");
  });

  it("asks which parameter an ambiguous sentence means, and refuses others with a reason only", () => {
    const ambiguous: ConfigGoalAssignment = { lease, state: "ambiguous", target: null, value: null, landing: null, blocked: null,
      candidates: [{ ...target, product: "mariadb", productLabel: "MariaDB", key: "wait_timeout", group: "mysqld" },
        { ...target, product: "mariadb", productLabel: "MariaDB", key: "wait_timeout", group: "client-server" }],
      rejection: null };
    const html = renderToStaticMarkup(<ConfigGoalAssignmentCard assignment={ambiguous} working={false} {...noop} />);
    expect(html).toContain('data-testid="config-goal-assignment-ambiguous"');
    expect(html.match(/data-testid="config-goal-assignment-candidate"/gu)?.length).toBe(2);
    expect(html).toContain("[mysqld] wait_timeout");
    expect(html).not.toContain("config-goal-assignment-value");

    const refused = renderToStaticMarkup(<ConfigGoalAssignmentCard assignment={{ lease: null, state: "rejected", target: null,
      value: null, landing: null, blocked: null, candidates: [], rejection: "unsupported-operator" }} working={false} {...noop} />);
    expect(refused).toContain('data-testid="config-goal-assignment-blocked"');
    expect(refused).toContain("“改成”这类说法不会被当作赋值");
    expect(refused).not.toContain("config-goal-assignment-confirm");
  });

  it("says every reason in plain Chinese, without the catalogue's working words", () => {
    const gaps: ConfigGoalGap[] = ["no-reviewed-intent", "no-recipe", "no-version-catalogue", "version-not-catalogued",
      "file-not-editable", "no-value-rules", "needs-capability", "needs-outside-steps", "secret-value"];
    const texts = [
      ...gaps.flatMap((gap) => [configGoalGapLabel(gap), configGoalGapExplanation(gap)]),
      ...(["query-refused", "unsupported-operator", "value-refused", "too-many-candidates", "empty-value"] as const)
        .map(configGoalRejectionText),
      ...(["other-file-unsaved", "other-version-unsaved", "duplicate", "line-locked", "writer-refused"] as const)
        .map(configGoalBlockText),
    ];
    for (const text of texts) {
      expect(text).toMatch(/[一-鿿]/u);
      expect(text).not.toMatch(/Schema|schema|typed|TargetGuard|edition|core|renderer|sidecar/u);
    }
    // A parameter offers the sentence to finish, never a value of its own.
    expect(configGoalAssignmentSentence(target)).toBe("PostgreSQL @postgresql-main max_connections = ");
    expect(configGoalAssignmentSentence({ ...target, productLabel: "MariaDB", group: "mysqld", key: "wait_timeout" }))
      .toBe("MariaDB @postgresql-main [mysqld] wait_timeout = ");
  });

  it("keeps an assignment on its own in the generator's search and opens results in the visual editor", () => {
    const page = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(page).toContain("onAssignment={setGoalAssignmentShown}");
    expect(page).toContain("{goalAssignmentShown ? null : forbiddenGoal === null ? null : (");
    expect(page).toContain("{goalAssignmentShown ? null : searchResults.length === 0 ? (");
    const configuration = readFileSync(new URL("./ConfigurationPage.tsx", import.meta.url), "utf8");
    // The document is made first; if the generator keeps the page, it is let go.
    const open = configuration.slice(configuration.indexOf("async function openVisualView"));
    expect(open.indexOf("await create()")).toBeLessThan(open.indexOf("beforeDeactivate() === false"));
    expect(open).toContain('api.configVisual({ action: "close", documentHandle: opened.documentHandle');
  });
});
