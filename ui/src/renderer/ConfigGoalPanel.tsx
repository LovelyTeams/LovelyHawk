import { useEffect, useRef, useState } from "react";

import {
  MAX_CONFIG_GOAL_QUERY_CHARS,
  isConfigGoalSearch,
  isConfigVisualView,
  type ConfigGoalAssignment,
  type ConfigGoalBlock,
  type ConfigGoalDocument,
  type ConfigGoalGap,
  type ConfigGoalRejection,
  type ConfigGoalResult,
  type ConfigGoalSearch,
  type ConfigGoalTarget,
  type ConfigVisualApi,
  type ConfigVisualView,
} from "../shared/config-visual-contract";
import { databaseActivationLabel, databaseRiskLabel } from "./DatabaseFilePanels";
import "./config-goal.css";

/*
 * The generator's search box read as goals, and a typed assignment held for
 * confirmation. Everything here comes from core's reviewed catalogue: a goal
 * found is guidance, a value written goes into a local draft only, and a
 * refusal says why without repeating the value.
 */

export function configGoalGapLabel(gap: ConfigGoalGap): string {
  switch (gap) {
    case "no-reviewed-intent": return "还没有收录这个目标";
    case "no-recipe": return "还没有可生成的做法";
    case "no-version-catalogue": return "缺少按版本审查的参数说明";
    case "version-not-catalogued": return "这个版本还没有收录";
    case "file-not-editable": return "这个文件不能在这里生成";
    case "no-value-rules": return "缺少可检查的取值规则";
    case "needs-capability": return "需要先确认目标具备相应能力";
    case "needs-outside-steps": return "还有配置文件之外的步骤";
    case "secret-value": return "含秘密的值不在这里填写";
  }
}

export function configGoalGapExplanation(gap: ConfigGoalGap): string {
  switch (gap) {
    case "no-reviewed-intent": return "这个产品已有部分目标或参数说明，但这句话没有对上任何一个；不会拿相近的做法来猜。";
    case "no-recipe": return "目前只登记了产品或文件格式，还没有把这个目标变成具体配置项的做法。";
    case "no-version-catalogue": return "已经知道配置文件，但还没有与具体版本对应的参数含义和取值范围。";
    case "version-not-catalogued": return "句子里指定的版本不在内置目录里；不会借用相邻版本的说明。";
    case "file-not-editable": return "参数说明存在，但对应的文件只读、格式还没有支持，或者不能保证其余内容原样保留。";
    case "no-value-rules": return "能看到参数名，但合法取值、范围或单位还没有整理成可检查的规则。";
    case "needs-capability": return "这个参数依赖插件、模块或特定功能，还没有对目标做过可靠的检测。";
    case "needs-outside-steps": return "配置文件只能完成一部分；访问控制、网络、重新加载和真实连接验证还要另外完成并核实。";
    case "secret-value": return "这个参数可能包含口令、私钥等秘密，页面不会保存、显示或复制它的明文。";
  }
}

export function configGoalRejectionText(rejection: ConfigGoalRejection): string {
  switch (rejection) {
    case "query-refused": return "这句话太长或含有控制字符。";
    case "unsupported-operator": return "请用“=”、“设为”或“设置为”表示赋值；“改成”这类说法不会被当作赋值。";
    case "missing-target": return "等号左边要以数据库产品名开头，例如 PostgreSQL 16 max_connections = 200。";
    case "missing-value": return "等号右边没有值。";
    case "multiple-operators": return "一句话里只能有一个赋值。";
    case "missing-product": return "没有认出是哪个数据库产品；请以产品名开头。";
    case "ambiguous-product": return "句子里提到了不止一个产品，不知道写给哪一个。";
    case "invalid-version": return "版本号写法不对，例如 16 或 8.0.36。";
    case "version-not-catalogued": return "这个版本还没有收录，不会借用相邻版本的说明。";
    case "no-version-catalogue": return "这个产品或文件还没有按版本审查的参数说明。";
    case "missing-parameter": return "没有写参数名。";
    case "invalid-qualifier": return "文件（@…）或分组（[…]）的写法不对，或者参数名里有空格。";
    case "unknown-file": return "@ 后面的文件不在内置目录里。";
    case "file-of-another-product": return "@ 后面的文件属于另一个产品。";
    case "unknown-group": return "这个参数不在所写的分组里。";
    case "unknown-parameter": return "所选版本的目录里没有这个参数。";
    case "unknown-candidate": return "所选的候选项已经不在列表里了。";
    case "too-many-candidates": return "符合的参数太多；请写上版本、文件（@…）或分组（[…]）缩小范围。";
    case "file-not-editable": return "这个参数所在的文件不能在这里生成。";
    case "secret-value": return "这个参数可能含秘密，不在这里填写。";
    case "needs-capability": return "这个参数需要先确认目标具备相应能力，不在这里直接写入。";
    case "no-value-rules": return "这个参数还没有可检查的取值规则，不在这里直接写入。";
    case "value-refused": return "这个值不符合所选版本目录对该参数的要求。";
    case "empty-value": return "这里不能写空值。";
  }
}

export function configGoalBlockText(block: ConfigGoalBlock): string {
  switch (block) {
    case "file-not-editable": return "这个文件不能在这里生成。";
    case "other-file-unsaved": return "可视化编辑里打开的另一个文件还有未另存的修改；先另存或放弃那些修改，再写入。";
    case "other-version-unsaved": return "打开的文件有未另存的修改，而且对照的是另一个版本；先另存，或把对照的版本换成这条赋值的版本。";
    case "duplicate": return "打开的文件里这个参数出现了多次，哪一行生效由服务器决定，所以这里不替你改。";
    case "line-locked": return "打开的文件里这个参数所在的那一行不能在这里修改（内容被隐藏或太长）。";
    case "ambiguous-group": return "这个参数在文件里的分组不明确，没有替你选。";
    case "writer-refused": return "这次写入没能通过检查，文档没有变化。";
  }
}

function targetName(target: ConfigGoalTarget): string {
  return target.group === null ? target.key : `[${target.group}] ${target.key}`;
}

function versionText(target: Pick<ConfigGoalTarget, "schema">): string {
  const { schema } = target;
  const range = schema.label.includes(schema.version) ? "" : `（${schema.version}）`;
  return `${schema.label}${range}${schema.complete ? "" : " · 部分参数"}`;
}

/** The assignment sentence for a parameter, for an operator to finish with a value. */
export function configGoalAssignmentSentence(target: ConfigGoalTarget): string {
  return `${target.productLabel} @${target.artifactKey} ${target.group === null ? "" : `[${target.group}] `}${target.key} = `;
}

/** An assignment written already: the same sentence never writes twice. */
function ConsumedAssignment() {
  return (
    <section className="config-goal-assignment is-done" data-testid="config-goal-assignment-consumed" aria-label="赋值">
      <p>这条赋值已经写入草稿。改一下句子可以写下一条。</p>
    </section>
  );
}

/** A resolved, ambiguous or refused assignment, and what confirming it does. */
export function ConfigGoalAssignmentCard({ assignment, working, onChoose, onConfirm }: {
  assignment: ConfigGoalAssignment;
  working: boolean;
  onChoose(candidate: number): void;
  onConfirm(value: string): void;
}) {
  const [value, setValue] = useState(assignment.value ?? "");
  // A new preview brings its own value; an edit in the box is kept until then.
  useEffect(() => { setValue(assignment.value ?? ""); }, [assignment.lease, assignment.value]);

  if (assignment.state === "rejected") {
    return (
      <section className="config-goal-assignment is-blocked" data-testid="config-goal-assignment-blocked" aria-label="赋值">
        <h3>没有当作赋值写入</h3>
        <p>{configGoalRejectionText(assignment.rejection)}</p>
        <p className="config-goal-hint">写法：产品 [版本] [@文件] [[分组]] 参数 = 值，例如 PostgreSQL 16 max_connections = 200。</p>
      </section>
    );
  }
  if (assignment.state === "ambiguous") {
    return (
      <section className="config-goal-assignment" data-testid="config-goal-assignment-ambiguous" aria-label="赋值">
        <h3>符合这句话的参数不止一个</h3>
        <p>请选择要写入哪一个；值在选好之前不会显示，也不会写入。</p>
        <ul className="config-goal-candidates">
          {assignment.candidates.map((candidate, index) => (
            <li key={`${candidate.schema.index}:${candidate.parameterIndex}`}>
              <button type="button" disabled={working} data-testid="config-goal-assignment-candidate"
                onClick={() => onChoose(index)}>
                <strong>{targetName(candidate)}</strong>
                <span>{`${versionText(candidate)} · ${candidate.fileLabel}`}</span>
              </button>
            </li>
          ))}
        </ul>
      </section>
    );
  }
  const { target } = assignment;
  return (
    <section className="config-goal-assignment" data-testid="config-goal-assignment-ready" aria-label="赋值">
      <h3>{`把 ${targetName(target)} 写入 ${target.productLabel} 的 ${target.fileLabel}`}</h3>
      <p className="config-goal-facts">
        {`对照版本：${versionText(target)} · 取值：${target.valueDomain} · ${databaseActivationLabel(target.activation)} · ${databaseRiskLabel(target.risk)}`}
      </p>
      <form onSubmit={(event) => { event.preventDefault(); if (assignment.blocked === null) onConfirm(value); }}>
        <label className="config-goal-value">
          <span>值（可以改；确认时会按所选版本的目录再检查一次）</span>
          <input value={value} maxLength={4096} spellCheck={false} data-testid="config-goal-assignment-value"
            onChange={(event) => setValue(event.target.value)} />
        </label>
        {assignment.blocked !== null ? (
          <p className="config-goal-blocking" role="alert" data-testid="config-goal-assignment-preflight-blocked">
            {configGoalBlockText(assignment.blocked)}
          </p>
        ) : (
          <p className="config-goal-hint">
            {assignment.landing === "open-draft"
              ? "确认后写进当前打开的文件：没有这一项就新加一行，只有一处就原位替换，写后读回核对。"
              : "确认后新建一份只含这一项的草稿，并在可视化编辑中打开；只写本地草稿，不会改动任何服务器。"}
          </p>
        )}
        <button type="submit" className="primary" data-testid="config-goal-assignment-confirm"
          disabled={working || assignment.blocked !== null || value.trim() === ""}>确认写入草稿</button>
      </form>
    </section>
  );
}

type GoalSearchState =
  | { status: "idle" }
  | { status: "searching" }
  | { status: "done"; search: ConfigGoalSearch; query: string }
  | { status: "failed"; message: string };

function errorText(error: unknown): string {
  return error instanceof Error && error.message.trim() !== "" ? error.message : "没有完成。";
}

/**
 * Reads the generator's search box as goals, a little after typing stops.
 * Answers to an older sentence are dropped.
 */
function useGoalSearch(api: Pick<ConfigVisualApi, "configVisual">, query: string, document: ConfigGoalDocument | null,
  enabled = true) {
  const [state, setState] = useState<GoalSearchState>({ status: "idle" });
  const sequence = useRef(0);
  const documentKey = document === null ? "" : `${document.documentHandle}:${document.revision}:${document.unsaved}`;
  const documentRef = useRef(document);
  documentRef.current = document;
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const trimmed = query.trim();
    const current = ++sequence.current;
    if (!enabled || trimmed === "" || [...trimmed].length > MAX_CONFIG_GOAL_QUERY_CHARS ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(trimmed)) {
      setState({ status: "idle" });
      return;
    }
    setState({ status: "searching" });
    const timer = window.setTimeout(() => {
      api.configVisual({ action: "goal-search", query: trimmed, document: documentRef.current })
        .then((answer) => {
          if (current !== sequence.current) return;
          if (!isConfigGoalSearch(answer)) throw new Error("目标搜索的结果没有通过校验。");
          setState({ status: "done", search: answer, query: trimmed });
        })
        .catch((error: unknown) => {
          if (current === sequence.current) setState({ status: "failed", message: errorText(error) });
        });
    }, 250);
    return () => window.clearTimeout(timer);
  }, [api, query, documentKey, enabled, refresh]);

  return {
    state,
    replace(search: ConfigGoalSearch) {
      if (state.status === "done") setState({ ...state, search });
    },
    again() { setRefresh((value) => value + 1); },
  };
}

/** Opens a database file in the visual editor, focused as asked. */
export type ConfigGoalOpenVisual = (
  create: () => Promise<ConfigVisualView>,
  focus: { dirty: boolean; parameterKey: string | null },
) => Promise<boolean>;

function OpenFileButton({ label, onOpen, working, testId }: {
  label: string; onOpen(): void; working: boolean; testId: string;
}) {
  return <button type="button" disabled={working} data-testid={testId} onClick={onOpen}>{label}</button>;
}

/**
 * The goal half of the generator's search: an assignment card on its own,
 * or reviewed recipes, database goals, parameters, files and gaps.
 */
export function ConfigGoalResults({ api, query, onRecipe, onQuery, onOpenVisual, onAssignment, hiddenRecipes = [] }: {
  api: Pick<ConfigVisualApi, "configVisual">;
  query: string;
  onRecipe(key: string): void;
  onQuery(query: string): void;
  onOpenVisual: ConfigGoalOpenVisual | undefined;
  /** Whether an assignment card is shown, so the page can keep other results out of its way. */
  onAssignment(shown: boolean): void;
  /** Recipes the page already offers in a card of its own. */
  hiddenRecipes?: readonly string[];
}) {
  const search = useGoalSearch(api, query, null);
  const [working, setWorking] = useState(false);
  const workingRef = useRef(false);
  const [message, setMessage] = useState<string | null>(null);
  const [consumedQuery, setConsumedQuery] = useState<string | null>(null);
  const done = search.state.status === "done" ? search.state : null;
  const assignment = done?.search.assignment ?? null;
  const consumed = consumedQuery !== null && consumedQuery === query.trim();
  const assignmentShown = assignment !== null || consumed;

  useEffect(() => { onAssignment(assignmentShown); }, [assignmentShown]);
  // An emptied search box takes this panel away; nothing is held back for it then.
  useEffect(() => () => onAssignment(false), []);
  useEffect(() => { setMessage(null); }, [query]);

  async function act(work: () => Promise<void>): Promise<void> {
    if (workingRef.current) return;
    workingRef.current = true;
    setWorking(true);
    setMessage(null);
    try {
      await work();
    } catch (error) {
      setMessage(errorText(error));
    } finally {
      workingRef.current = false;
      setWorking(false);
    }
  }

  function choose(candidate: number): void {
    if (assignment === null || assignment.lease === null) return;
    const lease = assignment.lease;
    void act(async () => {
      const answer = await api.configVisual({ action: "goal-choose", lease, candidate, document: null });
      if (!isConfigGoalSearch(answer)) throw new Error("候选项的结果没有通过校验。");
      search.replace(answer);
    });
  }

  function confirm(value: string): void {
    if (assignment === null || assignment.state !== "ready" || onOpenVisual === undefined) return;
    const { lease, target } = assignment;
    const sentence = query.trim();
    void act(async () => {
      const opened = await onOpenVisual(async () => {
        const view = await api.configVisual({ action: "goal-confirm", lease, value, document: null });
        if (!isConfigVisualView(view)) throw new Error("写入结果没有通过校验。");
        setConsumedQuery(sentence);
        return view;
      }, { dirty: true, parameterKey: target.key });
      // Staying here closed the new draft: look the sentence up again for a fresh preview.
      if (!opened) {
        setConsumedQuery(null);
        search.again();
      }
    });
  }

  function openFile(artifactKey: string, schema: number | null, parameterKey: string | null): void {
    if (onOpenVisual === undefined) return;
    void act(async () => {
      await onOpenVisual(async () => {
        const opened = await api.configVisual({ action: "new-database", artifactKey });
        if (!isConfigVisualView(opened)) throw new Error("文件没有通过校验。");
        if (schema === null || opened.database?.readOnly !== null) return opened;
        const chosen = await api.configVisual({ action: "select-schema", documentHandle: opened.documentHandle,
          revision: opened.revision, schema });
        if (!isConfigVisualView(chosen)) throw new Error("版本选择的结果没有通过校验。");
        return chosen;
      }, { dirty: false, parameterKey });
    });
  }

  if (search.state.status === "idle") return null;
  const failure = search.state.status === "failed" ? search.state.message : null;
  return (
    <div className="config-goal-results" data-testid="config-goal-results" aria-live="polite">
      {search.state.status === "searching" ? <p className="config-goal-hint">正在按目标查找…</p> : null}
      {failure !== null ? <p className="config-goal-blocking" role="alert">{failure}</p> : null}
      {message !== null ? <p className="config-goal-blocking" role="alert" data-testid="config-goal-message">{message}</p> : null}
      {consumed ? <ConsumedAssignment /> : assignment !== null ? (
        <ConfigGoalAssignmentCard assignment={assignment} working={working || onOpenVisual === undefined}
          onChoose={choose} onConfirm={confirm} />
      ) : done === null ? null : (
        <GoalResultList results={done.search.results} truncated={done.search.truncated} working={working}
          canOpen={onOpenVisual !== undefined} hiddenRecipes={hiddenRecipes} onRecipe={onRecipe} onQuery={onQuery}
          onOpenFile={openFile} />
      )}
    </div>
  );
}

function GoalResultList({ results, truncated, working, canOpen, hiddenRecipes, onRecipe, onQuery, onOpenFile }: {
  results: ConfigGoalResult[];
  truncated: boolean;
  working: boolean;
  canOpen: boolean;
  hiddenRecipes: readonly string[];
  onRecipe(key: string): void;
  onQuery(query: string): void;
  onOpenFile(artifactKey: string, schema: number | null, parameterKey: string | null): void;
}) {
  const recipes = results.filter((result): result is Extract<ConfigGoalResult, { kind: "recipe" }> =>
    result.kind === "recipe" && !hiddenRecipes.includes(result.key));
  const bundles = results.filter((result): result is Extract<ConfigGoalResult, { kind: "database-goal" }> =>
    result.kind === "database-goal");
  const parameters = results.filter((result): result is Extract<ConfigGoalResult, { kind: "database-parameter" }> =>
    result.kind === "database-parameter");
  const files = results.filter((result): result is Extract<ConfigGoalResult, { kind: "database-file" }> =>
    result.kind === "database-file");
  const gaps = results.filter((result): result is Extract<ConfigGoalResult, { kind: "unavailable" }> =>
    result.kind === "unavailable");
  if (recipes.length + bundles.length + parameters.length + files.length + gaps.length === 0) return null;
  return (
    <>
      {recipes.length === 0 ? null : (
        <section className="config-goal-group" data-testid="config-goal-recipes" aria-label="可以生成的目标">
          <h3>可以生成的目标</h3>
          <ul>
            {recipes.map((recipe) => (
              <li key={recipe.key}>
                <div>
                  <strong>{recipe.title}</strong><span>{recipe.productLabel}</span>
                  <p>{recipe.summary}</p>
                  <p className="config-goal-hint">{recipe.effect}</p>
                </div>
                <button type="button" disabled={working} onClick={() => onRecipe(recipe.key)}>在快速生成里设置</button>
              </li>
            ))}
          </ul>
        </section>
      )}
      {bundles.length === 0 ? null : (
        <section className="config-goal-group" data-testid="config-goal-database-bundles" aria-label="数据库目标">
          <h3>数据库目标（按版本的目录说明）</h3>
          <ul>
            {bundles.map((bundle) => (
              <li key={`${bundle.key}:${bundle.schema.index}`}>
                <div>
                  <strong>{bundle.title}</strong><span>{`${versionText(bundle)} · ${bundle.fileLabel}`}</span>
                  <p>{bundle.summary}</p>
                  <ol className="config-goal-steps">
                    {bundle.steps.map((step) => (
                      <li key={step.title} className={step.parameters.length === 0 ? "is-outside" : undefined}>
                        <strong>{step.title}{step.required ? "" : "（可选）"}</strong>
                        <span>{step.parameters.length === 0 ? "在配置文件之外完成" : step.parameters.join("、")}</span>
                        <small>{step.explanation}</small>
                      </li>
                    ))}
                  </ol>
                  {bundle.missingRequired > 0 ? (
                    <p className="config-goal-hint">{`有 ${bundle.missingRequired} 个必需步骤不能只靠这个文件完成。`}</p>
                  ) : null}
                  {bundle.gap === null ? null : <GapNote gap={bundle.gap} />}
                </div>
                {canOpen ? (
                  <OpenFileButton label="打开这个版本的文件" working={working} testId="config-goal-open-bundle"
                    onOpen={() => onOpenFile(bundle.artifactKey, bundle.schema.index, null)} />
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      )}
      {parameters.length === 0 ? null : (
        <section className="config-goal-group" data-testid="config-goal-database-parameters" aria-label="数据库参数">
          <h3>数据库参数</h3>
          <ul>
            {parameters.map(({ target, draftable, gap }) => (
              <li key={`${target.schema.index}:${target.parameterIndex}`}>
                <div>
                  <strong>{targetName(target)}</strong>
                  <span>{`${versionText(target)} · ${target.fileLabel}`}</span>
                  <p>{`取值：${target.valueDomain} · ${databaseActivationLabel(target.activation)} · ${databaseRiskLabel(target.risk)}`}</p>
                  {gap === null ? null : <GapNote gap={gap} />}
                </div>
                <div className="config-goal-actions">
                  {draftable ? (
                    <button type="button" disabled={working} data-testid="config-goal-write-sentence"
                      onClick={() => onQuery(configGoalAssignmentSentence(target))}>写一条赋值</button>
                  ) : null}
                  {canOpen ? (
                    <OpenFileButton label="在可视化编辑中查看" working={working} testId="config-goal-open-parameter"
                      onOpen={() => onOpenFile(target.artifactKey, target.schema.index, target.key)} />
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
      {files.length === 0 ? null : (
        <section className="config-goal-group" data-testid="config-goal-database-files" aria-label="数据库配置文件">
          <h3>数据库配置文件</h3>
          <ul>
            {files.map((file) => (
              <li key={file.artifactKey}>
                <div>
                  <strong>{file.fileLabel}</strong>
                  <span>{`${file.productLabel}${file.readOnly ? " · 只读" : ""}`}</span>
                  {file.gap === null ? null : <GapNote gap={file.gap} />}
                </div>
                {canOpen && file.opens ? (
                  <OpenFileButton label={file.readOnly ? "打开（只读）" : "打开起始内容"} working={working}
                    testId="config-goal-open-file" onOpen={() => onOpenFile(file.artifactKey, null, null)} />
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      )}
      {gaps.length === 0 ? null : (
        <section className="config-goal-group" data-testid="config-goal-unavailable" aria-label="暂时做不到">
          <h3>暂时做不到</h3>
          <ul>
            {gaps.map((gap) => (
              <li key={gap.subject}>
                <div>
                  <strong>{gap.subject}</strong>
                  <span>{coverageText(gap)}</span>
                  <GapNote gap={gap.gap} />
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
      {truncated ? <p className="config-goal-hint">结果太多，只列出了前面一部分；写得更具体一些可以缩小范围。</p> : null}
    </>
  );
}

function coverageText(gap: Extract<ConfigGoalResult, { kind: "unavailable" }>): string {
  const parts = [
    gap.recipes > 0 ? `已收录 ${gap.recipes} 个可生成的目标` : null,
    gap.parameters > 0 ? `${gap.parameters} 项按版本的参数说明` : null,
    gap.family === "database" && gap.files > 0 ? `${gap.files} 个配置文件` : null,
  ].filter((part) => part !== null);
  return parts.length === 0 ? "只登记了产品名称" : parts.join("、");
}

function GapNote({ gap }: { gap: ConfigGoalGap }) {
  return (
    <p className="config-goal-gap">
      <strong>{configGoalGapLabel(gap)}</strong>
      <span>{configGoalGapExplanation(gap)}</span>
    </p>
  );
}

/**
 * One assignment sentence against the database file open in the visual
 * editor: previewed first, and written only when confirmed.
 */
export function ConfigGoalAssignmentBox({ api, document, working, onLanded }: {
  api: Pick<ConfigVisualApi, "configVisual">;
  document: ConfigGoalDocument;
  working: boolean;
  /** The document the value went into: the open one, or a new draft. */
  onLanded(view: ConfigVisualView, message: string): Promise<void>;
}) {
  const [sentence, setSentence] = useState("");
  const search = useGoalSearch(api, sentence, document);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [message, setMessage] = useState<string | null>(null);
  const [consumedQuery, setConsumedQuery] = useState<string | null>(null);
  const done = search.state.status === "done" ? search.state : null;
  const assignment = done?.search.assignment ?? null;
  const consumed = consumedQuery !== null && consumedQuery === sentence.trim();

  async function act(work: () => Promise<void>): Promise<void> {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setMessage(null);
    try {
      await work();
    } catch (error) {
      setMessage(errorText(error));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  return (
    <section className="config-visual-panel config-goal-box" aria-label="用一句话写入参数" data-testid="config-goal-box">
      <h2>用一句话写入参数</h2>
      <label className="config-visual-search">
        <span>例如 PostgreSQL 16 max_connections = 200（先预览，确认后才写入）</span>
        <input type="search" value={sentence} maxLength={MAX_CONFIG_GOAL_QUERY_CHARS} spellCheck={false}
          data-testid="config-goal-box-input" onChange={(event) => { setSentence(event.target.value); setMessage(null); }} />
      </label>
      {message !== null ? <p className="config-goal-blocking" role="alert" data-testid="config-goal-message">{message}</p> : null}
      {search.state.status === "failed" ? <p className="config-goal-blocking" role="alert">{search.state.message}</p> : null}
      {consumed ? <ConsumedAssignment /> : assignment !== null ? (
        <ConfigGoalAssignmentCard assignment={assignment} working={working || busy}
          onChoose={(candidate) => {
            if (assignment.lease === null) return;
            const lease = assignment.lease;
            void act(async () => {
              const answer = await api.configVisual({ action: "goal-choose", lease, candidate, document });
              if (!isConfigGoalSearch(answer)) throw new Error("候选项的结果没有通过校验。");
              search.replace(answer);
            });
          }}
          onConfirm={(value) => {
            if (assignment.state !== "ready") return;
            const { lease, target } = assignment;
            const written = sentence.trim();
            void act(async () => {
              const view = await api.configVisual({ action: "goal-confirm", lease, value, document });
              if (!isConfigVisualView(view)) throw new Error("写入结果没有通过校验。");
              setConsumedQuery(written);
              await onLanded(view, view.documentHandle === document.documentHandle
                ? `已把 ${target.key} 写入当前文件，并按所选版本的目录核对过写回的内容。`
                : `已把 ${target.key} 写入一份新草稿。`);
            });
          }} />
      ) : done !== null ? (
        <p className="config-goal-hint">这不是一条赋值。要按目标查找参数、文件或做法，请到“生成新配置”的搜索框。</p>
      ) : null}
    </section>
  );
}
