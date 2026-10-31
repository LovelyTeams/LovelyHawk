import { TransientNotice } from "./NotificationCenter";
import { useEffect, useLayoutEffect, useReducer, useRef, useState, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";

import { targetFailureMessage } from "./target-lost";

import {
  isDockerContainerSnapshot,
  isDockerLogs,
  isDockerReadCollection,
  isDockerReadInspection,
  isDockerSecurityAudit,
  type DockerCollectionKind,
  type DockerContainerInspection,
  type DockerImageInspection,
  type DockerLogs,
  type DockerNetworkInspection,
  type DockerReadApi,
  type DockerReadCollection,
  type DockerReadInspection,
  type DockerResourceKind,
  type DockerSecurityAudit,
  type DockerVolumeInspection,
} from "../shared/docker-read-contract";
import {
  dockerBooleanLabel,
  dockerCollectionForTab,
  dockerReadScope,
  dockerSecuritySeverityLabel,
  dockerSnapshotMinutes,
  dockerStateText,
  dockerStateTone,
  dockerStatusText,
  DOCKER_PAGE_SIZES,
  dockerDistinctImages,
  dockerDistinctStates,
  dockerMemoryUsed,
  dockerPercentValue,
  dockerStatCards,
  dockerTabCount,
  containerRuntimeLabel,
  containerRuntimeNextStep,
  containerRuntimeMessage,
  dockerTabLabel,
  filterDockerContainers,
} from "./docker-read-helpers";
import {
  createDockerReadState,
  dockerReadReducer,
  type DockerReadStatus,
  type DockerTab,
} from "./docker-read-state";
import {
  isDockerActionPlan,
  isDockerActionReceipt,
  type DockerActionPlan,
  type DockerWriteAction,
  type DockerWriteApi,
} from "../shared/docker-write-contract";
import {
  createDockerActionState,
  dockerActionReducer,
} from "./docker-action-state";
import { DockerActionDialog } from "./DockerActionDialog";
import { DockerFileDialog } from "./DockerFileDialog";
import type { ContainerFilesApi } from "../shared/exec-files-contract";
import type { DockerForensicsApi } from "../shared/docker-forensics-contract";
import { DockerForensicsPanel } from "./DockerForensicsPanel";
import {
  availableDockerActions,
  canOpenContainerShell,
  dockerActionLabel,
  dockerActionTone,
} from "./docker-action-helpers";
import { DockerIcon } from "./docker-icons";
import { menuStep, placeDropdown } from "./menu-placement";
import { useModalScrim } from "./modal-scrim";
import "./docker-page.css";

export interface DockerPageProps {
  bindingHandle: string | null;
  api: DockerReadApi & DockerWriteApi & ContainerFilesApi & DockerForensicsApi;
  /**
   * Deterministic standalone/SSR fixture; production leaves this unset.
   *
   * The Kubernetes page has carried one of these for a while, and without it
   * this page could only ever be rendered empty in a test — so every assertion
   * about how it looks with data had to be made by reading the JSX.
   */
  initialState?: ReturnType<typeof createDockerReadState>;
  /**
   * Takes a running container to the command workbench with it already
   * chosen as where the checks run.
   */
  onInvestigate?: ((kind: "container", name: string) => void) | undefined;
}

const tabs: readonly DockerTab[] = [
  "containers", "images", "networks", "volumes", "compose-projects", "security",
];
const LOG_TAIL = 200;

interface DockerActionOperation {
  api: DockerWriteApi;
  bindingHandle: string;
  requestId: number;
  plan: DockerActionPlan | null;
  busy: boolean;
}

/**
 * An image reference with a line break allowed after each `:`, `/` and `@`,
 * so a narrow column shows "alpine:" over "3.20" rather than "alpine:3." over
 * "20". The text itself is unchanged and still read as plain text.
 */
export function withImageBreaks(image: string): ReactNode {
  const parts = image.split(/(?<=[:/@])/u);
  return parts.map((part, index) => (
    <span key={index}>{part}{index < parts.length - 1 ? <wbr /> : null}</span>
  ));
}

function discardDockerAction(operation: DockerActionOperation) {
  const plan = operation.plan;
  operation.plan = null;
  if (plan !== null) {
    void operation.api.cancelDockerContainerAction(operation.bindingHandle, plan.planHandle).catch(() => {});
  }
}

export function DockerPage({ bindingHandle, api, initialState, onInvestigate }: DockerPageProps) {
  const [state, dispatch] = useReducer(
    dockerReadReducer,
    initialState ?? createDockerReadState(),
  );
  const [actionState, actionDispatch] = useReducer(
    dockerActionReducer,
    undefined,
    createDockerActionState,
  );
  const [snapshotVersion, setSnapshotVersion] = useState(0);
  const [collectionVersion, setCollectionVersion] = useState(0);
  const [auditVersion, setAuditVersion] = useState(0);
  // A failed window launch has nowhere else to be seen: the window that would
  // have carried the message is the one that did not open.
  const [terminalError, setTerminalError] = useState<string | null>(null);
  // Which container's files are open, if any. Cleared on target or snapshot change below.
  const [fileDialog, setFileDialog] = useState<{ containerHandle: string; containerName: string } | null>(null);
  // Narrowing and paging are the operator's view of the list, not part of it,
  // so they live here rather than in the snapshot reducer: a refresh should
  // not throw away the filter someone just set.
  const [stateFilter, setStateFilter] = useState("");
  const [imageFilter, setImageFilter] = useState("");
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState<number>(DOCKER_PAGE_SIZES[0]);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : dockerReadScope(bindingHandle);
  const stateIsCurrent = state.scope === scope;

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
    // A file dialog belongs to one target's container; it never outlives it.
    setFileDialog(null);
  }, [scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "snapshot-started", scope, request });
    void api.refreshDockerContainers(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isDockerContainerSnapshot(result)) throw new Error();
      dispatch({ type: "snapshot-loaded", scope, request, snapshot: result });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "snapshot-failed",
          scope,
          request,
          error: containerRuntimeMessage(reason),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, snapshotVersion, state.scope]);

  const snapshotHandle = state.snapshot?.snapshotHandle ?? null;
  const collectionKind = dockerCollectionForTab(state.tab);

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || collectionKind === null) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({
      type: "collection-started",
      scope,
      snapshotHandle,
      kind: collectionKind,
      request,
    });
    void api.getDockerCollection(bindingHandle, snapshotHandle, collectionKind).then((result) => {
      if (cancelled) return;
      if (!isDockerReadCollection(result) || result.kind !== collectionKind ||
        result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({
        type: "collection-loaded",
        scope,
        snapshotHandle,
        kind: collectionKind,
        request,
        collection: result,
      });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "collection-failed",
          scope,
          snapshotHandle,
          kind: collectionKind,
          request,
          error: targetFailureMessage(reason, "资源快照已过期、目标已变化或 Docker 响应无效。"),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, collectionKind, collectionVersion, scope, snapshotHandle, state.scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || state.tab !== "security") return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "audit-started", scope, snapshotHandle, request });
    void api.getDockerSecurityAudit(bindingHandle, snapshotHandle).then((result) => {
      if (cancelled) return;
      if (!isDockerSecurityAudit(result) || result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({ type: "audit-loaded", scope, snapshotHandle, request, audit: result });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "audit-failed",
          scope,
          snapshotHandle,
          request,
          error: "无法完成当前快照的只读安全审计。",
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, auditVersion, bindingHandle, scope, snapshotHandle, state.scope, state.tab]);

  const selectedResource = selectedInspectionResource(state);
  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || selectedResource === null) return;
    const { kind, handle } = selectedResource;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "inspection-started", scope, snapshotHandle, kind, handle, request });
    void api.inspectDockerResource(bindingHandle, snapshotHandle, kind, handle).then((result) => {
      if (cancelled) return;
      if (!isDockerReadInspection(result) || result.kind !== kind ||
        result.snapshotHandle !== snapshotHandle || result.resourceHandle !== handle) throw new Error();
      dispatch({ type: "inspection-loaded", scope, snapshotHandle, kind, handle, request, inspection: result });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "inspection-failed",
          scope,
          snapshotHandle,
          kind,
          handle,
          request,
          error: targetFailureMessage(reason, "所选资源已失效、目标已变化或调查结果无效。"),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, selectedResource?.handle, selectedResource?.kind, snapshotHandle, state.scope]);

  // Ownership outlives a render, but never the target or dialog that requested it.
  const actionRef = useRef<DockerActionOperation | null>(null);
  const actionSequence = useRef(0);
  const actionContext = useRef({ api, bindingHandle });
  actionContext.current = { api, bindingHandle };
  const renderedAction = actionRef.current;
  function isCurrentAction(operation: DockerActionOperation | null): operation is DockerActionOperation {
    return operation !== null && actionRef.current === operation &&
      actionContext.current.api === operation.api &&
      actionContext.current.bindingHandle === operation.bindingHandle;
  }
  useEffect(() => {
    actionDispatch({ type: "closed" });
    return () => {
      const operation = actionRef.current;
      if (operation?.api === api && operation.bindingHandle === bindingHandle) {
        actionRef.current = null;
        discardDockerAction(operation);
      }
    };
  }, [api, bindingHandle]);

  async function openAction(
    containerHandle: string,
    containerName: string,
    action: DockerWriteAction,
  ) {
    if (actionRef.current !== null || bindingHandle === null || snapshotHandle === null ||
      actionContext.current.api !== api || actionContext.current.bindingHandle !== bindingHandle) return;
    const operation: DockerActionOperation = {
      api, bindingHandle, requestId: ++actionSequence.current, plan: null, busy: true,
    };
    actionRef.current = operation;
    const request = operation.requestId;
    actionDispatch({
      type: "opened",
      requestId: request,
      containerHandle,
      containerName,
      action,
      actionLabel: dockerActionLabel(action),
    });
    try {
      const plan = await api.planDockerContainerAction(
        bindingHandle, snapshotHandle, containerHandle, containerName, action,
      );
      if (!isDockerActionPlan(plan)) throw new Error();
      operation.plan = plan;
      if (!isCurrentAction(operation)) { discardDockerAction(operation); return; }
      if (plan.containerHandle !== containerHandle || plan.containerName !== containerName ||
        plan.action !== action || plan.actionLabel !== dockerActionLabel(action) || plan.confirmed) throw new Error();
      actionDispatch({ type: "planned", requestId: request, plan });
    } catch (reason: unknown) {
      if (!isCurrentAction(operation)) return;
      discardDockerAction(operation);
      actionDispatch({
        type: "failed",
        requestId: request,
        message: targetFailureMessage(reason, "这个容器已经不在当前列表里，或者当前状态做不了这个动作。"),
      });
    } finally {
      operation.busy = false;
    }
  }

  async function runAction() {
    const operation = renderedAction;
    const plan = actionState.plan;
    if (!isCurrentAction(operation) || operation.busy || plan === null || operation.plan !== plan) return;
    operation.busy = true;
    const request = operation.requestId;
    actionDispatch({ type: "executing", requestId: request });
    try {
      // Approval and execution stay two calls. Nothing runs until the sidecar
      // has recorded that the operator pressed this button.
      const confirmed = await operation.api.confirmDockerContainerAction(operation.bindingHandle, plan.planHandle);
      if (!isCurrentAction(operation)) return;
      if (!isDockerActionPlan(confirmed) || !confirmed.confirmed ||
        confirmed.expiresInSeconds <= 0 || confirmed.expiresInSeconds > plan.expiresInSeconds ||
        confirmed.planHandle !== plan.planHandle || confirmed.containerHandle !== plan.containerHandle ||
        confirmed.containerName !== plan.containerName || confirmed.action !== plan.action ||
        confirmed.actionLabel !== plan.actionLabel || confirmed.beforeState !== plan.beforeState ||
        confirmed.summary !== plan.summary || confirmed.dangerous !== plan.dangerous ||
        confirmed.restoreDescription !== plan.restoreDescription) throw new Error();
      const receipt = await operation.api.executeDockerContainerAction(operation.bindingHandle, plan.planHandle);
      if (!isCurrentAction(operation)) return;
      if (!isDockerActionReceipt(receipt) || receipt.planHandle !== plan.planHandle ||
        receipt.containerName !== plan.containerName || receipt.actionLabel !== plan.actionLabel) throw new Error();
      operation.plan = null;
      actionDispatch({ type: "executed", requestId: request, receipt });
      // Whatever the verification said, the list is now out of date.
      setSnapshotVersion((version) => version + 1);
    } catch (reason: unknown) {
      if (!isCurrentAction(operation)) return;
      discardDockerAction(operation);
      actionDispatch({
        type: "failed",
        requestId: request,
        message: targetFailureMessage(reason, "操作没有完成，主机上的状态请再确认一次。"),
      });
    } finally {
      operation.busy = false;
    }
  }

  // Opening a window is not a mutation, so it does not go through plan and
  // confirm — but it is still a remote call that a double click would run
  // twice, and two windows for one container is exactly what the key on the
  // main-process side exists to prevent.
  const terminalRef = useRef(false);
  async function openContainerTerminal(containerHandle: string, containerName: string) {
    if (terminalRef.current || snapshotHandle === null) return;
    terminalRef.current = true;
    try {
      await api.openDockerContainerTerminal(snapshotHandle, containerHandle, containerName);
    } catch (reason: unknown) {
      setTerminalError(targetFailureMessage(
        reason,
        `打不开 ${containerName} 的终端，这个容器里可能没有可用的 shell。`,
      ));
    } finally {
      terminalRef.current = false;
    }
  }

  function closeAction() {
    if (!isCurrentAction(renderedAction)) return;
    actionRef.current = null;
    discardDockerAction(renderedAction);
    actionDispatch({ type: "closed" });
  }

  if (bindingHandle === null) {
    return (
      <section className="page docker-page">
        <div className="docker-connect-prompt">
          <span aria-hidden="true">◇</span>
          <h1>连接目标后调查 Docker</h1>
          <p>连上之后可以看容器、镜像、网络、存储卷与安全审计；启停容器这类操作要先确认再执行。</p>
        </div>
      </section>
    );
  }

  const visibleState = stateIsCurrent ? state : createDockerReadState();
  const visibleCollectionKind = dockerCollectionForTab(visibleState.tab);
  const visibleCollection = visibleCollectionKind === null
    ? null
    : visibleState.collections[visibleCollectionKind] ?? null;

  async function loadLogs() {
    const snapshot = visibleState.snapshot;
    const handle = visibleState.selectedContainerHandle;
    if (scope === null || bindingHandle === null || snapshot === null || handle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "logs-started", scope, snapshotHandle: snapshot.snapshotHandle, handle, request });
    try {
      const result = await api.getDockerLogs(bindingHandle, snapshot.snapshotHandle, handle, LOG_TAIL);
      if (!isDockerLogs(result) || result.snapshotHandle !== snapshot.snapshotHandle ||
        result.containerHandle !== handle || result.tail !== LOG_TAIL) throw new Error();
      dispatch({
        type: "logs-loaded",
        scope,
        snapshotHandle: snapshot.snapshotHandle,
        handle,
        request,
        logs: result,
      });
    } catch {
      dispatch({
        type: "logs-failed",
        scope,
        snapshotHandle: snapshot.snapshotHandle,
        handle,
        request,
        error: "无法读取所选容器的日志。",
      });
    }
  }

  return (
    <section className="page docker-page" aria-label="Docker 调查与处置">
      {/* One line of identity, one line of fact. The old header stacked an
          all-caps kicker, a generic title and a subtitle, then a coloured
          banner under it — four bands before the first row of data, and the
          banner's text ("操作均未开放") had stopped being true. */}
      {/* Pinned: the operator scrolls a long container list constantly, and
          losing the runtime name, the counts and the tabs on the way down
          means scrolling back up to find out where they are. */}
      <div className="docker-page-top">
      <header className="docker-page-header">
        <div className="docker-page-identity">
          {/* Names what actually answered. A Podman machine used to read as
              an empty Docker one, which looks like an answer and is not. */}
          <h1>{visibleState.snapshot === null
            ? "容器"
            : containerRuntimeLabel(visibleState.snapshot.runtime)}</h1>
          {visibleState.snapshot !== null && (
            <span className="docker-runtime-tag">
              {visibleState.snapshot.containers.length} 个容器
              {" · "}
              快照 {dockerSnapshotMinutes(visibleState.snapshot.expiresInSeconds)}后失效
            </span>
          )}
        </div>
        <button
          className="docker-primary-button"
          type="button"
          disabled={visibleState.snapshotStatus === "loading"}
          onClick={() => setSnapshotVersion((version) => version + 1)}
        >
          {visibleState.snapshotStatus === "loading" ? "读取中…" : "刷新"}
        </button>
      </header>

      {/* The six numbers an operator wants before deciding where to look.
          Only counts that are actually loaded show a number; a card whose
          collection has not been read yet says so rather than showing a
          zero, because a zero here reads as "there are none". */}
      {visibleState.snapshot !== null && (
        <div className="docker-stat-row">
          {dockerStatCards(visibleState).map((card) => (
            <article key={card.id} className={`docker-stat-card is-${card.tone}`}>
              <span className="docker-stat-icon"><DockerIcon name={card.icon} size={19} /></span>
              <div>
                <p className="docker-stat-label">{card.label}</p>
                <p className="docker-stat-value">{card.value ?? "—"}</p>
                <p className="docker-stat-detail">{card.detail}</p>
              </div>
            </article>
          ))}
        </div>
      )}

      {/* Counts on the tabs, because "how many networks are there" is a
          question the operator is asking anyway and the tab strip was empty
          space that could answer it without a click. */}
      <nav className="docker-tabs view-tabs" aria-label="Docker 资源视图" hidden={visibleState.snapshotStatus === "error" && visibleState.snapshot === null}>
        {tabs.map((tab) => {
          const count = dockerTabCount(visibleState, tab);
          return (
            <button
              key={tab}
              type="button"
              aria-current={visibleState.tab === tab ? "page" : undefined}
              className={visibleState.tab === tab ? "docker-tab is-active" : "docker-tab"}
              onClick={() => dispatch({ type: "tab-selected", tab })}
            >
              {dockerTabLabel(tab)}
              {count === null ? null : <em>{count}</em>}
            </button>
          );
        })}
      </nav>
      </div>

      {/* When nothing could be listed at all, one panel says why and what to
          do; the error line above a second empty box said it twice. */}
      {visibleState.error !== null && !(visibleState.snapshotStatus === "error" && visibleState.snapshot === null) &&
        <TransientNotice source="容器管理" message={visibleState.error ?? ""} severity="error"><p className="docker-error" role="alert">{visibleState.error}</p></TransientNotice>}
      {visibleState.snapshotStatus === "loading" && visibleState.snapshot === null && (
        <StatusPanel label="正在读取这台主机上的容器…" />
      )}
      {visibleState.snapshotStatus === "error" && visibleState.snapshot === null && (
        <div role="alert" data-testid="docker-unavailable">
          <EmptyPanel title={visibleState.error ?? "没能读取容器清单。"} detail={containerRuntimeNextStep(visibleState.error)} />
        </div>
      )}
      {visibleState.snapshotStatus === "ready" && visibleState.snapshot !== null && (
        <main className="docker-page-content">
          {visibleState.tab === "containers" && (
            <ContainersView
              state={visibleState}
              collection={visibleCollection?.kind === "stats" ? visibleCollection : null}
              onFilter={(filter) => { dispatch({ type: "filter-changed", filter }); setPageIndex(0); }}
              onSelect={(handle) => dispatch({ type: "container-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
              onLoadLogs={() => void loadLogs()}
              onAction={(handle, name, action) => void openAction(handle, name, action)}
              onOpenTerminal={(handle, name) => void openContainerTerminal(handle, name)}
              onOpenFiles={(handle, name) => setFileDialog({ containerHandle: handle, containerName: name })}
              onInvestigate={onInvestigate}
              terminalError={terminalError}
              stateFilter={stateFilter}
              imageFilter={imageFilter}
              onStateFilter={(value) => { setStateFilter(value); setPageIndex(0); }}
              onImageFilter={(value) => { setImageFilter(value); setPageIndex(0); }}
              pageIndex={pageIndex}
              pageSize={pageSize}
              onPage={setPageIndex}
              onPageSize={(size) => { setPageSize(size); setPageIndex(0); }}
            />
          )}
          {visibleState.tab === "images" && (
            <ImagesView
              state={visibleState}
              status={visibleState.collectionStatus.images ?? "idle"}
              collection={visibleCollection?.kind === "images" ? visibleCollection : null}
              onSelect={(handle) => dispatch({ type: "image-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "networks" && (
            <NetworksView
              state={visibleState}
              collection={visibleCollection?.kind === "networks" ? visibleCollection : null}
              onSelect={(handle) => dispatch({ type: "network-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "volumes" && (
            <VolumesView
              state={visibleState}
              collection={visibleCollection?.kind === "volumes" ? visibleCollection : null}
              onSelect={(handle) => dispatch({ type: "volume-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "compose-projects" && (
            <ComposeView
              status={visibleState.collectionStatus["compose-projects"] ?? "idle"}
              collection={visibleCollection?.kind === "compose-projects" ? visibleCollection : null}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "security" && (
            <DockerSecurityView
              status={visibleState.auditStatus}
              audit={visibleState.audit}
              onRefresh={() => setAuditVersion((version) => version + 1)}
            />
          )}
        </main>
      )}
      {/* A dialog, not a column beside the table. Details are read in bursts —
          click a row, look, close — and a permanent rail charged the table a
          third of its width for the rest of the session to pay for that. */}
      {selectedResource !== null && (
        <InspectionDialog
          status={visibleState.inspectionStatus}
          inspection={visibleState.inspection}
          onClose={() => dispatch({ type: "selection-cleared" })}
          extra={selectedResource.kind === "container" && bindingHandle !== null && snapshotHandle !== null ? (
            <DockerForensicsPanel
              // A new container is a new panel: nothing read for the last one carries over.
              key={selectedResource.handle}
              api={api}
              bindingHandle={bindingHandle}
              snapshotHandle={snapshotHandle}
              containerHandle={selectedResource.handle}
              running={visibleState.snapshot?.containers.some((container) =>
                container.containerHandle === selectedResource.handle && container.state === "running") === true}
            />
          ) : undefined}
        />
      )}
      {isCurrentAction(renderedAction) && actionState.request !== null && (
        <DockerActionDialog
          containerName={actionState.request.containerName}
          actionLabel={actionState.request.actionLabel}
          plan={actionState.plan}
          receipt={actionState.receipt}
          busy={actionState.busy}
          error={actionState.error}
          onConfirm={() => void runAction()}
          onClose={closeAction}
        />
      )}
      {fileDialog !== null && snapshotHandle !== null && (
        <DockerFileDialog
          api={api}
          bindingHandle={bindingHandle}
          snapshotHandle={snapshotHandle}
          containerHandle={fileDialog.containerHandle}
          containerName={fileDialog.containerName}
          onClose={() => setFileDialog(null)}
        />
      )}
    </section>
  );
}

function selectedInspectionResource(state: ReturnType<typeof createDockerReadState>): {
  kind: DockerResourceKind;
  handle: string;
} | null {
  if (state.tab === "containers" && state.selectedContainerHandle !== null) {
    return { kind: "container", handle: state.selectedContainerHandle };
  }
  if (state.tab === "images" && state.selectedImageHandle !== null) {
    return { kind: "image", handle: state.selectedImageHandle };
  }
  if (state.tab === "networks" && state.selectedNetworkHandle !== null) {
    return { kind: "network", handle: state.selectedNetworkHandle };
  }
  if (state.tab === "volumes" && state.selectedVolumeHandle !== null) {
    return { kind: "volume", handle: state.selectedVolumeHandle };
  }
  return null;
}

interface ContainersViewProps {
  state: ReturnType<typeof createDockerReadState>;
  collection: Extract<DockerReadCollection, { kind: "stats" }> | null;
  onFilter(filter: string): void;
  onSelect(handle: string): void;
  onRefresh(): void;
  onLoadLogs(): void;
  onAction(containerHandle: string, containerName: string, action: DockerWriteAction): void;
  onOpenTerminal(containerHandle: string, containerName: string): void;
  onOpenFiles(containerHandle: string, containerName: string): void;
  onInvestigate?: ((kind: "container", name: string) => void) | undefined;
  terminalError: string | null;
  stateFilter: string;
  imageFilter: string;
  onStateFilter(value: string): void;
  onImageFilter(value: string): void;
  pageIndex: number;
  pageSize: number;
  onPage(index: number): void;
  onPageSize(size: number): void;
}

function ContainersView({
  state,
  collection,
  onFilter,
  onSelect,
  onRefresh,
  onLoadLogs,
  onAction,
  onOpenTerminal,
  onOpenFiles,
  onInvestigate,
  terminalError,
  stateFilter,
  imageFilter,
  onStateFilter,
  onImageFilter,
  pageIndex,
  pageSize,
  onPage,
  onPageSize,
}: ContainersViewProps) {
  const all = state.snapshot?.containers ?? [];
  const containers = filterDockerContainers(all, state.filter)
    .filter((item) => stateFilter === "" || item.state === stateFilter)
    .filter((item) => imageFilter === "" || item.image === imageFilter);
  const statsByHandle = new Map(collection?.items.map((item) => [item.containerHandle, item]) ?? []);
  const pageCount = Math.max(1, Math.ceil(containers.length / pageSize));
  // Clamped rather than trusted: a filter that shrinks the list while the
  // operator is on page four would otherwise leave them staring at an empty
  // table that looks like "no results".
  const safeIndex = Math.min(pageIndex, pageCount - 1);
  const page = containers.slice(safeIndex * pageSize, safeIndex * pageSize + pageSize);
  return (
    <>
      <ViewHeader
        title="容器与实时统计"
        status={state.collectionStatus.stats ?? "idle"}
        onRefresh={onRefresh}
      />
      {terminalError !== null && <TransientNotice source="容器管理" message={terminalError ?? ""} severity="error"><p className="docker-error" role="alert">{terminalError}</p></TransientNotice>}
      {/* Free text plus the two things worth narrowing by that the snapshot
          actually knows. Labels and nodes are not offered: the runtime gives
          neither on this page, and an empty dropdown is worse than no
          dropdown. */}
      <div className="docker-filter-row">
        <label className="docker-search">
          <span className="docker-search-glyph"><DockerIcon name="search" /></span>
          <input
            type="search"
            value={state.filter}
            placeholder="搜索容器名称、镜像或端口…"
            aria-label="搜索容器"
            onChange={(event) => onFilter(event.currentTarget.value)}
          />
        </label>
        <label className="docker-select">
          <span>状态</span>
          <select value={stateFilter} onChange={(event) => onStateFilter(event.currentTarget.value)}>
            <option value="">全部</option>
            {dockerDistinctStates(all).map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </label>
        <label className="docker-select">
          <span>镜像</span>
          <select value={imageFilter} onChange={(event) => onImageFilter(event.currentTarget.value)}>
            <option value="">全部</option>
            {dockerDistinctImages(all).map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </label>
      </div>
      {containers.length === 0 ? (
        <EmptyPanel
          title={(state.snapshot?.containers.length ?? 0) === 0 ? "当前目标没有 Docker 容器" : "没有匹配的容器"}
          detail="调整筛选条件或刷新快照。"
        />
      ) : (
        <div className="docker-table-wrap">
          <table className="docker-table">
            <thead>
              <tr>
                <th>容器</th><th>镜像</th><th>状态</th><th>CPU</th><th>内存</th>
                <th>网络 I/O</th><th>端口</th><th>运行时长</th><th>操作</th>
              </tr>
            </thead>
            <tbody>
              {page.map((container) => {
                const stats = statsByHandle.get(container.containerHandle);
                const actions = availableDockerActions(container.state);
                const selected = state.selectedContainerHandle === container.containerHandle;
                return (
                  <tr key={container.containerHandle} className={selected ? "is-selected" : undefined}>
                    <td>
                      <div className="docker-name-cell">
                        <span className="docker-row-glyph"><DockerIcon name="container" size={13} /></span>
                        <div>
                          <button className="docker-row-button" type="button" title={container.name || undefined}
                            onClick={() => onSelect(container.containerHandle)}>
                            {container.name || "（未命名）"}
                          </button>
                          {/* The runtime's own short id, so what is on screen
                              matches what `docker ps` on the machine prints.
                              Display only — every call still goes by handle. */}
                          <small className="docker-short-id">{container.shortId}</small>
                        </div>
                      </div>
                    </td>
                    <td className="docker-cell-image">{container.image ? withImageBreaks(container.image) : "—"}</td>
                    <td>
                      {/* The state is the first thing an operator scans for,
                          and it was a sentence in the same weight as every
                          other cell. The word is what matters; the rest of the
                          status line is detail beside it. */}
                      <span className={`docker-state is-${dockerStateTone(container.state)}`} title={container.state || undefined}>
                        {dockerStateText(container.state)}
                      </span>
                    </td>
                    <td className="docker-cell-metric">
                      <span>{stats?.cpuPercent || "—"}</span>
                      <DockerMeter percent={stats?.cpuPercent} />
                    </td>
                    <td className="docker-cell-metric">
                      <span>{dockerMemoryUsed(stats?.memoryUsage) || "—"}</span>
                      <DockerMeter percent={stats?.memoryPercent} />
                    </td>
                    <td className="docker-cell-metric"><span>{stats?.networkIo || "—"}</span></td>
                    <td className="docker-cell-ports">{container.ports || "—"}</td>
                    {/* The runtime's own words for how long it has been up.
                        Not computed from the creation time: the two disagree
                        for anything that has been restarted. */}
                    <td className="docker-cell-uptime" title={container.status || undefined}>{dockerStatusText(container.status)}</td>
                    <td>
                      {/* Only what this container can do from where it is.
                          Anything offered here is still re-checked remotely
                          before a plan exists. */}
                      <RowActions
                        container={container}
                        actions={actions}
                        onAction={onAction}
                        onOpenTerminal={onOpenTerminal}
                        onOpenFiles={onOpenFiles}
                        onInvestigate={onInvestigate}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {containers.length > 0 && (
        <div className="docker-table-footer">
          <span className="docker-muted">共 {containers.length} 条</span>
          <div className="docker-pager">
            <label className="docker-select is-compact">
              <select
                aria-label="每页条数"
                value={String(pageSize)}
                onChange={(event) => onPageSize(Number(event.currentTarget.value))}
              >
                {DOCKER_PAGE_SIZES.map((size) => (
                  <option key={size} value={String(size)}>{size} 条/页</option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="docker-page-step"
              aria-label="上一页"
              disabled={safeIndex === 0}
              onClick={() => onPage(safeIndex - 1)}
            >
              ‹
            </button>
            <span className="docker-page-current">{safeIndex + 1} / {pageCount}</span>
            <button
              type="button"
              className="docker-page-step"
              aria-label="下一页"
              disabled={safeIndex + 1 >= pageCount}
              onClick={() => onPage(safeIndex + 1)}
            >
              ›
            </button>
          </div>
        </div>
      )}
      <TruncatedNotice value={(state.snapshot?.truncated ?? false) || (collection?.truncated ?? false)} />
      {state.selectedContainerHandle !== null && (
        <section className="docker-card docker-logs-card">
          <div className="docker-section-heading">
            <div><h3>最近日志</h3><p>固定读取最后 {LOG_TAIL} 行，输出最多 256 KiB。</p></div>
            <button type="button" onClick={onLoadLogs} disabled={state.logsStatus === "loading"}>
              {state.logsStatus === "loading" ? "读取中…" : "读取最近日志"}
            </button>
          </div>
          {state.logsStatus === "idle" && <p className="docker-muted">按需读取，不持续跟踪远端输出。</p>}
          {state.logsStatus === "error" && <p className="docker-inline-error">日志不可用。</p>}
          {state.logsStatus === "ready" && state.logs !== null && <DockerLogsText logs={state.logs} />}
        </section>
      )}
    </>
  );
}

function ImagesView({ state, status, collection, onSelect, onRefresh }: {
  state: ReturnType<typeof createDockerReadState>;
  status: DockerReadStatus;
  collection: Extract<DockerReadCollection, { kind: "images" }> | null;
  onSelect(handle: string): void;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="镜像盘点" status={status} onRefresh={onRefresh} />
      {status === "loading" && collection === null ? <StatusPanel label="正在读取镜像…" /> :
        collection === null || collection.items.length === 0 ? <EmptyPanel title="没有镜像记录" detail="刷新当前资源以再次调查。" /> : (
          <div className="docker-card-grid">
            {/* A button, not an article: an image is worth opening — what it
                runs as, what it starts, what got baked into it. */}
            {collection.items.map((item) => (
              <button
                type="button"
                className={`docker-card${state.selectedImageHandle === item.imageHandle ? " is-selected" : ""}`}
                key={item.imageHandle}
                onClick={() => onSelect(item.imageHandle)}
              >
                <h3>{imageDisplayName(item.repository, item.tag, item.shortId)}</h3>
                <dl>
                  <dt>短 id</dt><dd>{item.shortId || "—"}</dd>
                  <dt>大小</dt><dd>{item.size || "—"}</dd>
                  <dt>创建时间</dt><dd>{item.createdAt || "—"}</dd>
                </dl>
              </button>
            ))}
          </div>
        )}
      <TruncatedNotice value={collection?.truncated ?? false} />
    </>
  );
}

function NetworksView({ state, collection, onSelect, onRefresh }: {
  state: ReturnType<typeof createDockerReadState>;
  collection: Extract<DockerReadCollection, { kind: "networks" }> | null;
  onSelect(handle: string): void;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="网络盘点" status={state.collectionStatus.networks ?? "idle"} onRefresh={onRefresh} />
      {collection === null || collection.items.length === 0 ? <EmptyPanel title="没有网络记录" detail="当前只展示 Docker 返回的清单。" /> : (
        <div className="docker-resource-list" role="list">
          {collection.items.map((item) => (
            <button key={item.networkHandle} role="listitem" type="button" className={state.selectedNetworkHandle === item.networkHandle ? "is-selected" : undefined} onClick={() => onSelect(item.networkHandle)}>
              <strong>{item.name || "（未命名）"}</strong><span>{item.driver || "—"} · {item.scope || "—"}</span>
              <small>内部：{dockerBooleanLabel(item.internal)} · IPv6：{dockerBooleanLabel(item.ipv6)}</small>
            </button>
          ))}
        </div>
      )}
      <TruncatedNotice value={collection?.truncated ?? false} />
    </>
  );
}

function VolumesView({ state, collection, onSelect, onRefresh }: {
  state: ReturnType<typeof createDockerReadState>;
  collection: Extract<DockerReadCollection, { kind: "volumes" }> | null;
  onSelect(handle: string): void;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="存储卷盘点" status={state.collectionStatus.volumes ?? "idle"} onRefresh={onRefresh} />
      {collection === null || collection.items.length === 0 ? <EmptyPanel title="没有存储卷记录" detail="当前只展示 Docker 返回的清单。" /> : (
        <div className="docker-resource-list" role="list">
          {collection.items.map((item) => (
            <button key={item.volumeHandle} role="listitem" type="button" className={state.selectedVolumeHandle === item.volumeHandle ? "is-selected" : undefined} onClick={() => onSelect(item.volumeHandle)}>
              <strong>{item.name || "（未命名）"}</strong><span>{item.driver || "—"} · {item.scope || "—"}</span>
              <small>{item.mountpoint || "无挂载点信息"}</small>
            </button>
          ))}
        </div>
      )}
      <TruncatedNotice value={collection?.truncated ?? false} />
    </>
  );
}

function ComposeView({ status, collection, onRefresh }: {
  status: DockerReadStatus;
  collection: Extract<DockerReadCollection, { kind: "compose-projects" }> | null;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="Compose 项目盘点" status={status} onRefresh={onRefresh} />
      {status === "loading" && collection === null ? <StatusPanel label="正在读取 Compose 项目…" /> :
        collection === null || collection.items.length === 0 ? <EmptyPanel title="没有 Compose 项目" detail="没有返回可展示的项目记录。" /> : (
          <div className="docker-card-grid">
            {collection.items.map((item, index) => (
              <article className="docker-card" key={`${item.name}\0${index}`}>
                <h3>{item.name || "（未命名）"}</h3><p>{item.status || "—"}</p>
                <dl><dt>服务</dt><dd>{item.services}</dd><dt>运行中</dt><dd>{item.running}</dd><dt>已停止</dt><dd>{item.stopped}</dd><dt>配置来源</dt><dd>{item.configFiles || "—"}</dd></dl>
              </article>
            ))}
          </div>
        )}
      <TruncatedNotice value={collection?.truncated ?? false} />
    </>
  );
}

export function DockerSecurityView({ status, audit, onRefresh }: {
  status: DockerReadStatus;
  audit: DockerSecurityAudit | null;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="只读安全审计" status={status} onRefresh={onRefresh} />
      {status === "loading" && audit === null ? <StatusPanel label="正在运行 Docker 安全调查…" /> :
        audit === null ? <EmptyPanel title="安全审计尚不可用" detail="刷新当前资源以重新调查。" /> : (
          <>
            <div className="docker-security-summary">
              <article><strong>{audit.summary.score}</strong><span>安全得分</span></article>
              <article><strong>{audit.containersScanned}</strong><span>扫描容器</span></article>
              <article><strong>{audit.summary.critical}</strong><span>严重</span></article>
              <article><strong>{audit.summary.high}</strong><span>高风险</span></article>
              <article><strong>{audit.summary.total}</strong><span>全部发现</span></article>
            </div>
            {audit.findings.length === 0 ? <EmptyPanel title="没有返回安全发现" /> : (
              <div className="docker-findings">
                {audit.findings.map((finding, index) => (
                  <article className={`docker-finding severity-${finding.severity}`} key={`${finding.containerName}\0${finding.category}\0${index}`}>
                    <header><span>{dockerSecuritySeverityLabel(finding.severity)}</span><strong>{finding.categoryLabel}</strong><small>{finding.containerName || "（未命名容器）"}</small></header>
                    <p>{finding.description}</p><p className="docker-recommendation">建议：{finding.recommendation || "未提供"}</p>
                    {finding.textTruncated && <small>这条发现里有文字过长，已截短显示。</small>}
                  </article>
                ))}
              </div>
            )}
            <TruncatedNotice value={audit.truncated} />
          </>
        )}
    </>
  );
}

/**
 * One line above a view: what it is, and how to reload it.
 *
 * It used to be a second header band with its own title and the sentence
 * "数据严格绑定到当前短期快照" under every view — a fact that never changes,
 * repeated six times, directly beneath a header that had just said the same
 * thing. The tab strip already names the view; the only thing worth keeping
 * here is the button and a word for when it is working.
 */
function ViewHeader({ title, status, onRefresh }: { title: string; status: DockerReadStatus; onRefresh(): void }) {
  return (
    <div className="docker-view-header">
      <h2>{title}</h2>
      {status === "loading" ? <span className="docker-muted" role="status">刷新中…</span> : null}
      <button type="button" disabled={status === "loading"} onClick={onRefresh}>刷新</button>
    </div>
  );
}

/**
 * The details of one container, network or volume, over the table.
 *
 * A dialog rather than a docked column: this is read in bursts — click a row,
 * look, close — and a rail that is only wanted for those few seconds was
 * charging the table a third of its width for the whole session.
 *
 * Being a dialog brings obligations a rail did not have, and they are all
 * here: it dims what is behind it, Escape closes it, a click on the backdrop
 * closes it, and focus lands inside it so the keyboard is not left behind on
 * the table.
 */
export function InspectionDialog({ status, inspection, onClose, extra }: {
  status: DockerReadStatus;
  inspection: DockerReadInspection | null;
  onClose(): void;
  /** Shown under a container's details once they are read: the 排查 panel. */
  extra?: ReactNode;
}) {
  useModalScrim();
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    function dismissOnEscape(event: KeyboardEvent): void {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", dismissOnEscape, true);
    return () => window.removeEventListener("keydown", dismissOnEscape, true);
  }, [onClose]);

  const body = status === "loading" ? <StatusPanel label="正在读取所选资源详情…" />
    : status === "error" || inspection === null
      ? <EmptyPanel title="资源详情不可用" detail="选择其他资源或刷新清单。" />
      : inspection.kind === "container" ? <ContainerInspectionView inspection={inspection} />
        : inspection.kind === "image" ? <ImageInspectionView inspection={inspection} />
          : inspection.kind === "network" ? <NetworkInspectionView inspection={inspection} />
            : <VolumeInspectionView inspection={inspection} />;
  return (
    <div
      className="docker-detail-backdrop"
      role="presentation"
      // Only a click that both starts and ends on the backdrop closes it, so a
      // drag that began on the text inside does not dismiss what was being read.
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="docker-detail-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="所选资源详情"
        data-testid="docker-detail-dialog"
      >
        <header className="docker-detail-head">
          <h2>{inspection === null ? "资源详情" : inspectionTitle(inspection)}</h2>
          <button
            ref={closeRef}
            type="button"
            className="docker-detail-close"
            aria-label="关闭详情"
            onClick={onClose}
          >
            <DockerIcon name="close" size={13} />
          </button>
        </header>
        <div className="docker-detail-body">
          {/* First, not under the details: it is what a responder opens the
              dialog for, and it costs nothing until one of its reads is asked for. */}
          {status === "ready" && inspection?.kind === "container" ? extra : null}
          {body}
        </div>
      </section>
    </div>
  );
}

/**
 * What to call the thing on screen. An image has no single name — it is a
 * repository and a tag, and an untagged one has neither — so it falls back to
 * the short id the runtime itself prints rather than to「未命名」.
 */
export function inspectionTitle(inspection: DockerReadInspection): string {
  if (inspection.kind !== "image") return inspection.name || "（未命名）";
  return imageDisplayName(inspection.repository, inspection.tag, inspection.shortId);
}

export function imageDisplayName(repository: string, tag: string, shortId: string): string {
  const named = repository && repository !== "<none>";
  const tagged = tag && tag !== "<none>";
  if (named && tagged) return `${repository}:${tag}`;
  if (named) return repository;
  return shortId ? `未命名镜像 ${shortId}` : "未命名镜像";
}

function ImageInspectionView({ inspection }: { inspection: DockerImageInspection }) {
  // Entrypoint and command are one thing to a reader — what the container will
  // run — so they are shown as the one line the runtime would actually run.
  const startup = [...inspection.entrypoint, ...inspection.command].join(" ");
  return (
    <section className="docker-inspection">
      <h3>镜像信息</h3>
      <dl className="docker-detail-grid">
        <dt>短 id</dt><dd>{inspection.shortId || "—"}</dd>
        <dt>标签</dt><dd>{inspection.repoTags.length === 0 ? "没有标签" : inspection.repoTags.join("、")}</dd>
        <dt>大小</dt><dd>{inspection.size || "—"}</dd>
        <dt>构建时间</dt><dd>{inspection.createdAt || "—"}</dd>
        <dt>平台</dt><dd>{[inspection.os, inspection.architecture].filter(Boolean).join("/") || "—"}</dd>
        <dt>运行身份</dt><dd>{inspection.user || "—"}</dd>
        <dt>启动命令</dt><dd>{startup || "没有记录"}</dd>
        <dt>工作目录</dt><dd>{inspection.workingDir || "—"}</dd>
        <dt>作者</dt><dd>{inspection.author || "—"}</dd>
      </dl>
      <h4>内置环境变量</h4>
      {/* Read as-is: a credential baked into an image is the finding, not
          something to hide from the person looking for it. */}
      {inspection.environment.length === 0 ? <p className="docker-muted">没有内置环境变量。</p>
        : <ul className="docker-plain-list">{inspection.environment.map((item, index) => <li key={index}>{item}</li>)}</ul>}
      <h4>暴露端口</h4>
      {inspection.exposedPorts.length === 0 ? <p className="docker-muted">没有暴露端口。</p>
        : <p className="docker-plain-row">{inspection.exposedPorts.join("、")}</p>}
      <h4>声明的数据卷</h4>
      {inspection.declaredVolumes.length === 0 ? <p className="docker-muted">没有声明数据卷。</p>
        : <p className="docker-plain-row">{inspection.declaredVolumes.join("、")}</p>}
      <h4>构建步骤</h4>
      {inspection.history.length === 0 ? <p className="docker-muted">读不到构建步骤（拉下来的镜像通常没有本地记录）。</p>
        : <ol className="docker-history">{inspection.history.map((step, index) => (
          <li key={index}>
            <code>{step.createdBy || "—"}</code>
            <em>{[step.size, step.createdAt, step.comment].filter(Boolean).join(" · ") || "—"}</em>
          </li>
        ))}</ol>}
      <h4>标签</h4><MetadataList items={inspection.labels} empty="没有标签。" />
      <h4>层</h4>
      {inspection.layers.length === 0 ? <p className="docker-muted">没有层记录。</p>
        : <p className="docker-muted">{inspection.layers.length} 层</p>}
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function ContainerInspectionView({ inspection }: { inspection: DockerContainerInspection }) {
  return (
    <section className="docker-inspection">
      {/* Grouped rather than listed: fifteen equal rows made the two that
          matter — privileged, and the network mode — sit at the same weight
          as the working directory. */}
      <h3>容器信息</h3>
      <MetadataList items={inspection.fields.map((item) => ({ key: item.label, value: item.value }))} empty="没有详情字段。" />
      <h3>挂载卷</h3>
      {inspection.mounts.length === 0 ? <p className="docker-muted">没有挂载记录。</p> : inspection.mounts.map((mount, index) => (
        <p className="docker-plain-row" key={index}>
          <span className="docker-mount-path">{mount.source || "—"}</span>
          <span aria-hidden="true"> → </span>
          <span className="docker-mount-path">{mount.destination || "—"}</span>
          <em>{mount.readWrite ? "可写" : "只读"}{mount.kind ? ` · ${mount.kind}` : ""}</em>
        </p>
      ))}
      <h3>网络连接</h3>
      {inspection.networks.length === 0 ? <p className="docker-muted">没有网络连接记录。</p> : inspection.networks.map((network, index) => (
        <p className="docker-plain-row" key={index}>
          <span className="docker-mount-path">{network.name || "—"}</span>
          <em>{network.ipv4Address || network.ipv6Address || "无地址"}</em>
        </p>
      ))}
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function NetworkInspectionView({ inspection }: { inspection: DockerNetworkInspection }) {
  return (
    <section className="docker-inspection">
      <h3>网络详情 · {inspection.name || "（未命名）"}</h3>
      <dl className="docker-detail-grid"><dt>驱动</dt><dd>{inspection.driver || "—"}</dd><dt>范围</dt><dd>{inspection.scope || "—"}</dd><dt>内部网络</dt><dd>{dockerBooleanLabel(inspection.internal)}</dd><dt>IPv6</dt><dd>{dockerBooleanLabel(inspection.ipv6)}</dd><dt>可附加</dt><dd>{dockerBooleanLabel(inspection.attachable)}</dd><dt>Ingress</dt><dd>{dockerBooleanLabel(inspection.ingress)}</dd><dt>IPAM 驱动</dt><dd>{inspection.ipamDriver || "—"}</dd></dl>
      <h4>IPAM</h4>{inspection.ipam.length === 0 ? <p className="docker-muted">没有 IPAM 记录。</p> : inspection.ipam.map((item, index) => <p className="docker-plain-row" key={index}>{item.subnet || "—"} · 网关 {item.gateway || "—"} · 范围 {item.ipRange || "—"}</p>)}
      <h4>连接容器</h4>{inspection.attachments.length === 0 ? <p className="docker-muted">没有连接记录。</p> : inspection.attachments.map((item, index) => <p className="docker-plain-row" key={index}>{item.name || "—"} · {item.ipv4Address || item.ipv6Address || "无地址"}</p>)}
      <h4>选项</h4><MetadataList items={inspection.options} empty="没有选项。" />
      <h4>标签</h4><MetadataList items={inspection.labels} empty="没有标签。" />
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function VolumeInspectionView({ inspection }: { inspection: DockerVolumeInspection }) {
  return (
    <section className="docker-inspection">
      <h3>存储卷详情 · {inspection.name || "（未命名）"}</h3>
      <dl className="docker-detail-grid"><dt>驱动</dt><dd>{inspection.driver || "—"}</dd><dt>范围</dt><dd>{inspection.scope || "—"}</dd><dt>挂载点</dt><dd>{inspection.mountpoint || "—"}</dd><dt>创建时间</dt><dd>{inspection.createdAt || "—"}</dd></dl>
      <h4>选项</h4><MetadataList items={inspection.options} empty="没有选项。" />
      <h4>标签</h4><MetadataList items={inspection.labels} empty="没有标签。" />
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function MetadataList({ items, empty }: { items: ReadonlyArray<{ key: string; value: string }>; empty: string }) {
  if (items.length === 0) return <p className="docker-muted">{empty}</p>;
  return <dl className="docker-metadata">{items.map((item, index) => <div key={`${item.key}\0${index}`}><dt>{item.key || "—"}</dt><dd>{item.value || "—"}</dd></div>)}</dl>;
}

export function DockerLogsText({ logs }: { logs: DockerLogs }) {
  return (
    <>
      {logs.text.length === 0 ? <p className="docker-muted">日志为空。</p> : <pre className="docker-log-text">{logs.text}</pre>}
      <TruncatedNotice value={logs.truncated} />
    </>
  );
}

function StatusPanel({ label }: { label: string }) {
  return <div className="docker-status-panel" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

/**
 * The buttons on one row.
 *
 * Everything a container can do fits, but not all of it fits in a line — and
 * a wrapped second line made every row twice as tall for the sake of the two
 * actions nobody wants to click by accident. So the reversible ones stay in
 * the row and the ones that cannot be taken back go behind 更多. Both still
 * open the same confirmation before anything runs; this is about which button
 * the mouse lands on, not about safety.
 */
export function RowActions({ container, actions, onAction, onOpenTerminal, onOpenFiles, onInvestigate }: {
  container: { containerHandle: string; name: string; state: string };
  actions: readonly DockerWriteAction[];
  onAction(containerHandle: string, containerName: string, action: DockerWriteAction): void;
  onOpenTerminal(containerHandle: string, containerName: string): void;
  onOpenFiles(containerHandle: string, containerName: string): void;
  onInvestigate?: ((kind: "container", name: string) => void) | undefined;
}) {
  const [open, setOpen] = useState(false);
  const moreRef = useRef<HTMLButtonElement>(null);
  const closeMenu = (returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) moreRef.current?.focus();
  };
  const name = container.name || "（未命名）";
  const inline = actions.filter((action) => dockerActionTone(action) !== "danger");
  const overflow = actions.filter((action) => dockerActionTone(action) === "danger");
  const button = (action: DockerWriteAction, extra: string) => (
    <button
      key={action}
      type="button"
      className={`docker-action-button is-${dockerActionTone(action)}${extra}`}
      data-testid={`docker-action-${action}`}
      title={`${dockerActionLabel(action)} ${name}`}
      onClick={() => { setOpen(false); onAction(container.containerHandle, name, action); }}
    >
      <DockerIcon name={action} />
      {dockerActionLabel(action)}
    </button>
  );
  return (
    <div className="docker-row-actions">
      {/* A shell is offered only where one can exist. The backend re-checks
          that the container is running before it opens anything, so this is a
          courtesy, not the guard. */}
      {canOpenContainerShell(container.state) && (
        <button
          type="button"
          className="docker-action-button is-terminal"
          data-testid="docker-open-terminal"
          title={`进入 ${name} 的终端`}
          onClick={() => onOpenTerminal(container.containerHandle, name)}
        >
          <DockerIcon name="terminal" />终端
        </button>
      )}
      {/* Reading and copying files runs inside the container, so it is offered
          where a shell is. The backend checks the container again first. */}
      {canOpenContainerShell(container.state) && (
        <button
          type="button"
          className="docker-action-button"
          data-testid="docker-open-files"
          title={`编辑或复制 ${name} 里的文件`}
          onClick={() => onOpenFiles(container.containerHandle, name)}
        >
          <DockerIcon name="volumes" />文件
        </button>
      )}
      {/* The workbench's read-only checks, run inside this container: who
          is running what, what listens, what changed lately. */}
      {canOpenContainerShell(container.state) && onInvestigate !== undefined && container.name !== "" && (
        <button
          type="button"
          className="docker-action-button"
          data-testid="docker-investigate"
          title={`在命令工作台里对 ${name} 运行只读检查`}
          onClick={() => onInvestigate("container", container.name)}
        >
          <DockerIcon name="search" />排查
        </button>
      )}
      {inline.map((action) => button(action, ""))}
      {overflow.length > 0 && (
        <div className="docker-overflow">
          <button
            ref={moreRef}
            type="button"
            className="docker-action-button"
            aria-expanded={open}
            aria-haspopup="menu"
            aria-label={`${name} 的更多操作`}
            onClick={() => setOpen((value) => !value)}
          >
            <DockerIcon name="more" />更多
          </button>
          {open && (
            <OverflowMenu label={`${name} 的不可撤销操作`} anchor={moreRef} onClose={closeMenu}>
              {overflow.map((action) => button(action, " is-menu-item"))}
            </OverflowMenu>
          )}
        </div>
      )}
      {actions.length === 0 && !canOpenContainerShell(container.state) && (
        <span className="docker-muted">—</span>
      )}
    </div>
  );
}

/**
 * The 更多 list of one row.
 *
 * Fixed to the window rather than absolute inside the row: the table scrolls,
 * and an absolute list was clipped by it — on the lower rows it opened under
 * the rows beneath and its items could not be reached. Its buttons keep their
 * look through `:is(.docker-page, .docker-overflow-menu)` in docker-page.css. Placed under the
 * button, or above it when the window runs out. It closes on Escape (focus back
 * on 更多), on a click elsewhere, and when the page scrolls or the window
 * resizes, since it would no longer sit beside its button.
 */
function OverflowMenu({ label, anchor, onClose, children }: {
  label: string;
  anchor: RefObject<HTMLButtonElement | null>;
  onClose(returnFocus: boolean): void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [placed, setPlaced] = useState<{ x: number; y: number } | null>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useLayoutEffect(() => {
    const button = anchor.current;
    const menu = ref.current;
    if (button === null || menu === null) return;
    const box = menu.getBoundingClientRect();
    setPlaced(placeDropdown(
      button.getBoundingClientRect(),
      { width: box.width, height: box.height },
      { width: window.innerWidth, height: window.innerHeight },
    ));
  }, [anchor]);

  useEffect(() => {
    if (placed === null) return;
    ref.current?.querySelector<HTMLElement>("button")?.focus();
  }, [placed]);

  useEffect(() => {
    const close = (returnFocus: boolean) => onCloseRef.current(returnFocus);
    function onMouseDown(event: MouseEvent): void {
      const target = event.target;
      if (!(target instanceof Node)) return;
      // The 更多 button toggles itself; treating its press as "elsewhere"
      // would close the list only for the click to open it again.
      if (ref.current?.contains(target) === true || anchor.current?.contains(target) === true) return;
      close(false);
    }
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      close(true);
    }
    function onScroll(event: Event): void {
      if (event.target instanceof Node && ref.current?.contains(event.target) === true) return;
      close(false);
    }
    function onResize(): void {
      close(false);
    }
    window.addEventListener("mousedown", onMouseDown, true);
    window.addEventListener("keydown", onKeyDown, true);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("mousedown", onMouseDown, true);
      window.removeEventListener("keydown", onKeyDown, true);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onResize);
    };
  }, [anchor]);

  // Into the document body, not the row: the actions column is sticky, and
  // each sticky cell is a layer of its own, so the next row's cell painted over
  // this list whatever its z-index — a click on 删除 landed on that row's 暂停.
  return createPortal(
    <div
      ref={ref}
      className="docker-overflow-menu"
      role="group"
      aria-label={label}
      onKeyDown={(event) => {
        if (event.key !== "ArrowDown" && event.key !== "ArrowUp" && event.key !== "Home" && event.key !== "End") return;
        const items = [...(ref.current?.querySelectorAll<HTMLElement>("button") ?? [])];
        const target = event.target instanceof HTMLElement ? event.target : null;
        const next = items[menuStep(target === null ? -1 : items.indexOf(target), items.length, event.key)];
        if (next === undefined) return;
        event.preventDefault();
        next.focus();
      }}
      style={{
        left: `${placed?.x ?? 0}px`,
        top: `${placed?.y ?? 0}px`,
        visibility: placed === null ? "hidden" : undefined,
      }}
    >
      {children}
    </div>,
    document.body,
  );
}

/**
 * A bar for a percentage the runtime actually reported.
 *
 * The design this follows shows a sparkline here. A sparkline needs a series
 * and the runtime gives one sample per refresh, so drawing one would be
 * inventing the shape between the points. A bar says exactly what was
 * measured, and nothing more.
 */
function DockerMeter({ percent }: { percent: string | undefined }) {
  const value = dockerPercentValue(percent);
  if (value === null) return null;
  return (
    <span className="docker-meter" role="img" aria-label={`占用 ${value}%`}>
      <span className="docker-meter-fill" style={{ width: `${value}%` }} />
    </span>
  );
}

function EmptyPanel({ title, detail }: { title: string; detail?: string }) {
  return <div className="docker-empty"><strong>{title}</strong>{detail ? <p>{detail}</p> : null}</div>;
}

function TruncatedNotice({ value }: { value: boolean }) {
  return value
    ? <p className="docker-truncated" role="status">结果中有内容过长，已截短显示。</p>
    : null;
}
