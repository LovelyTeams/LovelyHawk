import { useCallback, useEffect, useRef, useState } from "react";

import {
  isSystemInfoRowActions,
  isSystemInfoRowInspection,
  isSystemInfoRowPlan,
  isSystemInfoRowReceipt,
  type SystemInfoApi,
  type SystemInfoRow,
  type SystemInfoRowActionEntry,
  type SystemInfoRowActions,
  type SystemInfoRowInspection,
  type SystemInfoRowPlan,
  type SystemInfoRowReceipt,
} from "../shared/system-info-contract";

/** Where the menu was summoned and which row it is about. */
export interface SystemInfoRowMenuState {
  position: { x: number; y: number };
  row: SystemInfoRow;
  /** The cell under the cursor, so the menu can offer to copy just that. */
  cell: string | null;
  /** Null while the sidecar is still saying which actions apply. */
  actions: SystemInfoRowActions | null;
  error: string | null;
}

export interface SystemInfoRowActionState {
  subject: string;
  action: SystemInfoRowActionEntry;
  inspection: SystemInfoRowInspection | null;
  plan: SystemInfoRowPlan | null;
  receipt: SystemInfoRowReceipt | null;
  busy: boolean;
  error: string | null;
}

interface MenuEvent {
  clientX: number;
  clientY: number;
  preventDefault: () => void;
  stopPropagation?: () => void;
}

/**
 * Turns the sidecar's refusal into a sentence about what to do next. The
 * code sits at the end of the message in parentheses; the wording before it
 * is the boundary's, and is not what an operator needs to read.
 */
export function rowActionFailureText(error: unknown): string {
  const text = error instanceof Error && error.message.length > 0 ? error.message : "";
  const code = /\(([a-z0-9-]+)\)\s*$/u.exec(text)?.[1] ?? "";
  switch (code) {
    case "system-info-action-unavailable":
      // Not only "the row moved on": the target may also simply lack the tool
      // the change needs. Saying which one it was would mean putting the
      // target's own words on screen, so it goes to the application log and
      // the operator is told where to look.
      return "这一行现在做不了这个操作：目标机上的状态或可用工具不满足前提。具体原因见应用日志。";
    case "system-info-binding-unavailable":
      return "与目标机的连接已经断开。";
    case "system-info-snapshot-stale":
      return "这份表格比目标机的现状旧了，刷新一下再试。";
    case "system-info-row-gone":
      return "这一行在最近一次刷新之后就不在表里了。刷新看看它是不是真的没了。";
    case "system-info-detail-none":
      // The one worth telling apart from the other two: refreshing changes
      // nothing here, and saying "stale, try again" sent people round a loop
      // that could not end.
      return "这一行没有更多可看的内容——不是出错，刷新也不会变出来。";
    case "system-info-plan-unavailable":
      return "这份计划已经失效或已经用过，请重新发起。";
    case "system-info-timeout":
      return "目标机没有在限定时间内回应。";
    case "system-info-capacity":
      return "待处理的操作太多了，先关掉其他窗口再试。";
    default:
      return text.length > 0 ? text : "操作失败。";
  }
}

/**
 * Drives the right-click menu on a system-information row and the dialog it
 * opens.
 *
 * The window never names anything but a row id and a fixed action key; which
 * actions apply is the sidecar's answer, asked afresh for every row. A change
 * is planned and shown before it is confirmed, and a plan left behind is
 * cancelled rather than abandoned, so the target does not hold a live
 * approval nobody is going to use.
 */
export function useSystemInfoRowActions(
  api: SystemInfoApi,
  bindingHandle: string | null,
  snapshotHandle: string | null,
) {
  const [menu, setMenu] = useState<SystemInfoRowMenuState | null>(null);
  const [state, setState] = useState<SystemInfoRowActionState | null>(null);
  // A second click while a round trip is in flight would plan or execute
  // twice; a state flag is set too late to stop it.
  const inFlight = useRef(false);
  const planHandleRef = useRef<string | null>(null);
  // Menus opened in quick succession each ask the sidecar; only the newest
  // answer may fill the menu that is showing.
  const menuSequence = useRef(0);

  const close = useCallback(() => {
    const abandoned = planHandleRef.current;
    planHandleRef.current = null;
    inFlight.current = false;
    setState(null);
    if (abandoned !== null && bindingHandle !== null) {
      void api.cancelSystemInfoRowAction(bindingHandle, abandoned).catch(() => undefined);
    }
  }, [api, bindingHandle]);

  const dismissMenu = useCallback(() => {
    menuSequence.current += 1;
    setMenu(null);
  }, []);

  // A refreshed table or a switched target invalidates every row id the menu
  // or dialog was about.
  useEffect(() => {
    dismissMenu();
    close();
  }, [close, dismissMenu, snapshotHandle]);

  const openMenu = useCallback((event: MenuEvent, row: SystemInfoRow, cell: string | null) => {
    event.preventDefault();
    event.stopPropagation?.();
    if (bindingHandle === null || snapshotHandle === null) return;
    const sequence = menuSequence.current + 1;
    menuSequence.current = sequence;
    setMenu({
      position: { x: event.clientX, y: event.clientY },
      row,
      cell,
      actions: null,
      error: null,
    });
    void api.listSystemInfoRowActions(bindingHandle, snapshotHandle, row.id).then((result) => {
      if (menuSequence.current !== sequence) return;
      if (!isSystemInfoRowActions(result) || result.rowId !== row.id) {
        throw new Error("目标机返回的操作列表无法识别。");
      }
      setMenu((current) => current === null ? null : { ...current, actions: result });
    }).catch((error: unknown) => {
      if (menuSequence.current !== sequence) return;
      setMenu((current) => current === null ? null
        : { ...current, error: rowActionFailureText(error) });
    });
  }, [api, bindingHandle, snapshotHandle]);

  const choose = useCallback(async (action: SystemInfoRowActionEntry) => {
    const current = menu;
    menuSequence.current += 1;
    setMenu(null);
    if (
      current === null ||
      current.actions === null ||
      bindingHandle === null ||
      snapshotHandle === null ||
      inFlight.current
    ) return;
    const subject = current.actions.subject;
    const rowId = current.row.id;
    inFlight.current = true;
    setState({ subject, action, inspection: null, plan: null, receipt: null, busy: true, error: null });
    try {
      if (action.kind === "inspect") {
        const inspection = await api.inspectSystemInfoRow(
          bindingHandle,
          snapshotHandle,
          rowId,
          action.key,
        );
        if (!isSystemInfoRowInspection(inspection) || inspection.action !== action.key) {
          throw new Error("目标机返回的结果无法识别。");
        }
        setState((previous) => previous === null ? null
          : { ...previous, inspection, busy: false, error: null });
        return;
      }
      const plan = await api.planSystemInfoRowAction(
        bindingHandle,
        snapshotHandle,
        rowId,
        action.key,
      );
      if (!isSystemInfoRowPlan(plan) || plan.action !== action.key) {
        throw new Error("目标机返回的操作计划无法识别。");
      }
      planHandleRef.current = plan.planHandle;
      setState((previous) => previous === null ? null
        : { ...previous, plan, busy: false, error: null });
    } catch (error) {
      setState((previous) => previous === null ? null
        : { ...previous, busy: false, error: rowActionFailureText(error) });
    } finally {
      inFlight.current = false;
    }
  }, [api, bindingHandle, menu, snapshotHandle]);

  const confirm = useCallback(async () => {
    const planHandle = planHandleRef.current;
    if (bindingHandle === null || planHandle === null || inFlight.current) return;
    inFlight.current = true;
    setState((current) => current === null ? null : { ...current, busy: true, error: null });
    try {
      const confirmed = await api.confirmSystemInfoRowAction(bindingHandle, planHandle);
      if (!isSystemInfoRowPlan(confirmed) || confirmed.planHandle !== planHandle) {
        throw new Error("目标机没有记录这次确认。");
      }
      const receipt = await api.executeSystemInfoRowAction(bindingHandle, planHandle);
      if (!isSystemInfoRowReceipt(receipt) || receipt.planHandle !== planHandle) {
        throw new Error("目标机返回的执行回执无法识别。");
      }
      // The plan is spent either way, so there is nothing left to cancel.
      planHandleRef.current = null;
      setState((current) => current === null ? null
        : { ...current, plan: confirmed, receipt, busy: false, error: null });
    } catch (error) {
      setState((current) => current === null ? null
        : { ...current, busy: false, error: rowActionFailureText(error) });
    } finally {
      inFlight.current = false;
    }
  }, [api, bindingHandle]);

  return { menu, state, openMenu, dismissMenu, choose, confirm, close };
}
