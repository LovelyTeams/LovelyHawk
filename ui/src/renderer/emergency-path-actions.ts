import { useCallback, useEffect, useRef, useState } from "react";

import {
  isEmergencyPathDetail,
  isEmergencyPathPlan,
  isEmergencyPathReceipt,
  isEmergencyPathUndoResult,
  type EmergencyCommandApi,
  type EmergencyCommandPathOffer,
  type EmergencyPathAction,
  type EmergencyPathDetail,
  type EmergencyPathPlan,
  type EmergencyPathReceipt,
  type EmergencyPathUndoResult,
} from "../shared/emergency-command-contract";
import type { EmergencyPathMenuAction } from "./EmergencyPathMenu";

/** Where the menu was summoned and which line's file it is about. */
export interface EmergencyPathMenuState {
  position: { x: number; y: number };
  offer: EmergencyCommandPathOffer;
}

export interface EmergencyPathActionState {
  offer: EmergencyCommandPathOffer;
  /** Null while the operator is only looking at what the file is. */
  action: EmergencyPathAction | null;
  detail: EmergencyPathDetail | null;
  plan: EmergencyPathPlan | null;
  receipt: EmergencyPathReceipt | null;
  /** What the one undo attempt reported, once it has been made. */
  undo: EmergencyPathUndoResult | null;
  /** The undo was attempted, so it is no longer offered whatever came back. */
  undoSpent: boolean;
  busy: boolean;
  error: string | null;
}

interface PathContext {
  api: EmergencyCommandApi;
  bindingHandle: string | null;
}

interface PathOperation extends PathContext {
  bindingHandle: string;
  plan: EmergencyPathPlan | null;
  /** A verified, reversible receipt; cleared as soon as an undo is attempted. */
  done: EmergencyPathReceipt | null;
  busy: boolean;
}

function cancelPlan(operation: PathOperation): void {
  const plan = operation.plan;
  operation.plan = null;
  if (plan !== null) {
    void operation.api.cancelEmergencyPathAction(operation.bindingHandle, plan.planHandle)
      .catch(() => undefined);
  }
}

function message(error: unknown): string {
  return error instanceof Error && error.message.length > 0 ? error.message : "操作失败。";
}

/**
 * Drives the right-click actions on a path an output line named.
 *
 * Every call carries the opaque handle the run handed out, never a path the
 * window made up. A plan is built and shown before anything is confirmed, and
 * a plan left behind is cancelled rather than abandoned, so the target does
 * not hold a live approval nobody is going to use.
 */
export function useEmergencyPathActions(api: EmergencyCommandApi, bindingHandle: string | null) {
  const [menu, setMenu] = useState<(EmergencyPathMenuState & PathContext) | null>(null);
  const [state, setState] = useState<EmergencyPathActionState | null>(null);
  // Each dialog owns its request and plan. A closed dialog's finally block
  // must never unlock, fill, or execute the dialog that replaced it.
  const operationRef = useRef<PathOperation | null>(null);
  const contextRef = useRef<PathContext | null>({ api, bindingHandle });
  contextRef.current = { api, bindingHandle };

  function isCurrent(operation: PathOperation): boolean {
    return operationRef.current === operation &&
      contextRef.current?.api === operation.api &&
      contextRef.current.bindingHandle === operation.bindingHandle;
  }

  useEffect(() => {
    contextRef.current = { api, bindingHandle };
    return () => {
      const operation = operationRef.current;
      if (operation?.api === api && operation.bindingHandle === bindingHandle) {
        operationRef.current = null;
        cancelPlan(operation);
      }
      if (contextRef.current?.api === api && contextRef.current.bindingHandle === bindingHandle) {
        contextRef.current = null;
      }
    };
  }, [api, bindingHandle]);

  const openMenu = useCallback((event: { clientX: number; clientY: number; preventDefault: () => void },
    offer: EmergencyCommandPathOffer) => {
    event.preventDefault();
    if (bindingHandle === null || operationRef.current !== null) return;
    setMenu({ api, bindingHandle, position: { x: event.clientX, y: event.clientY }, offer });
  }, [api, bindingHandle]);

  const dismissMenu = useCallback(() => setMenu(null), []);

  const close = useCallback(() => {
    const abandoned = operationRef.current;
    operationRef.current = null;
    setMenu(null);
    setState(null);
    if (abandoned !== null) cancelPlan(abandoned);
  }, []);

  const start = useCallback(async (menuAction: Exclude<EmergencyPathMenuAction, "evidence">,
    offer: EmergencyCommandPathOffer) => {
    setMenu(null);
    if (bindingHandle === null || operationRef.current !== null ||
      contextRef.current?.api !== api || contextRef.current.bindingHandle !== bindingHandle) return;
    const action = menuAction === "properties" ? null : menuAction;
    const operation: PathOperation = { api, bindingHandle, plan: null, done: null, busy: true };
    operationRef.current = operation;
    setState({ offer, action, detail: null, plan: null, receipt: null, undo: null, undoSpent: false, busy: true, error: null });
    try {
      const detail = await api.inspectEmergencyPath(bindingHandle, offer.pathHandle);
      if (!isCurrent(operation)) return;
      if (!isEmergencyPathDetail(detail) || detail.pathHandle !== offer.pathHandle || detail.path !== offer.path) {
        throw new Error("文件信息与本次选择不一致，请关闭后重新检查。");
      }
      if (action === null) {
        setState({ offer, action, detail, plan: null, receipt: null, undo: null, undoSpent: false, busy: false, error: null });
        return;
      }
      const plan = await api.planEmergencyPathAction(bindingHandle, offer.pathHandle, action);
      if (!isEmergencyPathPlan(plan)) throw new Error("目标机返回的操作计划无法识别。");
      operation.plan = plan;
      if (!isCurrent(operation)) {
        cancelPlan(operation);
        return;
      }
      if (plan.pathHandle !== offer.pathHandle || plan.path !== offer.path ||
        plan.action !== action || plan.state !== "planned") {
        throw new Error("操作计划与本次选择不一致，请关闭后重新检查。");
      }
      setState({ offer, action, detail, plan, receipt: null, undo: null, undoSpent: false, busy: false, error: null });
    } catch (error) {
      cancelPlan(operation);
      if (!isCurrent(operation)) return;
      setState((current) => current === null ? null
        : { ...current, plan: null, busy: false, error: reason(message(error), action) });
    } finally {
      operation.busy = false;
    }
  }, [api, bindingHandle]);

  const renderedOperation = operationRef.current;
  const confirm = useCallback(async () => {
    const operation = renderedOperation;
    const plan = operation?.plan;
    if (operation === null || plan === null || plan === undefined || operation.busy || !isCurrent(operation)) return;
    const { planHandle } = plan;
    operation.busy = true;
    setState((current) => current === null ? null : { ...current, busy: true, error: null });
    try {
      const confirmed = await operation.api.confirmEmergencyPathAction(operation.bindingHandle, planHandle);
      if (!isCurrent(operation)) return;
      if (!isEmergencyPathPlan(confirmed) || confirmed.planHandle !== planHandle ||
        confirmed.pathHandle !== plan.pathHandle || confirmed.path !== plan.path ||
        confirmed.action !== plan.action || confirmed.summary !== plan.summary ||
        confirmed.dangerous !== plan.dangerous || confirmed.restoreDescription !== plan.restoreDescription ||
        confirmed.state !== "confirmed") {
        throw new Error("确认结果与所查看的计划不一致，请关闭后重新检查。");
      }
      const receipt = await operation.api.executeEmergencyPathAction(operation.bindingHandle, planHandle);
      // The plan is spent either way, so there is nothing left to cancel.
      operation.plan = null;
      if (!isCurrent(operation)) return;
      if (!isEmergencyPathReceipt(receipt) || receipt.planHandle !== planHandle ||
        receipt.path !== plan.path || receipt.action !== plan.action) {
        throw new Error("无法核对本次操作的结果，请重新检查目标文件，勿重复执行。");
      }
      operation.done = receipt.passed && receipt.undoable ? receipt : null;
      setState((current) => current === null ? null
        : { ...current, plan: confirmed, receipt, busy: false, error: null });
    } catch (error) {
      cancelPlan(operation);
      if (!isCurrent(operation)) return;
      setState((current) => current === null ? null
        : { ...current, plan: null, busy: false, error: message(error) });
    } finally {
      operation.busy = false;
    }
  }, [renderedOperation]);

  /**
   * Puts a verified action back, once. The target is read again first and the
   * undo is refused if the file changed after the action, so a later change is
   * never overwritten. Whatever comes back, it is not offered a second time.
   */
  const undo = useCallback(async () => {
    const operation = renderedOperation;
    const done = operation?.done;
    if (operation === null || done === null || done === undefined || operation.busy || !isCurrent(operation)) return;
    operation.done = null;
    operation.busy = true;
    setState((current) => current === null ? null : { ...current, undoSpent: true, busy: true, error: null });
    try {
      const result = await operation.api.undoEmergencyPathAction(operation.bindingHandle, done.planHandle);
      if (!isCurrent(operation)) return;
      if (!isEmergencyPathUndoResult(result) || result.planHandle !== done.planHandle || result.path !== done.path) {
        throw new Error("无法核对撤销的结果，请重新检查目标文件，勿重复操作。");
      }
      setState((current) => current === null ? null : { ...current, undo: result, busy: false, error: null });
    } catch (error) {
      if (!isCurrent(operation)) return;
      setState((current) => current === null ? null : { ...current, busy: false, error: undoFailure(message(error)) });
    } finally {
      operation.busy = false;
    }
  }, [renderedOperation]);

  return {
    menu: menu?.api === api && menu.bindingHandle === bindingHandle ? menu : null,
    state: operationRef.current !== null && isCurrent(operationRef.current) ? state : null,
    openMenu, dismissMenu, start, confirm, undo, close,
  };
}

/**
 * Turns the one refusal an operator will actually hit into something that says
 * what happened, instead of the boundary's generic wording.
 */
/**
 * An undo the target no longer holds was refused before anything was read or
 * written. The window is the backend's UNDO_TTL (emergency_path_api.rs).
 */
export function undoFailure(text: string): string {
  if (/\(emergency-path-unavailable\)$/u.test(text)) {
    return "撤销的时限已过（完成后 10 分钟内有效），这个文件没有被改动。请重新查看文件属性后再决定。";
  }
  // The undo may or may not have reached the file before the deadline.
  if (/\(emergency-command-timeout\)$/u.test(text)) {
    return "撤销没有在时限内返回结果，不确定文件是否已经放回。请在目标机上查看这个文件现在的状态。";
  }
  return text;
}

export function reason(text: string, action: EmergencyPathAction | null): string {
  if (action === "disarm" && text.includes("could not act on that path")) {
    return "暂时无法修改该文件权限，请重新查看文件属性并确认访问权限后再试。";
  }
  return text;
}
