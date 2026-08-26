import { useCallback, useRef, useState } from "react";

import {
  isEmergencyPathDetail,
  isEmergencyPathPlan,
  isEmergencyPathReceipt,
  type EmergencyCommandApi,
  type EmergencyCommandPathOffer,
  type EmergencyPathAction,
  type EmergencyPathDetail,
  type EmergencyPathPlan,
  type EmergencyPathReceipt,
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
  busy: boolean;
  error: string | null;
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
  const [menu, setMenu] = useState<EmergencyPathMenuState | null>(null);
  const [state, setState] = useState<EmergencyPathActionState | null>(null);
  // A second click while a round trip is in flight would plan or execute
  // twice; a state flag is set too late to stop it.
  const inFlight = useRef(false);
  const planHandleRef = useRef<string | null>(null);

  const openMenu = useCallback((event: { clientX: number; clientY: number; preventDefault: () => void },
    offer: EmergencyCommandPathOffer) => {
    event.preventDefault();
    setMenu({ position: { x: event.clientX, y: event.clientY }, offer });
  }, []);

  const dismissMenu = useCallback(() => setMenu(null), []);

  const close = useCallback(() => {
    const abandoned = planHandleRef.current;
    planHandleRef.current = null;
    inFlight.current = false;
    setState(null);
    if (abandoned !== null && bindingHandle !== null) {
      void api.cancelEmergencyPathAction(bindingHandle, abandoned).catch(() => undefined);
    }
  }, [api, bindingHandle]);

  const start = useCallback(async (menuAction: EmergencyPathMenuAction,
    offer: EmergencyCommandPathOffer) => {
    setMenu(null);
    if (bindingHandle === null || inFlight.current) return;
    const action = menuAction === "properties" ? null : menuAction;
    inFlight.current = true;
    setState({ offer, action, detail: null, plan: null, receipt: null, busy: true, error: null });
    try {
      const detail = await api.inspectEmergencyPath(bindingHandle, offer.pathHandle);
      if (!isEmergencyPathDetail(detail)) throw new Error("目标机返回的文件信息无法识别。");
      if (action === null) {
        setState({ offer, action, detail, plan: null, receipt: null, busy: false, error: null });
        return;
      }
      const plan = await api.planEmergencyPathAction(bindingHandle, offer.pathHandle, action);
      if (!isEmergencyPathPlan(plan)) throw new Error("目标机返回的操作计划无法识别。");
      planHandleRef.current = plan.planHandle;
      setState({ offer, action, detail, plan, receipt: null, busy: false, error: null });
    } catch (error) {
      setState((current) => current === null ? null
        : { ...current, busy: false, error: reason(message(error), action) });
    } finally {
      inFlight.current = false;
    }
  }, [api, bindingHandle]);

  const confirm = useCallback(async () => {
    const planHandle = planHandleRef.current;
    if (bindingHandle === null || planHandle === null || inFlight.current) return;
    inFlight.current = true;
    setState((current) => current === null ? null : { ...current, busy: true, error: null });
    try {
      const confirmed = await api.confirmEmergencyPathAction(bindingHandle, planHandle);
      if (!isEmergencyPathPlan(confirmed)) throw new Error("目标机没有记录这次确认。");
      const receipt = await api.executeEmergencyPathAction(bindingHandle, planHandle);
      if (!isEmergencyPathReceipt(receipt)) throw new Error("目标机返回的执行回执无法识别。");
      // The plan is spent either way, so there is nothing left to cancel.
      planHandleRef.current = null;
      setState((current) => current === null ? null
        : { ...current, plan: confirmed, receipt, busy: false, error: null });
    } catch (error) {
      setState((current) => current === null ? null
        : { ...current, busy: false, error: message(error) });
    } finally {
      inFlight.current = false;
    }
  }, [api, bindingHandle]);

  return { menu, state, openMenu, dismissMenu, start, confirm, close };
}

/**
 * Turns the one refusal an operator will actually hit into something that says
 * what happened, instead of the boundary's generic wording.
 */
export function reason(text: string, action: EmergencyPathAction | null): string {
  if (action === "disarm" && text.includes("could not act on that path")) {
    return "这个文件已经没有执行位了，不需要再去掉。";
  }
  return text;
}
