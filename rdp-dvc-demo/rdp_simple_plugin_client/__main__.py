#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Entry point for the Simple DVC client plugin."""

from __future__ import annotations

import argparse
import signal
import sys
import time
import traceback
from ctypes import byref, c_int, c_void_p
from ctypes.wintypes import DWORD
from dataclasses import dataclass
from typing import Optional

# Handle both module execution (-m) and direct execution (PyInstaller)
try:
    from .simple_plugin import SimplePlugin, shutdown_event
    from .registry_helper import register_addin, unregister_addin
except ImportError:
    from simple_plugin import SimplePlugin, shutdown_event
    from registry_helper import register_addin, unregister_addin


def log(msg: str) -> None:
    print(msg, flush=True)


def log_err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


@dataclass(frozen=True)
class CliOptions:
    register: bool
    unregister: bool
    per_user: bool
    embedding: bool


def parse_args(argv: list[str]) -> CliOptions:
    """Parse command line arguments (accepts both /switch and -switch)."""
    normalized = []
    for a in argv:
        a_lower = a.lower()
        if a_lower.startswith("/"):
            normalized.append("-" + a_lower[1:])
        else:
            normalized.append(a_lower)

    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-register", "-reg", action="store_true")
    p.add_argument("-unregister", "-unreg", action="store_true")
    p.add_argument("-machine", action="store_true")
    p.add_argument("-embedding", action="store_true")
    p.add_argument("-h", "-help", "-?", action="store_true")

    ns, unknown = p.parse_known_args(normalized)

    if ns.h:
        print_usage()
        sys.exit(0)

    if unknown:
        log_err(f"Unknown arguments: {unknown}")
        print_usage()
        sys.exit(2)

    return CliOptions(
        register=bool(ns.register),
        unregister=bool(ns.unregister),
        per_user=not bool(ns.machine),
        embedding=bool(ns.embedding),
    )


def print_usage() -> None:
    log("Simple DVC Client Plugin - Python Implementation")
    log("")
    log("Usage:")
    log("  rdp-simple-plugin-client-python.exe [options]")
    log("  python -m rdp_simple_plugin_client [options]")
    log("")
    log("Options:")
    log("  /register, -register       Register the plugin (per-user)")
    log("  /unregister, -unregister   Unregister the plugin")
    log("  /machine, -machine         Use HKLM instead of HKCU (requires admin)")
    log("  /help, -help, /?, -?       Show this help message")
    log("")
    log("Note: Both / and - prefixes are supported for all options.")
    log("-Embedding flag is used by COM runtime for LocalServer activation.")


class Shutdown:
    """Signal-friendly shutdown flag."""
    def __init__(self) -> None:
        self._requested = False

    @property
    def requested(self) -> bool:
        return self._requested or shutdown_event.is_set()

    def request(self) -> None:
        self._requested = True


def run_local_server(shutdown: Shutdown) -> int:
    """Run as COM LocalServer."""
    try:
        from win32more._win32api import Guid, HRESULT, S_OK, E_FAIL
        from win32more._comclass import ComClass
        from win32more.Windows.Win32.System.Com import (
            IClassFactory,
            CoInitializeEx,
            CoInitializeSecurity,
            CoRegisterClassObject,
            CoResumeClassObjects,
            CoRevokeClassObject,
            CoUninitialize,
            COINIT_MULTITHREADED,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE,
            REGCLS_SUSPENDED,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
        )
        from win32more.Windows.Win32.UI.WindowsAndMessaging import (
            PeekMessageW,
            TranslateMessage,
            DispatchMessageW,
            MSG,
            PM_REMOVE,
            WM_QUIT,
        )
        from win32more.Windows.Win32.Foundation import (
            RPC_E_CHANGED_MODE,
            RPC_E_TOO_LATE,
            CLASS_E_NOAGGREGATION,
        )

        # COM init
        hr = CoInitializeEx(None, COINIT_MULTITHREADED)
        if hr < 0 and hr != RPC_E_CHANGED_MODE:
            log_err(f"[Main] CoInitializeEx failed: 0x{hr & 0xFFFFFFFF:08X}")
            return 1
        log("[Main] COM initialized (MTA)")

        # COM security (best-effort, ignore RPC_E_TOO_LATE)
        hr = CoInitializeSecurity(
            None, -1, None, None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None, 0, None
        )
        if hr < 0 and hr != RPC_E_TOO_LATE:
            log(f"[Main] CoInitializeSecurity: 0x{hr & 0xFFFFFFFF:08X} (continuing)")

        # Class Factory
        class SimplePluginFactory(ComClass, IClassFactory):
            """Class factory that creates SimplePlugin instances."""

            def CreateInstance(self, pUnkOuter: c_void_p, riid: "Guid", ppvObject: "c_void_p") -> HRESULT:
                log(f"[Factory::CreateInstance] riid={riid}")

                if pUnkOuter:
                    log("[Factory::CreateInstance] Aggregation not supported")
                    return HRESULT(CLASS_E_NOAGGREGATION)

                try:
                    instance = SimplePlugin()
                    hr_qi = instance.QueryInterface(riid, ppvObject)
                    log(f"[Factory::CreateInstance] QueryInterface: 0x{int(hr_qi) & 0xFFFFFFFF:08X}")
                    return hr_qi
                except Exception as ex:
                    log_err(f"[Factory::CreateInstance] Exception: {ex}")
                    traceback.print_exc()
                    return HRESULT(E_FAIL)

            def LockServer(self, fLock: c_int) -> HRESULT:
                log(f"[Factory::LockServer] fLock={int(fLock)}")
                return HRESULT(S_OK)

        factory = SimplePluginFactory()

        clsid = Guid(SimplePlugin._clsid_)
        log(f"[Main] Registering CLSID: {SimplePlugin._clsid_}")

        # NOTE: CoRegisterClassObject's signature varies across win32more builds.
        # Most builds expect: clsid (Guid), factory (IUnknown), byref(cookie) for out param.
        # If you see "argument type mismatch", check win32more version.
        cookie = DWORD()
        hr = CoRegisterClassObject(
            clsid,
            factory,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
            byref(cookie),
        )
        if hr != 0:
            log_err(f"[Main] CoRegisterClassObject failed: 0x{hr & 0xFFFFFFFF:08X}")
            CoUninitialize()
            return 1

        hr = CoResumeClassObjects()
        if hr != 0:
            log_err(f"[Main] CoResumeClassObjects failed: 0x{hr & 0xFFFFFFFF:08X}")
            CoRevokeClassObject(cookie.value)
            CoUninitialize()
            return 1

        log(f"[Main] Class factory registered. Cookie={cookie.value}")
        log("[Main] Entering message loop (Ctrl+C to exit)")

        msg = MSG()
        while not shutdown.requested:
            if PeekMessageW(byref(msg), None, 0, 0, PM_REMOVE):
                if msg.message == WM_QUIT:
                    break
                TranslateMessage(byref(msg))
                DispatchMessageW(byref(msg))
            else:
                time.sleep(0.01)

        log("[Main] Shutting down")

        CoRevokeClassObject(cookie.value)
        CoUninitialize()
        log("[Main] LocalServer exited")
        return 0

    except Exception as ex:
        log_err(f"[Main] LocalServer failed: {ex}")
        traceback.print_exc()
        return 1


def handle_registration(opts: CliOptions) -> Optional[int]:
    if opts.register:
        scope = "per-user" if opts.per_user else "machine"
        log(f"Registering plugin ({scope})...")
        ok = register_addin(opts.per_user)
        if ok:
            log("Registration successful.")
            return 0
        log_err("Registration failed." + ("" if opts.per_user else " Try running as administrator."))
        return 1

    if opts.unregister:
        scope = "per-user" if opts.per_user else "machine"
        log(f"Unregistering plugin ({scope})...")
        ok = unregister_addin(opts.per_user)
        if ok:
            log("Unregistration successful.")
            return 0
        log_err("Unregistration failed." + ("" if opts.per_user else " Try running as administrator."))
        return 1

    return None


def main() -> int:
    opts = parse_args(sys.argv[1:])

    rc = handle_registration(opts)
    if rc is not None:
        return rc

    log("Simple DVC Client Plugin (Python) - Starting...")
    log(f"[Main] Python {sys.version}")

    if opts.embedding:
        log("[Main] -Embedding parameter detected (COM activation)")
    else:
        log("[Main] Starting COM LocalServer (default mode)")

    shutdown = Shutdown()

    def _on_signal(_sig, _frame) -> None:
        log("\n[Main] Shutdown signal received")
        shutdown.request()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    return run_local_server(shutdown)


if __name__ == "__main__":
    raise SystemExit(main())
