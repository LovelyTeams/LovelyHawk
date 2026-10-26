# Bidirectional chat demo - client-side COM LocalServer host.
# Run on the CLIENT machine (where mstsc runs):
#   python demo_client_host.py
#
# Same COM plumbing as rdp_simple_plugin_client/__main__.py, but:
#   - instantiates DemoPlugin
#   - a stdin thread lets you type messages that are sent to the server
import os
import signal
import sys
import threading
import time
import traceback
from ctypes import byref, c_int, c_void_p
from ctypes.wintypes import DWORD

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from demo_plugin import DemoPlugin, shutdown_event

current_plugin = None  # set by the class factory


def log(msg: str) -> None:
    print(msg, flush=True)


def log_err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run_local_server() -> int:
    global current_plugin
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
        PeekMessageW, TranslateMessage, DispatchMessageW, MSG, PM_REMOVE, WM_QUIT,
    )
    from win32more.Windows.Win32.Foundation import (
        RPC_E_CHANGED_MODE, RPC_E_TOO_LATE, CLASS_E_NOAGGREGATION,
    )

    hr = CoInitializeEx(None, COINIT_MULTITHREADED)
    if hr < 0 and hr != RPC_E_CHANGED_MODE:
        log_err(f"[Main] CoInitializeEx failed: 0x{hr & 0xFFFFFFFF:08X}")
        return 1
    log("[Main] COM initialized (MTA)")

    hr = CoInitializeSecurity(
        None, -1, None, None,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, None, 0, None,
    )
    if hr < 0 and hr != RPC_E_TOO_LATE:
        log(f"[Main] CoInitializeSecurity: 0x{hr & 0xFFFFFFFF:08X} (continuing)")

    class DemoPluginFactory(ComClass, IClassFactory):
        def CreateInstance(self, pUnkOuter: c_void_p, riid: "Guid", ppvObject: "c_void_p") -> HRESULT:
            global current_plugin
            log(f"[Factory::CreateInstance] riid={riid}")
            if pUnkOuter:
                return HRESULT(CLASS_E_NOAGGREGATION)
            try:
                current_plugin = DemoPlugin()
                hr_qi = current_plugin.QueryInterface(riid, ppvObject)
                log(f"[Factory::CreateInstance] QueryInterface: 0x{int(hr_qi) & 0xFFFFFFFF:08X}")
                return hr_qi
            except Exception as ex:
                log_err(f"[Factory::CreateInstance] Exception: {ex}")
                traceback.print_exc()
                return HRESULT(E_FAIL)

        def LockServer(self, fLock: c_int) -> HRESULT:
            return HRESULT(S_OK)

    factory = DemoPluginFactory()
    clsid = Guid(DemoPlugin._clsid_)
    log(f"[Main] Registering CLSID: {DemoPlugin._clsid_}")

    cookie = DWORD()
    hr = CoRegisterClassObject(
        clsid, factory, CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED, byref(cookie),
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
    log("[Main] Class factory registered; waiting for mstsc to connect")
    log("[Main] Type a message and press Enter to send to server (Ctrl+C to exit)")

    def stdin_loop():
        for line in sys.stdin:
            text = line.rstrip("\r\n")
            if not text:
                continue
            if current_plugin is None:
                log("[stdin] plugin not created yet - connect mstsc first")
                continue
            if text.startswith("/cmd "):
                current_plugin.send_text(text[5:], "cmd")
            elif text.startswith("/send "):
                path = text[6:].strip().strip('"')
                threading.Thread(
                    target=lambda: current_plugin.send_file(path),
                    daemon=True).start()
            else:
                current_plugin.send_text(text)

    threading.Thread(target=stdin_loop, daemon=True).start()

    msg = MSG()
    while not shutdown_event.is_set():
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
    return 0


def main() -> int:
    log("Demo chat DVC client host (Python) - Starting...")
    signal.signal(signal.SIGINT, lambda *_: shutdown_event.set())
    signal.signal(signal.SIGTERM, lambda *_: shutdown_event.set())
    return run_local_server()


if __name__ == "__main__":
    raise SystemExit(main())
