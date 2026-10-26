# Bidirectional chat demo - client DVC plugin.
# Same COM shape as SimplePlugin, but instead of ping/echo it:
#   - decodes length-prefixed JSON messages and prints them
#   - exposes send_text() so the host console can push messages to the server
from __future__ import annotations

import ctypes
import sys
import threading
import traceback
from ctypes import string_at, byref
from typing import Optional

from win32more._comclass import ComClass
from win32more._win32api import S_OK, E_FAIL
from win32more.Windows.Win32.System.RemoteDesktop import (
    IWTSPlugin,
    IWTSListenerCallback,
    IWTSVirtualChannelCallback,
    IWTSVirtualChannelManager,
    IWTSListener,
    IWTSVirtualChannel,
)

import os

from demo_protocol import encode, run_command, send_file, FileReceiver, StreamDecoder

CHANNEL_NAME = b"dvc::demo::chat"


def HR(x) -> int:
    if x is None:
        return 0x80004005
    try:
        return int(getattr(x, "value", x))
    except Exception:
        return 0x80004005


def _log(msg: str) -> None:
    print(msg, flush=True)


shutdown_event = threading.Event()


class DemoPlugin(ComClass, IWTSPlugin, IWTSListenerCallback, IWTSVirtualChannelCallback):
    _clsid_ = "{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}"

    def __init__(self):
        ComClass.__init__(self)
        _log("[DemoPlugin] __init__")
        self._channel: Optional[IWTSVirtualChannel] = None
        self._decoder = StreamDecoder()
        self._send_seq = 0
        self._write_lock = threading.Lock()
        self._files = FileReceiver(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "recv"))

    # ---------------- IWTSPlugin ----------------

    def Initialize(self, channel_manager) -> int:
        _log("[DemoPlugin] Initialize")
        if not channel_manager:
            return HR(E_FAIL)
        try:
            listener = IWTSListener()
            hr = channel_manager.CreateListener(CHANNEL_NAME, 0, self, byref(listener))
            _log(f"[DemoPlugin] CreateListener hr=0x{HR(hr) & 0xFFFFFFFF:08X}")
            return HR(hr)
        except Exception as e:
            _log(f"[DemoPlugin] Initialize exception: {e}")
            traceback.print_exc()
            return HR(E_FAIL)

    def Connected(self) -> int:
        _log("[DemoPlugin] Connected")
        return HR(S_OK)

    def Disconnected(self, disconnect_code: int) -> int:
        _log(f"[DemoPlugin] Disconnected code={disconnect_code}")
        return HR(S_OK)

    def Terminated(self) -> int:
        _log("[DemoPlugin] Terminated")
        shutdown_event.set()
        return HR(S_OK)

    # ------------- IWTSListenerCallback -------------

    def OnNewChannelConnection(self, channel, data, accept, callback) -> int:
        _log("[DemoPlugin] OnNewChannelConnection")
        accept[0] = False
        callback[0] = None
        if not channel:
            return HR(E_FAIL)
        try:
            self._channel = channel
            try:
                channel.AddRef()
            except Exception:
                pass
            accept[0] = True
            callback[0] = self
            _log("[DemoPlugin] channel accepted - you can now type messages")
            return HR(S_OK)
        except Exception as e:
            _log(f"[DemoPlugin] OnNewChannelConnection exception: {e}")
            traceback.print_exc()
            return HR(E_FAIL)

    # ----------- IWTSVirtualChannelCallback -----------

    def OnDataReceived(self, size: int, data_ptr) -> int:
        if not data_ptr or size <= 0:
            return HR(S_OK)
        try:
            payload = string_at(data_ptr, size)
            for msg in self._decoder.feed(payload):
                mtype = msg.get("type", "chat")
                text = msg.get("text", "")
                if mtype == "cmd":
                    _log(f"<- {msg.get('from')} cmd: {text}")
                    threading.Thread(
                        target=lambda: self.send_text(run_command(text), "result"),
                        daemon=True).start()
                elif mtype == "result":
                    _log(f"<- {msg.get('from')} result:\n{text}")
                elif mtype in ("file_start", "file_chunk", "file_end"):
                    self._files.handle(msg, _log)
                else:
                    _log(f"<- {msg.get('from')} seq={msg.get('seq')}: {text}")
        except Exception as e:
            _log(f"[DemoPlugin] OnDataReceived exception: {e}")
            traceback.print_exc()
            return HR(E_FAIL)
        return HR(S_OK)

    def OnClose(self) -> int:
        _log("[DemoPlugin] OnClose")
        self._channel = None
        return HR(S_OK)

    # ---------------- app API ----------------

    def send_msg(self, type: str, text: str = "", **fields) -> bool:
        """Send one framed message to the server side."""
        ch = self._channel
        if not ch:
            _log("[DemoPlugin] no channel yet - is the RDP session + demo_server up?")
            return False
        data = encode("client", self._send_seq, text, type, **fields)
        self._send_seq += 1
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        try:
            with self._write_lock:
                hr = ch.Write(len(data), ptr, None)
            if HR(hr) != S_OK:
                _log(f"[DemoPlugin] Write failed hr=0x{HR(hr) & 0xFFFFFFFF:08X}")
                return False
            if type in ("chat", "cmd", "result"):
                _log(f"-> server ({len(data)} bytes): {text}")
            return True
        except Exception as e:
            _log(f"[DemoPlugin] Write exception: {e}")
            traceback.print_exc()
            return False

    def send_text(self, text: str, type: str = "chat") -> bool:
        return self.send_msg(type, text)

    def send_file(self, path: str) -> bool:
        return send_file(path, self.send_msg, _log)
