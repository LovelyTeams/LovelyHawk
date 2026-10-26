# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Simple DVC Plugin COM implementation.

Implements IWTSPlugin, IWTSListenerCallback, and IWTSVirtualChannelCallback
using win32more for COM interface support.
"""

from __future__ import annotations

import struct
import threading
import time
import traceback
from ctypes import string_at, byref
from typing import Any, Optional

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

from rdp_simple_plugin_protocol import (
    PingMessage,
    PingMessageCodec,
    FrameParseStatus,
)


CHANNEL_NAME = b"dvc::sample::simpleplugin"

# Windows FILETIME epoch offset
UNIX_TO_FILETIME_OFFSET = 116444736000000000
TICKS_PER_SECOND = 10000000


def utc_ticks_100ns() -> int:
    """Returns UTC ticks in 100-nanosecond intervals (Windows FILETIME epoch)."""
    unix_time = time.time()
    unix_ticks = int(unix_time * TICKS_PER_SECOND)
    return unix_ticks + UNIX_TO_FILETIME_OFFSET


def HR(x: Any) -> int:
    """Convert HRESULT to plain Python int."""
    if x is None:
        return 0x80004005  # E_FAIL
    v = getattr(x, "value", x)
    try:
        return int(v)
    except Exception:
        return 0x80004005


def _hr(x: Any) -> str:
    """Format HRESULT as unsigned 32-bit hex."""
    return f"0x{HR(x) & 0xFFFFFFFF:08X}"


def com_addref(obj: object) -> None:
    """AddRef a COM object via IUnknown."""
    try:
        getattr(obj, 'AddRef')()
    except Exception:
        pass


def com_release(obj: object) -> None:
    """Release a COM object via IUnknown."""
    try:
        getattr(obj, 'Release')()
    except Exception:
        pass


def _log(msg: str) -> None:
    print(msg, flush=True)


shutdown_event = threading.Event()


class SimplePlugin(ComClass, IWTSPlugin, IWTSListenerCallback, IWTSVirtualChannelCallback):
    """Simple DVC plugin implementing ping/echo."""
    
    # CLSID must match cpp/dotnet implementations
    _clsid_ = "{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}"

    def __init__(self):
        ComClass.__init__(self)
        _log("[SimplePlugin] __init__")

        self._listener: Optional[IWTSListener] = None
        self._channel_mgr: Optional[IWTSVirtualChannelManager] = None
        self._channel: Optional[IWTSVirtualChannel] = None
        self._channel_ref_held: bool = False

    # ---------------- IWTSPlugin ----------------

    def Initialize(self, channel_manager: IWTSVirtualChannelManager) -> int:
        _log("[SimplePlugin] Initialize")

        if not channel_manager:
            _log("[SimplePlugin] Initialize: channel_manager is null")
            return HR(E_FAIL)

        self._channel_mgr = channel_manager

        try:
            listener = IWTSListener()
            hr = channel_manager.CreateListener(
                CHANNEL_NAME,
                0,
                self,
                byref(listener)
            )
            _log(f"[SimplePlugin] CreateListener hr={_hr(hr)}")

            if hr == S_OK:
                self._listener = listener
                _log("[SimplePlugin] Listener created for channel: dvc::sample::simpleplugin")
                return HR(S_OK)

            return HR(hr)

        except Exception as e:
            _log(f"[SimplePlugin] Initialize exception: {e}")
            traceback.print_exc()
            return HR(E_FAIL)

    def Connected(self) -> int:
        _log("[SimplePlugin] Connected")
        return HR(S_OK)

    def Disconnected(self, disconnect_code: int) -> int:
        _log(f"[SimplePlugin] Disconnected code={disconnect_code}")
        return HR(S_OK)

    def Terminated(self) -> int:
        _log("[SimplePlugin] Terminated")
        shutdown_event.set()
        return HR(S_OK)

    # ------------- IWTSListenerCallback -------------

    def OnNewChannelConnection(self, channel, data, accept, callback) -> int:
        _log("[SimplePlugin] OnNewChannelConnection")

        accept[0] = False
        callback[0] = None

        if not channel:
            _log("[SimplePlugin] OnNewChannelConnection: channel is null")
            return HR(E_FAIL)

        try:
            self._release_channel_if_held(reason="replaced by new channel")

            self._channel = channel
            com_addref(self._channel)
            self._channel_ref_held = True
            _log("[SimplePlugin] Channel AddRef held")

            accept[0] = True
            callback[0] = self
            _log("[SimplePlugin] Accepted channel connection")

            return HR(S_OK)

        except Exception as e:
            _log(f"[SimplePlugin] OnNewChannelConnection exception: {e}")
            traceback.print_exc()
            self._release_channel_if_held(reason="OnNewChannelConnection failure")
            accept[0] = False
            callback[0] = None
            return HR(E_FAIL)

    # ----------- IWTSVirtualChannelCallback -----------

    def OnDataReceived(self, size: int, data_ptr) -> int:
        _log(f"[SimplePlugin] OnDataReceived size={size}")

        if not data_ptr or size <= 0:
            return HR(S_OK)

        try:
            payload = string_at(data_ptr, size)
        except Exception as e:
            _log(f"[SimplePlugin] string_at failed: {e}")
            return HR(E_FAIL)

        # Parse the ping message
        status, message, _ = PingMessageCodec.try_parse_framed(payload)
        if status == FrameParseStatus.OK and message:
            now = utc_ticks_100ns()
            rtt = max(0, now - message.utc_ticks)
            rtt_ms = rtt / 10000.0

            _log(f"[SimplePlugin] Received ping seq={message.sequence_number}, "
                 f"payload={len(message.payload)} bytes, RTT={rtt_ms:.2f} ms")
        else:
            _log(f"[SimplePlugin] Received {size} bytes (raw)")

        # Echo the data back
        ch = self._channel
        if not ch:
            _log("[SimplePlugin] No channel to echo back")
            return HR(S_OK)

        try:
            hr = ch.Write(size, data_ptr, None)
            if hr != S_OK:
                _log(f"[SimplePlugin] Write failed hr={_hr(hr)}")
                return HR(hr)
            _log(f"[SimplePlugin] Echoed {size} bytes")
            return HR(S_OK)
        except Exception as e:
            _log(f"[SimplePlugin] Write exception: {e}")
            traceback.print_exc()
            return HR(E_FAIL)

    def OnClose(self) -> int:
        _log("[SimplePlugin] OnClose")
        self._release_channel_if_held(reason="OnClose")
        return HR(S_OK)

    # ---------------- helpers ----------------

    def _release_channel_if_held(self, reason: str) -> None:
        """Release the extra AddRef we took on the channel."""
        if self._channel and self._channel_ref_held:
            try:
                _log(f"[SimplePlugin] Releasing channel (reason: {reason})")
                com_release(self._channel)
            except Exception as e:
                _log(f"[SimplePlugin] Channel Release exception: {e}")
            finally:
                self._channel_ref_held = False
                self._channel = None
        else:
            self._channel = None
            self._channel_ref_held = False
