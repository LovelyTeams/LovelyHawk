# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Simple DVC server that runs inside an RDP session.

Features:
- WTS API mode (default): Uses WTSVirtualChannelRead/Write
- File handle mode (--filehandle): Uses ReadFile/WriteFile with OVERLAPPED I/O
- Ping/echo loop with RTT measurement
"""

from __future__ import annotations

import ctypes
import logging
import os
import signal
import struct
import threading
import time
from ctypes import wintypes
from queue import Queue, Empty, Full
from typing import Optional

from rdp_simple_plugin_protocol import (
    PingMessageCodec,
    FrameParseStatus,
    DEFAULT_PAYLOAD_SIZE,
)

# --- win32more imports (replace native_methods) ---
from win32more.Windows.Win32.Foundation import (
    CloseHandle,
    GetLastError,
    HANDLE,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    ERROR_IO_PENDING,
    ERROR_BROKEN_PIPE,
    ERROR_PIPE_NOT_CONNECTED,
    ERROR_INVALID_HANDLE,
)

from win32more.Windows.Win32.System.RemoteDesktop import (
    WTSVirtualChannelOpenEx,
    WTSVirtualChannelClose,
    WTSVirtualChannelRead,
    WTSVirtualChannelWrite,
    WTSVirtualChannelQuery,
    WTSFreeMemory,
    WTSVirtualFileHandle,
    WTS_CURRENT_SESSION,
    WTS_CHANNEL_OPTION_DYNAMIC,
    CHANNEL_FLAG_FIRST,
    CHANNEL_FLAG_LAST,
    CHANNEL_PDU_HEADER,
)

from win32more.Windows.Win32.System.Threading import (
    CreateEventW,
    ResetEvent,
    WaitForSingleObject,
    INFINITE,
)

from win32more.Windows.Win32.Storage.FileSystem import (
    ReadFile,
    WriteFile,
)

from win32more.Windows.Win32.System.IO import CancelIoEx, GetOverlappedResult, OVERLAPPED

# Compute header size from win32more struct
CHANNEL_PDU_HEADER_SIZE = ctypes.sizeof(CHANNEL_PDU_HEADER)


# Handle both module execution (-m) and direct execution (PyInstaller)
try:
    from .dvc_reassembler import DvcReassembler
except ImportError:
    from dvc_reassembler import DvcReassembler

_log = logging.getLogger(__name__)


CHANNEL_NAME = "dvc::sample::simpleplugin"
PING_INTERVAL_MS = 1000
WTS_READ_TIMEOUT_MS = 10000
READ_BUFFER_SIZE = 4096
MAX_WRITE_QUEUE_SIZE = 100

# Chunked wait timeout for interruptible waits (ms)
WAIT_CHUNK_MS = 500

# Windows FILETIME epoch offset (ticks from 1601-01-01 to 1970-01-01)
UNIX_TO_FILETIME_OFFSET = 116444736000000000


def utc_ticks_100ns() -> int:
    """Returns UTC ticks in 100-nanosecond intervals (Windows FILETIME epoch)."""
    # time.time_ns() avoids floating point drift
    unix_ticks = time.time_ns() // 100  # ns -> 100ns ticks
    return unix_ticks + UNIX_TO_FILETIME_OFFSET


class SimpleServer:
    """Simple DVC server that runs inside an RDP session."""
    
    def __init__(self, use_file_handle: bool = False):
        self._use_file_handle = use_file_handle
        self._channel: Optional[int] = None
        self._file_handle: Optional[int] = None
        self._read_event: Optional[int] = None
        self._write_event: Optional[int] = None
        self._sequence = 1
        self._reassembler = DvcReassembler()
        self._stop = threading.Event()
        self._write_queue: Queue[bytes] = Queue(maxsize=MAX_WRITE_QUEUE_SIZE)
        self._read_thread: Optional[threading.Thread] = None
        self._write_thread: Optional[threading.Thread] = None
    
    def run(self) -> int:
        """Main entry point. Returns exit code."""
        _log.info("Starting. PID=%d", os.getpid())
        _log.info("Mode: %s", 'File Handle' if self._use_file_handle else 'WTS API')
        
        # Install Ctrl+C handler
        def signal_handler(sig, frame):
            _log.info("Ctrl+C received, exiting...")
            self._stop.set()
            if self._file_handle:
                CancelIoEx(self._file_handle, None)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGBREAK, signal_handler)
        
        # Open channel
        if not self._open_channel():
            _log.error("Failed to open channel")
            return 1
        
        try:
            if self._use_file_handle:
                self._run_file_handle_mode()
            else:
                self._run_wts_api_mode()
        finally:
            self._cleanup()
        
        _log.info("Exit.")
        return 0
    
    def _open_channel(self) -> bool:
        """Opens the DVC channel."""
        mode_str = "filehandle" if self._use_file_handle else "wts"
        _log.info("Opening DVC '%s' mode=%s", CHANNEL_NAME, mode_str)
        
        # Open the DVC channel (win32more expects bytes for LPSTR parameter)
        handle = WTSVirtualChannelOpenEx(
            WTS_CURRENT_SESSION,
            CHANNEL_NAME.encode('ascii'),
            WTS_CHANNEL_OPTION_DYNAMIC
        )
        
        if not handle:
            _log.error("WTSVirtualChannelOpenEx failed: %d", GetLastError())
            return False
        
        self._channel = handle
        
        if self._use_file_handle:
            # Query file handle for overlapped I/O
            # WTSVirtualChannelQuery allocates a buffer containing the HANDLE value
            buffer_ptr = ctypes.c_void_p()
            bytes_returned = wintypes.DWORD(0)
            ok = WTSVirtualChannelQuery(
                handle,
                WTSVirtualFileHandle,
                ctypes.byref(buffer_ptr),
                ctypes.byref(bytes_returned)
            )
            
            if not ok or not buffer_ptr.value:
                _log.error("WTSVirtualChannelQuery(WTSVirtualFileHandle) failed: %d", GetLastError())
                WTSVirtualChannelClose(handle)
                self._channel = None
                return False
            
            # Dereference the buffer to get the actual HANDLE (buffer contains HANDLE*)
            if bytes_returned.value != ctypes.sizeof(ctypes.c_void_p):
                _log.error("WTSVirtualChannelQuery unexpected size: %d", bytes_returned.value)
                WTSFreeMemory(buffer_ptr.value)
                WTSVirtualChannelClose(handle)
                self._channel = None
                return False
            
            self._file_handle = ctypes.cast(buffer_ptr.value, ctypes.POINTER(ctypes.c_void_p)).contents.value
            WTSFreeMemory(buffer_ptr.value)
            _log.info("File handle acquired: 0x%X", self._file_handle)
            
            # Create events for overlapped I/O
            self._read_event = CreateEventW(None, True, False, None)
            self._write_event = CreateEventW(None, True, False, None)
            
            if not self._read_event or not self._write_event:
                _log.error("CreateEvent failed: %d", GetLastError())
                WTSVirtualChannelClose(handle)
                self._channel = None
                return False
            
            _log.info("File-handle mode activated")
        else:
            _log.info("WTS API mode activated")
        
        return True
    
    def _cleanup(self):
        """Unified cleanup: stop threads, cancel I/O, close handles in safe order.
        
        Order matters:
        1. Signal stop
        2. Cancel pending I/O (best-effort)
        3. Join threads (if started)
        4. Close channel (releases file handle)
        5. Close events (after threads are done using them)
        """
        self._stop.set()
        
        # Cancel pending I/O (best-effort, may already be closed)
        if self._file_handle:
            try:
                CancelIoEx(self._file_handle, None)
            except Exception:
                pass  # Handle may already be invalid
        
        # Join threads with timeout
        if self._read_thread and self._read_thread.is_alive():
            self._read_thread.join(timeout=1.0)
        if self._write_thread and self._write_thread.is_alive():
            self._write_thread.join(timeout=1.0)
        
        # Close channel (this also invalidates file_handle)
        if self._channel:
            WTSVirtualChannelClose(self._channel)
            self._channel = None
            self._file_handle = None
            _log.info("Channel closed")
        
        # Close events last (after threads are done)
        if self._read_event:
            CloseHandle(self._read_event)
            self._read_event = None
        
        if self._write_event:
            CloseHandle(self._write_event)
            self._write_event = None
    
    def _build_ping_frame(self) -> tuple[bytes, int]:
        """Builds a ping frame with the current sequence number.
        
        Returns:
            Tuple of (framed_message, sequence_number).
        """
        seq = self._sequence
        self._sequence += 1
        ticks = utc_ticks_100ns()
        msg = PingMessageCodec.create_message(seq, ticks, DEFAULT_PAYLOAD_SIZE)
        return (PingMessageCodec.serialize_with_framing(msg), seq)
    
    def _handle_received_payload(self, data: bytes):
        """Handles a complete reassembled payload.
        
        Note: This assumes one framed message per reassembled payload.
        If batching multiple frames, use PingMessageCodec.feed() instead.
        """
        status, message, _ = PingMessageCodec.try_parse_framed(data)
        
        if status == FrameParseStatus.OK and message:
            now = utc_ticks_100ns()
            rtt = max(0, now - message.utc_ticks)
            rtt_ms = rtt / 10000.0  # 100ns ticks to ms
            
            _log.info("Received echo seq=%d, payload=%d bytes, RTT=%.2f ms",
                     message.sequence_number, len(message.payload), rtt_ms)
        else:
            _log.warning("Failed to parse received message")
    
    # -------------------------------------------------------------------------
    # WTS API Mode
    # -------------------------------------------------------------------------
    
    def _run_wts_api_mode(self):
        """Runs the server in WTS API mode (synchronous)."""
        _log.info("Entering WTS ping/echo loop (Ctrl+C to exit)...")
        
        while not self._stop.is_set():
            if not self._channel:
                _log.info("Channel closed, exiting.")
                break
            
            # Send ping
            framed, seq = self._build_ping_frame()
            if not framed:
                _log.error("Failed to build ping frame")
                break
            
            bytes_written = wintypes.DWORD(0)
            result = WTSVirtualChannelWrite(
                self._channel,
                framed,
                len(framed),
                ctypes.byref(bytes_written)
            )
            if not result:
                _log.error("WTSVirtualChannelWrite failed: %d", GetLastError())
                break
            
            _log.info("Sent ping seq=%d, size=%d", seq, len(framed))
            
            # Read response
            self._reassembler.reset()
            if not self._read_and_handle_response_wts():
                break
            
            # Wait for next ping interval (interruptible)
            self._stop.wait(PING_INTERVAL_MS / 1000.0)
    
    def _read_and_handle_response_wts(self) -> bool:
        """Reads and handles response in WTS API mode."""
        while True:
            buffer = ctypes.create_string_buffer(READ_BUFFER_SIZE)
            bytes_read = wintypes.DWORD(0)
            
            result = WTSVirtualChannelRead(
                self._channel,
                WTS_READ_TIMEOUT_MS,
                buffer,
                READ_BUFFER_SIZE,
                ctypes.byref(bytes_read)
            )
            
            if not result:
                _log.error("WTSVirtualChannelRead failed: %d", GetLastError())
                return False
            
            if bytes_read.value == 0:
                _log.info("Channel closed (read 0)")
                return False
            
            # Convert buffer to bytes
            data = buffer.raw[:bytes_read.value]
            
            # WTS API provides CHANNEL_PDU_HEADER (8 bytes) + payload
            if len(data) < CHANNEL_PDU_HEADER_SIZE:
                _log.warning("Read too few bytes: %d", len(data))
                continue
            
            # Parse header to get flags
            flags = struct.unpack_from("<I", data, 4)[0]
            payload = data[CHANNEL_PDU_HEADER_SIZE:]
            
            full = self._reassembler.push(payload, flags)
            if full:
                self._handle_received_payload(full)
                return True
    
    # -------------------------------------------------------------------------
    # File Handle Mode
    # -------------------------------------------------------------------------
    
    def _run_file_handle_mode(self):
        """Runs the server in file handle mode (async overlapped I/O)."""
        _log.info("Entering file-handle mode (Ctrl+C to exit)...")
        
        if not self._read_event or not self._write_event:
            _log.error("Events not initialized")
            return
        
        # Start read/write threads
        self._read_thread = threading.Thread(target=self._file_handle_read_loop, daemon=True)
        self._write_thread = threading.Thread(target=self._file_handle_write_loop, daemon=True)
        self._read_thread.start()
        self._write_thread.start()
        
        # Ping loop on main thread
        while not self._stop.is_set():
            if not self._channel:
                break
            
            framed, seq = self._build_ping_frame()
            if framed:
                try:
                    self._write_queue.put_nowait(framed)
                    _log.info("Queued ping seq=%d", seq)
                except Full:
                    _log.warning("Write queue full, dropping message")
            
            self._stop.wait(PING_INTERVAL_MS / 1000.0)
        
        # Note: Thread cleanup is handled by _cleanup() in the finally block
        _log.info("File-handle mode exiting")
    
    def _file_handle_read_loop(self):
        """Read loop for file handle mode."""
        _log.info("Read loop started")
        
        reassembler = DvcReassembler()
        
        while not self._stop.is_set():
            if not self._file_handle:
                break
            
            buffer = (ctypes.c_ubyte * READ_BUFFER_SIZE)()
            bytes_read = wintypes.DWORD(0)
            
            ResetEvent(self._read_event)
            
            overlapped = OVERLAPPED()
            overlapped.hEvent = self._read_event
            
            ok = ReadFile(
                self._file_handle,
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                READ_BUFFER_SIZE,
                ctypes.byref(bytes_read),
                ctypes.byref(overlapped)
            )
            
            if not ok:
                error = GetLastError()
                if error == ERROR_IO_PENDING:
                    # Wait in chunks for interruptibility
                    while not self._stop.is_set():
                        wait_result = WaitForSingleObject(self._read_event, WAIT_CHUNK_MS)
                        if wait_result == WAIT_OBJECT_0:
                            break
                        elif wait_result == WAIT_TIMEOUT:
                            continue  # Check _stop and retry
                        else:
                            _log.warning("Unexpected wait result: %d", wait_result)
                            break
                    
                    if self._stop.is_set():
                        break
                    
                    if not GetOverlappedResult(
                        self._file_handle,
                        ctypes.byref(overlapped),
                        ctypes.byref(bytes_read),
                        False
                    ):
                        error = GetLastError()
                        if error in (ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, ERROR_INVALID_HANDLE):
                            _log.info("ReadFile: channel closed")
                        else:
                            _log.error("GetOverlappedResult(read) failed: %d", error)
                        break
                else:
                    if error in (ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, ERROR_INVALID_HANDLE):
                        _log.info("ReadFile: channel closed")
                    else:
                        _log.error("ReadFile failed: %d", error)
                    break
            
            cb = bytes_read.value
            if cb == 0:
                _log.info("Channel closed (read 0)")
                break
            
            # Process received data (convert c_ubyte array to bytes)
            data = bytes(buffer[:cb])
            full = reassembler.push_read(data)
            if full:
                self._handle_received_payload(full)
        
        _log.info("Read loop exited")
    
    def _file_handle_write_loop(self):
        """Write loop for file handle mode."""
        _log.info("Write loop started")
        
        while not self._stop.is_set():
            try:
                data = self._write_queue.get(timeout=0.1)
            except Empty:
                continue
            
            if self._stop.is_set() or not self._file_handle:
                break
            
            ResetEvent(self._write_event)
            
            overlapped = OVERLAPPED()
            overlapped.hEvent = self._write_event
            
            # Create c_ubyte buffer from data bytes
            buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            bytes_written = wintypes.DWORD(0)
            
            ok = WriteFile(
                self._file_handle,
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                len(data),
                ctypes.byref(bytes_written),
                ctypes.byref(overlapped)
            )
            
            if not ok:
                error = GetLastError()
                if error == ERROR_IO_PENDING:
                    # Wait in chunks for interruptibility
                    while not self._stop.is_set():
                        wait_result = WaitForSingleObject(self._write_event, WAIT_CHUNK_MS)
                        if wait_result == WAIT_OBJECT_0:
                            break
                        elif wait_result == WAIT_TIMEOUT:
                            continue  # Check _stop and retry
                        else:
                            _log.warning("Unexpected wait result: %d", wait_result)
                            break
                    
                    if self._stop.is_set():
                        break
                    
                    if not GetOverlappedResult(
                        self._file_handle,
                        ctypes.byref(overlapped),
                        ctypes.byref(bytes_written),
                        False
                    ):
                        _log.error("GetOverlappedResult(write) failed: %d", GetLastError())
                        break
                else:
                    _log.error("WriteFile failed: %d", error)
                    break
        
        _log.info("Write loop exited")
