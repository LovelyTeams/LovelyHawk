# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""DVC Reassembler for handling fragmented channel reads.

When using file handle mode, reads return raw PDU data with CHANNEL_PDU_HEADER.
This module reassembles fragments using CHANNEL_FLAG_FIRST and CHANNEL_FLAG_LAST.
"""

from __future__ import annotations

import ctypes
import logging
import struct
from typing import Optional

from win32more.Windows.Win32.System.RemoteDesktop import (
    CHANNEL_FLAG_FIRST,
    CHANNEL_FLAG_LAST,
    CHANNEL_PDU_HEADER,
)

_log = logging.getLogger(__name__)

# Compute header size from win32more struct
CHANNEL_PDU_HEADER_SIZE = ctypes.sizeof(CHANNEL_PDU_HEADER)

# Safety cap: max reassembled message size (16 MB, matches codec MAX_PAYLOAD_SIZE + headers)
MAX_REASSEMBLED_SIZE = 16 * 1024 * 1024


class DvcReassembler:
    """Reassembles DVC message fragments."""
    
    def __init__(self):
        self._buffer = bytearray()
        self._has_started = False
    
    def push_read(self, data: bytes) -> Optional[bytes]:
        """Parse PDU header and push fragment, return complete message if ready.
        
        The buffer format is: [length:u32][flags:u32][payload...]
        
        Args:
            data: Raw PDU data including CHANNEL_PDU_HEADER.
            
        Returns:
            Complete reassembled message, or None if incomplete.
        """
        if len(data) < CHANNEL_PDU_HEADER_SIZE:
            _log.warning("Buffer too small for PDU header: %d bytes", len(data))
            return None
        
        # Parse CHANNEL_PDU_HEADER
        # First 4 bytes: length (total message length for fragmented messages)
        # Next 4 bytes: flags
        total_length, flags = struct.unpack_from("<II", data, 0)
        
        # Payload starts after header
        payload = data[CHANNEL_PDU_HEADER_SIZE:]
        
        # Note: For fragmented messages, total_length is the complete message size,
        # not the size of this fragment's payload. The mismatch is expected.
        # We log at debug level for troubleshooting.
        if total_length != len(payload):
            _log.debug("Fragment: total_length=%d, this fragment=%d bytes, flags=0x%X",
                      total_length, len(payload), flags)
        
        return self._push_fragment(payload, flags)
    
    def push(self, payload: bytes, flags: int) -> Optional[bytes]:
        """Push fragment with flags (WTS API mode).
        
        Args:
            payload: Fragment payload (without PDU header).
            flags: Channel flags.
            
        Returns:
            Complete reassembled message, or None if incomplete.
        """
        return self._push_fragment(payload, flags)
    
    def _push_fragment(self, payload: bytes, flags: int) -> Optional[bytes]:
        """Internal: push fragment and handle reassembly logic.
        
        Args:
            payload: Fragment payload.
            flags: Channel flags.
            
        Returns:
            Complete reassembled message, or None if incomplete.
        """
        # Handle FIRST flag
        if flags & CHANNEL_FLAG_FIRST:
            if self._buffer:
                _log.warning("CHANNEL_FLAG_FIRST with in-progress buffer, "
                            "discarding %d bytes", len(self._buffer))
            self._buffer.clear()
            self._has_started = True
        elif not self._has_started:
            _log.warning("Fragment without CHANNEL_FLAG_FIRST (flags=0x%X), "
                        "discarding %d bytes", flags, len(payload))
            return None
        
        # Safety cap: prevent unbounded buffer growth from rogue peer
        if payload:
            new_size = len(self._buffer) + len(payload)
            if new_size > MAX_REASSEMBLED_SIZE:
                _log.warning("Reassembly buffer would exceed %d bytes (%d + %d), "
                            "resetting", MAX_REASSEMBLED_SIZE, len(self._buffer), len(payload))
                self.reset()
                return None
            self._buffer.extend(payload)
        
        # Handle LAST flag
        if flags & CHANNEL_FLAG_LAST:
            if not self._has_started:
                _log.warning("CHANNEL_FLAG_LAST without active buffer, discarding")
                self.reset()
                return None
            
            result = bytes(self._buffer)
            self._buffer.clear()
            self._has_started = False
            return result
        
        return None
    
    def reset(self):
        """Resets the reassembler state."""
        self._buffer.clear()
        self._has_started = False
