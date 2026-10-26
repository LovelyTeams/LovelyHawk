# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Codec for serializing and parsing PingMessage with framing.

Wire format (little-endian):
Frame: [framePayloadLen:u32][sequenceNumber:u32][utcTicks:i64][payloadLen:u32][payload...]

Where:
- framePayloadLen = MESSAGE_HEADER_SIZE + payloadLen (excludes the 4-byte prefix itself)
- MESSAGE_HEADER_SIZE = 16 bytes (seq:4 + ticks:8 + payloadLen:4)
- FRAME_HEADER_SIZE = 4 bytes (framePayloadLen)
- totalFrameSize = FRAME_HEADER_SIZE + framePayloadLen
"""

from __future__ import annotations

import struct
try:
    from collections.abc import Buffer  # Python 3.12+
except ImportError:  # Python <= 3.11: annotation-only fallback
    Buffer = bytes
from enum import IntEnum
from typing import List, Optional, Tuple, Union

from .ping_message import PingMessage


# Struct objects for speed + single source of truth for sizes
FRAME_HEADER = struct.Struct("<I")           # framePayloadLen: u32
MSG_HEADER = struct.Struct("<IqI")           # seq: u32, ticks: i64, payloadLen: u32
FRAME_WITH_MSG = struct.Struct("<IIqI")      # framePayloadLen + msg header combined

# Sizes derived from structs (cannot drift)
FRAME_HEADER_SIZE = FRAME_HEADER.size        # 4 bytes
MESSAGE_HEADER_SIZE = MSG_HEADER.size        # 16 bytes

# Default payload size (5 KB) - large enough to exercise fragmentation
DEFAULT_PAYLOAD_SIZE = 5 * 1024

# Maximum payload size to prevent absurd allocations (16 MB)
MAX_PAYLOAD_SIZE = 16 * 1024 * 1024

# Pre-computed pattern for efficient payload generation (avoids per-byte allocation)
_PATTERN_256 = bytes(range(256))


class FrameParseStatus(IntEnum):
    """Frame parsing status (IntEnum for easy logging and C-ish comparisons)."""
    OK = 0              # Frame parsed successfully
    NEED_MORE_DATA = 1  # Need more data to complete the frame
    INVALID_FRAME = 2   # Invalid frame detected


# Type alias for buffer inputs (bytes, bytearray, memoryview)
BufferLike = Union[bytes, bytearray, memoryview, Buffer]


def _generate_payload(size: int) -> bytes:
    """Generates deterministic payload pattern (0..255 repeating) efficiently.
    
    Uses pre-computed 256-byte pattern and multiplication to avoid
    per-byte allocation overhead for large payloads.
    """
    if size <= 0:
        return b""
    full_cycles, remainder = divmod(size, 256)
    return (_PATTERN_256 * full_cycles) + _PATTERN_256[:remainder]


class PingMessageCodec:
    """Codec for serializing and parsing PingMessage with framing."""
    
    @staticmethod
    def create_message(sequence_number: int, utc_ticks: int, 
                       payload_size: int = DEFAULT_PAYLOAD_SIZE) -> PingMessage:
        """Creates a PingMessage with deterministic payload pattern (0..255 repeating).
        
        Args:
            sequence_number: Sequence number for tracking (uint32).
            utc_ticks: UTC timestamp in 100ns ticks (int64).
            payload_size: Size of payload to generate.
            
        Returns:
            PingMessage with the specified values and deterministic payload.
            
        Raises:
            ValueError: If sequence_number or utc_ticks are out of wire type range.
        """
        # PingMessage.__post_init__ validates wire types
        payload_size = max(0, min(payload_size, MAX_PAYLOAD_SIZE))
        payload = _generate_payload(payload_size)
        
        return PingMessage(
            sequence_number=sequence_number,
            utc_ticks=utc_ticks,
            payload=payload
        )
    
    @staticmethod
    def serialize_with_framing(message: PingMessage) -> bytes:
        """Serializes a PingMessage with length-prefix framing.
        
        Returns: [framePayloadLen:u32][seq:u32][ticks:i64][payloadLen:u32][payload...]
        
        Note: PingMessage validates wire types in __post_init__, so no extra check needed.
        """
        payload = message.payload or b""
        payload_len = len(payload)
        frame_payload_len = MESSAGE_HEADER_SIZE + payload_len
        
        # Pack the frame header + message header
        header = FRAME_WITH_MSG.pack(
            frame_payload_len,      # excludes the 4-byte prefix itself
            message.sequence_number,
            message.utc_ticks,
            payload_len
        )
        
        return header + payload
    
    @staticmethod
    def serialize(message: PingMessage) -> bytes:
        """Serializes a PingMessage without framing.
        
        Returns: [seq:u32][ticks:i64][payloadLen:u32][payload...]
        
        Note: PingMessage validates wire types in __post_init__, so no extra check needed.
        """
        payload = message.payload or b""
        payload_len = len(payload)
        
        header = MSG_HEADER.pack(
            message.sequence_number,
            message.utc_ticks,
            payload_len
        )
        
        return header + payload
    
    @staticmethod
    def try_parse_framed(buffer: BufferLike) -> Tuple[FrameParseStatus, Optional[PingMessage], int]:
        """Tries to parse a framed PingMessage from the buffer.
        
        Args:
            buffer: Input buffer (bytes, bytearray, or memoryview).
            
        Returns:
            Tuple of (status, message, bytes_consumed).
            - status: Parse result status
            - message: Parsed message if successful, None otherwise
            - bytes_consumed: Number of bytes consumed from buffer
        """
        # Use memoryview for zero-copy slicing
        mv = memoryview(buffer) if not isinstance(buffer, memoryview) else buffer
        
        # Need at least frame header
        if len(mv) < FRAME_HEADER_SIZE:
            return (FrameParseStatus.NEED_MORE_DATA, None, 0)
        
        # Read frame payload length (excludes the 4-byte prefix)
        (frame_payload_len,) = FRAME_HEADER.unpack_from(mv, 0)
        
        # Must have at least message header within frame
        if frame_payload_len < MESSAGE_HEADER_SIZE:
            return (FrameParseStatus.INVALID_FRAME, None, 0)
        
        # Validate frame payload length
        if frame_payload_len > MAX_PAYLOAD_SIZE + MESSAGE_HEADER_SIZE:
            return (FrameParseStatus.INVALID_FRAME, None, 0)
        
        total_frame_size = FRAME_HEADER_SIZE + frame_payload_len
        
        # Check if we have complete frame
        if len(mv) < total_frame_size:
            return (FrameParseStatus.NEED_MORE_DATA, None, 0)
        
        offset = FRAME_HEADER_SIZE
        
        # Parse message header
        sequence_number, utc_ticks, payload_len = MSG_HEADER.unpack_from(mv, offset)
        offset += MESSAGE_HEADER_SIZE
        
        # Strict validation: payload_len must exactly match remaining frame bytes.
        # This catches framing bugs early. If future extensions need trailing bytes,
        # change to: payload_len <= frame_payload_len - MESSAGE_HEADER_SIZE
        expected_payload_len = frame_payload_len - MESSAGE_HEADER_SIZE
        if payload_len != expected_payload_len:
            return (FrameParseStatus.INVALID_FRAME, None, 0)
        
        if payload_len > MAX_PAYLOAD_SIZE:
            return (FrameParseStatus.INVALID_FRAME, None, 0)
        
        # Extract payload (convert slice to bytes at boundary)
        payload = bytes(mv[offset:offset + payload_len]) if payload_len > 0 else b""
        
        message = PingMessage(
            sequence_number=sequence_number,
            utc_ticks=utc_ticks,
            payload=payload
        )
        
        return (FrameParseStatus.OK, message, total_frame_size)
    
    @staticmethod
    def try_parse(buffer: BufferLike) -> Tuple[bool, Optional[PingMessage]]:
        """Tries to parse a PingMessage without framing.
        
        Args:
            buffer: Input buffer (bytes, bytearray, or memoryview).
            
        Returns:
            Tuple of (success, message).
        """
        mv = memoryview(buffer) if not isinstance(buffer, memoryview) else buffer
        
        if len(mv) < MESSAGE_HEADER_SIZE:
            return (False, None)
        
        # Parse message header
        sequence_number, utc_ticks, payload_len = MSG_HEADER.unpack_from(mv, 0)
        
        # Validate
        if payload_len > MAX_PAYLOAD_SIZE:
            return (False, None)
        
        if len(mv) < MESSAGE_HEADER_SIZE + payload_len:
            return (False, None)
        
        # Extract payload
        offset = MESSAGE_HEADER_SIZE
        payload = bytes(mv[offset:offset + payload_len]) if payload_len > 0 else b""
        
        message = PingMessage(
            sequence_number=sequence_number,
            utc_ticks=utc_ticks,
            payload=payload
        )
        
        return (True, message)
    
    @staticmethod
    def get_frame_size(payload_size: int) -> int:
        """Calculates total frame size for a given payload size."""
        return FRAME_HEADER_SIZE + MESSAGE_HEADER_SIZE + payload_size
    
    @staticmethod
    def feed(buffer: bytearray) -> List[PingMessage]:
        """Parses all complete framed messages from buffer, removing consumed bytes.
        
        This is a convenience method for stream processing / reassembly integration.
        Modifies buffer in-place by removing successfully parsed frames.
        
        Args:
            buffer: Mutable buffer to parse from. Consumed bytes are removed.
            
        Returns:
            List of parsed PingMessage objects (may be empty if no complete frames).
            
        Example:
            buf = bytearray()
            buf.extend(incoming_data)
            messages = PingMessageCodec.feed(buf)
            for msg in messages:
                handle(msg)
        """
        messages: List[PingMessage] = []
        
        while True:
            status, msg, consumed = PingMessageCodec.try_parse_framed(buffer)
            
            if status == FrameParseStatus.OK and msg is not None:
                messages.append(msg)
                del buffer[:consumed]
            elif status == FrameParseStatus.INVALID_FRAME:
                # Skip one byte and try to resync (or could raise/clear buffer)
                if buffer:
                    del buffer[:1]
            else:
                # NEED_MORE_DATA - stop parsing
                break
        
        return messages
